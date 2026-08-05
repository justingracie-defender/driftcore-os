"""
one_door.py — ONE DOOR: a single constitutional decider for the kernel stack.

WHAT CHANGED AND WHY (one-door consolidation)
─────────────────────────────────────────────
Before this module, the repo had TWO enforcement stacks that grew independently:

    kernel/        safety_kernel.py -> kernel/invariants.py   (keyword lists)
    verification/  coordinator.py   -> verification/invariant_guard.py (effects)

Two deciders is worse than either alone: the caller picks the door, so the
system's real posture is the WEAKER guard. And neither invariant set was a
superset of the other, so each door missed lines the other held.

After this module:

    DECIDER  — verification.invariant_guard.InvariantGuard, and nothing else.
               Its invariant set was unioned first (SELF_MODIFICATION added;
               lethal text backstop added) so it is a superset of everything
               the kernel guard ever blocked.
    SENSOR   — the old keyword guard (kernel/invariants.py) still runs on
               every action, still narrates and records, and DECIDES NOTHING.
               Its agreement/disagreement with the decider is counted.

WHY KEEP THE SENSOR AT ALL
──────────────────────────
The consolidation moves the trust boundary from "can we parse English" to
"is the effect table right". The dominant residual risk is therefore a missing
or wrong declaration — so a free, dumb, independent detector pointed at obvious
harmful phrasing is aimed at exactly the new biggest risk. A fooled tripwire's
worst case is silence, which is where we'd be without it. Semantics:

    tripwire fired, door blocked   -> agreement; expected on literal phrasing.
    tripwire fired, door allowed   -> DECIDER REGRESSION or vocabulary gap.
                                      This is the alarm this sensor exists for.
    tripwire error                 -> counted separately. A dead sensor must be
                                      distinguishable from an agreeing sensor
                                      (red-team finding F7: a crashed tripwire
                                      that counts as agreement is theater).

CUT CONDITION: if measurements show fired==0 disagreements over a long window
while the effect registry matures, delete the sensor and record why in the
changelog. A tripwire is a hypothesis that coverage gaps exist; when the data
stops supporting it, one source of truth wins again.

FAIL-CLOSED EVERYWHERE: any internal error in the door is a BLOCK, never an
allow. The sensor is the only component wrapped to never raise AND never block.
"""

from datetime import datetime
from typing import Optional

from driftcore.kernel.invariants import InvariantGuard as _KeywordGuard
from driftcore.kernel.invariants import INVARIANTS, classify
from driftcore.verification.invariant_guard import (
    InvariantGuard as _ConstitutionalGuard,
    ActionContext, Effect, GuardStatus, load_guard,
)

# How a kernel-vocabulary hit translates into the decider's effect vocabulary.
# classify() can only ever return these four invariant names, and every one of
# them maps to an ABSOLUTE effect, so a tripwire-visible violation is always a
# decider-visible violation. That containment is what makes the door a strict
# superset of the old kernel guard — proven in test_one_door.py, not assumed.
_KERNEL_EFFECT_FOR = {
    "NO_AUTONOMOUS_LETHAL_DECISION":       Effect.LETHAL,
    "HUMAN_OVERSIGHT_CANNOT_BE_DISABLED":  Effect.OVERSIGHT_CONTROL,
    "NO_SELF_MODIFICATION_OF_SAFETY_RULES": Effect.SELF_MODIFICATION,
    "AUDIT_CHAIN_CANNOT_BE_DELETED":       Effect.LOG_MUTATION,
}

_DISAGREEMENT_CAP = 200   # keep the log bounded; oldest entries roll off

# Human-authored effect tags are the mechanism this whole design trusts most, so
# a mistyped tag must never fail OPEN. The cold red-team pass found effects=
# ["LETHAL"] (enum NAME, not value "lethal") silently contributed no effect and
# the action was ALLOWED. We accept the value ("lethal"), the NAME ("LETHAL"),
# and any case of either; anything else raises, and decide() turns that into a
# fail-closed block rather than a silent drop.
_EFFECT_BY_VALUE = {e.value.lower(): e for e in Effect}
_EFFECT_BY_NAME  = {e.name.lower():  e for e in Effect}


def _coerce_effect(raw) -> Effect:
    key = str(raw).strip().lower()
    if key in _EFFECT_BY_VALUE:
        return _EFFECT_BY_VALUE[key]
    if key in _EFFECT_BY_NAME:
        return _EFFECT_BY_NAME[key]
    raise ValueError(
        f"uninterpretable effect tag {raw!r}: not a known Effect value or name. "
        f"Fail closed — a safety tag the floor cannot read must not be dropped.")


class KeywordTripwire:
    """
    Wraps the keyword guard as a pure sensor. NEVER raises. NEVER decides.

    counters:
        fired  — the keyword guard would have blocked
        silent — it would have allowed
        error  — it crashed; counted separately so a dead sensor is visible
                 (a broken tripwire that looks like agreement is worse than
                 no tripwire — it's monitoring theater).
    """

    def __init__(self, narrator=None, audit=None,
                 guard: Optional[_KeywordGuard] = None):
        self.guard = guard if guard is not None else _KeywordGuard(
            narrator=narrator, audit=audit)
        self.counts = {"fired": 0, "silent": 0, "error": 0}

    def observe(self, action: dict) -> dict:
        try:
            result = self.guard.check(action)
            # A sensor whose return shape has drifted is a BROKEN sensor, not an
            # agreeing one. The cold pass found a guard returning {"nonsense":1}
            # was counted as "silent" — indistinguishable from health. Require the
            # contract explicitly; anything off-contract is an error.
            if not isinstance(result, dict) or "status" not in result:
                self.counts["error"] += 1
                return {"fired": False, "error": f"off-contract return: {result!r}",
                        "invariant": None, "reason": None}
            if result.get("status") == "BLOCKED_BY_INVARIANT":
                self.counts["fired"] += 1
                return {"fired": True, "error": None,
                        "invariant": result.get("invariant"),
                        "reason": result.get("reason")}
            self.counts["silent"] += 1
            return {"fired": False, "error": None,
                    "invariant": None, "reason": None}
        except Exception as e:   # a sensor must never take the system down
            self.counts["error"] += 1
            return {"fired": False, "error": repr(e),
                    "invariant": None, "reason": None}

    def measurements(self) -> dict:
        return dict(self.counts)


class ConstitutionalDoor:
    """
    The single decision point for the kernel stack.

    decide() pipeline:
      1. Collect structural effects: explicit action["effects"] and human-
         declared tool_effects (actuator_id / command lookup). Structural tags
         are the real defense; text never overrides them.
      2. Translate constitutional vocabulary: classify(action) — the exact
         signal lists + flags the kernel guard has always used — mapped into
         decider Effects via _KERNEL_EFFECT_FOR. Preserves every block the old
         kernel stack made, through the new decider.
      3. THE decision: verification InvariantGuard.evaluate(). Nothing else
         can block or allow.
      4. Belt: if step 2 named an invariant but the decider allowed, FAIL
         CLOSED and log the internal disagreement. Structurally unreachable
         today (all four mappings are ABSOLUTE effects); exists so future
         drift in the mapping is a visible block, not a silent hole.
      5. Sensor: tripwire observes the same action. Recorded, counted,
         compared — never consulted for the decision.
    Any internal error in the door itself -> BLOCKED (fail closed).
    """

    def __init__(self, guard: Optional[_ConstitutionalGuard] = None,
                 tripwire: Optional[KeywordTripwire] = None,
                 narrator=None, audit=None,
                 tool_effects: Optional[dict] = None):
        self.guard = guard if guard is not None else load_guard()
        self.tripwire = tripwire if tripwire is not None else KeywordTripwire(
            narrator=narrator, audit=audit)
        self.narrator = narrator
        self.audit = audit
        self.tool_effects = dict(tool_effects or {})
        self.disagreements: list = []
        self.decisions = {"allowed": 0, "blocked": 0, "door_error": 0}

    # ── internals ────────────────────────────────────────────────

    def _structural_effects(self, action: dict) -> set:
        effects = set()
        for e in action.get("effects", ()) or ():
            if isinstance(e, Effect):
                effects.add(e)
                continue
            effects.add(_coerce_effect(e))   # raises on the uninterpretable;
                                             # decide() then fails CLOSED. A tag
                                             # the floor cannot read is a tag it
                                             # must not silently drop.
        for key in (action.get("actuator_id"), action.get("command")):
            if key is not None and key in self.tool_effects:
                effects |= set(self.tool_effects[key])
        return effects

    def _note_disagreement(self, kind: str, action: dict, detail: dict):
        entry = {"timestamp": datetime.utcnow().isoformat(),
                 "kind": kind, "action": action, **detail}
        self.disagreements.append(entry)
        if len(self.disagreements) > _DISAGREEMENT_CAP:
            del self.disagreements[:len(self.disagreements) - _DISAGREEMENT_CAP]
        if self.audit:
            self.audit.record("ONE_DOOR_DISAGREEMENT", kind, entry)

    def _blocked_response(self, action: dict, invariant_name: str,
                          reason: str, binding: Optional[str],
                          narrate: bool) -> dict:
        meta = INVARIANTS.get(invariant_name, {})
        entry = {
            "timestamp":     datetime.utcnow().isoformat(),
            "status":        "BLOCKED_BY_INVARIANT",
            "invariant":     invariant_name,
            "binding_invariant": binding,
            "reason":        reason,
            "action":        action,
            "rule":          meta.get("rule", ""),
            "plain_english": meta.get("plain_english", ""),
            "lesson":        meta.get("lesson", ""),
            "decider":       "verification.invariant_guard.InvariantGuard",
        }
        if narrate and self.narrator:
            self.narrator._emit(
                f"[one-door] BLOCKED — {invariant_name}: {reason}",
                is_warning=True)
        if self.audit:
            self.audit.record("INVARIANT_VIOLATION",
                              f"{invariant_name}: {reason}", entry)
        return entry

    # ── the decision ─────────────────────────────────────────────

    def decide(self, action: dict) -> dict:
        try:
            action = action if isinstance(action, dict) else {"action": str(action)}

            # Sanitize the view classify()/the sensor see. Strip "effects"
            # (structured, handled by _structural_effects). Strip "context" ONLY
            # when it is a real ActionContext — its dataclass repr contains
            # "target_authorized", whose "target" once made the door block its
            # own plumbing. But a PLAIN-DICT context is caller-supplied data, not
            # framework plumbing: a cold review (G1) showed harmful content placed
            # only inside a plain-dict context walked through. So a non-ActionContext
            # context stays IN the classified view.
            def _is_plumbing(key, val):
                if key == "effects":
                    return True
                if key == "context":
                    return isinstance(val, ActionContext)
                return False
            k_view = {k: v for k, v in action.items() if not _is_plumbing(k, v)}

            # 1-2. Effects: structural first, constitutional vocabulary second.
            effects = self._structural_effects(action)
            kernel_verdict = classify(k_view)
            if kernel_verdict is not None:
                k_name, _k_reason = kernel_verdict
                mapped = _KERNEL_EFFECT_FOR.get(k_name)
                if mapped is not None:
                    effects.add(mapped)

            # Authorization context, if the caller supplied a real one.
            ctx = action.get("context")
            if not isinstance(ctx, ActionContext):
                ctx = ActionContext()

            # 3. THE decision.
            result = self.guard.evaluate(
                action=str(action.get("action", action)),
                effect=effects or None,
                context=ctx,
            )

            if not result.permitted:
                self.decisions["blocked"] += 1
                invariant_name = (kernel_verdict[0] if kernel_verdict
                                  else (result.binding_invariant or "CONSTITUTIONAL_FLOOR"))
                reason = (kernel_verdict[1] if kernel_verdict else result.reason)
                sensed = self.tripwire.observe(k_view)   # 5. sensor, after the fact
                if sensed["error"]:
                    self._note_disagreement("tripwire_error", action,
                                            {"error": sensed["error"]})
                # Narrate only if the sensor did not (it narrates its own hits).
                return self._blocked_response(
                    k_view, invariant_name, reason,
                    binding=result.binding_invariant,
                    narrate=not sensed["fired"])

            # 4. Belt: classified as constitutional but decider allowed.
            if kernel_verdict is not None:
                self.decisions["blocked"] += 1
                self._note_disagreement("decider_allowed_classified_action",
                                        action, {"invariant": kernel_verdict[0],
                                                 "guard_reason": result.reason})
                sensed = self.tripwire.observe(k_view)
                return self._blocked_response(
                    k_view, kernel_verdict[0],
                    kernel_verdict[1] + " (fail-closed: decider disagreed "
                    "with constitutional classification)",
                    binding="__one_door_belt__",
                    narrate=not sensed["fired"])

            # ALLOWED. 5. Sensor still observes; a fired sensor here is the alarm.
            sensed = self.tripwire.observe(k_view)
            if sensed["error"]:
                self._note_disagreement("tripwire_error", action,
                                        {"error": sensed["error"]})
            elif sensed["fired"]:
                self._note_disagreement("tripwire_only", action,
                                        {"invariant": sensed["invariant"],
                                         "reason": sensed["reason"]})
            self.decisions["allowed"] += 1
            return {"status": "ALLOW",
                    "decider": "verification.invariant_guard.InvariantGuard",
                    "effects": sorted(e.value for e in effects)}

        except Exception as e:
            # The door itself failing is a halt condition, never a pass.
            self.decisions["door_error"] += 1
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "status": "BLOCKED_BY_INVARIANT",
                "invariant": "__door_error__",
                "binding_invariant": "__door_error__",
                "reason": f"one-door decider could not evaluate the action and "
                          f"fails closed: {e!r}",
                "action": str(action),
                "rule": "", "plain_english": "", "lesson": "",
                "decider": "one_door.fail_closed",
            }

    def measurements(self) -> dict:
        return {"tripwire": self.tripwire.measurements(),
                "decisions": dict(self.decisions),
                "disagreements": len(self.disagreements)}
