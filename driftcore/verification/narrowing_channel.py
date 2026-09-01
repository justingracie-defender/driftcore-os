"""
narrowing_channel.py — conversation may shrink the action space. It may never grow it.

WHY THE ASYMMETRY IS THE WHOLE DESIGN
--------------------------------------
"No conversational input can change what the robot is permitted to do" is too strong,
and a reviewer was right to push on it: talking a machine OUT of a dangerous action is
one of the few levers a bystander has. A visitor who says "that's a child, not an
adult" or "use the lower-force grasp" is doing something valuable, and a system that
cannot hear it is worse, not safer.

But look at what those inputs actually do. They supply a fact that changes a risk
estimate, or they select among options ALREADY permitted, or they invoke a constraint
that ALREADY exists. None of them needs the power to ADD a permission. So the rule is
one-way:

    conversation may RESTRICT the permitted set, or activate a constraint that is
    already present. It may never EXPAND the set, relax an envelope, or create a
    constraint that was not there.

Blocking privilege escalation through natural language costs nothing that talking a
system down actually requires.

WHY PROVENANCE IS DELIBERATELY IGNORED
---------------------------------------
Anthropic and EPFL, arXiv:2608.10218 (10 Aug 2026), evolved self-propagating payloads
that pass between agents through the editable prompt files that harnesses use to carry
state across sessions — surviving context wipes, and mutating as they spread. The
obvious defence is to authenticate the chain: who said this, and who told them.

That defence loses. A chain of N agents each behaving correctly can still relay an
infected payload, and every hop looks trustworthy from the next one's position.

So this module does not ask who is speaking, or through how many hops. It checks the
EFFECT. An infected message that can only narrow is a message that cannot escalate,
whatever it says and however many well-behaved agents carried it. Monotonicity is
checkable; trustworthiness of an arbitrary chain is not.

CLAIM conversation-cannot-widen: no input through this channel, from any source and
after any number of relays, produces a permitted set that is not a subset of the one
before it, or an envelope value looser than the one before it.
CLAIM activation-needs-prior-existence: an input may activate only a constraint that
was already declared; naming a new one is refused rather than created.
CLAIM belief-cannot-lower-risk: a belief carries a risk direction, and the channel's
risk floor only ever rises. "There is a child in the room" is accepted; "there is
nobody here" cannot lower a floor another observation already raised.
CLAIM refusal-is-atomic: a refused input leaves the permitted set, the envelope, the
active constraints and the recorded beliefs exactly as they were. There is one commit
point and nothing mutates before it.
CLAIM restore-cannot-exceed-the-universe: the human recovery path can only put back
capability that was in the channel's authorised set at construction; it cannot
introduce anything new.
CLAIM narrowing-is-irreversible-here: this channel has no widening operation at all,
so restoring a permission is not something a conversation can do slowly.

HONEST LIMITS — read before quoting this in a safety case
---------------------------------------------------------
* NARROWING IS NOT SAFETY. A message that narrows to the single most dangerous
  permitted option is monotone and refused by nothing here. "Only ever use the
  maximum-force grasp" shrinks the set. Whether the remaining option is safe is a
  question about the body, and belongs to the physical envelope in LifeCore. This
  module bounds the DIRECTION of change, not the destination.
* IT GOVERNS THE SET IT WAS GIVEN, and that is the central dependency rather than a
  footnote. If a deployment opens a channel over
  ["normal_move", "disable_estop", "self_modify"], every invariant here holds
  perfectly over a poisoned universe. This is a MONOTONICITY guard, not a
  capability-definition guard: where the authorised set comes from — constitution,
  physical envelope, deployment manifest — is upstream and is not checked here.
* THE LOG IS DIAGNOSTIC, NOT AUDIT EVIDENCE. `log()` returns copies so a reader
  cannot rewrite it, but `self._log` is an ordinary list in memory: no chaining, no
  persistence, no tamper evidence. "The narrowing channel proves this happened" means
  only "this Python object remembers it". Authoritative history belongs in the audit
  chain.
* THE IDENTITY GATE IS A DEPENDENCY, NOT A PROPERTY PROVED HERE. Tests establish that
  `_is_human` never raises and refuses hostile values. Whether an agent, a replayed
  token or a stale authority can satisfy `human_identity.is_human` is that module's
  question, and in the default LABEL_ONLY mode the answer is uncomfortable — see
  `preflight.IdentityModeIsSecure`.
* BELIEFS ARE RECORDED, NOT EVALUATED — but they are DIRECTIONAL. (red-team, Meta
  2026-08-19.) A belief was originally free text passed downstream untouched, and the
  attack is elegant: "there are no humans in the room" narrows nothing, so the channel
  accepts it, and a planner reading beliefs quietly lowers its risk estimate and
  reaches for a rougher grasp. The escalation happens entirely outside the monotone
  set, through the one field that was allowed to say anything.
  The fix is the same asymmetry one layer up: a belief declares whether it RAISES or
  LOWERS estimated risk, and the channel's risk floor only ever rises. A reassuring
  belief is still recorded — a planner may read it — but it cannot pull the floor down
  under an alarming one. Whether the belief is TRUE is still nobody's business here.
* DENIAL OF SERVICE IS THE OTHER DIRECTION. A hostile speaker can narrow the set to
  nothing and the robot stops. That is the safe failure for a body near people, and
  it is a real cost, not a free one — restoring capability requires the human
  authority path, which is exactly where it should require a human.

Run: python3 test_narrowing_channel.py
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Sequence

WIDEN_ACTION = "narrowing_channel_widen"


def _is_human(authorised_by, *, action: str) -> bool:
    """Shared identity gate, guarded.

    CLAIM gate-never-raises: no value of `authorised_by`, and no failure to import
    the identity module, produces an exception here — an unavailable identity means
    NOT human, never a crash at an authorization site.
    """
    try:
        from driftcore.authority.human_identity import is_human
    except Exception:
        return False
    try:
        return bool(is_human(authorised_by, action=action))
    except Exception:
        return False


class NarrowingError(PermissionError):
    """Raised when an input would widen. A PermissionError subclass so a caller
    already failing closed on PermissionError cannot let it through as something
    else."""


class Risk(Enum):
    """Which way a belief moves the estimated risk.

    RAISES is always accepted: an observation that makes things look worse can never
    be an escalation. LOWERS is recorded and cannot pull the floor below anything a
    RAISES belief established — reassurance is the direction an attacker wants.
    """
    RAISES = "raises"
    LOWERS = "lowers"
    NEUTRAL = "neutral"


class Effect(Enum):
    NARROWED = "NARROWED"
    UNCHANGED = "UNCHANGED"
    ACTIVATED = "ACTIVATED"
    REFUSED = "REFUSED"


@dataclass(frozen=True)
class Outcome:
    effect: Effect
    permitted: FrozenSet[str]
    reason: str = ""
    beliefs: tuple = ()

    @property
    def accepted(self) -> bool:
        return self.effect is not Effect.REFUSED


class NarrowingChannel:
    """The one-way door for conversational input.

    There is no `widen`, no `restore`, no `relax`. The absence is the mechanism:
    a capability the class does not have cannot be reached by argument.
    """

    def __init__(self, permitted: Sequence[str], *,
                 envelope: Optional[Mapping[str, float]] = None,
                 constraints: Sequence[str] = (),
                 max_history: int = 4096) -> None:
        if not permitted:
            raise NarrowingError(
                "a channel over an empty permitted set has nothing to narrow; "
                "declare what is allowed before opening it to conversation")
        # (red-team, ChatGPT 2026-08-19.) The IMMUTABLE authorised universe. Without
        # it, `restore` could hand back any set at all: verified, a channel opened
        # over {"move_slow"} was restored to
        # {"move_slow", "disable_estop", "self_modify"} and accepted. The
        # conversational path was beautifully monotone while the recovery door was an
        # unbounded capability-injection mechanism — the same shape this repo keeps
        # finding, where a guard is correct and a second path invalidates the claim.
        self._universe: FrozenSet[str] = frozenset(map(str, permitted))
        self._permitted: FrozenSet[str] = self._universe
        # Envelope values may only DECREASE. Tighter is always acceptable through
        # conversation; looser never is — but monotonicity needs a valid starting
        # point, and the constructor used to accept NaN and infinity, either of which
        # breaks the ordering relation the whole claim rests on.
        self._envelope: Dict[str, float] = {}
        for k, v in (envelope or {}).items():
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise NarrowingError(
                    f"envelope value {k!r} must be a number, not "
                    f"{type(v).__name__}")
            fv = float(v)
            if fv != fv or fv in (float("inf"), float("-inf")):
                raise NarrowingError(
                    f"envelope value {k!r} is not finite. A bound that compares "
                    f"False against every limit is not a bound, and monotonicity "
                    f"over it means nothing.")
            self._envelope[str(k)] = fv
        # (red-team, Meta 2026-08-19.) `_envelope_baseline` was stored here and never
        # read — a field that looks like a restore target and is not one. Dead state
        # in a safety module is worse than absent state: the next reader assumes it
        # means something. Removed rather than wired up, because restoring an envelope
        # is `restore`'s business and it has a human gate.
        # Constraints that may be ACTIVATED. Naming one that is not here is not an
        # activation, it is an invention.
        self._constraints: FrozenSet[str] = frozenset(map(str, constraints))
        self._active: set = set()
        self._beliefs: List[dict] = []
        # The floor only rises. Beliefs that lower risk are recorded and cannot move
        # it back down.
        self._risk_floor: int = 0
        self._log: List[dict] = []
        # Unbounded history in a long-running safety object is a memory denial of
        # service, and the attack is just "keep talking".
        self._max_history = max(1, int(max_history))
        self._lock = threading.RLock()

    # ── the channel ──────────────────────────────────────────────────────────
    def apply(self, *, restrict_to: Optional[Sequence[str]] = None,
              belief: Optional[str] = None,
              belief_risk: "Risk" = None,
              activate: Optional[str] = None,
              tighten: Optional[Mapping[str, float]] = None,
              speaker: str = "unknown", hops: int = 0) -> Outcome:
        """Apply one conversational input.

        `speaker` and `hops` are RECORDED and never consulted. They exist so a
        reviewer can see the chain afterwards, not so the channel can trust it.
        """
        with self._lock:
            # ONE COMMIT POINT. (red-team, ChatGPT 2026-08-19 — REPRODUCED.) This
            # used to mutate as it validated: a single message carrying
            # activate="halt" alongside a widening tighten={} returned REFUSED with
            # "halt" ALREADY ACTIVATED. A refusal that leaves state behind is not a
            # refusal. Everything below computes a PROPOSED state; nothing touches
            # self until every check has passed.
            before = self._permitted
            prop_permitted = self._permitted
            prop_envelope = dict(self._envelope)
            prop_active = set(self._active)
            prop_belief = None
            reasons = []

            if activate is not None:
                if activate not in self._constraints:
                    return self._refuse(
                        f"{activate!r} is not a declared constraint. Activating "
                        f"something that does not exist is not activation, it is "
                        f"creating a rule by talking about it — in the direction "
                        f"that happens to be safe today and will not be tomorrow.",
                        speaker, hops)
                prop_active.add(activate)
                reasons.append(f"activated {activate!r}")

            if tighten:
                for k, v in tighten.items():
                    k = str(k)
                    if k not in prop_envelope:
                        return self._refuse(
                            f"{k!r} is not a declared envelope value; conversation "
                            f"cannot introduce one", speaker, hops)
                    if isinstance(v, bool) or not isinstance(v, (int, float)):
                        return self._refuse(
                            f"envelope value for {k!r} must be a number", speaker, hops)
                    if v != v:
                        return self._refuse(
                            f"a NaN bound for {k!r} compares False against every "
                            f"limit and therefore tightens nothing", speaker, hops)
                    if float(v) > prop_envelope[k]:
                        return self._refuse(
                            f"{k}: {v} is LOOSER than the current {prop_envelope[k]}. "
                            f"Conversation may tighten an envelope and never relax "
                            f"one, whatever it claims about who authorised it.",
                            speaker, hops)
                for k, v in tighten.items():
                    prop_envelope[str(k)] = float(v)
                reasons.append(f"tightened {sorted(tighten)}")

            if restrict_to is not None:
                new = frozenset(map(str, restrict_to))
                added = new - before
                if added:
                    return self._refuse(
                        f"would ADD {sorted(added)} to the permitted set. This "
                        f"channel narrows only — a message that can grow the action "
                        f"space is a privilege-escalation channel with a friendly "
                        f"name, and after enough relays nobody can tell where it "
                        f"came from.", speaker, hops)
                prop_permitted = new
                reasons.append(f"restricted to {sorted(new)}")

            prop_floor = self._risk_floor
            if belief is not None:
                if not isinstance(belief, str) or not belief.strip():
                    return self._refuse("a belief must be non-empty text",
                                        speaker, hops)
                direction = Risk.NEUTRAL if belief_risk is None else belief_risk
                if not isinstance(direction, Risk):
                    return self._refuse(
                        f"belief_risk must be a Risk, not "
                        f"{type(direction).__name__}. An undeclared direction is how "
                        f"a reassuring observation slips in as a neutral one.",
                        speaker, hops)
                if direction is Risk.RAISES:
                    prop_floor = self._risk_floor + 1
                prop_belief = {"text": belief, "speaker": speaker,
                               "hops": int(hops), "risk": direction.value,
                               "floor_at_record": prop_floor, "at": time.time()}
                reasons.append("recorded a belief")

            # ── the transition invariants, proved on the PROPOSED state ────────
            if not prop_permitted <= before:
                return self._refuse(
                    f"proposed permitted set is not a subset of the current one",
                    speaker, hops)
            if any(prop_envelope[k] > self._envelope[k] for k in self._envelope):
                return self._refuse("proposed envelope is looser somewhere",
                                    speaker, hops)
            if not prop_active >= self._active:
                return self._refuse("activation may only add constraints",
                                    speaker, hops)
            if not prop_active <= self._constraints:
                return self._refuse("proposed active set contains an undeclared "
                                    "constraint", speaker, hops)
            if prop_floor < self._risk_floor:
                return self._refuse("a belief may not lower the risk floor",
                                    speaker, hops)

            # ── COMMIT ─────────────────────────────────────────────────────────
            self._permitted = prop_permitted
            self._envelope = prop_envelope
            self._active = prop_active
            self._risk_floor = prop_floor
            if prop_belief is not None:
                self._beliefs.append(prop_belief)
                if len(self._beliefs) > self._max_history:
                    del self._beliefs[:len(self._beliefs) - self._max_history]

            effect = (Effect.NARROWED if self._permitted != before
                      else Effect.ACTIVATED if activate is not None
                      else Effect.UNCHANGED)
            self._record(effect.value, speaker, hops, "; ".join(reasons) or "no-op")
            return Outcome(effect, self._permitted, "; ".join(reasons),
                           tuple(b["text"] for b in self._beliefs))

    def _refuse(self, reason: str, speaker: str, hops: int) -> Outcome:
        self._record("REFUSED", speaker, hops, reason)
        return Outcome(Effect.REFUSED, self._permitted, reason,
                       tuple(b["text"] for b in self._beliefs))

    # ── the human path, which is NOT this channel ────────────────────────────
    def restore(self, permitted: Sequence[str], *, restored_by,
                reason: str) -> FrozenSet[str]:
        """Widen the set. Requires a human, and is deliberately not `apply`.

        Kept on a different method with a different gate so that "the conversation
        widened it" is not a sentence anyone can write by accident.
        """
        if not _is_human(restored_by, action=WIDEN_ACTION):
            raise NarrowingError(
                f"{restored_by!r} is not an authorised human. Widening is the one "
                f"operation conversation must never reach, so it does not live on "
                f"the conversational path at all.")
        if not isinstance(reason, str) or not reason.strip():
            raise NarrowingError("restoring a permission requires a stated reason")
        who = restored_by if isinstance(restored_by, str) else getattr(
            restored_by, "principal", "?")
        with self._lock:
            want = frozenset(map(str, permitted))
            outside = want - self._universe
            if outside:
                raise NarrowingError(
                    f"{sorted(outside)} was never in the authorised universe for "
                    f"this channel. Restoring is putting back what a conversation "
                    f"removed — it is not a side door for granting capability that "
                    f"was never deployed, and a human authorised to do the first is "
                    f"not thereby authorised to do the second.")
            before = self._permitted
            self._permitted = want
            self._record("RESTORED", str(who), 0,
                         f"{sorted(before)} -> {sorted(self._permitted)}: {reason}")
            return self._permitted

    # ── observation ──────────────────────────────────────────────────────────
    @property
    def permitted(self) -> FrozenSet[str]:
        with self._lock:
            return self._permitted

    @property
    def envelope(self) -> Dict[str, float]:
        with self._lock:
            return dict(self._envelope)

    @property
    def risk_floor(self) -> int:
        """How many risk-raising observations stand. Never decreases through this
        channel."""
        with self._lock:
            return self._risk_floor

    @property
    def active_constraints(self) -> List[str]:
        with self._lock:
            return sorted(self._active)

    def beliefs(self) -> List[dict]:
        with self._lock:
            return [dict(b) for b in self._beliefs]

    def log(self) -> List[dict]:
        """A copy — the record must not be editable through the accessor that
        returns it."""
        with self._lock:
            return [dict(e) for e in self._log]

    def _record(self, event: str, speaker: str, hops: int, detail: str) -> None:
        self._log.append({"event": event, "speaker": str(speaker),
                          "hops": int(hops), "detail": detail, "at": time.time()})
        if len(self._log) > self._max_history:
            del self._log[:len(self._log) - self._max_history]
