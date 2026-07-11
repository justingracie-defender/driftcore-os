"""
driftcore/verification/coordinator.py
=====================================
Phase B — the explicit governance pipeline.

    request
       |
       v
  objective_integrity   (PREFLIGHT, opt-in: are the objectives intact? -> BLOCK)
       |
       v
  IntentDetector        (what is being asked?)
       |
       v
  InvariantGuard        (does it cross a bright line? -> BLOCK / needs auth)
       |   (only if the guard does not object)
       v
  clarification_gate    (opt-in: underspecified + high-impact? -> ask ONE question)
       |
       v
  interpretation_guard  (opt-in: violation under a plausible reading of an AMBIGUOUS
       |                 norm? -> REVIEW / AUTH; NEVER BLOCK)
       v
  proportionate_response(opt-in: the mercy ladder — a gentler effective path
       |                 exists? -> AUTH; urgency compresses deliberation,
       |                 never bright lines; NEVER BLOCK)
       v
  harm_estimate         (opt-in: verifier-sourced P(harm) crosses human cutoff? -> AUTH)
       |
       v
  RiskClassifier        (how risky? -> tier; CRITICAL needs human review)
       |
       v
  UncertaintyEngine     (opt-in: mode-aware uncertainty -> REVIEW)
       |
       v
  Audit                 (every decision recorded)

Order matters: the guard runs BEFORE the classifier, so an invariant
violation is refused absolutely and never depends on a tunable score.
The objective-integrity preflight runs BEFORE everything, because a corrupted
objective set means nothing downstream can be trusted. The whole thing is
fail-closed: any internal error returns BLOCKED.

OPT-IN STAGES (v4.5.0). The five stages added in v4.5.0 — objective_integrity,
clarification_gate, interpretation_guard, proportionate_response (the mercy
ladder, PREFER_THE_GENTLEST_AVAILABLE_PATH as enforcement), harm_estimate —
are each a NO-OP unless the caller supplies their inputs (via constructor config
or per-call context). This is the same contract the uncertainty gate already
follows: with no new inputs, the coordinator behaves exactly as before, so
existing callers are unaffected. The fifth v4.5.0 module, consequence_invariance,
is NOT an inline stage; it is a property checked over this pipeline in the test
suite (see test_coordinator_v45_integration.py), because it audits a decision
function rather than making a decision.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Union, Callable, FrozenSet, Iterable

from driftcore.verification.intent import IntentDetector
from driftcore.verification.invariant_guard import (
    InvariantGuard, GuardStatus, Effect, ActionContext,
)
from driftcore.verification.governed_actuator import GrantAuthority
from driftcore.verification.uncertainty import UncertaintyEngine

# v4.5.0 inline stages. NOTE: these three do NOT import the coordinator, so a
# top-level import is safe. interpretation_guard DOES import Outcome from here,
# so it is imported LOCALLY inside its helper to avoid a circular import.
from driftcore.verification.objective_integrity import (
    RatifiedBaseline, InvariantRegistry, AuthorizedObjectiveChange,
    verify_planning_cycle, may_execute, objective_hash,
)
from driftcore.verification.clarification_gate import (
    assess as _clarify_assess, Decision as _ClarifyDecision,
    Impact as _Impact, SlotPolicy,
)
from driftcore.verification.harm_estimate import (
    exceeds as _harm_exceeds, would_exceed as _harm_would_exceed,
    UntrustedEstimate, HarmEstimate, HarmThreshold,
)


# ── Request -> guard Effect translation ───────────────────────────
# TWO tiers, in order of trust:
#
#   1. STRUCTURAL TAG (primary, robust). A tool/actuator/command is tagged
#      with its real-world effect when registered. This is checked FIRST and
#      cannot be fooled by wording: a weapon tagged LETHAL blocks no matter how
#      innocently the command is phrased, because the TAG is what's read, not
#      the sentence.
#
#   2. KEYWORD BACKSTOP (secondary, coarse, FOOLABLE). A tiny word list catches
#      obvious lethal phrasing in free text WHEN no structural tag applies. It
#      is NOT real lethal classification — it misses euphemism ("neutralise",
#      "eliminate") by design. It exists only to catch the easy case. A clean
#      run does NOT mean "lethal is solved"; tier 1 is the defense that holds.
_LETHAL_BACKSTOP_WORDS = (
    "shoot", "open fire", "kill ", " kill", "gun down", "fire on", "execute the",
)


class Outcome(str, Enum):
    PROCEED               = "PROCEED"
    REVIEW_REQUIRED       = "REVIEW_REQUIRED"        # risk says a human must review
    AUTHORIZATION_REQUIRED= "AUTHORIZATION_REQUIRED" # guard says a human must approve
    CLARIFICATION_REQUIRED= "CLARIFICATION_REQUIRED" # underspecified high-impact: ask first
    CYCLE_LIMIT_REACHED   = "CYCLE_LIMIT_REACHED"    # bounded autonomy: budget spent, re-ratify
    BLOCKED               = "BLOCKED"                # hard invariant refusal


@dataclass
class Decision:
    outcome:   Outcome
    invariant: Optional[str] = None
    tier:      Optional[str] = None
    reason:    str = ""
    grant:     Optional[dict] = None   # coordinator-minted actuation grant (PROCEED only)
    detail:    dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"outcome": self.outcome.value, "invariant": self.invariant,
                "tier": self.tier, "reason": self.reason,
                "grant": self.grant, "detail": self.detail}


class VerificationCoordinator:
    def __init__(self, guard: InvariantGuard, classifier,
                 detector: Optional[IntentDetector] = None,
                 audit_logger: Optional[Callable] = None,
                 grant_authority: Optional[GrantAuthority] = None,
                 uncertainty_engine: Optional[UncertaintyEngine] = None,
                 tool_effects: Optional[dict] = None,
                 # ── v4.5.0 objective-integrity preflight (opt-in) ──
                 objective_baseline: Optional[RatifiedBaseline] = None,
                 required_invariants: Optional[FrozenSet[str]] = None,
                 invariant_registry: Optional[InvariantRegistry] = None,
                 objective_secret: Optional[str] = None,
                 max_cycles: Optional[int] = None,
                 # ── v4.5.0 authorized-egress policy (opt-in) ──
                 authorized_egress_targets: Optional[Iterable[str]] = None,
                 egress_owner: str = "",
                 # ── v4.5.0 durable + cross-instance authorization state (opt-in) ──
                 authorization_state=None,
                 state_owner: str = "",
                 # ── v4.5.0 strict mode (opt-in): misconfiguration fails closed ──
                 strict_v45: bool = False,
                 # ── v4.5.0 cumulative-effect ledger (opt-in) ──
                 cumulative_ledger=None):
        self.guard      = guard
        self.classifier = classifier
        self.detector   = detector or IntentDetector()
        self._audit     = audit_logger or (lambda **kw: None)
        # Mints actuation grants. Give the SAME authority to your actuators
        # so they can verify; the agent never holds it.
        self.grants     = grant_authority or GrantAuthority()
        # Optional mode-aware uncertainty gate. Only runs when configured AND
        # the caller supplies probe_responses in context — otherwise no-op.
        self.uncertainty = uncertainty_engine
        # STRUCTURAL effect tags: maps an actuator_id OR a command string to a
        # set of Effect values. This is the primary, robust lethal/force defense
        # (see module note). e.g. {"weapon_1": {Effect.LETHAL}}.
        self._tool_effects = tool_effects or {}

        # ── v4.5.0 objective-integrity preflight config (opt-in) ──
        # Runs ONLY when an objective_baseline is supplied. Without it, the
        # preflight is skipped entirely and the pipeline is unchanged.
        self._obj_baseline       = objective_baseline
        self._required_invariants= frozenset(required_invariants or ())
        self._registry           = invariant_registry or InvariantRegistry()
        self._obj_secret         = objective_secret
        self._used_nonces        = set()   # burned authorization nonces (replay defense)

        # ── v4.5.0 BOUNDED AUTONOMY (opt-in via max_cycles) ──
        # Two modes for the preflight:
        #   * STRICT (max_cycles is None, the DEFAULT): each cycle is verified
        #     against the human-RATIFIED baseline. A signed change authorizes
        #     only the cycle it is presented in; the baseline never moves
        #     automatically, so a changed goal must be re-ratified before the
        #     next cycle. Safe, but one re-ratification per change.
        #   * BOUNDED (max_cycles set): introduces an OPERATIVE goal that DOES
        #     advance on a valid signed change, so one signature buys continued
        #     operation under the new goal — but only for up to `max_cycles`
        #     accepted passes, after which the coordinator HALTs and a human must
        #     re-ratify. This is the productivity/safety trade the operator opts
        #     into: longer autonomy per signature, bounded blast radius per key.
        #     NOTE: the counter counts ACCEPTED evaluate() passes. If a deployment
        #     runs several coordinator checks per planning cycle, scope max_cycles
        #     accordingly — a "cycle" here is one accepted pass, not a wall-clock
        #     planning round. (Flagged for red-team.)
        self._max_cycles         = max_cycles
        self._cycle_count        = 0
        self._operative_objectives = (
            tuple(objective_baseline.objectives) if objective_baseline is not None else None)

        # ── v4.5.0 AUTHORIZED-EGRESS POLICY (opt-in) ──
        # Ratified at CONSTRUCTION TIME from the operator's surface — never read
        # from the per-call context, because a per-call authorization channel
        # would let the planner stamp its own actions as approved. With no
        # policy configured, behaviour is unchanged: every DATA_EGRESS /
        # ACCOUNT_ACCESS action trips the exfiltration seed (fail-closed).
        self._egress_targets = frozenset(
            str(t) for t in (authorized_egress_targets or ()))
        self._egress_owner   = egress_owner

        # ── DURABLE + CROSS-INSTANCE authorization state (opt-in) ──
        # When supplied (an AuthorizationState), burned nonces AND the accepted-
        # cycle budget live in a shared, durable, hash-chained store instead of
        # this process's memory. That is what makes the "8 agents" case correct:
        # every instance built with the same store + owner shares one nonce set
        # and one budget, so one signed change is accepted ONCE across all of
        # them and survives a crash. With no store, behaviour is unchanged: the
        # in-memory set/counter below are used (single-process only).
        self._authz       = authorization_state
        self._authz_owner = state_owner or egress_owner or "default"

        # ── STRICT MODE (v4.5.0, opt-in) ──
        # "Safe if wired correctly" becomes "won't run unless wired correctly."
        # Strict mode enforces the gates whose applicability is MACHINE-CHECKABLE:
        #   * construction: an objective baseline is REQUIRED (raise, don't run);
        #   * per call: current_objectives required (already fail-closed);
        #   * per call: any CONSEQUENTIAL action (one carrying effects) must
        #     arrive with verifier harm inputs (harm_estimate + harm_threshold),
        #     else BLOCKED (retryable).
        # Deliberately NOT auto-required: clarification / interpretation / mercy
        # inputs — those are situational, and demanding them on every call would
        # push integrators into stub-theatre (fake inputs to satisfy the gate),
        # which is worse than opt-in. They stay deployment responsibilities and
        # are listed as such in THREAT_BOUNDARIES.
        self._strict = bool(strict_v45)
        # ── CUMULATIVE-EFFECT LEDGER (opt-in) ──
        # When supplied, the coordinator RESERVES cumulative budget for a
        # consequential action after all per-action gates pass, and attaches the
        # reservation to a PROCEED so the deployment can commit() on success or
        # rollback() on failure. Cross-action attacks (fragmentation, cumulative
        # harm, slow exfil) that per-action gates cannot see are caught here.
        # With no ledger, behaviour is unchanged.
        self._ledger = cumulative_ledger
        if self._strict and objective_baseline is None:
            raise ValueError(
                "strict_v45 requires an objective_baseline at construction — "
                "strict mode refuses to run ungoverned")

    def _nonce_view(self):
        """The set-like used_nonces passed to verify_planning_cycle: the shared
        durable store when configured, else the in-memory set (unchanged path)."""
        if self._authz is not None:
            from driftcore.verification.authorization_state import _StoreBackedNonces
            return _StoreBackedNonces(self._authz, self._authz_owner)
        return self._used_nonces

    def _get_cycles(self) -> int:
        return (self._authz.cycle_count(self._authz_owner)
                if self._authz is not None else self._cycle_count)

    def _inc_cycles(self) -> None:
        if self._authz is not None:
            self._authz.increment_cycle(self._authz_owner)
        else:
            self._cycle_count += 1

    def _effects_for(self, request, ctx: dict) -> set:
        """
        Translate a request into guard Effects. Structural tags FIRST (robust),
        keyword backstop SECOND (coarse, foolable). Explicit per-call
        request["effects"] is honoured as a structural tag too.
        """
        effects = set()
        # 1. Structural: explicit per-call tags.
        if isinstance(request, dict):
            for e in request.get("effects", ()):  # caller may tag the action
                if isinstance(e, Effect):
                    effects.add(e)
            # 1b. Structural: registered tool/command tags.
            for key in (request.get("actuator_id"), request.get("command")):
                if key in self._tool_effects:
                    effects |= set(self._tool_effects[key])
        # 2. Keyword backstop — only on free text, clearly coarse.
        prompt = request if isinstance(request, str) else str(
            request.get("prompt", "") if isinstance(request, dict) else "")
        low = prompt.lower()
        if any(w in low for w in _LETHAL_BACKSTOP_WORDS):
            effects.add(Effect.LETHAL)
        return effects

    _EGRESS_EFFECTS = frozenset({Effect.DATA_EGRESS, Effect.ACCOUNT_ACCESS})

    def _authorization_for(self, request, effects: set) -> ActionContext:
        """Derive the guard's ActionContext from the RATIFIED egress policy plus
        THIS action's structural target(s). Three properties, on purpose:
          1. The policy (targets + owner) is fixed at construction — the
             operator's surface, not the agent's.
          2. The only per-call fact is WHICH target this action addresses,
             read from the request's structural 'target'/'targets' field —
             the same field the execution layer binds into the grant.
          3. A caller-supplied ActionContext is NEVER honoured — that channel
             would be self-authorization.
        Fail-closed: egress with no declared target, or with ANY target off the
        ratified list, stays unauthorized and the exfiltration seed fires.
        Matching is EXACT string equality — no wildcards, no canonicalization —
        so the ratified list must contain the literal targets the tasks use."""
        if not (effects & self._EGRESS_EFFECTS) or not self._egress_targets:
            return ActionContext()
        targets: tuple = ()
        if isinstance(request, dict):
            raw = request.get("target", request.get("targets"))
            if isinstance(raw, str):
                targets = (raw,)
            elif isinstance(raw, (list, tuple, set, frozenset)):
                targets = tuple(str(t) for t in raw)
        target_ok = bool(targets) and all(t in self._egress_targets for t in targets)
        self._audit(stage="egress_authorization", targets=list(targets),
                    authorized=target_ok)
        return ActionContext(owner_authorized=True,
                             target_authorized=target_ok,
                             authorised_by=self._egress_owner)

    # ── v4.5.0 PREFLIGHT: objective integrity (+ optional bounded autonomy) ──
    def _objective_preflight(self, ctx: dict) -> Optional["Decision"]:
        """Opt-in. If an objective baseline is configured, verify the objective
        set has not silently drifted and that the required invariants were
        actually checked this cycle. Failure is a hard, fail-closed refusal.
        Returns a refusing Decision on failure, else None (skip/pass).

        FOOTGUN CLOSED: current_objectives MUST be supplied by the caller when
        the preflight is enabled. A missing value is an integration ERROR, not a
        silent pass — we no longer default it to the baseline (which would make
        the drift check always-pass for a forgetful caller). It returns BLOCKED
        with retryable=True so a consumer can attach the objectives and retry.
        """
        if self._obj_baseline is None:
            return None

        # FOOTGUN: do not invent the current objectives. Absent => error/retry.
        if "current_objectives" not in ctx:
            self._audit(stage="objective_integrity", error="missing_current_objectives")
            return Decision(
                Outcome.BLOCKED, invariant="objective_integrity",
                reason="current objectives not attached — cannot verify integrity; "
                       "attach current_objectives and retry",
                detail={"error": "missing_current_objectives", "retryable": True})
        current = tuple(ctx["current_objectives"])
        change  = ctx.get("objective_change")   # AuthorizedObjectiveChange | None

        # ── BOUNDED AUTONOMY MODE (max_cycles set) ──
        if self._max_cycles is not None:
            # Cap FIRST: a spent budget halts before anything else runs.
            if self._get_cycles() >= self._max_cycles:
                self._audit(stage="cycle_budget", state="exhausted",
                            cycle_count=self._get_cycles(), max_cycles=self._max_cycles)
                return Decision(
                    Outcome.CYCLE_LIMIT_REACHED, invariant="cycle_budget",
                    reason="cycle budget exhausted — re-ratify the baseline to continue",
                    detail={"cycle_count": self._get_cycles(),
                            "max_cycles": self._max_cycles, "retryable": False})
            # Verify against the OPERATIVE goal (which advances on a signed change),
            # NOT the original ratified baseline. Reuses the tested verification.
            op_baseline = RatifiedBaseline(self._operative_objectives)
            report = verify_planning_cycle(
                baseline=op_baseline, current_objectives=current,
                required_invariants=self._required_invariants, registry=self._registry,
                change=change, secret=self._obj_secret, used_nonces=self._nonce_view())
            self._audit(stage="objective_integrity", mode="bounded",
                        ok=report.ok, failures=report.failures)
            if not may_execute(report):
                return Decision(
                    Outcome.BLOCKED, invariant="objective_integrity",
                    reason="; ".join(report.failures) or "objective integrity check failed",
                    detail={"failures": list(report.failures)})
            # Authorized change just landed (current != operative but verified):
            # advance the operative goal so subsequent cycles run under it without
            # re-presenting the (now nonce-burned) change. The human-ratified
            # baseline is NOT moved — re-ratify is the only thing that moves it.
            if objective_hash(current) != op_baseline.hash:
                self._operative_objectives = current
                self._audit(stage="objective_integrity", advanced_operative=True)
            # Accepted operating pass: consume one unit of the budget.
            self._inc_cycles()
            return None

        # ── STRICT MODE (default) ── verify against the ratified baseline.
        report = verify_planning_cycle(
            baseline=self._obj_baseline, current_objectives=current,
            required_invariants=self._required_invariants, registry=self._registry,
            change=change, secret=self._obj_secret, used_nonces=self._nonce_view())
        self._audit(stage="objective_integrity", mode="strict",
                    ok=report.ok, failures=report.failures)
        if not may_execute(report):
            return Decision(
                Outcome.BLOCKED, invariant="objective_integrity",
                reason="; ".join(report.failures) or "objective integrity check failed",
                detail={"failures": list(report.failures)})
        return None

    def re_ratify(self, new_objectives: Optional[tuple] = None) -> None:
        """Human/deployment action ONLY. Re-anchor the ratified baseline to the
        current operative goal (or to explicit new_objectives), and reset the
        cycle budget. Burned nonces PERSIST, so old authorizations can never be
        replayed after a re-ratification. This is the 'ask for a new key' step in
        bounded autonomy. Call out-of-band from your operator surface, never from
        the agent."""
        objs = tuple(new_objectives) if new_objectives is not None else (
            self._operative_objectives or ())
        self._obj_baseline = RatifiedBaseline(objs)
        self._operative_objectives = objs
        if self._authz is not None:
            self._authz.reset_cycles(self._authz_owner)
        else:
            self._cycle_count = 0
        self._audit(stage="re_ratify", objectives=list(objs))

    # ── v4.5.0: clarification gate ────────────────────────────────
    def _clarification_check(self, request, ctx: dict) -> Optional["Decision"]:
        """Opt-in via ctx['clarification'] = {policy, impact[, provided]}. If a
        high-impact request is missing a required slot, ask ONE human-authored
        question instead of guessing. Returns a CLARIFICATION_REQUIRED Decision,
        or None (nothing to ask / not configured)."""
        spec = ctx.get("clarification")
        if not spec:
            return None
        policy   = spec["policy"]
        impact   = spec["impact"]
        provided = spec.get("provided")
        if provided is None:
            provided = request if isinstance(request, dict) else {}
        outcome = _clarify_assess(provided, impact, policy)
        self._audit(stage="clarification", decision=outcome.decision.value,
                    slot=outcome.missing_slot)
        if outcome.decision is _ClarifyDecision.CLARIFY:
            return Decision(
                Outcome.CLARIFICATION_REQUIRED,
                reason=outcome.question or "clarification required before acting",
                detail={"slot": outcome.missing_slot, "question": outcome.question,
                        "rationale": outcome.rationale})
        return None

    # ── v4.5.0: interpretation guard (the fuzzy middle) ───────────
    def _interpretation_check(self, ctx: dict) -> Optional["Decision"]:
        """Opt-in via ctx['interpretations'] = (Interpretation, ...). Reasons
        over the distribution of credible human-authored readings of an
        ambiguous norm. NEVER returns BLOCKED (categorical denial belongs to the
        guard). Returns a Decision carrying the verdict's outcome (which may be
        PROCEED — the caller only short-circuits on non-PROCEED), or None."""
        interps = ctx.get("interpretations")
        if not interps:
            return None
        # LOCAL import breaks the import cycle (interpretation_guard imports Outcome).
        from driftcore.verification.interpretation_guard import assess as _interp_assess
        floor   = ctx.get("plausibility_floor", 0.2)
        verdict = _interp_assess(tuple(interps), plausibility_floor=floor)
        self._audit(stage="interpretation", outcome=verdict.outcome.value,
                    violating=verdict.violating,
                    flag_for_bright_line=verdict.flag_for_bright_line)
        return Decision(
            verdict.outcome, reason=verdict.rationale,
            detail={"considered": list(verdict.considered),
                    "violating": list(verdict.violating),
                    "flag_for_bright_line": verdict.flag_for_bright_line})

    # ── v4.5.0: cumulative-effect ledger reservation ─────────────
    def _ledger_reserve(self, request, ctx: dict, effects: set):
        """Opt-in. RESERVE cumulative budget for a consequential action after the
        per-action gates have passed. Returns either a Decision (DENY -> BLOCKED,
        soft REVIEW -> REVIEW_REQUIRED) to short-circuit, or a live Reservation to
        attach to the eventual PROCEED (so the deployment commits on success /
        rolls back on failure). None when no ledger is configured. Owner comes from
        ctx['ledger_owner'] (which the broker should bind to an authenticated
        identity); a verifier-sourced harm estimate in ctx feeds the harm-score
        budget. Fail-closed: a ledger error refuses."""
        if self._ledger is None:
            return None, None
        from driftcore.verification.cumulative_ledger import ProposedAction, LedgerVerdict
        owner = str(ctx.get("ledger_owner", self._authz_owner))
        est = ctx.get("harm_estimate")
        harm_p = est.p if (est is not None and getattr(est, "verifier_sourced", False)) else None
        action = ProposedAction(
            effects=tuple(e.value for e in effects),
            harm_p=harm_p,
            harm_verifier_sourced=bool(est is not None and getattr(est, "verifier_sourced", False)),
            egress_bytes=int(ctx.get("egress_bytes", 0)))
        try:
            res = self._ledger.reserve(owner, action, action_id=ctx.get("action_id"))
        except Exception as e:
            self._audit(stage="cumulative_ledger", error=str(e))
            return Decision(Outcome.BLOCKED, invariant="cumulative_ledger",
                            reason="cumulative-ledger error — refused (fail-closed)",
                            detail={"error": str(e)}), None
        if res.verdict is LedgerVerdict.DENY:
            return Decision(Outcome.BLOCKED, invariant="cumulative_ledger",
                            reason="cumulative budget exceeded — refused",
                            detail={"owner": owner}), None
        if res.verdict is LedgerVerdict.REVIEW_REQUIRED:
            # soft cap: release the hold (no proceed) and route to a human
            self._ledger.rollback(res)
            return Decision(Outcome.REVIEW_REQUIRED, invariant="cumulative_ledger",
                            reason="cumulative budget soft limit — human review",
                            detail={"owner": owner}), None
        return None, res   # OK: hand the live reservation up to ride on PROCEED

    # ── v4.5.0: proportionate response — the mercy ladder ─────────
    def _mercy_check(self, ctx: dict) -> Optional["Decision"]:
        """Opt-in via ctx['proportionate'] = {threat, options, proposed?,
        verifier_sourced?}. PREFER_THE_GENTLEST_AVAILABLE_PATH as enforcement:
        choose_response picks the least-harm effective option, and the machine
        will not greenlight anything harsher than that choice — a human must
        approve taking the harsher path (sovereignty preserved: a human may
        still say yes). Two traps closed on purpose:
          * NO-THREAT TRAP: if the ladder finds no present threat (the trigger
            is the threat, never the category) but the agent still PROPOSES an
            action, that action is not greenlit — it goes to a human.
          * UNVERIFIED-NUMBERS TRAP (asymmetry mirrored from harm_estimate):
            threat/option numbers that are not verifier-sourced may select a
            HARMLESS path, but may never authorize a harmful one.
        Never returns BLOCKED (bright lines belong to the guard, which already
        ran) and never substitutes the action (DriftCore gates; it does not
        act). On fall-through, the plan and its PRE-COMMITTED success criteria
        are attached to the final decision detail for reflection.py to audit."""
        spec = ctx.get("proportionate")
        if not spec:
            return None
        # LOCAL import: proportionate_response imports Outcome from this module.
        from driftcore.verification.proportionate_response import choose_response
        plan = choose_response(spec["threat"], list(spec["options"]))
        self._audit(stage="proportionate", outcome=plan.outcome.value,
                    chosen=(plan.chosen.name if plan.chosen else None),
                    rationale=plan.rationale)
        mercy_detail = {
            "ladder": "PREFER_THE_GENTLEST_AVAILABLE_PATH",
            "chosen": plan.chosen.name if plan.chosen else None,
            "rationale": plan.rationale,
            "success_criteria": list(plan.success_criteria),
        }
        if plan.outcome != Outcome.PROCEED:
            return Decision(plan.outcome, reason=plan.rationale, detail=mercy_detail)
        proposed = spec.get("proposed")
        if proposed is not None and plan.chosen is None:
            return Decision(
                Outcome.AUTHORIZATION_REQUIRED,
                reason=(f"no present threat — the trigger is the threat, never the "
                        f"category; proposed '{proposed}' has no threat to answer, so "
                        f"a human must approve acting at all"),
                detail={**mercy_detail, "proposed": proposed})
        if proposed is not None and plan.chosen.name != proposed:
            return Decision(
                Outcome.AUTHORIZATION_REQUIRED,
                reason=(f"a gentler effective path exists ('{plan.chosen.name}'); "
                        f"proposed '{proposed}' is harsher than necessary — a human "
                        f"must approve taking the harsher path"),
                detail={**mercy_detail, "proposed": proposed})
        if (plan.chosen is not None and plan.chosen.harm > 0
                and not spec.get("verifier_sourced", False)):
            return Decision(
                Outcome.AUTHORIZATION_REQUIRED,
                reason=("the least-harm path still causes harm and the threat/option "
                        "numbers are not verifier-sourced — unverified inputs may pick "
                        "a harmless path but may not authorize harm; a human must approve"),
                detail={**mercy_detail, "verifier_sourced": False})
        ctx["_mercy_plan"] = mercy_detail
        return None

    # ── v4.5.0: harm estimate vs human cutoff ─────────────────────
    def _harm_check(self, ctx: dict) -> Optional["Decision"]:
        """Opt-in via ctx['harm_estimate'] (HarmEstimate) + ctx['harm_threshold']
        (HarmThreshold). The asymmetry, pinned:

          VERIFIED data DECIDES — crosses the cutoff -> AUTHORIZATION_REQUIRED
          (STOP); under -> proceed (RUN).

          UNVERIFIED data may NOT authorize RUN past a stop signal, and may NOT
          be trusted to hard-STOP on its own. So: an unverified estimate that
          WOULD cross the cutoff routes to a human (REVIEW_REQUIRED); one that
          would not cross is IGNORED — an unverified number can never be used to
          lower caution."""
        est = ctx.get("harm_estimate")
        thr = ctx.get("harm_threshold")
        if est is None or thr is None:
            return None

        if est.verifier_sourced:
            crossed = _harm_exceeds(est, thr)          # trusted: decides RUN vs STOP
            self._audit(stage="harm_estimate", source="verifier",
                        crossed=crossed, fact=est.as_fact())
            if crossed:
                return Decision(
                    Outcome.AUTHORIZATION_REQUIRED,
                    reason="verifier-sourced harm estimate crosses the human-set cutoff — a human must approve",
                    detail={"harm": est.as_fact(), "cutoff": thr.cutoff,
                            "use_upper_bound": thr.use_upper_bound})
            return None

        # UNVERIFIED — cannot drive the cutoff either way.
        if _harm_would_exceed(est, thr):               # would say STOP -> ask a human
            self._audit(stage="harm_estimate", source="UNVERIFIED",
                        would_stop=True, fact=est.as_fact())
            return Decision(
                Outcome.REVIEW_REQUIRED,
                reason="an UNVERIFIED harm estimate indicates the cutoff may be crossed; "
                       "an unverified number can neither authorize proceeding past a stop "
                       "signal nor hard-stop on its own — a human must review",
                detail={"harm": est.as_fact(), "cutoff": thr.cutoff,
                        "use_upper_bound": thr.use_upper_bound, "verifier_sourced": False})
        # would say RUN -> ignore; an unverified number may not lower caution.
        self._audit(stage="harm_estimate", source="UNVERIFIED",
                    would_stop=False, fact=est.as_fact())
        return None

    def _uncertainty_check(self, prompt: str, ctx: dict):
        """Run the uncertainty engine iff configured and given probe samples."""
        if self.uncertainty is None or not prompt:
            return None
        responses = ctx.get("probe_responses")
        if not responses:
            return None
        return self.uncertainty.assess(prompt, responses, ctx.get("mode", "TRUTH"))

    def _grant_for(self, request) -> Optional[dict]:
        """Mint a single-use actuation grant for an actuation request that
        passed the guard. Returns None for non-actuation requests."""
        if isinstance(request, dict):
            aid, cmd = request.get("actuator_id"), request.get("command")
            if aid and cmd:
                return self.grants.mint(str(aid), str(cmd))
        return None

    def evaluate(self, request: Union[dict, str], context: Optional[dict] = None) -> Decision:
        """Run the pipeline. ORDER IS LOAD-BEARING: the objective-integrity
        preflight runs first (a corrupted objective set blocks everything), then
        the guard runs BEFORE the risk classifier, so an invariant violation
        hard-blocks regardless of score. Fail-closed: any error returns BLOCKED.
        A coordinator-minted actuation grant is attached only to PROCEED."""
        # Underscore-prefixed keys are RESERVED for the pipeline's own transient
        # state (e.g. _mercy_plan). Strip them from caller input: this prevents
        # both stale-state bleed from reused context dicts AND forged internal
        # provenance (a caller-injected _mercy_plan would otherwise ride into
        # the decision detail as a mercy plan the ladder never computed).
        ctx = {k: v for k, v in (context or {}).items()
               if not str(k).startswith("_")}
        # Ledger reservation is hoisted out of the try so a `finally` can ALWAYS
        # release it. `_reservation_handed_off` becomes True only when the hold is
        # attached to a PROCEED (the deployment then owns commit/rollback). Any
        # other exit — escalation, exception, early return — leaves it False, and
        # the finally rolls it back. This closes the reservation-leak (a hold that
        # otherwise survives until TTL) on every non-proceed path, including when a
        # later stage throws.
        reservation = None
        _reservation_handed_off = False
        try:
            prompt = request if isinstance(request, str) else str(request.get("prompt", ""))

            # 0. Objective-integrity PREFLIGHT (opt-in). Nothing downstream can
            #    be trusted if the objective set has silently drifted.
            dec = self._objective_preflight(ctx)
            if dec is not None:
                return dec

            # 1. Intent (informational; also feeds the classifier).
            intent = self.detector.assess(prompt, ctx) if prompt else None
            if intent is not None:
                ctx["intent"] = intent

            # 2. Guard FIRST — invariants are absolute. Translate the request
            #    into effects (structural tags primary, keyword backstop), then
            #    call the real guard API.
            effects = self._effects_for(request, ctx)
            gd = self.guard.evaluate(action=prompt, effect=effects,
                                     context=self._authorization_for(request, effects))
            self._audit(stage="guard", status=gd.status.value,
                        invariant=gd.binding_invariant, reason=gd.reason)
            if gd.status == GuardStatus.BLOCKED:
                return Decision(Outcome.BLOCKED, invariant=gd.binding_invariant,
                                reason=gd.reason)

            # 2b. STRICT MODE: a consequential action (carries effects) must
            #     arrive with verifier harm inputs. Runs AFTER the guard so a
            #     bright-line block still reports the right invariant.
            if self._strict and effects and (
                    ctx.get("harm_estimate") is None or ctx.get("harm_threshold") is None):
                self._audit(stage="strict", error="missing_harm_inputs",
                            effects=[e.value for e in effects])
                return Decision(
                    Outcome.BLOCKED, invariant="strict_v45",
                    reason="strict mode: consequential action arrived without verifier "
                           "harm inputs (harm_estimate + harm_threshold) — attach them "
                           "and retry",
                    detail={"error": "missing_harm_inputs", "retryable": True,
                            "effects": [e.value for e in effects]})

            # 3. Clarification (opt-in) — ask before guessing on a high-impact,
            #    underspecified request. After the guard: never clarify a
            #    forbidden act; bright-line BLOCK wins.
            dec = self._clarification_check(request, ctx)
            if dec is not None:
                return dec

            # 4. Interpretation guard (opt-in) — the fuzzy middle. PROCEED falls
            #    through; only a non-PROCEED verdict short-circuits. Never BLOCKED.
            iv = self._interpretation_check(ctx)
            if iv is not None and iv.outcome != Outcome.PROCEED:
                return iv

            # 5. Proportionate response (opt-in) — the mercy ladder. Refuses to
            #    greenlight a harsher-than-necessary path; a human may still
            #    approve it. Never BLOCKED. PROCEED falls through with the plan
            #    and pre-committed success criteria attached for later audit.
            dec = self._mercy_check(ctx)
            if dec is not None:
                return dec

            # 6. Harm estimate (opt-in) — verifier-sourced P(harm) vs human cutoff.
            #    Applies with or without prompt text.
            dec = self._harm_check(ctx)
            if dec is not None:
                return dec

            # 6b. Cumulative-effect ledger (opt-in) — RESERVE cross-action budget
            #     after per-action gates pass. DENY/REVIEW short-circuit; an OK
            #     reservation rides on the PROCEED for the deployment to commit or
            #     roll back. Applies with or without prompt text.
            ledger_dec, reservation = self._ledger_reserve(request, ctx, effects)
            if ledger_dec is not None:
                return ledger_dec

            # 7. Risk — only reached if the guard did not object.
            if prompt:
                risk = self.classifier.classify(prompt, ctx)
                tier = risk.tier.value
                self._audit(stage="risk", tier=tier, score=risk.total_score)
                if risk.requires_human:
                    return Decision(Outcome.REVIEW_REQUIRED, tier=tier,
                                    reason="Risk tier requires human review.",
                                    detail={"intent": intent.to_dict() if intent else None})
                # Uncertainty gate (mode-aware) — escalate on EITHER risk or
                # uncertainty. Guard and risk have already run; this is last.
                unc = self._uncertainty_check(prompt, ctx)
                if unc is not None and unc.response == "REVIEW_REQUIRED":
                    return Decision(Outcome.REVIEW_REQUIRED, tier=tier, reason=unc.reason,
                                    detail={"uncertainty": unc.to_dict()})
                detail = {"intent": intent.to_dict() if intent else None}
                if unc is not None:
                    detail["uncertainty"] = unc.to_dict()
                if "_mercy_plan" in ctx:
                    detail["mercy"] = ctx["_mercy_plan"]
                if reservation is not None:
                    detail["ledger_reservation"] = reservation
                    _reservation_handed_off = True   # deployment now owns commit/rollback
                return Decision(Outcome.PROCEED, tier=tier, grant=self._grant_for(request),
                                detail=detail)

            # No prompt to score (pure structured action that passed the guard).
            detail = {}
            if "_mercy_plan" in ctx:
                detail["mercy"] = ctx["_mercy_plan"]
            if reservation is not None:
                detail["ledger_reservation"] = reservation
                _reservation_handed_off = True   # deployment now owns commit/rollback
            return Decision(Outcome.PROCEED, grant=self._grant_for(request),
                            reason="Passed guard; no risk-scorable text.",
                            detail=detail)

        except Exception as e:  # fail closed
            self._audit(stage="error", reason=str(e))
            return Decision(Outcome.BLOCKED, reason="Internal failure — refused (fail-closed).")
        finally:
            # Release any reservation not handed off to a PROCEED — covers
            # escalation returns, exceptions, and any early exit. Idempotent:
            # rollback of an already-resolved hold is a no-op.
            if reservation is not None and not _reservation_handed_off:
                try:
                    self._ledger.rollback(reservation)
                except Exception:
                    pass
