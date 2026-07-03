"""
driftcore/verification/review_router.py
=======================================
STATUS: PROPOSED (stdlib-only). The HUMAN END OF THE PIPELINE, made real.

The gap this closes: every hard case in the coordinator terminates at
"a human must review" (REVIEW_REQUIRED / AUTHORIZATION_REQUIRED /
CLARIFICATION_REQUIRED) — but there was no queue, no fatigue defense, no
anti-anchoring, nothing on the far side. Two independent red-team reviews flagged
the same thing: the human becomes the vulnerability. An attacker who cannot beat
any single gate can still spam escalations until a worn-down human rubber-stamps
the one that matters (alert fatigue). Consequence invariance does not help here —
the machine is correct on every request; the FAILURE IS THE HUMAN.

This module is where an escalated Decision goes, and it composes the two existing
human-side governance modules into one governed surface:

  * ApprovalThrottle (approval_governance.py) — the fatigue defense. A
    CONTENT-BLIND per-approver rate cap plus bundling, so flooding a human with
    approvals, or splitting one batch into many, buys the attacker nothing. Over
    the cap, further items CANNOT be routed to that human this window — fail-
    closed: they wait, or go to a different approver. This is what bounds how many
    times the fatigue attack can be exploited per window.

  * SecondReaderGate / ReadSession (second_reader.py) — for review that needs a
    human READ, enforces commit-before-reveal (defeats anchoring/automation bias)
    and a workload floor the AI cannot raise (anti-deskilling).

WHAT IT DOES NOT DO (kept honest):
  * It does NOT auto-decide. It governs HOW a human is asked; it never substitutes
    the machine's judgment for the human's. A ticket is a request for a human, not
    an approval.
  * PROCEED / BLOCKED never reach here — those need no human — so routing them is a
    no-op passthrough that consumes no budget.
  * The irreversibility judgment that decides "needs a second approver" is DERIVED
    by the verifier-owned classifier inside ApprovalThrottle, never taken from the
    planner. The classifier is the remaining trust anchor and is named in
    THREAT_BOUNDARIES.
  * It does not, and cannot, defend against a human who is socially manipulated
    into ratifying something harmful (the world-model-manipulation attack). That
    is out of scope and named in THREAT_BOUNDARIES; the throttle bounds VOLUME,
    not a human's beliefs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Sequence

from driftcore.verification.coordinator import Outcome, Decision
from driftcore.verification.approval_governance import (
    ApprovalThrottle, Operation, ApprovalRateExceeded, SplitEvasion,
)
from driftcore.verification.second_reader import (
    SecondReaderGate, WorkloadPolicy, WorkloadFloorExceeded,
)

# Only these outcomes need a human. PROCEED / BLOCKED are terminal for the machine.
ESCALATING = frozenset({
    Outcome.REVIEW_REQUIRED,
    Outcome.AUTHORIZATION_REQUIRED,
    Outcome.CLARIFICATION_REQUIRED,
})


@dataclass(frozen=True)
class ReviewTicket:
    """A governed request for a human. Carries WHY the machine escalated, WHO must
    look, whether a second approver is required (verifier-derived), and the delta
    FACT for the surface — never a system verdict of 'this looks scary'."""
    outcome: Outcome
    reason: str
    approver: str
    needs_second_approver: bool
    irreversible_count: int
    delta_fact: str
    detail: dict = field(default_factory=dict)


class ReviewRouter:
    """Sits between the coordinator's escalating decisions and the human.

    Usage:
        router = ReviewRouter(ApprovalThrottle(policy),
                              second_reader_gate=SecondReaderGate(wl_policy))
        ticket = router.route(decision, approver="operator",
                              bundle_key="nightly-batch",
                              operations=[Operation("o1","delete"), ...])
        # ticket is None for PROCEED/BLOCKED; raises if the approver is over cap.
    """

    def __init__(self, throttle: ApprovalThrottle, *,
                 second_reader_gate: Optional[SecondReaderGate] = None,
                 audit_logger=None):
        self._throttle = throttle
        self._reader_gate = second_reader_gate
        self._audit = audit_logger or (lambda **kw: None)

    @property
    def throttle(self) -> ApprovalThrottle:
        return self._throttle

    def route(self, decision: Decision, approver: str, *,
              bundle_key: Optional[str] = None,
              operations: Sequence[Operation] = (),
              recent_irreversible: Sequence[int] = ()) -> Optional[ReviewTicket]:
        """Route one coordinator Decision to the human surface.

        Returns None if the decision does not need a human (PROCEED / BLOCKED) —
        no budget consumed. For an escalating decision, consumes ONE unit of the
        approver's content-blind per-window budget (this is the item being put in
        front of that human), and raises ApprovalRateExceeded once the cap is hit
        (fail-closed: the item must wait or go to another approver) or SplitEvasion
        if a batch is being split across the window. `operations` drives the
        verifier-DERIVED irreversible count and the second-approver requirement;
        the planner never supplies that count."""
        if decision.outcome not in ESCALATING:
            return None   # machine-terminal; no human needed, no budget spent

        # Fatigue defense (raises on cap / split). This is the load-bearing line:
        # it bounds how many approvals this human is asked to make per window.
        self._throttle.register_approval(approver, bundle_key=bundle_key)

        needs_second = self._throttle.second_approver_required(operations)
        irreversible = self._throttle.count_irreversible(operations)
        fact = ApprovalThrottle.delta_fact(irreversible, list(recent_irreversible))

        self._audit(stage="review_router", outcome=decision.outcome.value,
                    approver=approver, needs_second_approver=needs_second,
                    irreversible=irreversible)

        return ReviewTicket(
            outcome=decision.outcome, reason=decision.reason, approver=approver,
            needs_second_approver=needs_second, irreversible_count=irreversible,
            delta_fact=fact, detail=dict(decision.detail))

    # ── read-workflow review (anti-anchoring), delegated to the gate ──
    def open_read_session(self, case_id: str, reader_id: str):
        """Hand out an anti-anchoring second-reader session (commit-before-reveal
        + workload floor). Requires a SecondReaderGate to have been supplied.
        Raises WorkloadFloorExceeded past the human-set floor."""
        if self._reader_gate is None:
            raise RuntimeError(
                "no SecondReaderGate configured; construct ReviewRouter with "
                "second_reader_gate=SecondReaderGate(WorkloadPolicy(...)) to use read review")
        return self._reader_gate.open_session(case_id, reader_id)
