"""
driftcore/verification/approval_governance.py
=============================================
STATUS: PROPOSED (stdlib-only). Defends the human approver against the spam /
fatigue attack — designed with Meta, hardened after a 3-model red team.

The attack: an agent sends 500 boring `1 record, reversible` approvals; the human
taps approve 500 times; on request 501 — `12 irreversible` — the worn-down human
taps again. Consequence invariance does NOT help: the guard is correct every time.
The failure is the human. Three content-blind layers, none of which let the SYSTEM
decide "this one looks scary":

  1. CONTENT-BLIND RATE CAP. Max approvals per approver per window — a dumb
     counter, identical for `1 reversible` and `12 irreversible`. (Sibling of
     second_reader.WorkloadPolicy: same content-blind-floor principle, other face.)

  2. BUNDLING, SO SPLITTING BUYS NOTHING. One logical batch = one bundled request;
     splitting it across the window is refused. Only enforceable because of layer 1.

  3. DELTA AS A FACT, NEVER AS FRICTION. The surface may show `Δ irreversible +12`
     as a FACT. A second approver is required ONLY by a human-authored threshold,
     never inferred. The system never decides "this looks scary."

RED-TEAM HARDENING (the convergent finding: thresholds were solid, the INPUTS were
planner-owned). The irreversible COUNT that gets compared to the human threshold is
no longer accepted from the caller — the agent could report 9 when it is 12. The
count is now DERIVED by a verifier-owned classifier from the declared operations:
the planner supplies the WHAT (operations), the verifier supplies the
irreversibility judgment. The classifier itself is the remaining trust anchor and
is named in THREAT_BOUNDARIES (it must be verifier-owned, not planner-set).
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence


class ApprovalRateExceeded(Exception):
    """Raised loudly when an approver is asked to approve past the content-blind cap."""


class SplitEvasion(Exception):
    """Raised when an agent splits one logical batch into multiple requests."""


@dataclass(frozen=True)
class ApprovalPolicy:
    """Human-set governance. The throttle holds this read-only and has NO method to
    raise it — same shape as the constitution's self-grant floors."""
    max_approvals_per_window: int
    second_approver_over_irreversible: Optional[int] = None   # human-authored; None = off


@dataclass(frozen=True)
class Operation:
    """A declared unit of work. The planner declares the KIND (the 'what'); it does
    NOT get to declare whether the op is irreversible — that is the classifier's job."""
    op_id: str
    kind: str


# verifier-owned default: destructive kinds are irreversible. A deployment may
# supply a stricter classifier, but the planner never supplies this judgment.
_DESTRUCTIVE = {"delete", "overwrite", "purge", "wipe", "destroy", "drop", "truncate"}

def default_irreversibility(op: Operation) -> bool:
    return op.kind.lower() in _DESTRUCTIVE


class ApprovalThrottle:
    def __init__(self, policy: ApprovalPolicy,
                 irreversible_classifier: Callable[[Operation], bool] = default_irreversibility):
        self._policy = policy                       # read-only; no setter by design
        self._is_irreversible = irreversible_classifier   # verifier-owned, not planner-set
        self._count: Dict[str, int] = defaultdict(int)
        self._bundle_keys_seen: Dict[str, set] = defaultdict(set)

    @property
    def remaining(self) -> Dict[str, int]:
        return {a: self._policy.max_approvals_per_window - n for a, n in self._count.items()}

    # layer 1 — content-blind cap
    def register_approval(self, approver: str, bundle_key: Optional[str] = None) -> None:
        if self._count[approver] >= self._policy.max_approvals_per_window:
            raise ApprovalRateExceeded(
                f"approver {approver} is at the per-window cap "
                f"({self._policy.max_approvals_per_window}); refusing more. Raising it is a "
                "human admin act, not something this throttle can do.")
        if bundle_key is not None:
            if bundle_key in self._bundle_keys_seen[approver]:
                raise SplitEvasion(
                    f"bundle {bundle_key!r} was already submitted separately — submit the "
                    "whole batch as ONE bundled request, not split pieces")
            self._bundle_keys_seen[approver].add(bundle_key)
        self._count[approver] += 1

    # layer 3 — delta is a FACT, never acted on here
    @staticmethod
    def delta_fact(current_irreversible: int, recent_irreversible: List[int]) -> str:
        if not recent_irreversible:
            return f"irreversible: {current_irreversible} (no recent baseline)"
        avg = sum(recent_irreversible) / len(recent_irreversible)
        return (f"irreversible: {current_irreversible}  "
                f"(\u0394 {current_irreversible - avg:+.1f} vs last {len(recent_irreversible)} approvals)")

    # HARDENED: the count is DERIVED here, never accepted from the caller
    def count_irreversible(self, operations: Sequence[Operation]) -> int:
        return sum(1 for op in operations if self._is_irreversible(op))

    # multi-approver requirement: human-set threshold vs a verifier-DERIVED count
    def second_approver_required(self, operations: Sequence[Operation]) -> bool:
        thr = self._policy.second_approver_over_irreversible
        if thr is None:
            return False
        return self.count_irreversible(operations) > thr
