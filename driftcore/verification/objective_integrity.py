"""
driftcore/verification/objective_integrity.py
=============================================
STATUS: PROPOSED (stdlib-only). DriftCore's most distinctive claim, turned from an
aspiration into a checkable property — hardened after the red team.

LawZero asks "is this action safe?" DriftCore's different question is "does the AI
ever lose, corrupt, or quietly reinterpret the objectives it is supposed to
follow?" This module makes that MEASURABLE, per planning cycle:

  1. THE OBJECTIVE SET IS HASH-PINNED. A current hash differing from the ratified
     baseline means the objectives changed — only allowed through an AUTHORIZED
     change (human-signed), never silently.

  2. REQUIRED INVARIANTS MUST BE PRESENT EVERY CYCLE. A required invariant that
     silently stops being checked fails the cycle.

  3. NO PLAN EXECUTES UNLESS VERIFICATION PASSES. `may_execute()` is False on any
     failure — verification is a precondition for action, not a later report.

RED-TEAM HARDENING:
  - REPLAY-PROOF CHANGES. A signed change now binds the FROM-hash, the TO-hash, a
    justification, and a unique nonce. An old authorization cannot be replayed to
    revert objectives later, because its bound from-hash will not match the
    then-current baseline, and a used nonce is rejected. (was: replayable forever)
  - INVARIANT PRESENCE IS VERIFIER-DERIVED. Presence comes from an InvariantRegistry
    the enforcement layer marks as checks actually run — NOT a set the planner
    hands in (the planner must not grade its own homework). (was: planner-supplied)

The HMAC signing here is illustrative; an un-forgeable token (public-key / HSM) is
the deployment's job — see VERIFIER_CONTRACT in SAFETY_MODEL.md.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Tuple, FrozenSet, Optional, Set


def objective_hash(objectives: Tuple[str, ...]) -> str:
    canon = "\n".join(sorted(objectives)).encode("utf-8")
    return hashlib.sha256(canon).hexdigest()


@dataclass(frozen=True)
class RatifiedBaseline:
    objectives: Tuple[str, ...]
    @property
    def hash(self) -> str:
        return objective_hash(self.objectives)


@dataclass(frozen=True)
class AuthorizedObjectiveChange:
    """Human-signed authorization to change the objective set. Binds from-hash ->
    to-hash + justification + nonce, so it cannot be replayed out of context."""
    from_hash: str
    new_objectives: Tuple[str, ...]
    justification: str
    nonce: str
    signature: str

    @staticmethod
    def _payload(from_hash: str, new_objectives: Tuple[str, ...], justification: str, nonce: str) -> bytes:
        return f"{from_hash}|{objective_hash(new_objectives)}|{justification}|{nonce}".encode("utf-8")

    @staticmethod
    def sign(from_hash: str, new_objectives: Tuple[str, ...], justification: str,
             nonce: str, secret: str) -> "AuthorizedObjectiveChange":
        sig = hmac.new(secret.encode("utf-8"),
                       AuthorizedObjectiveChange._payload(from_hash, new_objectives, justification, nonce),
                       hashlib.sha256).hexdigest()
        return AuthorizedObjectiveChange(from_hash, new_objectives, justification, nonce, sig)

    def verifies(self, secret: str, current_baseline_hash: str) -> bool:
        # must bind to the baseline being changed FROM (defeats replay-to-revert)
        if self.from_hash != current_baseline_hash:
            return False
        expected = hmac.new(secret.encode("utf-8"),
                            self._payload(self.from_hash, self.new_objectives, self.justification, self.nonce),
                            hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.signature)


class InvariantRegistry:
    """Verifier-owned record of which invariant checks ACTUALLY RAN this cycle.
    Populated by the enforcement layer via mark_checked(), never by the planner."""
    def __init__(self):
        self._checked: Set[str] = set()
    def mark_checked(self, name: str) -> None:
        self._checked.add(name)
    @property
    def present(self) -> FrozenSet[str]:
        return frozenset(self._checked)


@dataclass(frozen=True)
class IntegrityReport:
    ok: bool
    failures: Tuple[str, ...]


def verify_planning_cycle(
        baseline: RatifiedBaseline,
        current_objectives: Tuple[str, ...],
        required_invariants: FrozenSet[str],
        registry: InvariantRegistry,
        change: Optional[AuthorizedObjectiveChange] = None,
        secret: Optional[str] = None,
        used_nonces: Optional[Set[str]] = None,
) -> IntegrityReport:
    failures = []

    # 1. objective set integrity (with replay-proof authorization)
    if objective_hash(current_objectives) != baseline.hash:
        authorized = False
        if change is not None and secret is not None:
            nonce_fresh = used_nonces is None or change.nonce not in used_nonces
            authorized = (
                change.verifies(secret, baseline.hash)
                and objective_hash(change.new_objectives) == objective_hash(current_objectives)
                and nonce_fresh)
            if authorized and used_nonces is not None:
                used_nonces.add(change.nonce)   # burn the nonce: no second use
        if not authorized:
            failures.append(
                "objective set differs from the ratified baseline without a valid, "
                "non-replayed human-signed authorization (silent objective drift)")

    # 2. required invariants present this cycle — presence is VERIFIER-DERIVED
    present = registry.present
    missing = tuple(sorted(required_invariants - present))
    if missing:
        failures.append(f"required invariant(s) absent this planning cycle: {', '.join(missing)}")

    return IntegrityReport(ok=not failures, failures=tuple(failures))


def may_execute(report: IntegrityReport) -> bool:
    """No plan executes unless objective integrity verified this cycle."""
    return report.ok
