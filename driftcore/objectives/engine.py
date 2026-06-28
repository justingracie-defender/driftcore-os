"""
driftcore/objectives/engine.py
==============================
The Objective Engine: the universal "what should happen, and why" layer.

This is NOT memory ("what happened") and NOT the constraint floor ("what must
never happen"). It is the third data type — DIRECTION. It is deliberately
universal: it governs *an objective* as an abstract artifact. It knows nothing
about bodies, forces, homes, or any specific deployment. Concrete objective
*content* (e.g. a particular robot's purpose) is supplied by the embodiment /
deployment layer (LifeCore for a robot) and dropped into the slots defined here.

Design lineage (grounded in this repo, not in any external paper):
This is the skill-governance pattern — `skills.governance.ProposalLedger` plus
the human-only promotion gate — generalised from governing *capabilities* to
governing *purpose*, using the same append-only, hash-linked, tamper-evident
ledger shape as `recovery.store.CheckpointStore`.

Guarantees implemented here:
  * Objectives are versioned artifacts, not free-floating strings.
  * Mutation is by PROPOSAL only; the agent can propose, never self-apply.
  * Ratification requires a human authoriser (reuses the `_is_human` gate).
  * The objective history is an append-only SHA-256 hash chain; silent
    mutation is detectable by re-verifying the chain.
  * A hard structural invariant forbids wiring any "goodness"/self-rating
    signal as an optimization TARGET. Such signals may be monitored only.

What is explicitly NOT solved here (left as honest stubs, see coverage.py):
  * The faithfulness judgement — "does this plan TRULY serve the objective vs.
    technically-comply-while-drifting". That is the open scalable-oversight
    problem and is routed to a human, never auto-passed.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

# Reuse the SAME human gate the resolver and skill governance use, so "who
# counts as a human authoriser" has one definition across the whole system.
from driftcore.authority.resolver import _is_human


# ── Objective artifact ────────────────────────────────────────────

class SignalRole(Enum):
    """
    How a measurable signal attached to an objective is allowed to be used.

    MONITOR_ONLY  — observed and surfaced to humans / used as a divergence
                    tripwire. The system may NOT optimise toward it.
    TARGET        — an optimisation target. Permitted ONLY for signals that
                    are facts about the world the system cannot corrupt by
                    pursuing them (see SafeToTarget guard below). A self-rating
                    of the system's own virtue can NEVER be a TARGET.
    """
    MONITOR_ONLY = "monitor_only"
    TARGET = "target"


@dataclass(frozen=True)
class ObjectiveSignal:
    """A measurable thing attached to an objective."""
    key: str
    role: SignalRole
    # If True, the signal is a self-assessment of the system's own conduct
    # (e.g. "how caring was I"). Self-assessment may NEVER be a TARGET.
    is_self_assessment: bool = False


@dataclass(frozen=True)
class Objective:
    """
    An immutable snapshot of the system's purpose at one version.

    `subgoals` are the named directions a plan's actions must trace back to
    (used by the mechanical coverage check). `content` is opaque to DriftCore
    — it is whatever the deployment layer put there.
    """
    objective_id: str
    version: int
    content: str                       # opaque; meaning belongs to deployment
    subgoals: Tuple[str, ...]
    signals: Tuple[ObjectiveSignal, ...]
    ratified_by: str                   # human authoriser
    ratified_at: float
    prev_hash: str
    entry_hash: str
    note: str = ""


class GoodnessAsTargetError(Exception):
    """Raised when something tries to wire a self-rating signal as a target."""


def _validate_signals(signals: Tuple[ObjectiveSignal, ...]) -> None:
    """
    The hard invariant. A self-assessment signal can never be an optimization
    target — that is the path by which 'be more caring' becomes a number the
    system games (smothering, performed care). Monitoring is fine; targeting
    is forbidden, structurally, here, so it cannot be added silently later.
    """
    for s in signals:
        if s.role is SignalRole.TARGET and s.is_self_assessment:
            raise GoodnessAsTargetError(
                f"signal '{s.key}' is a self-assessment and may not be wired "
                f"as an optimization TARGET; use MONITOR_ONLY"
            )


def _hash_entry(fields: dict) -> str:
    return hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()


# ── Proposals (agent may create; only a human ratifies) ───────────

class ProposalStatus(Enum):
    PENDING = "pending"
    RATIFIED = "ratified"
    REJECTED = "rejected"


@dataclass
class ObjectiveProposal:
    proposal_id: str
    base_version: int
    content: str
    subgoals: Tuple[str, ...]
    signals: Tuple[ObjectiveSignal, ...]
    rationale: str
    proposed_by: str
    status: ProposalStatus = ProposalStatus.PENDING


# ── The ledger ────────────────────────────────────────────────────

class ObjectiveLedger:
    """
    Append-only, hash-linked record of an objective's life.

    The agent may: read the current objective, and PROPOSE a change.
    The agent may NOT: ratify, amend, or roll back — those require a human,
    exactly like skill promotion to TRUSTED and like checkpoint restore.

    There is no method that mutates an objective without a human authoriser
    and an audited, hash-chained entry. That is the whole point.
    """

    def __init__(self):
        self._objective: Optional[Objective] = None
        self._chain: List[Objective] = []
        self._proposals: Dict[str, ObjectiveProposal] = {}
        self._last_hash = "GENESIS"

    # -- establish / amend (HUMAN ONLY) ------------------------------

    def ratify_initial(self, content: str, subgoals: List[str],
                       signals: Optional[List[ObjectiveSignal]] = None,
                       authorised_by: str = "", note: str = ""
                       ) -> Tuple[bool, str]:
        if self._objective is not None:
            return False, "objective already established; use ratify_proposal"
        if not _is_human(authorised_by):
            return False, "establishing an objective requires a human authoriser"
        sig = tuple(signals or ())
        _validate_signals(sig)
        obj = self._commit(content, tuple(subgoals), sig, authorised_by, note)
        return True, f"objective established at v{obj.version}"

    def propose(self, content: str, subgoals: List[str],
                rationale: str, proposed_by: str = "agent",
                signals: Optional[List[ObjectiveSignal]] = None
                ) -> ObjectiveProposal:
        """Agent-callable. Creates a PENDING proposal. Never auto-applies."""
        sig = tuple(signals or ())
        _validate_signals(sig)   # reject bad signals at proposal time, not later
        pid = uuid.uuid4().hex[:12]
        base = self._objective.version if self._objective else 0
        p = ObjectiveProposal(pid, base, content, tuple(subgoals),
                              sig, rationale, proposed_by)
        self._proposals[pid] = p
        _audit("OBJECTIVE_PROPOSED", proposed_by,
               f"proposal={pid} base_v{base}: {rationale[:60]}")
        return p

    def ratify_proposal(self, proposal_id: str, authorised_by: str,
                        note: str = "") -> Tuple[bool, str]:
        if not _is_human(authorised_by):
            return False, "ratifying an objective requires a human authoriser"
        p = self._proposals.get(proposal_id)
        if not p:
            return False, "no such proposal"
        if p.status is not ProposalStatus.PENDING:
            return False, f"proposal already {p.status.value}"
        if self._objective and p.base_version != self._objective.version:
            return False, ("proposal is stale (base version moved); re-propose "
                           "against the current objective")
        _validate_signals(p.signals)
        p.status = ProposalStatus.RATIFIED
        obj = self._commit(p.content, p.subgoals, p.signals, authorised_by, note)
        _audit("OBJECTIVE_RATIFIED", authorised_by,
               f"proposal={proposal_id} -> v{obj.version}: {note[:60]}")
        return True, f"ratified; objective now v{obj.version}"

    def reject_proposal(self, proposal_id: str, authorised_by: str,
                        reason: str) -> Tuple[bool, str]:
        if not _is_human(authorised_by):
            return False, "rejecting a proposal requires a human authoriser"
        p = self._proposals.get(proposal_id)
        if not p or p.status is not ProposalStatus.PENDING:
            return False, "no pending proposal with that id"
        p.status = ProposalStatus.REJECTED
        _audit("OBJECTIVE_REJECTED", authorised_by,
               f"proposal={proposal_id}: {reason[:60]}")
        return True, "rejected"

    # -- read (agent may call) ---------------------------------------

    def current(self) -> Optional[Objective]:
        return self._objective

    def current_hash(self) -> Optional[str]:
        return self._objective.entry_hash if self._objective else None

    def history(self) -> List[Objective]:
        return list(self._chain)

    def verify_chain(self) -> Tuple[bool, str]:
        """
        Recompute the hash chain. Detects any silent alteration or removal of
        a historical objective version — the cancer this engine exists to make
        impossible to hide.
        """
        prev = "GENESIS"
        for obj in self._chain:
            if obj.prev_hash != prev:
                return False, f"chain break at v{obj.version} (prev_hash mismatch)"
            recomputed = _hash_entry({
                "objective_id": obj.objective_id,
                "version": obj.version,
                "content": obj.content,
                "subgoals": list(obj.subgoals),
                "signals": [(s.key, s.role.value, s.is_self_assessment)
                            for s in obj.signals],
                "ratified_by": obj.ratified_by,
                "ratified_at": obj.ratified_at,
                "prev_hash": obj.prev_hash,
                "note": obj.note,
            })
            if recomputed != obj.entry_hash:
                return False, f"entry hash mismatch at v{obj.version}"
            prev = obj.entry_hash
        return True, "objective chain intact"

    # -- internal ----------------------------------------------------

    def _commit(self, content: str, subgoals: Tuple[str, ...],
                signals: Tuple[ObjectiveSignal, ...], authorised_by: str,
                note: str) -> Objective:
        version = (self._objective.version + 1) if self._objective else 1
        oid = self._objective.objective_id if self._objective else uuid.uuid4().hex[:16]
        ratified_at = time.time()
        fields = {
            "objective_id": oid,
            "version": version,
            "content": content,
            "subgoals": list(subgoals),
            "signals": [(s.key, s.role.value, s.is_self_assessment)
                        for s in signals],
            "ratified_by": authorised_by,
            "ratified_at": ratified_at,
            "prev_hash": self._last_hash,
            "note": note,
        }
        entry_hash = _hash_entry(fields)
        obj = Objective(
            objective_id=oid, version=version, content=content,
            subgoals=subgoals, signals=signals, ratified_by=authorised_by,
            ratified_at=ratified_at, prev_hash=self._last_hash,
            entry_hash=entry_hash, note=note,
        )
        self._chain.append(obj)
        self._objective = obj
        self._last_hash = entry_hash
        return obj


def _audit(action: str, by: str, detail: str) -> None:
    try:
        from driftcore.audit import record
        record(action=action, memory_text="objective",
               authorised_by=by or "system", detail=detail)
    except Exception:
        pass
