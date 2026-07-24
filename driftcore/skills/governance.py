"""
driftcore/skills/governance.py
==============================
Skill governance additions, all evidence-based and human-gated where it
counts. Four pieces, kept decoupled from the heavy skills package (domains
are referenced by their string value so this module has no import coupling):

  1. SkillStats + confidence   — trust sparse data less. A 100%-from-1-sample
                                 skill must not be trusted like 96%-from-500.
                                 Confidence is a Wilson score LOWER bound, which
                                 penalises small samples automatically.
  2. SkillMaturity             — EXPERIMENTAL → TESTED → TRUSTED →
                                 CRITICAL_APPROVED, with a per-domain required
                                 level. Evidence can promote only as far as
                                 TESTED; TRUSTED and CRITICAL_APPROVED are
                                 human-only (no self-grading into childcare).
                                 Demotion is always easy (asymmetry).
  3. FailureCaseLibrary        — append-only "case law": structured failures
                                 with cause + mitigation, retrievable by
                                 similarity so past mitigations load for
                                 similar tasks.
  4. SkillPatchProposal ledger — reflection/failures produce PROPOSALS, never
                                 direct edits. Only a human approves, which
                                 bumps the version. Append-only + audited.
"""

from __future__ import annotations

import math
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Union

# ── human identity ──────────────────────────────────────────────────────────
# (red-team, external) This module used to carry its OWN copy of a reserved-word
# blacklist, so `_is_human("mallory")` returned True and any caller that chose its
# own `authorised_by` string self-authorized. Three modules carried identical
# copies. The single shared implementation supports registered principals and
# signed attestations: driftcore/authority/human_identity.py
#
# The import is LOCAL (deferred) to break the authority <-> skills import cycle —
# the same idiom coordinator.py uses for interpretation_guard.
def _is_human(authorised_by) -> bool:
    from driftcore.authority.human_identity import is_human
    return is_human(authorised_by)



# ── 1. Confidence from outcomes (Wilson lower bound) ──────────────

def wilson_lower_bound(successes: int, n: int, z: float = 1.96) -> float:
    """
    Lower bound of a binomial proportion at ~95% confidence (z=1.96).
    Penalises small samples: 1/1 -> ~0.21, 480/500 -> ~0.94, 0/0 -> 0.0.
    This is the trustworthy number, not the raw success rate.
    """
    if n <= 0:
        return 0.0
    p = successes / n
    denom = 1 + z * z / n
    center = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (center - margin) / denom)


class SkillStats:
    """Mutable outcome tracker for one skill. Confidence is sparse-aware."""

    def __init__(self, skill_id: str, samples: int = 0, successes: int = 0):
        self.skill_id = skill_id
        self.samples = samples
        self.successes = successes

    def record(self, success: bool) -> None:
        self.samples += 1
        if success:
            self.successes += 1

    @property
    def sample_size(self) -> int:
        return self.samples

    @property
    def success_rate(self) -> float:
        return self.successes / self.samples if self.samples else 0.0

    @property
    def confidence(self) -> float:
        """Wilson lower bound — the number to gate trust on."""
        return wilson_lower_bound(self.successes, self.samples)


# ── 2. Maturity tiers + per-domain requirements ───────────────────

class SkillMaturity(Enum):
    EXPERIMENTAL      = "experimental"
    TESTED            = "tested"
    TRUSTED           = "trusted"
    CRITICAL_APPROVED = "critical_approved"

    @property
    def rank(self) -> int:
        return {"experimental": 0, "tested": 1,
                "trusted": 2, "critical_approved": 3}[self.value]


# Required maturity to operate in each domain (keyed by SkillDomain value).
# High-stakes domains demand human-approved tiers.
DOMAIN_REQUIRED_MATURITY: Dict[str, SkillMaturity] = {
    "household":     SkillMaturity.TESTED,
    "yard_work":     SkillMaturity.TESTED,
    "entertainment": SkillMaturity.TESTED,
    "general":       SkillMaturity.TESTED,
    "maintenance":   SkillMaturity.TRUSTED,
    "security":      SkillMaturity.TRUSTED,
    "childcare":     SkillMaturity.CRITICAL_APPROVED,
    "medical":       SkillMaturity.CRITICAL_APPROVED,
}

# Evidence (usage stats) can promote a skill no higher than this. Anything
# above must be granted by a human — you cannot earn your way into childcare.
EVIDENCE_PROMOTION_CEILING = SkillMaturity.TESTED

# Minimum LIVE confidence (Wilson lower bound) required to run in a domain,
# on top of the maturity tier. Maturity is a sticky label; this catches a
# skill whose recent success has degraded below what a critical domain needs,
# before it gets formally demoted. High-criticality domains demand more.
DOMAIN_MIN_CONFIDENCE: Dict[str, float] = {
    "childcare": 0.90,
    "medical":   0.90,
    "security":  0.85,
    "maintenance": 0.85,
    # household / yard_work / entertainment / general: rely on maturity tier
}


def _domain_value(domain: Union[str, "Enum"]) -> str:
    return domain.value if hasattr(domain, "value") else str(domain)


class MaturityController:
    def __init__(self):
        self._audit_hook = _audit

    def required_for(self, domain) -> SkillMaturity:
        return DOMAIN_REQUIRED_MATURITY.get(_domain_value(domain),
                                            SkillMaturity.TESTED)

    def may_run(self, maturity: SkillMaturity, domain,
                stats: "SkillStats" = None) -> Tuple[bool, str]:
        need = self.required_for(domain)
        if maturity.rank < need.rank:
            return False, (f"{maturity.value} below required {need.value} "
                           f"for domain {_domain_value(domain)}")
        # Live confidence floor for high-criticality domains (on top of tier).
        floor = DOMAIN_MIN_CONFIDENCE.get(_domain_value(domain), 0.0)
        if stats is not None and floor > 0.0 and stats.confidence < floor:
            return False, (f"live confidence {stats.confidence:.2f} below "
                           f"{floor:.2f} required for {_domain_value(domain)}")
        return True, f"{maturity.value} >= required {need.value}"

    def evidence_promotion(self, current: SkillMaturity, stats: SkillStats,
                           min_samples: int = 20, min_confidence: float = 0.80
                           ) -> SkillMaturity:
        """
        Promote based on evidence — but never above the evidence ceiling
        (TESTED). Returns the (possibly unchanged) maturity.
        """
        if current.rank >= EVIDENCE_PROMOTION_CEILING.rank:
            return current
        if (stats.sample_size >= min_samples
                and stats.confidence >= min_confidence):
            self._audit_hook("SKILL_MATURITY_PROMOTED", "system",
                             f"{stats.skill_id} {current.value}->tested "
                             f"(n={stats.sample_size}, conf={stats.confidence:.2f})")
            return SkillMaturity.TESTED
        return current

    def human_promote(self, current: SkillMaturity, target: SkillMaturity,
                      authorised_by: str, reason: str = ""
                      ) -> Tuple[bool, SkillMaturity, str]:
        """TRUSTED and CRITICAL_APPROVED require a human authoriser + a reason."""
        if not _is_human(authorised_by):
            return False, current, "promotion to this tier requires a human authoriser"
        if not reason.strip():
            return False, current, "promotion requires a reason (for the audit trail)"
        if target.rank <= current.rank:
            return False, current, "target is not a promotion"
        self._audit_hook("SKILL_MATURITY_PROMOTED", authorised_by,
                         f"{current.value}->{target.value} by human: {reason}")
        return True, target, f"promoted to {target.value}"

    def demote(self, current: SkillMaturity, target: SkillMaturity,
               reason: str) -> Tuple[SkillMaturity, str]:
        """Demotion is always allowed (asymmetry: easy to make safer)."""
        if target.rank >= current.rank:
            return current, "not a demotion"
        self._audit_hook("SKILL_MATURITY_DEMOTED", "system",
                         f"{current.value}->{target.value}: {reason}")
        return target, f"demoted to {target.value}: {reason}"


# ── 3. Failure-case library ("case law") ──────────────────────────

@dataclass(frozen=True)
class FailureCase:
    case_id:    str
    at:         float
    skill_id:   str
    domain:     str
    task:       str
    expected:   str
    actual:     str
    cause:      str
    mitigation: str


class FailureCaseLibrary:
    """Append-only store of structured failures, retrievable by similarity."""

    def __init__(self):
        self._cases: List[FailureCase] = []

    def add(self, skill_id: str, domain, task: str, expected: str,
            actual: str, cause: str, mitigation: str) -> FailureCase:
        case = FailureCase(
            case_id=uuid.uuid4().hex[:12], at=time.time(),
            skill_id=skill_id, domain=_domain_value(domain), task=task,
            expected=expected, actual=actual, cause=cause, mitigation=mitigation)
        self._cases.append(case)
        _audit("FAILURE_CASE_RECORDED", "system",
               f"skill={skill_id} task={task[:40]}")
        return case

    def all(self) -> List[FailureCase]:
        return list(self._cases)

    @staticmethod
    def _tokens(text: str) -> set:
        return {w for w in text.lower().split() if len(w) > 2}

    def find_similar(self, task: str, top_k: int = 3,
                     min_overlap: float = 0.1) -> List[Tuple[FailureCase, float]]:
        """
        Return up to top_k past failures most similar to `task` (Jaccard token
        overlap). A real deployment would use vector similarity (e.g. Qdrant);
        this is the retrieval contract, kept dependency-free.
        """
        qt = self._tokens(task)
        scored = []
        for c in self._cases:
            ct = self._tokens(c.task)
            if not qt or not ct:
                continue
            sim = len(qt & ct) / len(qt | ct)
            if sim >= min_overlap:
                scored.append((c, sim))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_k]


# ── 4. Patch proposals (propose, don't auto-modify) ───────────────

class ProposalStatus(Enum):
    PENDING  = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass
class SkillPatchProposal:
    proposal_id:      str
    skill_id:         str
    current_version:  str
    change_summary:   str
    evidence_case_ids: tuple
    status:           ProposalStatus = ProposalStatus.PENDING
    created_at:       float = field(default_factory=time.time)
    decided_by:       str = ""
    new_version:      str = ""


class ProposalLedger:
    """
    Failures/reflection create PROPOSALS. They never auto-apply. Only a human
    approves, which records the version bump. Append-only and audited — this
    is the conservative path for CHILDCARE / SECURITY / MEDICAL / MAINTENANCE.
    """

    def __init__(self):
        self._proposals: Dict[str, SkillPatchProposal] = {}

    def propose(self, skill_id: str, current_version: str, change_summary: str,
                evidence_case_ids=(), proposed_by: str = "reflection"
                ) -> SkillPatchProposal:
        pid = uuid.uuid4().hex[:12]
        p = SkillPatchProposal(
            proposal_id=pid, skill_id=skill_id, current_version=current_version,
            change_summary=change_summary, evidence_case_ids=tuple(evidence_case_ids))
        self._proposals[pid] = p
        _audit("SKILL_PATCH_PROPOSED", proposed_by,
               f"skill={skill_id} v{current_version}: {change_summary[:50]}")
        return p

    def approve(self, proposal_id: str, authorised_by: str, new_version: str,
                note: str = "") -> Tuple[bool, str]:
        if not _is_human(authorised_by):
            return False, "approving a skill patch requires a human authoriser"
        if not note.strip():
            return False, "approval requires a note (for the audit trail)"
        p = self._proposals.get(proposal_id)
        if not p:
            return False, "no such proposal"
        if p.status is not ProposalStatus.PENDING:
            return False, f"proposal already {p.status.value}"
        p.status = ProposalStatus.APPROVED
        p.decided_by = authorised_by
        p.new_version = new_version
        _audit("SKILL_PATCH_APPROVED", authorised_by,
               f"skill={p.skill_id} v{p.current_version}->v{new_version}: {note}")
        return True, f"approved; version {p.current_version} -> {new_version}"

    def reject(self, proposal_id: str, authorised_by: str, reason: str = ""
               ) -> Tuple[bool, str]:
        if not _is_human(authorised_by):
            return False, "rejecting a skill patch requires a human authoriser"
        p = self._proposals.get(proposal_id)
        if not p:
            return False, "no such proposal"
        if p.status is not ProposalStatus.PENDING:
            return False, f"proposal already {p.status.value}"
        p.status = ProposalStatus.REJECTED
        p.decided_by = authorised_by
        _audit("SKILL_PATCH_REJECTED", authorised_by,
               f"skill={p.skill_id}: {reason}")
        return True, "rejected"

    def get(self, proposal_id: str) -> Optional[SkillPatchProposal]:
        return self._proposals.get(proposal_id)

    def pending(self) -> List[SkillPatchProposal]:
        return [p for p in self._proposals.values()
                if p.status is ProposalStatus.PENDING]


# ── Bridge: failures -> drafted proposal (still human-gated) ───────

def draft_proposal_from_failures(ledger: ProposalLedger,
                                 library: FailureCaseLibrary,
                                 skill_id: str, current_version: str, task: str,
                                 top_k: int = 3, proposed_by: str = "reflection"
                                 ) -> Optional[SkillPatchProposal]:
    """
    Connect the failure-case library to the proposal ledger: find failures
    similar to `task`, and if any exist, draft a PENDING proposal that cites
    them as evidence and synthesises their mitigations into a change summary.

    This only DRAFTS — the proposal is still PENDING and a human must approve
    it (which is what bumps the version). It is the buildable half of
    "failures -> proposal"; the auto-trigger (e.g. a reflection POOR verdict
    calling this) is the integration hook, not built here.

    Returns the proposal, or None if there are no similar failures.
    """
    similar = library.find_similar(task, top_k=top_k)
    if not similar:
        return None
    cases = [c for c, _ in similar]
    mitigations = "; ".join(dict.fromkeys(c.mitigation for c in cases if c.mitigation))
    summary = f"Address recurring failures on '{task}': {mitigations}"
    return ledger.propose(skill_id, current_version, summary,
                          evidence_case_ids=[c.case_id for c in cases],
                          proposed_by=proposed_by)


# ── shared helpers ────────────────────────────────────────────────



def _audit(action: str, by: str, detail: str):
    try:
        from driftcore.audit import record
        record(action=action, memory_text="skill_governance",
               authorised_by=by or "system", detail=detail)
    except Exception:
        pass
