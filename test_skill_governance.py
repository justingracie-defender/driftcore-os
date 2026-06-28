"""
test_skill_governance.py
=======================
Proves the skill-governance additions:

  - Confidence is sparse-aware (1/1 << 480/500).
  - Maturity gates per domain; evidence promotes only to TESTED;
    TRUSTED / CRITICAL_APPROVED are human-only; demotion is free.
  - Failure-case library is append-only and retrieves similar cases.
  - Patch proposals never auto-apply; only a human approves (version bump).

Run:  python test_skill_governance.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from driftcore.skills.governance import (
    wilson_lower_bound, SkillStats,
    SkillMaturity, MaturityController, DOMAIN_REQUIRED_MATURITY,
    FailureCaseLibrary,
    ProposalLedger, ProposalStatus,
)

PASS, FAIL = "PASS", "FAIL"
_results = []


def check(name, cond):
    _results.append(bool(cond))
    print(f"  [{PASS if cond else FAIL}] {name}")


# ── Confidence ─────────────────────────────────────────────────────
print("\nConfidence is sparse-aware")

c_1 = wilson_lower_bound(1, 1)
c_500 = wilson_lower_bound(480, 500)
check("100%-from-1 confidence is low (<0.3)", c_1 < 0.3)
check("96%-from-500 confidence is high (>0.9)", c_500 > 0.9)
check("more samples at same rate -> higher confidence",
      wilson_lower_bound(48, 50) > wilson_lower_bound(4, 5))
check("zero samples -> zero confidence", wilson_lower_bound(0, 0) == 0.0)

s = SkillStats("skill.x")
for _ in range(48): s.record(True)
for _ in range(2):  s.record(False)
check("SkillStats tracks rate and confidence",
      abs(s.success_rate - 0.96) < 1e-9 and 0.8 < s.confidence < 0.96)


# ── Maturity gating ────────────────────────────────────────────────
print("\nMaturity gates per domain")

mc = MaturityController()
check("childcare requires CRITICAL_APPROVED",
      mc.required_for("childcare") is SkillMaturity.CRITICAL_APPROVED)
check("household requires TESTED",
      mc.required_for("household") is SkillMaturity.TESTED)

ok_run, _ = mc.may_run(SkillMaturity.TESTED, "childcare")
check("TESTED skill may NOT run in childcare", ok_run is False)
ok_run2, _ = mc.may_run(SkillMaturity.CRITICAL_APPROVED, "childcare")
check("CRITICAL_APPROVED skill may run in childcare", ok_run2 is True)
ok_run3, _ = mc.may_run(SkillMaturity.TESTED, "household")
check("TESTED skill may run in household", ok_run3 is True)


# ── Maturity promotion rules ───────────────────────────────────────
print("\nPromotion: evidence to TESTED only; higher tiers human-only")

stats = SkillStats("skill.y")
for _ in range(30): stats.record(True)   # 30/30, high confidence
promoted = mc.evidence_promotion(SkillMaturity.EXPERIMENTAL, stats)
check("strong evidence promotes EXPERIMENTAL -> TESTED",
      promoted is SkillMaturity.TESTED)

# evidence cannot exceed the ceiling
beyond = mc.evidence_promotion(SkillMaturity.TESTED, stats)
check("evidence cannot promote past TESTED", beyond is SkillMaturity.TESTED)

# sparse data does NOT promote
sparse = SkillStats("skill.z")
sparse.record(True)
no_promo = mc.evidence_promotion(SkillMaturity.EXPERIMENTAL, sparse)
check("1/1 does not earn promotion", no_promo is SkillMaturity.EXPERIMENTAL)

# TRUSTED / CRITICAL_APPROVED require a human
ok_sys, m_sys, _ = mc.human_promote(SkillMaturity.TESTED,
                                    SkillMaturity.CRITICAL_APPROVED, "system",
                                    reason="x")
check("'system' cannot promote to CRITICAL_APPROVED", ok_sys is False)
ok_noreason, _, _ = mc.human_promote(SkillMaturity.TESTED,
                                     SkillMaturity.CRITICAL_APPROVED, "justin")
check("human promotion without a reason is rejected", ok_noreason is False)
ok_h, m_h, _ = mc.human_promote(SkillMaturity.TESTED,
                                SkillMaturity.CRITICAL_APPROVED, "justin",
                                reason="vetted against childcare safety cases")
check("human can promote to CRITICAL_APPROVED with a reason",
      ok_h and m_h is SkillMaturity.CRITICAL_APPROVED)

# demotion is free
dem, _ = mc.demote(SkillMaturity.TRUSTED, SkillMaturity.EXPERIMENTAL,
                   "repeated failures")
check("demotion needs no human (easy to make safer)",
      dem is SkillMaturity.EXPERIMENTAL)


# ── Live confidence floor for high-criticality domains ─────────────
print("\nLive confidence floor (criticality-scaled)")

good = SkillStats("skill.crit")
for _ in range(200): good.record(True)       # high confidence
weak = SkillStats("skill.crit2")
for _ in range(8): good.record(True)         # (noise)
for _ in range(10): weak.record(True)
for _ in range(3):  weak.record(False)       # ~0.77 -> below 0.90 floor

ok_g, _ = mc.may_run(SkillMaturity.CRITICAL_APPROVED, "childcare", stats=good)
ok_w, why_w = mc.may_run(SkillMaturity.CRITICAL_APPROVED, "childcare", stats=weak)
check("high live confidence passes childcare floor", ok_g is True)
check("degraded confidence blocked in childcare even at right tier",
      ok_w is False)
# household has no live floor — tier alone suffices
ok_house, _ = mc.may_run(SkillMaturity.TESTED, "household", stats=weak)
check("low-criticality domain has no live-confidence floor", ok_house is True)


# ── Failure-case library ───────────────────────────────────────────
print("\nFailure-case library (append-only + retrieval)")

lib = FailureCaseLibrary()
api = dir(lib)
check("library has no delete/modify", not any(m in api for m in ("delete", "remove", "modify")))

lib.add("skill.dish", "household", "carry dinner plates to sink",
        "plates delivered intact", "plate slipped and broke",
        "grip too loose on ceramic", "increase grip force on smooth surfaces")
lib.add("skill.toy", "household", "pick up toys from floor",
        "floor clear", "missed a small toy under couch",
        "occlusion not checked", "scan low/occluded areas before declaring done")

hits = lib.find_similar("carry the plates to the kitchen sink")
check("retrieves the relevant plate failure first",
      hits and hits[0][0].skill_id == "skill.dish")
check("mitigation is available on retrieval",
      hits and "grip" in hits[0][0].mitigation)


# ── Patch proposals (human-gated) ──────────────────────────────────
print("\nPatch proposals never auto-apply")

ledger = ProposalLedger()
p = ledger.propose("skill.dish", "1.0.0",
                   "raise default grip force for smooth ceramics",
                   evidence_case_ids=[c.case_id for c in lib.all()],
                   proposed_by="reflection")
check("proposal starts PENDING", p.status is ProposalStatus.PENDING)

ok_sys, _ = ledger.approve(p.proposal_id, "system", "1.0.1", note="ok")
check("'system' cannot approve a patch", ok_sys is False)
ok_refl, _ = ledger.approve(p.proposal_id, "reflection", "1.0.1", note="ok")
check("'reflection' cannot approve its own patch", ok_refl is False)
ok_nonote, _ = ledger.approve(p.proposal_id, "justin", "1.0.1")
check("approval without a note is rejected", ok_nonote is False)
check("proposal still pending after rejected approvals",
      ledger.get(p.proposal_id).status is ProposalStatus.PENDING)

ok_h, msg = ledger.approve(p.proposal_id, "justin", "1.0.1",
                           note="reproduced the plate-grip failure; fix verified")
check("human approval bumps the version",
      ok_h and ledger.get(p.proposal_id).new_version == "1.0.1")
check("approved proposal is no longer pending",
      ledger.get(p.proposal_id).status is ProposalStatus.APPROVED)

# re-approving a decided proposal is rejected
ok_again, _ = ledger.approve(p.proposal_id, "justin", "1.0.2", note="retry")
check("cannot re-decide an already-approved proposal", ok_again is False)


# ── Bridge: failures -> drafted proposal (still human-gated) ────────
print("\nFailures -> drafted proposal (connecting the two ledgers)")

from driftcore.skills.governance import draft_proposal_from_failures

ledger2 = ProposalLedger()
drafted = draft_proposal_from_failures(
    ledger2, lib, "skill.dish", "1.0.0",
    task="carry the plates to the kitchen sink")
check("a relevant failure produces a drafted proposal", drafted is not None)
check("drafted proposal starts PENDING",
      drafted.status is ProposalStatus.PENDING)
check("drafted proposal cites the failure cases as evidence",
      len(drafted.evidence_case_ids) >= 1)
ok_auto, _ = ledger2.approve(drafted.proposal_id, "reflection", "1.0.1", note="auto")
check("drafted proposal still cannot self-approve", ok_auto is False)

none_drafted = draft_proposal_from_failures(
    ledger2, lib, "skill.dish", "1.0.0", task="quantum chromodynamics lecture")
check("no similar failures -> no proposal drafted", none_drafted is None)


# ── Summary ────────────────────────────────────────────────────────
print("\n" + "=" * 56)
passed, total = sum(_results), len(_results)
print(f"{passed}/{total} checks passed")
print("=" * 56)
if passed < total:
    sys.exit(1)
