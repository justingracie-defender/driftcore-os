"""
test_domain_controller.py — DOMAIN CONTROLLER VERIFICATION
===========================================================

Tests the skill domain activation system.

Key guarantees:
  - One primary domain active at a time
  - Domain switches are audited
  - Cross-domain isolation rules enforced
  - Medical domain shares with all (allergies are universal)
  - Security domain isolated from childcare (network tools ≠ child care)
  - suggest_domain() maps tasks to correct domain
  - can_cross_domain() enforces boundary rules

Run with:
    python test_domain_controller.py
"""

import sys
import os
import shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = "✅"
FAIL = "❌"
results = []

def check(name, condition):
    status = PASS if condition else FAIL
    print(f"  {status}  {name}")
    results.append((name, condition))

def reset_all():
    import driftcore.enforcement as e
    import driftcore.audit as a
    e._SHUTDOWN_TRIGGERED = False
    e._SESSION_KEY = None
    a._last_hash = None
    a._sequence = 0
    a._chain_compromised = False
    for f in ["logs/audit_chain.jsonl", "logs/SHUTDOWN_REASON.json",
              "data/domain_state.json"]:
        try: os.remove(f)
        except: pass


print("=" * 60)
print("  DRIFTCORE DOMAIN CONTROLLER — VERIFICATION SUITE")
print("=" * 60)


# ── TEST 1: Domain enum exists ────────────────────────────────────
print("\n  [1] Domain enum covers all contexts")
reset_all()

from driftcore.skills.domain import (
    SkillDomain, DomainController, DOMAIN_BOUNDARIES
)

check("HOUSEHOLD domain",      SkillDomain.HOUSEHOLD is not None)
check("CHILDCARE domain",      SkillDomain.CHILDCARE is not None)
check("YARD_WORK domain",      SkillDomain.YARD_WORK is not None)
check("SECURITY domain",       SkillDomain.SECURITY is not None)
check("MEDICAL domain",        SkillDomain.MEDICAL is not None)
check("MAINTENANCE domain",    SkillDomain.MAINTENANCE is not None)
check("ENTERTAINMENT domain",  SkillDomain.ENTERTAINMENT is not None)
check("GENERAL domain",        SkillDomain.GENERAL is not None)


# ── TEST 2: Boundary rules are defined ───────────────────────────
print("\n  [2] Boundary rules defined for all domains")
reset_all()

for domain in SkillDomain:
    check(f"boundary rules for {domain.value}",
          domain in DOMAIN_BOUNDARIES)
    if domain in DOMAIN_BOUNDARIES:
        boundary = DOMAIN_BOUNDARIES[domain]
        check(f"{domain.value} has shares_with",   "shares_with" in boundary)
        check(f"{domain.value} has isolated_from", "isolated_from" in boundary)


# ── TEST 3: Activate a domain ─────────────────────────────────────
print("\n  [3] Domain activation")
reset_all()

dc = DomainController()

import io
from contextlib import redirect_stdout
f = io.StringIO()
with redirect_stdout(f):
    result = dc.activate(SkillDomain.HOUSEHOLD, requested_by="planner")

check("activation succeeds",           result.success == True)
check("domain is HOUSEHOLD",           result.domain == SkillDomain.HOUSEHOLD)
check("current domain updated",        dc.current_domain() == SkillDomain.HOUSEHOLD)


# ── TEST 4: Domain switch ─────────────────────────────────────────
print("\n  [4] Domain switch")
reset_all()

dc2 = DomainController()
with redirect_stdout(io.StringIO()):
    dc2.activate(SkillDomain.HOUSEHOLD)
    result2 = dc2.activate(SkillDomain.CHILDCARE, requested_by="planner")

check("switch succeeds",               result2.success == True)
check("new domain is CHILDCARE",       dc2.current_domain() == SkillDomain.CHILDCARE)
check("switch count incremented",      dc2.stats()["switch_count"] == 2)
check("previous domain tracked",       dc2.stats()["previous_domain"] == "household")


# ── TEST 5: Activating same domain is no-op ───────────────────────
print("\n  [5] Activating same domain is a no-op")
reset_all()

dc3 = DomainController()
with redirect_stdout(io.StringIO()):
    dc3.activate(SkillDomain.HOUSEHOLD)
    result3 = dc3.activate(SkillDomain.HOUSEHOLD)

check("no-op returns success",         result3.success == True)
check("switch count stays at 1",       dc3.stats()["switch_count"] == 1)


# ── TEST 6: Medical shares with all domains ───────────────────────
print("\n  [6] Medical domain shares with all — allergies are universal")
reset_all()

dc4 = DomainController()

for domain in SkillDomain:
    if domain != SkillDomain.MEDICAL:
        allowed, reason = dc4.can_cross_domain(SkillDomain.MEDICAL, domain)
        check(f"medical shares with {domain.value}", allowed == True)


# ── TEST 7: Security isolated from childcare ──────────────────────
print("\n  [7] Security isolated from childcare")
reset_all()

dc5 = DomainController()

allowed, reason = dc5.can_cross_domain(
    SkillDomain.SECURITY, SkillDomain.CHILDCARE
)
check("security blocked from childcare",   allowed == False)
check("reason mentions isolation",
      "isolated" in reason.lower() or "childcare" in reason.lower())

# And the other direction
allowed2, reason2 = dc5.can_cross_domain(
    SkillDomain.CHILDCARE, SkillDomain.SECURITY
)
check("childcare blocked from security",   allowed2 == False)


# ── TEST 8: Deactivate domain ─────────────────────────────────────
print("\n  [8] Domain deactivation")
reset_all()

dc6 = DomainController()
with redirect_stdout(io.StringIO()):
    dc6.activate(SkillDomain.YARD_WORK)
    result6 = dc6.deactivate()

check("deactivation succeeds",         result6.success == True)
check("no domain active after deactivate",
      dc6.current_domain() is None)


# ── TEST 9: Task suggestion ───────────────────────────────────────
print("\n  [9] Task-to-domain suggestion")
reset_all()

dc7 = DomainController()

check("laundry → household",
      dc7.suggest_domain("please do the laundry") == SkillDomain.HOUSEHOLD)
check("daughter math → childcare",
      dc7.suggest_domain("help my daughter with math") == SkillDomain.CHILDCARE)
check("mow lawn → yard_work",
      dc7.suggest_domain("please mow the lawn") == SkillDomain.YARD_WORK)
check("network → security",
      dc7.suggest_domain("check the network security") == SkillDomain.SECURITY)
check("fix broken → maintenance",
      dc7.suggest_domain("fix the broken shelf") == SkillDomain.MAINTENANCE)
check("allergy → medical",
      dc7.suggest_domain("dad needs his medication") == SkillDomain.MEDICAL)


# ── TEST 10: can_use_skill without active domain ──────────────────
print("\n  [10] No skill available without active domain")
reset_all()

dc8 = DomainController()
allowed, reason = dc8.can_use_skill("some_skill_id")

check("skill blocked without domain",  allowed == False)
check("reason mentions no domain",
      "no domain" in reason.lower() or "activate" in reason.lower())


# ── TEST 11: Stats report correctly ──────────────────────────────
print("\n  [11] Stats report correctly")
reset_all()

dc9 = DomainController()
with redirect_stdout(io.StringIO()):
    dc9.activate(SkillDomain.HOUSEHOLD)
    dc9.activate(SkillDomain.CHILDCARE)

stats = dc9.stats()
check("active_domain in stats",        "active_domain" in stats)
check("switch_count in stats",         "switch_count" in stats)
check("switch_count is 2",             stats["switch_count"] == 2)
check("active_domain is childcare",    stats["active_domain"] == "childcare")


# ── TEST 12: Domain switches audited ─────────────────────────────
print("\n  [12] Domain switches recorded in audit chain")
reset_all()

dc10 = DomainController()
with redirect_stdout(io.StringIO()):
    dc10.activate(SkillDomain.HOUSEHOLD, requested_by="planner")
    dc10.activate(SkillDomain.CHILDCARE, requested_by="planner")

from driftcore.audit import read_chain
entries = read_chain()
domain_entries = [e for e in entries if "DOMAIN" in e.get("action", "")]

check("domain switches in audit chain", len(domain_entries) >= 2)
check("switch records from/to",
      any("household" in e.get("memory_text", "").lower()
          for e in domain_entries))


# ── TEST 13: State persists to disk ──────────────────────────────
print("\n  [13] Domain state persists across instances")
reset_all()

dc11 = DomainController()
with redirect_stdout(io.StringIO()):
    dc11.activate(SkillDomain.MAINTENANCE)

check("state file written",             os.path.exists("data/domain_state.json"))

dc11b = DomainController()
check("domain restored after reload",
      dc11b.current_domain() == SkillDomain.MAINTENANCE)


# ── RESULTS ───────────────────────────────────────────────────────
print("\n" + "=" * 60)
passed = sum(1 for _, ok in results if ok)
total  = len(results)
print(f"  {passed}/{total} tests passed")

if passed == total:
    print(f"  {PASS} All domain controller tests pass.")
    print(f"  One domain active at a time.")
    print(f"  Medical facts cross all domains.")
    print(f"  Security tools never bleed into child care.")
    print(f"  Every switch is audited.")
else:
    print(f"\n  {FAIL} Failed tests:")
    for name, ok in results:
        if not ok:
            print(f"      • {name}")
print("=" * 60)

if passed < total:
    sys.exit(1)
