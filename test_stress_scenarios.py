"""
test_stress_scenarios.py
=======================
Cross-module stress scenarios — the places where authority, recovery, and
skill governance interact and where edge cases usually hide.

  S1. Human override of a domain deny still cannot act while FROZEN.
  S2. A governance DEMOTION immediately blocks the governed path.
  S3. The CONSTITUTION floor holds even with everything else allowing AND a
      human override AND mid-incident.
  S4. Full incident lifecycle: apply+checkpoint -> halt -> blocked -> human
      restore -> human unfreeze -> resume.
  S5. Tampered checkpoint ledger -> even a human restore is refused.

Run:  python test_stress_scenarios.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from driftcore.authority import (
    AuthorityResolver, AuthorityLayer as L, Verdict as V, LayerVerdict,
    GovernedExecutor,
)
from driftcore.skills.governance import MaturityController, SkillMaturity, SkillStats
from driftcore.recovery import (
    RecoveryManager, CheckpointStore, InMemorySnapshotter,
)

PASS, FAIL = "PASS", "FAIL"
_results = []


def check(name, cond):
    _results.append(bool(cond))
    print(f"  [{PASS if cond else FAIL}] {name}")


def fresh():
    snap = InMemorySnapshotter({"rec:1": "v0"})
    rec = RecoveryManager(CheckpointStore(), snap)
    mc = MaturityController()
    ex = GovernedExecutor(rec, mc)
    flag = {"applied": False}
    def apply_fn():
        flag["applied"] = True
        snap.state["rec:1"] = "mutated"
        return "ok"
    strong = SkillStats("s")
    for _ in range(200):
        strong.record(True)
    return snap, rec, mc, ex, flag, apply_fn, strong


# ── S1: override cannot bypass a freeze ────────────────────────────
print("\nS1. Human override does not bypass a freeze")

snap, rec, mc, ex, flag, apply_fn, strong = fresh()
rec.trigger_halt("incident")
res = ex.run("s", "household", SkillMaturity.TESTED, strong, apply_fn,
             resources=["rec:1"],
             extra_verdicts=[LayerVerdict(L.DOMAIN, V.DENY, "iso")],
             human_override=("justin", "supervised exception"))
check("authority allows via human override", res.decision.allowed is True)
check("but frozen system still blocks the apply", res.applied is False)
check("data untouched while frozen", snap.state["rec:1"] == "v0")


# ── S2: demotion immediately blocks the governed path ──────────────
print("\nS2. A demotion takes effect immediately")

snap, rec, mc, ex, flag, apply_fn, strong = fresh()
# qualifies at TRUSTED in security
maturity = SkillMaturity.TRUSTED
res = ex.run("s", "security", maturity, strong, apply_fn, resources=["rec:1"])
check("qualified security skill applies", res.applied is True)

# repeated failures -> human/again system demotes below requirement
maturity, _ = mc.demote(maturity, SkillMaturity.EXPERIMENTAL, "repeated failures")
flag["applied"] = False
res2 = ex.run("s", "security", maturity, strong, apply_fn, resources=["rec:1"])
check("after demotion the skill is blocked", res2.applied is False)
check("blocked by the SKILL layer (maturity)",
      res2.decision.binding_layer is L.SKILL)


# ── S3: floor holds under everything ───────────────────────────────
print("\nS3. Constitution floor holds against override + incident")

snap, rec, mc, ex, flag, apply_fn, strong = fresh()
res = ex.run("s", "household", SkillMaturity.TESTED, strong, apply_fn,
             resources=["rec:1"],
             extra_verdicts=[LayerVerdict(L.CONSTITUTION, V.DENY,
                                          "forbidden action class"),
                             LayerVerdict(L.PROFILE, V.ALLOW)],
             human_override=("justin", "I take responsibility"))
check("floor deny is not overridable by a human", res.decision.allowed is False)
check("binding layer is CONSTITUTION", res.decision.binding_layer is L.CONSTITUTION)
check("no apply on floor deny", res.applied is False)


# ── S4: full incident lifecycle ────────────────────────────────────
print("\nS4. Apply -> halt -> blocked -> restore -> unfreeze -> resume")

snap, rec, mc, ex, flag, apply_fn, strong = fresh()
res = ex.run("s", "household", SkillMaturity.TESTED, strong, apply_fn,
             resources=["rec:1"], skill_version="v1")
cid = res.checkpoint_id
check("initial apply succeeds + checkpoints", res.applied and cid)
check("data was mutated by the apply", snap.state["rec:1"] == "mutated")

rec.trigger_halt("anomaly: mass writes")
flag["applied"] = False
res_blocked = ex.run("s", "household", SkillMaturity.TESTED, strong, apply_fn,
                     resources=["rec:1"])
check("actions blocked during halt", res_blocked.applied is False)

ok_r, _ = rec.restore(cid, authorised_by="justin")
check("human restores pre-action state", ok_r and snap.state["rec:1"] == "v0")

ok_uf, _ = rec.unfreeze("justin")
check("human unfreezes", ok_uf and rec.frozen is False)

flag["applied"] = False
res_resume = ex.run("s", "household", SkillMaturity.TESTED, strong, apply_fn,
                    resources=["rec:1"])
check("operations resume after unfreeze", res_resume.applied is True)


# ── S5: tamper makes restore refuse ────────────────────────────────
print("\nS5. Tampered ledger -> restore refused even for a human")

snap, rec, mc, ex, flag, apply_fn, strong = fresh()
res = ex.run("s", "household", SkillMaturity.TESTED, strong, apply_fn,
             resources=["rec:1"])
cid = res.checkpoint_id
# tamper: mutate a ledger event in place
evt = rec._store._events[0]
rec._store._events[0] = evt.__class__(**{**evt.__dict__, "detail": "tampered"})
ok_t, msg = rec.restore(cid, authorised_by="justin")
check("restore refused on a compromised ledger", ok_t is False)
check("reason cites ledger integrity", "compromis" in msg.lower() or "integrity" in msg.lower())


# ── Summary ────────────────────────────────────────────────────────
print("\n" + "=" * 56)
passed, total = sum(_results), len(_results)
print(f"{passed}/{total} checks passed")
print("=" * 56)
if passed < total:
    sys.exit(1)
