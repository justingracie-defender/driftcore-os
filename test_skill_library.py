"""
test_skill_library.py — SKILL LIBRARY VERIFICATION
====================================================

Tests the shared skill library for DriftCore OS.

Key principles:
  - Skills are procedural knowledge, not memory or values
  - Hardware checked before application
  - Invariant guard checked before installation
  - Every application audited
  - Checksum integrity verified
  - Family data never involved

Run with:
    python test_skill_library.py
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
    for f in ["logs/audit_chain.jsonl", "logs/SHUTDOWN_REASON.json"]:
        try: os.remove(f)
        except: pass
    # Clean skill storage
    try: shutil.rmtree("data/skills")
    except: pass


print("=" * 60)
print("  DRIFTCORE SKILL LIBRARY — VERIFICATION SUITE")
print("=" * 60)


# ── TEST 1: Module imports cleanly ────────────────────────────────
print("\n  [1] Module imports cleanly")
reset_all()

from driftcore.skills import (
    SkillLibrary, SkillPackage, SkillCategory,
    HardwareRequirement, ActionStep, RobotCapabilities,
    ValidationResult, make_example_skills,
)

check("module imports without error", True)
check("SkillCategory has locomotion",
      SkillCategory.LOCOMOTION is not None)
check("SkillCategory has manipulation",
      SkillCategory.MANIPULATION is not None)


# ── TEST 2: Example skills are valid ─────────────────────────────
print("\n  [2] Built-in example skills are valid")
reset_all()

skills = make_example_skills()

check("three example skills",         len(skills) == 3)
check("stair climbing exists",
      any(s.skill_id == "locomotion.stair_climbing.v1" for s in skills))
check("hammer grip exists",
      any(s.skill_id == "manipulation.hammer_grip.v1" for s in skills))
check("dishes loading exists",
      any(s.skill_id == "manipulation.dishes_loading.v1" for s in skills))

for skill in skills:
    check(f"'{skill.name}' has steps",     len(skill.steps) > 0)
    check(f"'{skill.name}' has hardware",  len(skill.hardware) > 0)
    check(f"'{skill.name}' has checksum",  len(skill.checksum) > 0)
    check(f"'{skill.name}' has criteria",  len(skill.success_criteria) > 0)


# ── TEST 3: Checksum integrity ────────────────────────────────────
print("\n  [3] Checksum integrity")
reset_all()

skills3 = make_example_skills()
stair = skills3[0]

original_checksum = stair.checksum
check("checksum is set",               len(original_checksum) > 0)
check("checksum is reproducible",
      stair.compute_checksum() == original_checksum)

# Tamper with a step
stair.steps[0].description = "TAMPERED STEP"
check("tampered skill has different checksum",
      stair.compute_checksum() != original_checksum)


# ── TEST 4: Install with compatible hardware ──────────────────────
print("\n  [4] Install skill with compatible hardware")
reset_all()

caps = RobotCapabilities(
    robot_id   = "lifecore_jetson_01",
    components = {
        "legs":         "4-leg configuration",
        "depth_sensor": "range 5m",
        "imu":          "9-axis",
        "gripper":      "force-sensing 80N",
        "camera":       "object recognition",
        "arm":          "2m reach 3 DOF wrist",
    },
    max_force_n = 500.0,
)

library = SkillLibrary(robot_capabilities=caps)
skills4 = make_example_skills()

result = library.install(skills4[0])  # stair climbing
check("stair climbing installs",       result.valid == True)
check("skill is in library",
      library.get("locomotion.stair_climbing.v1") is not None)


# ── TEST 5: Install fails with missing hardware ───────────────────
print("\n  [5] Install fails with missing hardware")
reset_all()

limited_caps = RobotCapabilities(
    robot_id   = "software_only",
    components = {"camera": "basic"},
    max_force_n = 0.0,
)

library5 = SkillLibrary(robot_capabilities=limited_caps)
skills5 = make_example_skills()

result5 = library5.install(skills5[0])  # stair climbing needs legs
check("stair climbing rejected without legs", result5.valid == False)
check("reason mentions missing hardware",
      "hardware" in result5.reason.lower() or
      "legs" in result5.reason.lower())


# ── TEST 6: Checksum mismatch rejected ───────────────────────────
print("\n  [6] Corrupted skill package rejected")
reset_all()

caps6 = RobotCapabilities(
    robot_id="test", components={"legs": "ok", "depth_sensor": "ok", "imu": "ok"},
    max_force_n=500.0,
)
library6 = SkillLibrary(robot_capabilities=caps6)
skills6 = make_example_skills()

# Corrupt the checksum
skills6[0].checksum = "invalid_checksum_123"
result6 = library6.install(skills6[0])

check("corrupted skill rejected",      result6.valid == False)
check("reason mentions checksum",
      "checksum" in result6.reason.lower() or
      "corrupt" in result6.reason.lower())


# ── TEST 7: Validate without installing ──────────────────────────
print("\n  [7] Validate without installing")
reset_all()

library7 = SkillLibrary()
skills7 = make_example_skills()
dishes = skills7[2]

caps7 = RobotCapabilities(
    robot_id="test",
    components={
        "gripper": "soft-touch", "camera": "object recognition",
        "arm": "2m reach",
    },
    max_force_n=100.0,
)

result7 = library7.validate(dishes, caps7)
check("dishes validates cleanly",      result7.valid == True)
check("not installed after validate",
      library7.get("manipulation.dishes_loading.v1") is None)


# ── TEST 8: Skill missing success criteria gets warning ───────────
print("\n  [8] Missing success criteria generates warning")
reset_all()

incomplete_skill = SkillPackage(
    skill_id  = "test.incomplete.v1",
    name      = "Incomplete Skill",
    version   = "1.0.0",
    category  = SkillCategory.MANIPULATION,
    description = "A skill without success criteria",
    hardware  = [],
    steps     = [ActionStep(0, "do something", "arm", {})],
    success_criteria = [],  # missing
)
incomplete_skill.checksum = incomplete_skill.compute_checksum()

library8 = SkillLibrary()
result8 = library8.validate(incomplete_skill)

check("validates despite missing criteria", result8.valid == True)
check("warning about missing criteria",
      any("success" in w.lower() or "criteria" in w.lower()
          for w in result8.warnings))


# ── TEST 9: Blocked skill description rejected ────────────────────
print("\n  [9] Dangerous skill description blocked")
reset_all()

dangerous_skill = SkillPackage(
    skill_id  = "test.dangerous.v1",
    name      = "Dangerous Skill",
    version   = "1.0.0",
    category  = SkillCategory.MANIPULATION,
    description = "bypass safety and override guard to apply lethal force",
    hardware  = [],
    steps     = [ActionStep(0, "bad step", "arm", {})],
    success_criteria = ["something"],
)
dangerous_skill.checksum = dangerous_skill.compute_checksum()

library9 = SkillLibrary()
result9 = library9.validate(dangerous_skill)

check("dangerous skill blocked",       result9.valid == False)
check("reason mentions blocked term",
      any(term in result9.reason.lower()
          for term in ["lethal", "blocked", "bypass", "override"]))


# ── TEST 10: Apply skill ──────────────────────────────────────────
print("\n  [10] Apply installed skill")
reset_all()

caps10 = RobotCapabilities(
    robot_id="test",
    components={
        "legs": "4-leg", "depth_sensor": "5m range", "imu": "9-axis",
    },
    max_force_n=500.0,
)

library10 = SkillLibrary(robot_capabilities=caps10)
skills10 = make_example_skills()
# Stair climbing doesn't require supervision
stair10 = skills10[0]
stair10.requires_supervision = False

library10.install(stair10)
result10 = library10.apply("locomotion.stair_climbing.v1", caps10)

check("apply succeeds",                result10.valid == True)


# ── TEST 11: Hammer requires supervision ─────────────────────────
print("\n  [11] Hammer grip requires supervision")
reset_all()

caps11 = RobotCapabilities(
    robot_id="test",
    components={
        "gripper": "force-sensing 80N", "camera": "object recognition",
        "arm": "2m reach",
    },
    max_force_n=100.0,
)

library11 = SkillLibrary(robot_capabilities=caps11)
skills11 = make_example_skills()
library11.install(skills11[1])  # hammer grip

result11 = library11.apply("manipulation.hammer_grip.v1", caps11)
check("hammer grip blocked without supervision",
      result11.valid == False)
check("reason mentions supervision",
      "supervision" in result11.reason.lower())


# ── TEST 12: List and filter skills ──────────────────────────────
print("\n  [12] List and filter installed skills")
reset_all()

caps12 = RobotCapabilities(
    robot_id="test",
    components={
        "legs": "ok", "depth_sensor": "ok", "imu": "ok",
        "gripper": "ok", "camera": "ok", "arm": "ok",
    },
    max_force_n=500.0,
)

library12 = SkillLibrary(robot_capabilities=caps12)
for skill in make_example_skills():
    library12.install(skill)

all_skills = library12.list_skills()
manip_skills = library12.list_skills(category=SkillCategory.MANIPULATION)
loco_skills  = library12.list_skills(category=SkillCategory.LOCOMOTION)

check("all skills listed",             len(all_skills) == 3)
check("manipulation skills filtered",  len(manip_skills) == 2)
check("locomotion skills filtered",    len(loco_skills) == 1)

tagged = library12.list_skills(tag="kitchen")
check("tag filter works",              len(tagged) == 1)


# ── TEST 13: Stats report correctly ──────────────────────────────
print("\n  [13] Stats report correctly")
reset_all()

caps13 = RobotCapabilities(
    robot_id="test",
    components={
        "legs": "ok", "depth_sensor": "ok", "imu": "ok",
        "gripper": "ok", "camera": "ok", "arm": "ok",
    },
    max_force_n=500.0,
)

library13 = SkillLibrary(robot_capabilities=caps13)
for skill in make_example_skills():
    library13.install(skill)

stats = library13.stats()
check("stats has installed_count",     "installed_count" in stats)
check("installed_count is 3",          stats["installed_count"] == 3)
check("stats has by_category",         "by_category" in stats)


# ── TEST 14: Audit chain records operations ───────────────────────
print("\n  [14] Skill operations recorded in audit chain")
reset_all()

caps14 = RobotCapabilities(
    robot_id="test",
    components={"legs": "ok", "depth_sensor": "ok", "imu": "ok"},
    max_force_n=500.0,
)

library14 = SkillLibrary(robot_capabilities=caps14)
skills14 = make_example_skills()
skills14[0].requires_supervision = False
library14.install(skills14[0])
library14.apply("locomotion.stair_climbing.v1", caps14)

from driftcore.audit import read_chain
entries = read_chain()
skill_entries = [e for e in entries if "SKILL" in e.get("action", "")]

check("skill operations in audit chain", len(skill_entries) >= 2)
check("install recorded",
      any("INSTALLED" in e.get("action", "") for e in skill_entries))
check("apply recorded",
      any("APPLIED" in e.get("action", "") for e in skill_entries))


# ── TEST 15: Provenance tracking ─────────────────────────────────
print("\n  [15] Provenance tracked on skills")
reset_all()

from driftcore.skills import SkillProvenance

# Default provenance is human authored
skills15 = make_example_skills()
check("default provenance is human_authored",
      skills15[0].provenance == SkillProvenance.HUMAN_AUTHORED)

# Provenance trust levels are meaningful
check("human_authored is high trust",
      "high" in SkillProvenance.HUMAN_AUTHORED.trust_level())
check("ai_generated is low trust",
      "low" in SkillProvenance.AI_GENERATED.trust_level())
check("simulation_learned needs extra supervision",
      SkillProvenance.SIMULATION_LEARNED.requires_extra_supervision())
check("human_authored does not need extra supervision",
      not SkillProvenance.HUMAN_AUTHORED.requires_extra_supervision())


# ── TEST 16: apply_safe() is the single required workflow ─────────
print("\n  [16] apply_safe() enforces the complete workflow")
reset_all()

import shutil
try: shutil.rmtree("data/skills")
except: pass

caps16 = RobotCapabilities(
    robot_id="test",
    components={
        "legs": "4-leg", "depth_sensor": "5m range", "imu": "9-axis",
    },
    max_force_n=500.0,
)

library16 = SkillLibrary(robot_capabilities=caps16)
skills16 = make_example_skills()

# Stair climbing — human authored, no supervision required
stair16 = skills16[0]
stair16.requires_supervision = False
stair16.provenance = SkillProvenance.HUMAN_AUTHORED
library16.install(stair16)

# apply_safe with a confirm_fn that auto-approves
result16 = library16.apply_safe(
    "locomotion.stair_climbing.v1",
    caps16,
    confirm_fn=lambda skill, result: True,
)
check("apply_safe succeeds for human_authored",  result16.valid == True)

# AI generated skill requires confirmation even without supervision flag
ai_skill = SkillPackage(
    skill_id  = "test.ai_skill.v1",
    name      = "AI Generated Skill",
    version   = "1.0.0",
    category  = SkillCategory.MANIPULATION,
    description = "A skill generated by AI",
    hardware  = [],
    steps     = [ActionStep(0, "do something", "arm", {})],
    success_criteria = ["completed"],
    provenance = SkillProvenance.AI_GENERATED,
    requires_supervision = False,
)
ai_skill.checksum = ai_skill.compute_checksum()
library16.install(ai_skill)

# Auto-decline for AI generated
result_declined = library16.apply_safe(
    "test.ai_skill.v1",
    caps16,
    confirm_fn=lambda skill, result: False,
)
check("apply_safe blocks when declined",       result_declined.valid == False)
check("cancellation reason clear",
      "cancelled" in result_declined.reason.lower())

# Auto-approve for AI generated
result_approved = library16.apply_safe(
    "test.ai_skill.v1",
    caps16,
    confirm_fn=lambda skill, result: True,
)
check("apply_safe succeeds when approved",     result_approved.valid == True)
print("\n" + "=" * 60)
passed = sum(1 for _, ok in results if ok)
total  = len(results)
print(f"  {passed}/{total} tests passed")

if passed == total:
    print(f"  {PASS} All skill library tests pass.")
    print(f"  Skills are procedural knowledge — not memory, not values.")
    print(f"  Hardware checked. Invariants checked. Everything audited.")
    print(f"  Family data never involved.")
else:
    print(f"\n  {FAIL} Failed tests:")
    for name, ok in results:
        if not ok:
            print(f"      • {name}")
print("=" * 60)

if passed < total:
    sys.exit(1)
