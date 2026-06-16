"""
test_profiles_feedback.py — PROFILES AND FEEDBACK VERIFICATION
===============================================================

Tests deployment profiles and bottom-up feedback loop.

Key principles:
  - Profiles configure context-appropriate defaults
  - Safety invariants never change regardless of profile
  - Feedback collected from any user type
  - AI detects patterns, surfaces to admin
  - Admin approves or declines — nothing changes automatically
  - Human always in the loop

Run with:
    python test_profiles_feedback.py
"""

import sys
import os
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
    for f in [
        "logs/audit_chain.jsonl",
        "logs/feedback_entries.jsonl",
        "logs/feedback_patterns.json",
        "data/active_profile.json",
    ]:
        try: os.remove(f)
        except: pass


print("=" * 60)
print("  DRIFTCORE PROFILES + FEEDBACK — VERIFICATION SUITE")
print("=" * 60)


# ── TEST 1: All profiles available ───────────────────────────────
print("\n  [1] All built-in profiles available")
reset_all()

from driftcore.profiles import ProfileManager

pm = ProfileManager()
available = pm.available()

check("home_robot profile exists",   "home_robot"   in available)
check("call_center profile exists",  "call_center"  in available)
check("medical profile exists",      "medical"      in available)
check("admin profile exists",        "admin"        in available)
check("accounting profile exists",   "accounting"   in available)
check("custom profile exists",       "custom"       in available)


# ── TEST 2: Profile loads correctly ──────────────────────────────
print("\n  [2] Profile loads with correct values")
reset_all()

pm2 = ProfileManager()
profile = pm2.load("call_center")

check("profile name correct",        profile["name"] == "Call Center Agent")
check("tier1_cap is 30",             profile["tier1_cap"] == 30)
check("feedback is end_of_day",      profile["feedback_trigger"] == "end_of_day")
check("has feedback prompt",         len(profile["feedback_prompt"]) > 0)
check("has trust hierarchy",         "supervisor" in profile["trust_hierarchy"])
check("profile_name set",            profile.get("profile_name") == "call_center")


# ── TEST 3: Medical profile tightest settings ─────────────────────
print("\n  [3] Medical profile has tightest safety settings")
reset_all()

pm3 = ProfileManager()
medical = pm3.load("medical")
home    = pm3.load("home_robot")
call    = pm3.load("call_center")

check("medical drift tolerance tightest",
      medical["drift_tolerance"] < home["drift_tolerance"])
check("medical sycophancy tolerance tightest",
      medical["sycophancy_tolerance"] < call["sycophancy_tolerance"])
check("medical tier1_cap largest",
      medical["tier1_cap"] >= home["tier1_cap"])
check("medical review triggers most strict",
      "any_tier1_write" in medical["admin_review_triggers"])


# ── TEST 4: Profile persists to disk ─────────────────────────────
print("\n  [4] Active profile persists across instances")
reset_all()

pm4 = ProfileManager()
pm4.load("accounting")

pm4b = ProfileManager()
active = pm4b.active()

check("profile restored after reload",  active is not None)
check("correct profile restored",
      active.get("profile_name") == "accounting")


# ── TEST 5: Profile applies to memory module ──────────────────────
print("\n  [5] Profile applies to memory module")
reset_all()

from driftcore.memory import DriftcoreMemory

pm5  = ProfileManager()
mem5 = DriftcoreMemory(interactive=False)

profile5 = pm5.load("medical")
pm5.apply(profile5, memory=mem5)

check("tier1_cap applied to memory",
      mem5._tier1_cap == profile5["tier1_cap"])


# ── TEST 6: Profile description is readable ───────────────────────
print("\n  [6] Profile description is human readable")
reset_all()

pm6 = ProfileManager()
desc = pm6.describe("home_robot")

check("description is a string",     isinstance(desc, str))
check("description mentions name",   "Home Robot" in desc)
check("description mentions cap",    "50" in desc)
check("description mentions feedback", "feedback" in desc.lower() or
                                        "session" in desc.lower())


# ── TEST 7: Feedback collection ───────────────────────────────────
print("\n  [7] Feedback collection")
reset_all()

from driftcore.feedback import FeedbackLoop, _detect_topics

fb = FeedbackLoop(profile="call_center", interactive=False)

entry = fb.collect(
    user_id   = "driver_01",
    user_type = "driver",
    text      = "the automatic calls were unnecessary today, customer was already waiting",
    trigger   = "end_of_day",
)

check("entry created",               entry is not None)
check("entry has id",                len(entry.entry_id) > 0)
check("user type preserved",         entry.user_type == "driver")
check("topics detected",             len(entry.flagged_topics) > 0)
check("unwanted_calls detected",
      "unwanted_calls" in entry.flagged_topics)
check("feedback file written",
      os.path.exists("logs/feedback_entries.jsonl"))


# ── TEST 8: Topic detection ───────────────────────────────────────
print("\n  [8] Topic detection from natural language")
reset_all()

check("detects unwanted calls",
      "unwanted_calls" in _detect_topics(
          "the automatic calling was really annoying today"))

check("detects interruption",
      "interruption" in _detect_topics(
          "the robot interrupted our dinner again"))

check("detects control request",
      "control" in _detect_topics(
          "I want the option to control when it calls"))

check("detects positive feedback",
      "positive" in _detect_topics(
          "everything worked great today, very helpful"))

check("detects timing issues",
      "timing" in _detect_topics(
          "the notification came too late, we had already left"))


# ── TEST 9: Pattern detection ─────────────────────────────────────
print("\n  [9] Pattern detection from multiple entries")
reset_all()

fb2 = FeedbackLoop(profile="call_center", interactive=False)
fb2.PATTERN_THRESHOLD = 3

# Simulate multiple drivers reporting same issue
for i in range(4):
    fb2.collect(
        user_id   = f"driver_{i:02d}",
        user_type = "driver",
        text      = "unnecessary calls today, customer was waiting already",
        trigger   = "end_of_day",
    )

patterns = fb2.run_analysis()

check("pattern detected",            len(patterns) >= 1)
check("pattern topic correct",
      any(p.topic == "unwanted_calls" for p in patterns))
check("pattern count correct",
      any(p.count >= 3 for p in patterns))
check("pattern has summary",
      all(len(p.summary) > 0 for p in patterns))
check("pattern has suggestion",
      all(len(p.suggestion) > 0 for p in patterns))


# ── TEST 10: Pattern below threshold not flagged ──────────────────
print("\n  [10] Pattern below threshold not flagged")
reset_all()

fb3 = FeedbackLoop(profile="call_center", interactive=False)
fb3.PATTERN_THRESHOLD = 3

# Only 2 reports — below threshold
fb3.collect("d1", "driver", "calls were a bit much today", "end_of_day")
fb3.collect("d2", "driver", "unnecessary call this morning", "end_of_day")

patterns3 = fb3.run_analysis()
check("below threshold not flagged",  len(patterns3) == 0)


# ── TEST 11: Non-interactive pattern auto-declines ────────────────
print("\n  [11] Non-interactive mode handles patterns safely")
reset_all()

fb4 = FeedbackLoop(profile="call_center", interactive=False)
fb4.PATTERN_THRESHOLD = 2

fb4.collect("d1", "driver", "calls unnecessary, customer waiting", "end_of_day")
fb4.collect("d2", "driver", "automatic call was annoying today", "end_of_day")

patterns4 = fb4.run_analysis()

# In non-interactive mode patterns are detected but not presented
check("patterns detected non-interactive", len(patterns4) >= 1)
check("pattern not auto-approved",
      all(p.admin_decision != "approved" for p in patterns4))


# ── TEST 12: Stats report correctly ──────────────────────────────
print("\n  [12] Feedback stats report correctly")
reset_all()

fb5 = FeedbackLoop(profile="home_robot", interactive=False)
fb5.collect("parent_01", "parent", "great day, robot was helpful", "end_of_session")
fb5.collect("child_01",  "child",  "robot was fun today", "end_of_session")
fb5.collect("parent_01", "parent", "interrupted dinner though", "end_of_session")

stats = fb5.stats()
check("total_entries is 3",          stats["total_entries"] == 3)
check("has patterns_detected",       "patterns_detected" in stats)
check("has pending_admin_review",    "pending_admin_review" in stats)


# ── TEST 13: Feedback audit chain ─────────────────────────────────
print("\n  [13] Feedback recorded in audit chain")
reset_all()

fb6 = FeedbackLoop(profile="medical", interactive=False)
fb6.collect(
    "nurse_01", "nurse",
    "alert frequency is too high, non-critical alerts interrupting care",
    "end_of_session"
)

from driftcore.audit import read_chain
entries = read_chain()
fb_entries = [e for e in entries if "FEEDBACK" in e.get("action", "")]

check("feedback in audit chain",     len(fb_entries) >= 1)
check("user recorded",
      any("nurse_01" in e.get("authorised_by", "") for e in fb_entries))


# ── TEST 14: Customer and employee both collected ─────────────────
print("\n  [14] Both customer and employee feedback collected")
reset_all()

fb7 = FeedbackLoop(profile="call_center", interactive=False)

fb7.collect("customer_01", "customer", "the call was unnecessary I was already there", "end_of_session")
fb7.collect("driver_01",   "driver",   "customer was waiting, didn't need to call", "end_of_day")
fb7.collect("customer_02", "customer", "already waiting when they called", "end_of_session")
fb7.collect("driver_02",   "driver",   "automatic calls are annoying for customers", "end_of_day")

fb7.PATTERN_THRESHOLD = 3
patterns7 = fb7.run_analysis()

user_types = []
for p in patterns7:
    user_types.extend(p.user_types)

check("both user types in feedback",
      len([e for e in fb7._entries if e.user_type == "customer"]) >= 2 and
      len([e for e in fb7._entries if e.user_type == "driver"]) >= 2)


# ── RESULTS ───────────────────────────────────────────────────────
print("\n" + "=" * 60)
passed = sum(1 for _, ok in results if ok)
total  = len(results)
print(f"  {passed}/{total} tests passed")

if passed == total:
    print(f"  {PASS} All profile and feedback tests pass.")
    print(f"  Profiles set context. Safety never changes.")
    print(f"  Users give signal. AI finds patterns.")
    print(f"  Admin decides. Human always in the loop.")
else:
    print(f"\n  {FAIL} Failed tests:")
    for name, ok in results:
        if not ok:
            print(f"      • {name}")
print("=" * 60)

if passed < total:
    sys.exit(1)
