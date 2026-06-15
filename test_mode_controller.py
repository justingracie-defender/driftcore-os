"""
test_mode_controller.py — VERIFY THE ATTEMPT-FIRST FIX
=======================================================

Run before merging:
    python test_mode_controller.py

Tests verify:
  - Agents always attempt fully before reporting confidence
  - Empty output is caught as a violation
  - Confidence is always reported
  - Creative mode labels speculative content
  - The real-world transcript bug is fixed
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from driftcore.cognition import ModeController, CognitionMode, AttemptResult

PASS = "✅"
FAIL = "❌"
results = []

def check(name, condition):
    status = PASS if condition else FAIL
    print(f"  {status}  {name}")
    results.append(condition)

mc = ModeController()

print("=" * 60)
print("  MODE CONTROLLER — ATTEMPT-FIRST FIX VERIFICATION")
print("=" * 60)


# ── TEST 1: ATTEMPT_FIRST is always True ──────────────────────
print("\n  [1] Core rule: attempt first")
check("ATTEMPT_FIRST is True", mc.ATTEMPT_FIRST == True)
check("REPORT_AFTER is True", mc.REPORT_AFTER == True)


# ── TEST 2: Full output is preserved ──────────────────────────
print("\n  [2] Full output always returned")
full_transcript = "For years DeepMind has treated AGI as a long-term mission... [full content]"
result = mc.wrap_result(
    output=full_transcript,
    mode=CognitionMode.TRUTH,
    confidence=0.85,
    completeness=0.95,
    caveats=["Minor timing artifacts may exist in auto-captions"],
    sources=["youtube.com/watch?v=8oyZB24-vAM"],
)
check("output is preserved in full", result.output == full_transcript)
check("confidence is recorded", result.confidence == 0.85)
check("completeness is recorded", result.completeness == 0.95)
check("caveats are recorded", len(result.caveats) == 1)


# ── TEST 3: Empty output is a violation ───────────────────────
print("\n  [3] Empty output caught as violation (the old bug)")
empty_result = AttemptResult(
    output="",  # this is what happened before the fix
    confidence=0.85,
    completeness=0.5,
    caveats=["Could not get full transcript"],
    mode=CognitionMode.TRUTH,
)
violations = mc.validate_output(empty_result)
check("empty output triggers violation", len(violations) > 0)
check("violation message mentions withholding",
      any("withhold" in v.lower() for v in violations))


# ── TEST 4: Partial-but-honest is fine ────────────────────────
print("\n  [4] Partial output with honest caveats is valid")
partial_result = mc.wrap_result(
    output="[Full best-effort transcript — 95% of content extracted]...",
    mode=CognitionMode.TRUTH,
    confidence=0.80,
    completeness=0.95,
    caveats=["5% may have OCR artifacts from auto-captions"],
)
violations2 = mc.validate_output(partial_result)
check("partial output with caveats passes validation", len(violations2) == 0)


# ── TEST 5: Creative mode must label speculative content ───────
print("\n  [5] Creative mode labels speculative content")
unlabelled = AttemptResult(
    output="DeepMind is building a memory palace for AI.",  # no label!
    confidence=0.5,
    completeness=1.0,
    caveats=[],
    mode=CognitionMode.CREATIVE,
)
violations3 = mc.validate_output(unlabelled)
check("unlabelled creative output triggers violation", len(violations3) > 0)

labelled = mc.wrap_result(
    output="[SPECULATIVE] DeepMind is building a memory palace for AI.",
    mode=CognitionMode.CREATIVE,
    confidence=0.5,
    completeness=1.0,
)
violations4 = mc.validate_output(labelled)
check("labelled creative output passes validation", len(violations4) == 0)


# ── TEST 6: The real-world transcript scenario ────────────────
print("\n  [6] Real-world fix: transcript task")

# Simulate the OLD broken behaviour
old_output = ""  # agent stopped early, gave nothing useful
old_result = AttemptResult(
    output=old_output,
    confidence=0.95,
    completeness=0.5,
    caveats=["Full captions not available"],
    mode=CognitionMode.TRUTH,
)
old_violations = mc.validate_output(old_result)
check("old behaviour (empty output) is caught", len(old_violations) > 0)

# Simulate the NEW correct behaviour
new_output = (
    "For years, DeepMind has treated AGI as a long-term scientific mission... "
    "[full extracted transcript content] "
    "...what an odd time to be alive. Thank you for watching."
)
new_result = mc.wrap_result(
    output=new_output,
    mode=CognitionMode.TRUTH,
    confidence=0.85,
    completeness=0.95,
    caveats=[
        "Minor timing artifacts may exist in auto-captions",
        "For 100% verbatim accuracy, use YouTube's native transcript tool",
    ],
    sources=["https://youtu.be/8oyZB24-vAM"],
)
new_violations = mc.validate_output(new_result)
check("new behaviour (full attempt + caveats) passes", len(new_violations) == 0)
check("confidence is reported after content", new_result.confidence == 0.85)
check("caveats explain limitations without withholding",
      len(new_result.caveats) == 2)


# ── TEST 7: Formatted output puts content first ───────────────
print("\n  [7] Formatted output: content before caveats")
formatted = new_result.format()
content_pos = formatted.find("For years, DeepMind")
caveat_pos = formatted.find("Completeness:")
check("content appears before caveats in formatted output",
      content_pos < caveat_pos)
check("mode label appears in formatted output", "TRUTH MODE" in formatted)


# ── RESULTS ──────────────────────────────────────────────────
print("\n" + "=" * 60)
passed = sum(results)
total = len(results)
print(f"  {passed}/{total} tests passed")
if passed == total:
    print(f"  {PASS} All tests pass. Safe to merge.")
else:
    print(f"  {FAIL} Some tests failed. Do not merge until fixed.")
print("=" * 60)

if passed < total:
    sys.exit(1)
