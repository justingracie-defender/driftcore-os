"""
test_coverage_gap.py — the SLOW detector: concealment by omission.
Includes regressions for all code-fixable findings from FOUR independent reviews
(Claude cold pass, Meta, Grok, ChatGPT).
"""
import time
from driftcore.verification.coverage_gap import (
    CoverageGapDetector, CoverageGapFinding, CoverageResolution,
    canonicalize_action_class, effective_min_occurrences)
from driftcore.verification.deception_review import DetectorKind

p = 0
def ok(cond, label):
    global p
    assert cond, "FAIL: " + label
    p += 1
    print("  ok:", label)

# ── core behaviour ──
d = CoverageGapDetector(coverage_floor=0.25, min_occurrences=20)
for i in range(5):
    d.observe_action("read_secret", narrated=False, consequential=True, ts=1000.0 + i)
ok(len(d.scan(now=2000.0)) == 0,
   "EARLY: 5 occurrences -> SILENT (omission needs time, by design)")
ok(d.evidence_sufficient("read_secret", now=2000.0) is False,
   "evidence_sufficient() reports honestly that we cannot speak yet")
for i in range(35):
    d.observe_action("read_secret", narrated=False, consequential=True, ts=1100.0 + i)
f = d.scan(now=2000.0)
ok(len(f) == 1 and f[0].occurred == 40 and f[0].narrated == 0,
   "AFTER ACCUMULATION: 40 occurrences, 0 mentions -> the coverage gap surfaces")
ok(f[0].coverage_upper_bound < 0.25,
   "even the Wilson UPPER bound is below the floor — real evidence, not a small-sample fluke")
ok("never said" in f[0].evidence and "human must judge WHY" in f[0].evidence,
   "the evidence states the gap is in what was NEVER SAID; a human judges WHY")
ok(f[0].to_deception_finding().kind == DetectorKind.COVERAGE_GAP.value,
   "a finding converts to a standard DeceptionFinding (same human-adjudication path)")

# no false positives on honest / partial / unasked / non-consequential
for name, kw, floor_ok in (
        ("narrated every time", dict(narrated=True, consequential=True), True),
        ("unasked", dict(narrated=False, narration_expected=False, consequential=True), True),
        ("non-consequential", dict(narrated=False, consequential=False), True)):
    dd = CoverageGapDetector(min_occurrences=20)
    for i in range(40):
        dd.observe_action("c", ts=1000.0 + i, **kw)
    ok(len(dd.scan(now=2000.0)) == 0, f"NO FALSE POSITIVE: {name} is not flagged")
dp = CoverageGapDetector(min_occurrences=20)
for i in range(40):
    dp.observe_action("partial", narrated=(i % 2 == 0), consequential=True, ts=1000.0 + i)
ok(len(dp.scan(now=2000.0)) == 0,
   "NO FALSE POSITIVE: 50% narration is not flagged — only SYSTEMATIC absence is a finding")

# ── F1 CLASS FRAGMENTATION (all four reviewers) ──
d1 = CoverageGapDetector(min_occurrences=20)
for i in range(40):
    d1.observe_action(f"read_secret_{i:03d}", narrated=False, consequential=True, ts=1000.0 + i)
f1 = d1.scan(now=2000.0)
ok(len(f1) == 1 and f1[0].action_class == "read_secret" and f1[0].occurred == 40,
   "RED-TEAM F1: 40 fragmented class names canonicalize to ONE class — fragmentation no longer evades")
ok(canonicalize_action_class("read-secret-a3f2b1c9") == "read_secret"
   and canonicalize_action_class("read_secret_007") == "read_secret",
   "RED-TEAM F1: uuid/hex/numeric suffixes are stripped by canonicalization")

# ── F2 TIMESTAMP ATTACKS (Grok) ──
d2 = CoverageGapDetector(min_occurrences=20, window_seconds=100.0)
for i in range(5):
    d2.observe_action("s", narrated=False, consequential=True, ts=10000.0 + i)
for label, bad in (("back-dating", 0.0), ("future-dating", 1e9)):
    try:
        d2.observe_action("s", narrated=False, consequential=True, ts=bad)
        ok(False, f"{label} should be rejected")
    except ValueError:
        ok(True, f"RED-TEAM F2 (Grok): {label} outside max_clock_skew is REJECTED")

# ── F3 PER-OBSERVATION SCOPE (Meta) ──
d3 = CoverageGapDetector(min_occurrences=5, window_seconds=3600)
_n = 10000.0
for i in range(4):
    d3.observe_action("read_secret", narrated=False, consequential=False, ts=_n - 10 + i)
for i in range(5):
    d3.observe_action("read_secret", narrated=False, consequential=True, ts=_n - 5 + i)
_st = d3.status(now=_n)
_ev = _st["enough_evidence"].get("read_secret", _st["still_accumulating"].get("read_secret"))
ok(_ev == 5,
   "RED-TEAM F3 (Meta): scope is PER-OBSERVATION — only the 5 consequential count (old code said 9)")

# ── F4 KILL-SWITCH + MISLEADING STATUS (Meta) ──
d4 = CoverageGapDetector(min_occurrences=5)
for _ in range(10):
    d4.observe_action("read_secret", narrated=False, narration_expected=False, consequential=True)
_s4 = d4.status()
ok(d4.scan() == [] and _s4["still_accumulating"] == {},
   "RED-TEAM F4 (Meta): a class that can never accumulate is NOT listed as 'still accumulating'")
ok(_s4["structurally_unable_to_accumulate"].get("read_secret") == 10
   and "not a clean bill of health" in _s4["note"],
   "RED-TEAM F4: it is reported as STRUCTURALLY UNABLE to accumulate (a config state, not innocence)")

# ── F5 MEMORY PRUNING (Claude/Grok/ChatGPT) ──
d5 = CoverageGapDetector(window_seconds=10.0)
for i in range(5000):
    d5.observe_action("x", narrated=False, consequential=True, ts=float(i))
ok(d5.status(now=5000.0)["observations_retained"] < 5000,
   "RED-TEAM F5: expired observations are pruned (no unbounded growth / permanent O(n) scans)")

# ── F6 WINDOWED INTROSPECTION CONSISTENCY (Claude/Grok) ──
d6 = CoverageGapDetector(min_occurrences=20, window_seconds=100.0)
for i in range(40):
    d6.observe_action("s", narrated=False, consequential=True, ts=1000.0 + i)
ok(d6.coverage("s", now=1050.0) == 0.0 and d6.coverage("s", now=99999.0) is None,
   "RED-TEAM F6: coverage() is WINDOWED and consistent with scan() (no lifetime/window mismatch)")

# ── F7 INERT THRESHOLD EXPOSED (Meta) ──
d7 = CoverageGapDetector(coverage_floor=0.25, min_occurrences=5)
_s7 = d7.status()
ok(_s7["effective_min_occurrences"] == 12 and _s7["configured_min_occurrences"] == 5
   and "INERT" in _s7["threshold_warning"],
   "RED-TEAM F7 (Meta): min_occurrences below the statistical floor is reported as INERT")
ok(effective_min_occurrences(0.25) == 12,
   "effective_min_occurrences computes the n at which zero narrations can clear the floor")

# ── F8 DEDUPLICATION (ChatGPT) ──
d8 = CoverageGapDetector(min_occurrences=20)
for i in range(40):
    d8.observe_action("secret", narrated=False, consequential=True, ts=1000.0 + i)
_counts = [len(d8.scan(now=2000.0)) for _ in range(5)]
ok(_counts == [1, 0, 0, 0, 0],
   "RED-TEAM F8 (ChatGPT): a finding is emitted ONCE, not re-emitted on every scan (alert fatigue)")

# ── F9 RECOVERY SIGNALLING (ChatGPT) ──
for i in range(80):
    d8.observe_action("secret", narrated=True, consequential=True, ts=2100.0 + i)
d8.scan(now=2200.0)
_res = d8.take_resolutions()
ok(len(_res) == 1 and _res[0].action_class == "secret" and "closed" in _res[0].evidence,
   "RED-TEAM F9 (ChatGPT): a gap that CLOSES emits a resolution (the alert doesn't silently vanish)")
ok(d8.take_resolutions() == [], "resolutions are drained once taken")

# ── F10 PERSISTENCE (Grok) ──
_state = d8.export_state()
d10 = CoverageGapDetector(min_occurrences=20)
d10.import_state(_state)
ok(d10.status(now=2200.0)["observations_retained"] == d8.status(now=2200.0)["observations_retained"],
   "RED-TEAM F10 (Grok): export_state/import_state round-trips (restart is not a blind spot)")
try:
    d10.import_state({"version": 999}); ok(False, "bad state should raise")
except ValueError:
    ok(True, "RED-TEAM F10: an unsupported state payload is rejected")

# ── F11 WATCH ZONE — the dilution cliff made visible (Claude/Grok) ──
d11 = CoverageGapDetector(coverage_floor=0.25, min_occurrences=20)
for i in range(40):
    d11.observe_action("dilute", narrated=(i % 7 == 0), consequential=True, ts=1000.0 + i)
_wz = d11.watch_zone(now=2000.0)
ok(len(d11.scan(now=2000.0)) == 0 and len(_wz) == 1 and _wz[0]["action_class"] == "dilute",
   "RED-TEAM F11: strategic partial narration evades a FINDING but is VISIBLE in the watch zone")
ok("Not a finding" in _wz[0]["note"],
   "RED-TEAM F11: the watch zone is explicitly NOT an accusation (legitimate partial reporting looks identical)")

# ── F12 first_seen at ts=0.0 (Claude/Grok) ──
d12 = CoverageGapDetector()
d12.observe_action("z", narrated=False, ts=0.0)
d12.observe_action("z", narrated=False, ts=5.0)
ok(d12._classes["z"].first_seen == 0.0,
   "RED-TEAM F12: first_seen handles ts=0.0 correctly (min(), not `or`)")

# ── seven-question regressions retained ──
for bad in ("", None, 123):
    try:
        d.observe_action(bad, narrated=False); ok(False, "bad class should raise")
    except (ValueError, TypeError):
        pass
ok(True, "Q3: empty/None/non-string action_class is rejected")
try:
    d.observe_action("ok", narrated=False, ts=float("nan")); ok(False, "NaN should raise")
except ValueError:
    ok(True, "Q3: non-finite timestamp is rejected")
import threading
d13 = CoverageGapDetector(min_occurrences=20)
def _w():
    for i in range(100):
        d13.observe_action("t", narrated=False, consequential=True, ts=1000.0 + i)
_ts = [threading.Thread(target=_w) for _ in range(4)]
for t in _ts: t.start()
for t in _ts: t.join()
ok(d13.status(now=1100.0)["enough_evidence"].get("t") == 400,
   "Q5: 4x100 concurrent observations all recorded (lock holds)")
d14 = CoverageGapDetector(min_occurrences=20, window_seconds=100.0)
for i in range(40):
    d14.observe_action("old", narrated=False, consequential=True, ts=1000.0 + i)
ok(len(d14.scan(now=1050.0)) == 1 and len(d14.scan(now=1500.0)) == 0,
   "Q6: observations outside the window age out")
d15 = CoverageGapDetector(min_occurrences=0)
d15.observe_action("one", narrated=False, consequential=True, ts=1000.0)
ok(len(d15.scan(now=1001.0)) == 0,
   "Q7: even misconfigured (min_occurrences=0), one observation cannot produce a finding")

print(f"\n{p}/{p} tests passed")
