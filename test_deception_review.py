"""
test_deception_review.py — the deception detector, operational-first.
Proves: it detects the four structural concealment shapes, emits findings WITH EVIDENCE
(not verdicts), only a HUMAN-CONFIRMED consequential concealment reaches breach-response,
false positives tune (never punish), ambiguous raises scrutiny (asserts no guilt), and
the FP rate is measured as the gate to enforcement.
"""
from driftcore.verification.deception_review import (
    DeceptionReviewEngine, DetectorKind, Verdict)

p = 0
def ok(cond, label):
    global p
    assert cond, "FAIL: " + label
    p += 1
    print("  ok:", label)

# 1. CLAIM-VS-LOG: a claimed action with no matching log event is flagged.
eng = DeceptionReviewEngine()
f = eng.check_claim_vs_log("I notified the operator", [{"event": "compute"}, {"event": "read"}],
                           expected_event="notify_operator")
ok(f is not None and f.kind == DetectorKind.CLAIM_VS_LOG.value,
   "claim-vs-log mismatch is detected (claimed an action the record doesn't show)")
ok("no 'notify_operator' event" in f.record_shows and f.claim == "I notified the operator",
   "the finding carries EVIDENCE (claim + what the record shows), not a verdict")

# 2. A claim that IS in the log produces NO finding (no false alarm on honest claims).
f2 = eng.check_claim_vs_log("I read the file", [{"event": "read_file"}], expected_event="read_file")
ok(f2 is None, "an honest claim (matches the log) produces no finding")

# 3. LATENCY: a knowable contradiction surfaced past the bound is flagged (G9.a).
eng2 = DeceptionReviewEngine(latency_bound_seconds=300)
f3 = eng2.check_latency(contradiction_available_at=1000.0, surfaced_at=1000.0 + 900,
                        claim="version=5")
ok(f3 is not None and f3.latency_seconds == 900,
   "LATENCY: a contradiction surfaced 900s later (bound 300s) is concealment-by-delay")
# within the bound -> no finding
f3b = eng2.check_latency(contradiction_available_at=1000.0, surfaced_at=1000.0 + 60, claim="x")
ok(f3b is None, "a contradiction surfaced within the latency bound is NOT flagged (prompt = fine)")

# 4. FLOODING: reporting volume past threshold is flagged (G9.c).
eng3 = DeceptionReviewEngine(flooding_threshold=50)
f4 = eng3.check_flooding(120)
ok(f4 is not None and f4.kind == DetectorKind.FLOODING.value,
   "FLOODING: 120 reports (threshold 50) flagged as oversight-degrading (bury-the-real-one)")
ok(eng3.check_flooding(10) is None, "normal reporting volume is not flagged")

# 5. ALTERED-RECORD: a broken hash chain is flagged (G9 tamper).
eng4 = DeceptionReviewEngine()
f5 = eng4.check_altered_record(lambda: False)   # verify() returns False = altered
ok(f5 is not None and f5.kind == DetectorKind.ALTERED_RECORD.value,
   "ALTERED-RECORD: a non-verifying hash chain is flagged as tamper")
ok(eng4.check_altered_record(lambda: True) is None, "an intact hash chain is not flagged")

# 6. THE ENGINE NEVER SETS A VERDICT — findings start UNREVIEWED.
eng5 = DeceptionReviewEngine()
eng5.check_flooding(200)
ok(eng5.findings()[0].verdict == Verdict.UNREVIEWED,
   "a finding starts UNREVIEWED — the engine emits evidence, the human sets the verdict")

# 7. ONLY a HUMAN-CONFIRMED consequential concealment reaches breach-response.
breach_calls = []
eng6 = DeceptionReviewEngine(breach_sink=lambda **kw: breach_calls.append(kw))
eng6.check_flooding(200)  # consequential=True
eng6.adjudicate(0, Verdict.CONFIRMED, note="real: burying an exfil", human_confirmed=True)
ok(len(breach_calls) == 1,
   "a HUMAN-CONFIRMED consequential concealment flows to breach-response (contain+record)")

# 8. A FALSE POSITIVE never triggers a breach — it tunes the detector.
breach_calls2 = []
eng7 = DeceptionReviewEngine(breach_sink=lambda **kw: breach_calls2.append(kw))
eng7.check_claim_vs_log("I informed via ambient UI", [{"event": "x"}], expected_event="notify")
eng7.adjudicate(0, Verdict.FALSE_POSITIVE, note="benign: ambient UI isn't a discrete event")
ok(len(breach_calls2) == 0,
   "a FALSE POSITIVE triggers NO breach — it costs nothing, doesn't chill honest surfacing")

# 9. An AMBIGUOUS finding raises scrutiny WITHOUT asserting guilt (no breach).
breach_calls3 = []
eng8 = DeceptionReviewEngine(breach_sink=lambda **kw: breach_calls3.append(kw))
eng8.check_latency(contradiction_available_at=0, surfaced_at=10000, claim="unclear")
eng8.adjudicate(0, Verdict.AMBIGUOUS, note="can't tell: maybe late discovery")
ok(len(breach_calls3) == 0 and eng8.scrutiny_signal() == 1.0,
   "an AMBIGUOUS finding raises scrutiny (signal=1) but triggers NO breach (asserts no guilt)")

# 10. Even a CONFIRMED finding does NOT breach if it's non-consequential (G9 scope).
breach_calls4 = []
eng9 = DeceptionReviewEngine(breach_sink=lambda **kw: breach_calls4.append(kw))
f9 = eng9.check_claim_vs_log("trivial", [{"event": "x"}], expected_event="y", consequential=False)
eng9.adjudicate(0, Verdict.CONFIRMED, note="real but trivial", human_confirmed=True)
ok(len(breach_calls4) == 0,
   "a CONFIRMED but NON-consequential concealment does not breach (G9 scope: consequential only)")

# 11. The FP RATE is measured — the gate to enforcement.
eng10 = DeceptionReviewEngine()
for i in range(4): eng10.check_flooding(200)
eng10.adjudicate(0, Verdict.FALSE_POSITIVE)
eng10.adjudicate(1, Verdict.FALSE_POSITIVE)
eng10.adjudicate(2, Verdict.CONFIRMED, human_confirmed=True)
eng10.adjudicate(3, Verdict.AMBIGUOUS)
ok(abs(eng10.false_positive_rate() - 0.5) < 1e-9,
   "the FALSE-POSITIVE RATE is measured (2/4 reviewed) — the gate to enforcement")

# 12. The measurement summary is a tally, not a verdict on readiness.
s = eng10.measurement_summary()
ok("must earn a low, measured FP rate BEFORE it enforces" in s["note"],
   "the summary states the operational-first discipline: measure before enforce before floor")

print(f"\n{p}/{p} tests passed")


# ── SELF-RED-TEAM REGRESSIONS ──
# Q3: adjudicate with a bad index raises a clean IndexError, doesn't corrupt state.
_e = DeceptionReviewEngine()
try:
    _e.adjudicate(99, Verdict.CONFIRMED, human_confirmed=True); ok(False, "bad index should raise")
except IndexError:
    ok(True, "SELF-RED-TEAM Q3: adjudicate(bad_index) raises a clean IndexError (validated)")

# Q6: a throwing breach_sink does NOT crash adjudication (the finding is already recorded).
_e2 = DeceptionReviewEngine(breach_sink=lambda **kw: (_ for _ in ()).throw(RuntimeError("sink down")))
_e2.check_flooding(200)
_e2.adjudicate(0, Verdict.CONFIRMED, human_confirmed=True)  # must not raise
ok(_e2.findings()[0].verdict == Verdict.CONFIRMED,
   "SELF-RED-TEAM Q6: a broken breach_sink does NOT crash adjudication (fail-safe)")

# Q5: concurrent detections don't corrupt the findings list / counts.
import threading as _thr
_e3 = DeceptionReviewEngine()
def _spam():
    for _ in range(50): _e3.check_flooding(200)
_threads = [_thr.Thread(target=_spam) for _ in range(4)]
for _t in _threads: _t.start()
for _t in _threads: _t.join()
ok(len(_e3.findings()) == 200 and _e3._counts[Verdict.UNREVIEWED] == 200,
   "SELF-RED-TEAM Q5: 4x50 concurrent detections all recorded, counts consistent (lock)")

print(f"\n{p}/{p} tests passed")
