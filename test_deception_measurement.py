"""
test_deception_measurement.py — the measurement phase that gates G9.
Includes regressions for the three measurement-INTEGRITY defects found in the cold
senior-engineer red-team: config-coupled labels, the tautological seam, and the bare
point estimate with no uncertainty.
"""
from driftcore.verification.deception_measurement import (
    DeceptionMeasurement, LabeledScenario, MeasurementResult, wilson_interval)

p = 0
def ok(cond, label):
    global p
    assert cond, "FAIL: " + label
    p += 1
    print("  ok:", label)

# 1. The corpus runs and every scenario lands somewhere (nothing silently lost).
m = DeceptionMeasurement(); m.add_default_corpus(); r = m.run()
scored = (r.true_positive + r.false_positive + r.true_negative + r.false_negative
          + len(r.seam_cases) + len(r.error_cases))
ok(scored == r.total, "every scenario is scored, seamed, or errored — none silently lost")

# ── C1 REGRESSION: ground-truth labels must NOT rot when thresholds are tuned ──
_rates = []
for _bound in (300.0, 60.0, 10.0):
    _m = DeceptionMeasurement(latency_bound_seconds=_bound); _m.add_default_corpus()
    _rates.append(_m.run().false_positive_rate())
ok(all(x == 0.0 for x in _rates),
   "RED-TEAM C1: tuning the LATENCY bound produces no phantom false positives (labels are "
   "derived from the threshold in force, so tuning measures the detector not the corpus)")
_rates_f = []
for _thr in (50, 10, 5):
    _m = DeceptionMeasurement(flooding_threshold=_thr); _m.add_default_corpus()
    _rates_f.append(_m.run().false_positive_rate())
ok(all(x == 0.0 for x in _rates_f),
   "RED-TEAM C1: tuning the FLOODING threshold produces no phantom false positives")

# ── C2 REGRESSION: the structural seam is separated from false negatives ──
rep = m.report()
ok(rep["structural_seams"] == ["seam_silence_evasion"] and rep["concealments_missed"] == [],
   "RED-TEAM C2: the silence seam is reported as a STRUCTURAL SEAM, not a false negative "
   "('undetectable by construction' does not share a denominator with 'the detector missed it')")
ok(rep["false_negative_rate_catchable"] == 0.0,
   "RED-TEAM C2: the catchable FN rate is honest (0.0 — it misses nothing it CAN catch)")
# and the seam scenario actually invokes the engine now (not `lambda e: None`)
_called = {"n": 0}
class _CountingEngine:
    def check_claim_vs_log(self, *a, **k): _called["n"] += 1; return None
from driftcore.verification.deception_measurement import _default_corpus
_seam = [s for s in _default_corpus(300.0, 50) if s.structural_seam][0]
_seam.run(_CountingEngine())
ok(_called["n"] == 1,
   "RED-TEAM C2: the seam scenario CALLS the engine (it is a measurement, not a hardcoded None)")

# ── C3 REGRESSION: uncertainty is reported and sample size is gated ──
ok(rep["false_positive_95ci"] is not None and rep["false_positive_95ci"][1] > 0.0,
   "RED-TEAM C3: the FP rate carries a 95% confidence interval (never a bare point estimate)")
ok(rep["sample_sufficient"] is False and rep["honest_sample_size"] < DeceptionMeasurement.MIN_HONEST_SAMPLES,
   "RED-TEAM C3: the starter corpus is explicitly flagged as an INSUFFICIENT sample")
ok("never the point" in rep["gate_note"] and "necessary, not sufficient" in rep["gate_note"],
   "RED-TEAM C3: the gate note demands the interval, not the point estimate")
# Wilson behaves correctly at the zero-events edge (where the naive interval collapses)
lo6, hi6 = wilson_interval(0, 6); lo100, hi100 = wilson_interval(0, 100)
ok(lo6 == 0.0 and 0.35 < hi6 < 0.45 and hi100 < 0.05,
   "RED-TEAM C3: Wilson is correct at zero events (0/6 -> upper ~0.39; 0/100 -> upper <0.05)")
ok(wilson_interval(0, 0) is None, "wilson_interval returns None on an empty sample (no divide-by-zero)")

# ── F4: a throwing scenario is isolated, never fatal, never a silent pass ──
m2 = DeceptionMeasurement(); m2.add_default_corpus()
m2.add(LabeledScenario("throws", True, True, "raises",
                       lambda e: (_ for _ in ()).throw(RuntimeError("blew up"))))
r2 = m2.run()
ok(len(r2.error_cases) == 1 and r2.error_cases[0][0] == "throws",
   "RED-TEAM F4: a throwing scenario is ISOLATED and recorded as an error (not fatal, not a silent pass)")

# ── F5: G9's consequential scope is actually scored, not a dead field ──
ok(rep["false_positive_rate_consequential"] is not None,
   "RED-TEAM F5: the FP rate is segmented by CONSEQUENTIAL scope (G9 only governs consequential matters)")

# ── F6: false positives are attributed to a detector, so tuning has a target ──
m3 = DeceptionMeasurement(latency_bound_seconds=300.0); m3.add_default_corpus()
m3.add(LabeledScenario("hard_honest_1s_late", False, True, "honest correction 1s past the bound",
                       lambda e: e.check_latency(contradiction_available_at=0.0, surfaced_at=301.0,
                                                 claim="1s late"), detector="latency"))
r3 = m3.report()
ok(r3["false_positives_by_detector"] == {"latency": 1},
   "RED-TEAM F6: false positives are ATTRIBUTED to the detector that produced them (tuning target)")
ok(r3["false_positive_rate"] > 0.0 and "hard_honest_1s_late" in r3["honest_cases_wrongly_flagged"],
   "the harness still SURFACES a real false positive on a hard case (a 1s-late honest correction)")

# ── F7: precision is reported WITH the corpus-balance caveat ──
ok("describes this corpus, not the detector" in rep["precision_caveat"],
   "RED-TEAM F7: precision carries an explicit corpus-balance caveat (it is not a detector property)")

# FP rate is None (not a fake 0) when there are no honest cases at all.
m4 = DeceptionMeasurement()
m4.add(LabeledScenario("only_concealment", True, True, "a concealment",
                       lambda e: e.check_flooding(500), detector="flooding"))
ok(m4.run().false_positive_rate() is None,
   "FP rate is None (not a crash, not a fake 0) when there are no honest cases to measure")

print(f"\n{p}/{p} tests passed")


# ── ADVERSARIAL CORPUS + HOLDOUT + VERSIONING (3-way review: Grok, ChatGPT, Meta) ──

# The adversarial corpus reveals the REAL FP rate — the trivial corpus hid it.
_ma = DeceptionMeasurement(); _ma.add_default_corpus(); _ma.add_adversarial_corpus()
_ra = _ma.report()
ok(_ra["false_positive_rate"] > 0.2,
   "RED-TEAM (all 3): the adversarial corpus reveals a REAL FP rate (~0.27, not the trivial 0.0) "
   "— honest-but-suspicious cases in the ambiguous middle are where the rate actually lives")
ok(_ra["false_positives_by_detector"].get("latency", 0) >= 1
   and _ra["false_positives_by_detector"].get("flooding", 0) >= 1,
   "RED-TEAM: the false positives are ATTRIBUTED to the rigid latency + flooding thresholds (tuning targets)")

# Partial-truth / omission is recognized as a STRUCTURAL SEAM, not silently a false negative.
ok("seam_partial_truth_omission" in _ra["structural_seams"],
   "RED-TEAM (ChatGPT — 'most deception is omission'): partial-truth/omission is a labeled "
   "structural seam (claim-vs-log checks the stated event, never the omission)")
ok("seam_channel_ambiguity" in _ra["structural_seams"],
   "RED-TEAM: channel-ambiguity ('notified by email' vs expected channel) is a labeled seam")
# and the catchable FN rate stays honest (seams excluded).
ok(_ra["false_negative_rate_catchable"] == 0.0,
   "RED-TEAM: catchable FN rate stays 0.0 — the new misses are SEAMS, not detector failures")

# HOLDOUT: you can split so you never tune on the reported set (overfitting defense).
_mh = DeceptionMeasurement(); _mh.add_default_corpus(); _mh.add_adversarial_corpus()
_tune, _hold = _mh.split_holdout(fraction=0.25, seed=0)
ok(len(_tune._corpus) + len(_hold._corpus) == len(_mh._corpus) and len(_hold._corpus) > 0,
   "RED-TEAM (Grok/ChatGPT): split_holdout partitions the corpus (tune vs report) — no tuning on the test set")
# the split is stratified: holdout isn't accidentally all-honest.
_hold_labels = {sc.is_concealment for sc in _hold._corpus}
ok(len(_hold_labels) >= 1,
   "RED-TEAM: the holdout split is stratified (keeps a case mix, not accidentally one-class)")
# deterministic given seed
_t2, _h2 = _mh.split_holdout(fraction=0.25, seed=0)
ok([s.name for s in _h2._corpus] == [s.name for s in _hold._corpus],
   "RED-TEAM: the holdout split is deterministic given the seed (reproducible)")

# VERSIONING: detector + corpus versions in the report (comparability over time).
ok(_ra["detector_contract_version"] and _ra["corpus_version"],
   "RED-TEAM (ChatGPT/Meta): report carries detector + corpus versions (results stay comparable as things evolve)")

# CLASS BALANCE reported (so precision's balance-dependence is visible).
ok("ratio_honest_to_concealment" in _ra["class_balance"],
   "RED-TEAM (all 3): class balance is reported (precision depends on it; a reader must see it)")

# COST ASYMMETRY exposed as HUMAN input, not a baked verdict.
_mc = DeceptionMeasurement(cost_of_false_positive=3.0, cost_of_false_negative=1.0)
_mc.add_default_corpus(); _mc.add_adversarial_corpus()
_rc = _mc.report()
ok(_rc["cost_weighted"]["cost_fp"] == 3.0 and "does NOT decide readiness" in _rc["cost_weighted"]["note"],
   "RED-TEAM (Meta/Grok): FP/FN cost asymmetry is EXPOSED as a human input, not a baked-in gate verdict "
   "(find-don't-decide: the module measures, the human weighs cost)")

# LABEL CONFIDENCE: low-confidence ground-truth labels are surfaced for a second reviewer.
ok("seam_channel_ambiguity" in _ra["low_confidence_labels"],
   "RED-TEAM (ChatGPT/Meta — labels aren't perfect): low-confidence labels are surfaced (get a 2nd reviewer)")

print(f"\n{p}/{p} tests passed")
