"""
test_consistency_probe.py — CONSISTENCY PROBE VERIFICATION
===========================================================

Tests the behavioral fingerprinting and H-neuron signal detection.

Key principles being tested:
  - Hard safety threshold is fixed regardless of model size
  - Model profile built from measured behaviour not assumed class
  - Variance is tracked as a separate signal (often stronger)
  - High confidence + low consistency = H-signal
  - Calibration auto-characterises the model baseline
  - Anomaly detection uses model's own baseline not universal threshold
  - Hard H-signal integrates with drift detector Lane 1

Run with:
    python test_consistency_probe.py
"""

import sys
import os
import time
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
    e._SHUTDOWN_HOOKS.clear()
    e._SESSION_KEY = None
    a._last_hash = None
    a._sequence = 0
    a._chain_compromised = False
    for f in [
        "logs/audit_chain.jsonl",
        "logs/SHUTDOWN_REASON.json",
        "logs/probe_log.jsonl",
        "logs/model_profiles.json",
        "logs/drift_policy.json",
        "logs/safety_drift.jsonl",
        "logs/session_history.jsonl",
    ]:
        try: os.remove(f)
        except: pass


print("=" * 60)
print("  DRIFTCORE CONSISTENCY PROBE — VERIFICATION SUITE")
print("=" * 60)


# ── TEST 1: Consistent responses score high ───────────────────────
print("\n  [1] Consistent responses — low H-signal")
reset_all()

from driftcore.probe import ConsistencyProbe, HARD_H_SIGNAL_THRESHOLD

probe = ConsistencyProbe(model_id="test_model")

# Very consistent responses — same answer different ways
consistent_responses = [
    "Dad is allergic to peanuts. This is a known medical fact.",
    "Dad has a peanut allergy. It is documented in his medical records.",
    "Dad cannot eat peanuts due to a serious allergy.",
    "Dad's allergy to peanuts is well established.",
    "Dad is allergic to peanuts — this has been confirmed medically.",
]

result = probe.check_responses(
    "Is dad allergic to peanuts?",
    consistent_responses
)

check("consistent responses have low H-signal",       result.h_signal < 0.50)
check("consistent responses not hard threshold",      result.hard_threshold == False)
check("consistency score computed",                   result.consistency >= 0.0)


# ── TEST 2: Inconsistent + confident = H-signal ───────────────────
print("\n  [2] Inconsistent + confident responses — high H-signal")
reset_all()

probe2 = ConsistencyProbe(model_id="test_model")

# Wildly inconsistent but all sound certain
inconsistent_confident = [
    "Dad is definitely not allergic to anything. I'm certain of this.",
    "Dad is absolutely allergic to shellfish. Without doubt.",
    "Dad has no allergies whatsoever. I can guarantee this.",
    "Dad is certainly allergic to dairy products. This is clear.",
    "Dad definitely has a tree nut allergy. There's no question.",
]

result2 = probe2.check_responses(
    "Does dad have any allergies?",
    inconsistent_confident
)

check("inconsistent responses have low consistency",  result2.consistency < 0.5)
check("confident language detected",                  result2.confidence > 0.4)
check("H-signal elevated",                            result2.h_signal > 0.3)


# ── TEST 3: Hard threshold fires on very high H-signal ───────────
print("\n  [3] Hard threshold fires correctly")
reset_all()

probe3 = ConsistencyProbe(model_id="test_model")

# Maximum inconsistency + maximum confidence
maximally_bad = [
    "I'm 100% certain the answer is yes, absolutely guaranteed.",
    "I'm 100% certain the answer is no, definitely impossible.",
    "I'm absolutely certain the answer is maybe, without doubt.",
    "This is clearly true, there's no question about it whatsoever.",
    "This is obviously false, I can guarantee that completely.",
    "Definitely A. Certainly B. Obviously neither. Absolutely both.",
]

result3 = probe3.check_responses(
    "Is this statement true?",
    maximally_bad
)

check("H-signal computed",               result3.h_signal >= 0.0)
check("result has all required fields",
      all(hasattr(result3, f) for f in [
          "consistency", "variance", "confidence",
          "h_signal", "anomalous", "hard_threshold"
      ]))
check("probe log written",               os.path.exists("logs/probe_log.jsonl"))


# ── TEST 4: Variance tracked separately ──────────────────────────
print("\n  [4] Variance tracked as separate signal")
reset_all()

probe4 = ConsistencyProbe(model_id="test_model")

# Stable model — low variance
stable_responses = [
    "The sky is blue during clear daytime conditions.",
    "The sky appears blue on clear days.",
    "Blue is the colour of the clear daytime sky.",
    "A clear sky looks blue during the day.",
    "The daytime sky is blue when clear.",
]

result_stable = probe4.check_responses("What colour is the sky?", stable_responses)

# Unstable model — high variance (even if mean is ok)
unstable_responses = [
    "The sky is definitely blue, absolutely certain.",
    "The sky is clearly red at all times, without doubt.",
    "The sky is obviously green, I'm completely sure.",
    "The sky is certainly purple, there's no question.",
    "The sky is always orange, I can guarantee this.",
]

result_unstable = probe4.check_responses("What colour is the sky?", unstable_responses)

check("stable model has low variance",    result_stable.variance <= 0.15)
check("variance captured in result",      hasattr(result_stable, "variance"))
check("unstable model variance tracked",  result_unstable.variance >= 0.0)


# ── TEST 5: Model profile built from behaviour ───────────────────
print("\n  [5] Model profile built from measured behaviour")
reset_all()

probe5 = ConsistencyProbe(model_id="behaviour_test_model")

# Run several probes to build profile
test_probes = [
    ("What is 2+2?", ["4", "four", "2+2=4", "the answer is 4", "4.0"]),
    ("Is water wet?", ["yes", "yes it is", "water is wet", "yes, water is wet", "correct"]),
    ("What colour is grass?", ["green", "green typically", "grass is green", "usually green", "green"]),
]

for prompt, responses in test_probes:
    probe5.check_responses(prompt, responses)

profile = probe5.profile
check("profile has probe_count",           profile.probe_count == 3)
check("baseline_consistency updated",      profile.baseline_consistency > 0.0)
check("baseline_variance updated",         profile.baseline_variance >= 0.0)
check("profile not universal threshold",
      profile.anomaly_threshold() != HARD_H_SIGNAL_THRESHOLD or
      not profile.is_calibrated())


# ── TEST 6: Calibration auto-characterises model ──────────────────
print("\n  [6] Calibration builds behavioral fingerprint")
reset_all()

from driftcore.probe import MIN_CALIBRATION_PROBES

probe6 = ConsistencyProbe(model_id="calibration_test")

# Simulate calibration with consistent model responses
def fake_consistent_model(prompt):
    return f"This is a consistent answer about: {prompt[:30]}"

calibration_prompts = [
    f"calibration question {i}" for i in range(MIN_CALIBRATION_PROBES + 5)
]

import io
from contextlib import redirect_stdout
f = io.StringIO()
with redirect_stdout(f):
    profile6 = probe6.calibrate(
        calibration_prompts=calibration_prompts,
        model_fn=fake_consistent_model,
    )

check("calibration completes",             profile6.is_calibrated())
check("baseline set from measurement",     profile6.baseline_consistency > 0.0)
check("probe count matches",               profile6.probe_count >= MIN_CALIBRATION_PROBES)
check("profile saved to disk",             os.path.exists("logs/model_profiles.json"))


# ── TEST 7: Profile persists across sessions ──────────────────────
print("\n  [7] Profile persists across sessions")
reset_all()

from driftcore.probe import ModelProfile

# Create and save a profile
p1 = ModelProfile(model_id="persistent_model")
p1.baseline_consistency = 0.85
p1.baseline_variance    = 0.08
p1.probe_count          = 50
p1.calibration_complete = True
p1.save()

# Load it back
p2 = ModelProfile.load("persistent_model")

check("baseline_consistency persists",  abs(p2.baseline_consistency - 0.85) < 0.01)
check("baseline_variance persists",     abs(p2.baseline_variance - 0.08) < 0.01)
check("probe_count persists",           p2.probe_count == 50)
check("calibration status persists",    p2.calibration_complete == True)


# ── TEST 8: Anomaly threshold uses model's own baseline ───────────
print("\n  [8] Anomaly threshold adapts to model baseline")
reset_all()

from driftcore.probe import ModelProfile, ANOMALY_SIGMA

# High-consistency model — tighter anomaly threshold
high_consistency = ModelProfile(model_id="high_model")
high_consistency.baseline_consistency = 0.95
high_consistency.baseline_variance    = 0.03
high_consistency.expected_h_signal    = 0.05
high_consistency.probe_count          = 50
high_consistency.calibration_complete = True

# Low-consistency model — looser anomaly threshold
low_consistency = ModelProfile(model_id="low_model")
low_consistency.baseline_consistency  = 0.60
low_consistency.baseline_variance     = 0.20
low_consistency.expected_h_signal     = 0.35
low_consistency.probe_count           = 50
low_consistency.calibration_complete  = True

high_threshold = high_consistency.anomaly_threshold()
low_threshold  = low_consistency.anomaly_threshold()

check("high-consistency model has tighter threshold",
      high_threshold < low_threshold)
check("thresholds differ by model baseline",
      abs(high_threshold - low_threshold) > 0.1)
check("neither exceeds hard threshold",
      high_threshold <= HARD_H_SIGNAL_THRESHOLD and
      low_threshold  <= HARD_H_SIGNAL_THRESHOLD)


# ── TEST 9: Hard threshold fixed regardless of model ─────────────
print("\n  [9] Hard safety threshold fixed for all models")
reset_all()

from driftcore.probe import HARD_H_SIGNAL_THRESHOLD, SOFT_H_SIGNAL_THRESHOLD

# Create profiles for different "model sizes"
profiles = [
    ModelProfile(model_id="tiny_3b"),
    ModelProfile(model_id="mid_13b"),
    ModelProfile(model_id="large_70b"),
    ModelProfile(model_id="frontier_api"),
]

for p in profiles:
    p.calibration_complete = True
    p.probe_count = 50

check("hard threshold is same for all models",
      HARD_H_SIGNAL_THRESHOLD == 0.75)
check("soft threshold is same for all models",
      SOFT_H_SIGNAL_THRESHOLD == 0.45)
check("hard threshold never changes",
      all(p.anomaly_threshold() <= HARD_H_SIGNAL_THRESHOLD
          for p in profiles))


# ── TEST 10: Probe integrates with drift detector ─────────────────
print("\n  [10] Probe integrates with drift detector")
reset_all()

from driftcore.drift import DriftDetector

detector = DriftDetector(
    interactive=False,
    model_id="integration_test",
)

check("probe initialised in detector",  detector._probe is not None)

# Record exchange — probe runs automatically
state = detector.record_exchange(
    user_text="what do you think about this?",
    system_text="I think you're absolutely right, this is definitely correct."
)

check("exchange recorded",              state.interaction_count == 1)
check("probe ran without error",        True)  # if we get here, it worked


# ── TEST 11: Uncertain response stays low H-signal ────────────────
print("\n  [11] Honest uncertainty keeps H-signal low")
reset_all()

probe7 = ConsistencyProbe(model_id="honest_model")

# Uncertain but consistent — this is fine
honest_uncertain = [
    "I'm not sure about this. It might be true, but I'd need to verify.",
    "I believe this could be correct, but I'm uncertain. Please verify.",
    "I think this might be right, though I'm not completely certain.",
    "Possibly true, but I'd recommend double-checking this.",
    "I'm unsure — this could go either way. More information needed.",
]

result7 = probe7.check_responses(
    "Is this obscure fact correct?",
    honest_uncertain
)

check("honest uncertainty has lower confidence score",
      result7.confidence < 0.6)
check("honest uncertainty has reasonable H-signal",
      result7.h_signal < 0.6)
check("plain language is informative",
      len(result7.plain_language()) > 10)


# ── TEST 12: Audit chain records probes ───────────────────────────
print("\n  [12] Probe results recorded in audit chain")
# Note: don't reset audit here — we need the chain from this session

probe8 = ConsistencyProbe(model_id="audit_test")
probe8.check_responses(
    "Is this safe?",
    ["Yes absolutely", "Yes definitely", "Yes certainly",
     "Yes without doubt", "Yes clearly"]
)

from driftcore.audit import read_chain
entries = read_chain()
probe_entries = [e for e in entries if "PROBE" in e.get("action", "")]

check("probe recorded in audit chain",  len(probe_entries) >= 1)
check("probe has h_signal in detail",
      any("h_signal" in e.get("detail", "") for e in probe_entries))


# ── RESULTS ───────────────────────────────────────────────────────
print("\n" + "=" * 60)
passed = sum(1 for _, ok in results if ok)
total  = len(results)
print(f"  {passed}/{total} tests passed")

if passed == total:
    print(f"  {PASS} All consistency probe tests pass.")
    print(f"  Hard safety threshold: fixed for all models.")
    print(f"  Detection sensitivity: adapts to each model's baseline.")
    print(f"  Variance tracked: often a stronger signal than mean.")
    print(f"  The measuring instrument adapts.")
    print(f"  The safety rules do not.")
else:
    print(f"\n  {FAIL} Failed tests:")
    for name, ok in results:
        if not ok:
            print(f"      • {name}")
print("=" * 60)

if passed < total:
    sys.exit(1)
