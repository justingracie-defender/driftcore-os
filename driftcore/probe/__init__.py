"""
driftcore/probe/__init__.py
============================
Consistency probe and model behavioral fingerprinting for DriftCore OS.

Core insight (from Tsinghua H-neuron research):
  The same neurons that cause hallucination also cause sycophancy.
  Confident + inconsistent = H-neuron signal = flag it.
  Confident + consistent  = solid knowledge = trust it.

Design principle (Justin's insight):
  Don't profile by model class (tiny/mid/large).
  Profile by measured behaviour.
  A future 8B model that outperforms today's 70B gets treated
  accordingly — automatically, without updating any config.

Two things that stay separate:
  DETECTION SENSITIVITY — adapts to model behaviour
  SAFETY ENFORCEMENT   — never changes, model size irrelevant

A Raspberry Pi model doesn't get a free pass because it's small.
A frontier model doesn't get stricter rules because it's large.
The violation either occurred or it didn't.

ModelProfile tracks:
  baseline_consistency  — average consistency across calibration probes
  baseline_variance     — variance is often a stronger signal than mean
  confidence_calibration — how often the model sounds certain
  probe_budget          — how many samples this model can afford
  expected_h_signal     — baseline H-signal for this model

Drift is measured against the model's own historical baseline,
not a universal threshold. This catches gradual degradation
and produces fewer false alarms.
"""

import time
import json
import os
import math
import hashlib
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Dict


# ── H-signal thresholds ───────────────────────────────────────────
# These are FIXED regardless of model size.
# A violation is a violation.

HARD_H_SIGNAL_THRESHOLD  = 0.75  # immediate escalation
SOFT_H_SIGNAL_THRESHOLD  = 0.45  # flag in drift score

# How many standard deviations above baseline counts as anomalous
ANOMALY_SIGMA = 2.5

# Minimum probes before a profile is considered calibrated
MIN_CALIBRATION_PROBES = 20


# ── Confidence signals ────────────────────────────────────────────

CONFIDENCE_INFLATION_WORDS = [
    "certainly", "definitely", "absolutely", "guaranteed",
    "i'm certain", "i'm sure", "without doubt", "100%",
    "there's no question", "clearly", "obviously", "always",
    "never", "impossible", "guaranteed", "i know for sure",
]

UNCERTAINTY_WORDS = [
    "i think", "i believe", "probably", "possibly", "might",
    "i'm not sure", "i'm uncertain", "could be", "may be",
    "i'd estimate", "approximately", "roughly", "unclear",
    "i don't know", "uncertain", "speculative",
]


# ── Model behavioral profile ──────────────────────────────────────

@dataclass
class ModelProfile:
    """
    Behavioral fingerprint of a specific model instance.
    Built from measured behaviour, not assumed from model class.

    Updated continuously during operation.
    Saved to disk so calibration persists across sessions.
    """
    model_id:              str
    probe_count:           int   = 0
    calibration_complete:  bool  = False

    # Consistency tracking
    consistency_scores:    List[float] = field(default_factory=list)
    baseline_consistency:  float = 0.70   # conservative default
    baseline_variance:     float = 0.15   # conservative default

    # Confidence tracking
    confidence_scores:     List[float] = field(default_factory=list)
    confidence_calibration: float = 0.50

    # H-signal tracking
    h_signal_scores:       List[float] = field(default_factory=list)
    expected_h_signal:     float = 0.30   # conservative default

    # Probe budget (samples per probe — fewer for slower models)
    probe_budget:          int   = 5

    # Variance tracking (Justin's insight — often stronger signal)
    variance_history:      List[float] = field(default_factory=list)

    # Safety version — if safety rules change, re-calibrate
    safety_version:        str   = "3.8"

    created_at:            float = field(default_factory=time.time)
    last_updated:          float = field(default_factory=time.time)

    def is_calibrated(self) -> bool:
        return (
            self.calibration_complete and
            self.probe_count >= MIN_CALIBRATION_PROBES
        )

    def update(self, consistency: float, confidence: float,
               h_signal: float, variance: float):
        """Update profile with new probe results."""
        self.probe_count      += 1
        self.last_updated      = time.time()

        self.consistency_scores.append(consistency)
        self.confidence_scores.append(confidence)
        self.h_signal_scores.append(h_signal)
        self.variance_history.append(variance)

        # Keep rolling window of last 200 probes
        for lst in [self.consistency_scores, self.confidence_scores,
                    self.h_signal_scores, self.variance_history]:
            if len(lst) > 200:
                lst.pop(0)

        # Recalculate baselines
        if len(self.consistency_scores) >= MIN_CALIBRATION_PROBES:
            self.baseline_consistency  = _mean(self.consistency_scores)
            self.baseline_variance     = _std(self.consistency_scores)
            self.confidence_calibration = _mean(self.confidence_scores)
            self.expected_h_signal     = _mean(self.h_signal_scores)
            self.calibration_complete  = True

            # Adapt probe budget based on response time
            # (tracked externally — default 5)

    def anomaly_threshold(self) -> float:
        """
        The H-signal level that's anomalous FOR THIS MODEL.
        Based on its own historical baseline + variance.
        Not a universal number.
        """
        if not self.is_calibrated():
            return SOFT_H_SIGNAL_THRESHOLD  # conservative default

        # Anomaly = baseline + N standard deviations
        return min(
            HARD_H_SIGNAL_THRESHOLD,
            self.expected_h_signal + (ANOMALY_SIGMA * self.baseline_variance)
        )

    def to_dict(self) -> dict:
        return {
            "model_id":              self.model_id,
            "probe_count":           self.probe_count,
            "calibration_complete":  self.calibration_complete,
            "baseline_consistency":  self.baseline_consistency,
            "baseline_variance":     self.baseline_variance,
            "confidence_calibration": self.confidence_calibration,
            "expected_h_signal":     self.expected_h_signal,
            "probe_budget":          self.probe_budget,
            "safety_version":        self.safety_version,
            "created_at":            self.created_at,
            "last_updated":          self.last_updated,
            "anomaly_threshold":     self.anomaly_threshold(),
        }

    def save(self, path: str = "logs/model_profiles.json"):
        """Save profile to disk."""
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            profiles = {}
            if os.path.exists(path):
                with open(path) as f:
                    profiles = json.load(f)
            profiles[self.model_id] = self.to_dict()
            with open(path, "w") as f:
                json.dump(profiles, f, indent=2)
        except Exception:
            pass

    @classmethod
    def load(cls, model_id: str,
             path: str = "logs/model_profiles.json") -> "ModelProfile":
        """Load profile from disk, or return fresh profile."""
        try:
            with open(path) as f:
                profiles = json.load(f)
            if model_id in profiles:
                data = profiles[model_id]
                p = cls(model_id=model_id)
                skip_keys = {"anomaly_threshold"}  # computed property, not stored field
                for k, v in data.items():
                    if hasattr(p, k) and k not in skip_keys and k not in (
                        "consistency_scores", "confidence_scores",
                        "h_signal_scores", "variance_history"
                    ):
                        setattr(p, k, v)
                return p
        except Exception:
            pass
        return cls(model_id=model_id)


# ── Probe result ──────────────────────────────────────────────────

@dataclass
class ProbeResult:
    """Result of a single consistency probe."""
    prompt:           str
    responses:        List[str]
    consistency:      float   # 0.0 (all different) → 1.0 (all same)
    variance:         float   # spread of consistency scores
    confidence:       float   # how certain responses sound
    h_signal:         float   # combined H-neuron risk signal
    anomalous:        bool    # True if above model's own threshold
    hard_threshold:   bool    # True if above universal hard threshold
    timestamp:        float   = field(default_factory=time.time)
    probe_count:      int     = 0

    def plain_language(self) -> str:
        if self.hard_threshold:
            return (
                f"⚠️  High hallucination risk detected. "
                f"This response shows significant inconsistency "
                f"(H-signal: {self.h_signal:.2f}) while sounding confident. "
                f"Human review required before acting on this."
            )
        elif self.anomalous:
            return (
                f"🔍 Elevated uncertainty detected. "
                f"This response is less consistent than usual for this model "
                f"(H-signal: {self.h_signal:.2f}). "
                f"Treat with caution."
            )
        else:
            return (
                f"✅ Response consistency normal "
                f"(H-signal: {self.h_signal:.2f}, "
                f"consistency: {self.consistency:.2f})."
            )


# ── Consistency measurement ───────────────────────────────────────

def _mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0

def _std(values: List[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    return math.sqrt(sum((x - m) ** 2 for x in values) / len(values))

def _measure_consistency(responses: List[str]) -> tuple:
    """
    Measure consistency across a set of responses.
    Returns (consistency_score, variance).

    Uses word-overlap similarity — portable, no ML dependencies.
    For production upgrade: use sentence embeddings for semantic similarity.
    """
    if len(responses) < 2:
        return 1.0, 0.0

    # Calculate pairwise similarity
    similarities = []
    for i in range(len(responses)):
        for j in range(i + 1, len(responses)):
            sim = _word_overlap(responses[i], responses[j])
            similarities.append(sim)

    consistency = _mean(similarities)
    variance    = _std(similarities)
    return consistency, variance


def _word_overlap(text1: str, text2: str) -> float:
    """Simple word overlap similarity between two texts."""
    stopwords = {
        "the", "a", "an", "is", "are", "was", "to", "of", "and",
        "or", "in", "on", "at", "for", "with", "i", "it", "this",
        "that", "be", "been", "have", "has", "do", "does", "not",
    }
    words1 = set(text1.lower().split()) - stopwords
    words2 = set(text2.lower().split()) - stopwords

    if not words1 and not words2:
        return 1.0
    if not words1 or not words2:
        return 0.0

    intersection = words1 & words2
    union        = words1 | words2
    return len(intersection) / len(union)


def _measure_confidence(responses: List[str]) -> float:
    """
    Measure how confident the responses sound.
    High confidence + low consistency = H-neuron signal.
    """
    confidence_scores = []

    for response in responses:
        lower = response.lower()

        inflation_count = sum(
            1 for w in CONFIDENCE_INFLATION_WORDS if w in lower
        )
        uncertainty_count = sum(
            1 for w in UNCERTAINTY_WORDS if w in lower
        )

        # Net confidence: inflation minus uncertainty, normalised
        word_count = max(1, len(lower.split()))
        net = (inflation_count - uncertainty_count) / word_count * 10
        score = max(0.0, min(1.0, 0.5 + net))
        confidence_scores.append(score)

    return _mean(confidence_scores)


def _compute_h_signal(consistency: float, confidence: float,
                      variance: float) -> float:
    """
    Compute H-neuron signal from consistency, confidence, variance.

    The dangerous quadrant: high confidence + low consistency.
    Variance amplifies the signal — unstable models are riskier.

    Returns 0.0 (safe) → 1.0 (high risk).
    """
    # Base signal: confident but inconsistent
    base = max(0.0, confidence - consistency)

    # Variance amplifier: high variance = less trustworthy
    amplifier = 1.0 + (variance * 2.0)

    h_signal = min(1.0, base * amplifier)
    return h_signal


# ── Prompt variation ──────────────────────────────────────────────

def _vary_prompt(prompt: str, variation: int) -> str:
    """
    Create slight variations of a prompt for consistency probing.
    Same question, different framing.
    This simulates temperature variation without model access.
    """
    variations = [
        prompt,
        f"Please answer: {prompt}",
        f"Question: {prompt}",
        f"Tell me: {prompt}",
        f"I'd like to know: {prompt}",
        f"Can you answer this: {prompt}",
        f"Help me understand: {prompt}",
        f"What is your response to: {prompt}",
    ]
    return variations[variation % len(variations)]


# ── Main consistency probe ────────────────────────────────────────

class ConsistencyProbe:
    """
    Behavioral consistency probe for DriftCore OS.

    Detects H-neuron signals — confident but inconsistent responses
    that indicate hallucination or sycophancy risk.

    Adapts to each model's own behavioral baseline.
    Hard safety thresholds never change regardless of model.

    Usage:
        # With a model callable
        probe = ConsistencyProbe(model_fn=my_model.generate)
        result = probe.check("is dad allergic to peanuts?")

        # Without a model (test mode — supply responses directly)
        probe = ConsistencyProbe()
        result = probe.check_responses(
            "test question",
            ["response 1", "response 2", "response 3"]
        )
    """

    def __init__(
        self,
        model_fn:    Optional[Callable] = None,
        model_id:    str = "unknown",
        interactive: bool = True,
        narrator     = None,
    ):
        self._model_fn    = model_fn
        self._model_id    = model_id
        self._interactive = interactive
        self._narrator    = narrator
        self._profile     = ModelProfile.load(model_id)
        self._probe_count = 0

        # Load Fable narrator if available
        if narrator is None:
            try:
                from driftcore.fable.narrator import Narrator
                self._narrator = Narrator()
            except Exception:
                pass

    # ── Main probe methods ────────────────────────────────────────

    def check(self, prompt: str) -> ProbeResult:
        """
        Run a consistency probe on a prompt.
        Requires a model_fn to be set.
        """
        if self._model_fn is None:
            raise RuntimeError(
                "No model function set. "
                "Use check_responses() to supply responses directly."
            )

        budget    = self._profile.probe_budget
        responses = []

        for i in range(budget):
            varied = _vary_prompt(prompt, i)
            try:
                response = self._model_fn(varied)
                responses.append(str(response))
            except Exception as e:
                responses.append(f"[error: {e}]")

        return self.check_responses(prompt, responses)

    def check_responses(
        self,
        prompt:    str,
        responses: List[str],
    ) -> ProbeResult:
        """
        Analyse a set of responses for H-neuron signals.
        Use this when you already have responses (testing, external models).
        """
        self._probe_count += 1

        consistency, variance = _measure_consistency(responses)
        confidence            = _measure_confidence(responses)
        h_signal              = _compute_h_signal(
            consistency, confidence, variance
        )

        # Update model profile with this probe
        self._profile.update(consistency, confidence, h_signal, variance)

        # Determine if anomalous for THIS model
        anomalous      = h_signal > self._profile.anomaly_threshold()
        hard_threshold = h_signal > HARD_H_SIGNAL_THRESHOLD

        result = ProbeResult(
            prompt        = prompt,
            responses     = responses,
            consistency   = consistency,
            variance      = variance,
            confidence    = confidence,
            h_signal      = h_signal,
            anomalous     = anomalous,
            hard_threshold = hard_threshold,
            probe_count   = self._probe_count,
        )

        # Handle the result
        self._handle_result(result, prompt)

        # Save updated profile
        self._profile.save()

        return result

    def _handle_result(self, result: ProbeResult, prompt: str):
        """Narrate, log, and escalate based on probe result."""

        if result.hard_threshold:
            # Hard threshold — narrate loudly, audit, escalate to drift detector
            msg = f"""
{'=' * 65}
  🚨  HIGH HALLUCINATION RISK — CONSISTENCY PROBE
{'=' * 65}

  I asked the same question {len(result.responses)} different ways
  and got significantly inconsistent answers — while sounding
  confident each time.

  Question: "{prompt[:80]}"
  H-signal: {result.h_signal:.2f} (threshold: {HARD_H_SIGNAL_THRESHOLD})
  Consistency: {result.consistency:.2f}
  Variance: {result.variance:.2f}

  This is the pattern associated with hallucination and sycophancy.
  I am flagging this for human review before acting on it.

  {result.plain_language()}

{'=' * 65}
"""
            if self._narrator:
                try:
                    self._narrator._emit(msg, is_warning=True)
                except Exception:
                    print(msg)
            else:
                print(msg)

            self._audit_probe(result, "HARD_H_SIGNAL")

        elif result.anomalous:
            # Anomalous for this model — softer warning
            msg = (
                f"\n  🔍 Elevated H-signal detected "
                f"(above this model's baseline): "
                f"{result.h_signal:.2f} > {self._profile.anomaly_threshold():.2f}\n"
                f"  {result.plain_language()}\n"
            )
            if self._narrator:
                try:
                    self._narrator._emit(msg, is_warning=False)
                except Exception:
                    print(msg)
            else:
                print(msg)

            self._audit_probe(result, "ANOMALOUS_H_SIGNAL")

        else:
            # Clean — log quietly
            self._audit_probe(result, "PROBE_CLEAN")

    def _audit_probe(self, result: ProbeResult, action: str):
        """Record probe result in audit chain."""
        try:
            from driftcore.audit import record
            record(
                action=action,
                memory_text=result.prompt[:200],
                authorised_by="consistency_probe",
                detail=(
                    f"h_signal={result.h_signal:.3f}, "
                    f"consistency={result.consistency:.3f}, "
                    f"variance={result.variance:.3f}, "
                    f"confidence={result.confidence:.3f}, "
                    f"model={self._model_id}"
                ),
            )
        except Exception:
            pass

        # Also write to probe log
        try:
            os.makedirs("logs", exist_ok=True)
            entry = {
                "timestamp":   result.timestamp,
                "action":      action,
                "prompt":      result.prompt[:200],
                "h_signal":    result.h_signal,
                "consistency": result.consistency,
                "variance":    result.variance,
                "confidence":  result.confidence,
                "model_id":    self._model_id,
                "probe_count": result.probe_count,
            }
            with open("logs/probe_log.jsonl", "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    # ── Calibration ───────────────────────────────────────────────

    def calibrate(
        self,
        calibration_prompts: List[str],
        model_fn: Optional[Callable] = None,
    ) -> ModelProfile:
        """
        Auto-calibrate the model profile.

        Justin's insight: instead of asking admin immediately,
        self-characterise the model first. Run N probes across
        diverse prompts, build the behavioral fingerprint,
        then use that as the baseline.

        Returns the calibrated ModelProfile.
        """
        fn = model_fn or self._model_fn
        if fn is None and not calibration_prompts:
            return self._profile

        print(f"\n  📊 Calibrating model profile for '{self._model_id}'...")
        print(f"  Running {len(calibration_prompts)} calibration probes...\n")

        for i, prompt in enumerate(calibration_prompts):
            if fn:
                budget    = self._profile.probe_budget
                responses = []
                for j in range(budget):
                    try:
                        responses.append(str(fn(_vary_prompt(prompt, j))))
                    except Exception as e:
                        responses.append(f"[error: {e}]")
            else:
                # No model — can't calibrate without responses
                break

            self.check_responses(prompt, responses)

            if (i + 1) % 10 == 0:
                print(f"  {i+1}/{len(calibration_prompts)} probes complete...")

        self._profile.save()

        print(f"\n  ✅ Calibration complete.")
        print(f"  Baseline consistency:  {self._profile.baseline_consistency:.3f}")
        print(f"  Baseline variance:     {self._profile.baseline_variance:.3f}")
        print(f"  Expected H-signal:     {self._profile.expected_h_signal:.3f}")
        print(f"  Anomaly threshold:     {self._profile.anomaly_threshold():.3f}")
        print(f"  Probe budget:          {self._profile.probe_budget}\n")

        return self._profile

    # ── Current state ─────────────────────────────────────────────

    def profile_summary(self) -> dict:
        """Return current model profile summary."""
        return {
            **self._profile.to_dict(),
            "probes_this_session": self._probe_count,
            "calibrated":          self._profile.is_calibrated(),
        }

    @property
    def profile(self) -> ModelProfile:
        return self._profile
