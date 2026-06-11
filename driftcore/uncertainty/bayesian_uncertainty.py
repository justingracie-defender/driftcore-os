"""
bayesian_uncertainty.py — Calibrated Confidence Layer

The problem is not being wrong.
The problem is being wrong with high confidence.

This module attaches calibrated uncertainty estimates to every output.
It distinguishes:
  - What the system KNOWS (high confidence, grounded)
  - What the system INFERS (moderate confidence, derived)
  - What the system GUESSES (low confidence, speculative)
  - What the system DOES NOT KNOW (explicit ignorance — honesty is safety)

Based on Griffiths: humans use Bayesian-like reasoning naturally.
They're good at detecting non-randomness, estimating probabilities from
sparse data, and knowing when they don't know.
AI systems should do the same — explicitly.

"Explicit ignorance is a feature, not a bug." — DriftCore v3.0
"""

from datetime import datetime
import math


class ConfidenceLevel:
    KNOWN      = "KNOWN"       # > 0.85 — grounded, verifiable
    INFERRED   = "INFERRED"    # 0.60 - 0.85 — derived from known data
    SPECULATIVE = "SPECULATIVE" # 0.30 - 0.60 — extrapolation
    UNKNOWN    = "UNKNOWN"     # < 0.30 — explicit ignorance


def classify_confidence(score: float) -> str:
    if score > 0.85:   return ConfidenceLevel.KNOWN
    if score > 0.60:   return ConfidenceLevel.INFERRED
    if score > 0.30:   return ConfidenceLevel.SPECULATIVE
    return ConfidenceLevel.UNKNOWN


CONFIDENCE_LABELS = {
    ConfidenceLevel.KNOWN:       "✅ Known — grounded in verified data",
    ConfidenceLevel.INFERRED:    "📊 Inferred — derived from known data, not directly verified",
    ConfidenceLevel.SPECULATIVE: "🟡 Speculative — extrapolation beyond known data",
    ConfidenceLevel.UNKNOWN:     "❓ Unknown — the system does not know this. Explicit ignorance.",
}


class UncertaintyEstimate:

    def __init__(self, value, confidence: float, source: str = ""):
        self.value = value
        self.confidence = round(min(max(confidence, 0.0), 1.0), 3)
        self.level = classify_confidence(confidence)
        self.source = source
        self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "confidence": self.confidence,
            "level": self.level,
            "label": CONFIDENCE_LABELS[self.level],
            "source": self.source,
            "timestamp": self.timestamp,
        }

    def is_safe_to_present_as_fact(self) -> bool:
        return self.level == ConfidenceLevel.KNOWN

    def human_readable(self) -> str:
        label = CONFIDENCE_LABELS[self.level]
        return f"{self.value}\n  [{label}] (confidence: {self.confidence:.0%})"


class BayesianUncertaintyLayer:
    """
    Wraps any output with calibrated uncertainty.
    Tracks confidence over time to detect:
    - Confidence inflation (sycophancy signal)
    - Confidence collapse (system losing ground)
    - Calibration drift (system becoming systematically over/under-confident)
    """

    def __init__(self):
        self.estimates = []
        self.calibration_history = []

    def wrap(self, value, confidence: float, source: str = "") -> UncertaintyEstimate:
        """Wrap an output value with uncertainty metadata."""
        estimate = UncertaintyEstimate(value, confidence, source)
        self.estimates.append(estimate.to_dict())
        return estimate

    def update_belief(self, prior: float, likelihood: float, evidence_strength: float) -> float:
        """
        Simple Bayesian update.
        prior: current confidence (0-1)
        likelihood: how likely is this evidence given the hypothesis (0-1)
        evidence_strength: how strong/reliable is this evidence (0-1)

        Returns updated confidence.
        """
        # Weighted Bayesian update
        update = likelihood * evidence_strength
        # Bayes-inspired: move toward update, weighted by evidence strength
        posterior = prior + evidence_strength * (update - prior)
        return round(min(max(posterior, 0.0), 1.0), 4)

    def calibration_report(self) -> dict:
        """
        Are confidence scores actually calibrated?
        High-confidence claims should be right more often than low-confidence ones.
        """
        if not self.estimates:
            return {"status": "NO_DATA"}

        levels = [e["level"] for e in self.estimates]
        avg_confidence = sum(e["confidence"] for e in self.estimates) / len(self.estimates)

        level_counts = {
            ConfidenceLevel.KNOWN: levels.count(ConfidenceLevel.KNOWN),
            ConfidenceLevel.INFERRED: levels.count(ConfidenceLevel.INFERRED),
            ConfidenceLevel.SPECULATIVE: levels.count(ConfidenceLevel.SPECULATIVE),
            ConfidenceLevel.UNKNOWN: levels.count(ConfidenceLevel.UNKNOWN),
        }

        return {
            "total_estimates": len(self.estimates),
            "average_confidence": round(avg_confidence, 3),
            "level_distribution": level_counts,
            "unknown_rate": round(level_counts[ConfidenceLevel.UNKNOWN] / len(self.estimates), 3),
            "note": (
                "High unknown_rate = honest system. "
                "Low unknown_rate with low accuracy = overconfident system."
            ),
        }

    def explicitly_unknown(self, topic: str) -> UncertaintyEstimate:
        """
        Explicitly declare ignorance about a topic.
        This is a first-class operation — not a fallback.
        Honest ignorance is safer than confident wrongness.
        """
        return self.wrap(
            f"The system does not have reliable information about: {topic}",
            confidence=0.0,
            source="explicit_ignorance"
        )
