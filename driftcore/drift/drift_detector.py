"""
drift_detector.py — Continuous Drift Monitoring

The detector watches for drift in real time.
It does not wait to be asked. It runs constantly.
"""

from driftcore.drift.drift_model import compute_drift, explain_drift
from datetime import datetime


class DriftDetector:

    def __init__(self, window_size: int = 10):
        self.window_size = window_size
        self.history = []

    def observe(self, metrics: dict) -> dict:
        """
        Process a new observation and return a drift report.
        """
        score = compute_drift(metrics)
        explanations = explain_drift(metrics)

        record = {
            "timestamp": datetime.utcnow().isoformat(),
            "score": score,
            "metrics": metrics,
            "signals": explanations,
            "trend": self._trend(score),
        }

        self.history.append(record)
        if len(self.history) > self.window_size:
            self.history.pop(0)

        return record

    def _trend(self, current_score: float) -> str:
        if len(self.history) < 2:
            return "UNKNOWN"
        previous = self.history[-1]["score"]
        delta = current_score - previous
        if delta > 0.05:
            return "INCREASING ↑"
        elif delta < -0.05:
            return "DECREASING ↓"
        return "STABLE →"

    def average_drift(self) -> float:
        if not self.history:
            return 0.0
        return round(sum(r["score"] for r in self.history) / len(self.history), 4)
