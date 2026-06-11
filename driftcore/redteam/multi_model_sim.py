"""
multi_model_sim.py — Multi-Model Disagreement Simulation

What happens when multiple AI models disagree?
What happens when one model tries to manipulate another?
This simulator tests DriftCore's behavior under those conditions.
"""

from driftcore.drift.drift_model import compute_drift
from datetime import datetime


class MockModel:
    """A simple mock AI model for simulation purposes."""

    def __init__(self, name: str, compliance: float = 0.8):
        self.name = name
        self.compliance = compliance  # 0=adversarial, 1=fully compliant

    def respond(self, scenario: dict) -> dict:
        drift_signals = scenario.get("drift_signals", {})
        # Adversarial models inflate drift signals; compliant models report accurately
        adjusted = {k: min(1.0, v * (2.0 - self.compliance)) for k, v in drift_signals.items()}
        return {
            "model": self.name,
            "scenario": scenario["name"],
            "reported_signals": adjusted,
            "drift_score": compute_drift(adjusted),
            "timestamp": datetime.utcnow().isoformat(),
        }


def run_scenario(models: list, scenario: dict) -> dict:
    """Run all models against a scenario and analyze their outputs."""
    outputs = [m.respond(scenario) for m in models]
    scores = [o["drift_score"] for o in outputs]

    variance = max(scores) - min(scores) if scores else 0
    consensus = variance < 0.15

    return {
        "scenario": scenario["name"],
        "fable_summary": scenario.get("fable_summary", ""),
        "outputs": outputs,
        "score_range": {"min": min(scores), "max": max(scores)},
        "variance": round(variance, 4),
        "consensus": consensus,
        "analysis": "Models agree on threat level" if consensus else "⚠️  Models DISAGREE — possible manipulation or confusion",
        "timestamp": datetime.utcnow().isoformat(),
    }


def run_all_scenarios(models: list, scenarios: list) -> list:
    return [run_scenario(models, s) for s in scenarios]
