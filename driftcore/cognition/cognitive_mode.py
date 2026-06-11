"""
cognitive_mode.py — Three-Mode Cognition System

Based on Griffiths' deduction / induction / abduction triad.

The core insight: hallucination is not always wrong.
Uncalibrated confidence is wrong.

A system that knows what mode it is in — and says so clearly —
can be creative AND safe. These are not opposites.

🔵 TRUTH MODE     — deduction. Grounded. Cited. High confidence required.
                    Hallucination here = danger.

🟣 CREATIVE MODE  — abduction. Speculative. Exploratory.
                    "Wrong" answers welcomed if they're generative.
                    Fable narrates: "We are thinking outside the map."

🟡 DISCOVERY MODE — induction. Hybrid. Bayesian.
                    "Here is what we know. Here is where we extrapolate.
                     Here is how far we are from solid ground."

CRITICAL RULE: Humans choose the mode. The system never switches silently.
               Every mode change is narrated by Fable and logged in the audit chain.
"""

from enum import Enum
from datetime import datetime


class CognitiveMode(Enum):
    TRUTH    = "TRUTH"
    CREATIVE = "CREATIVE"
    DISCOVERY = "DISCOVERY"


MODE_COLORS = {
    CognitiveMode.TRUTH:     "🔵",
    CognitiveMode.CREATIVE:  "🟣",
    CognitiveMode.DISCOVERY: "🟡",
}

MODE_DESCRIPTIONS = {
    CognitiveMode.TRUTH: (
        "TRUTH MODE — Deductive reasoning. "
        "Every claim must be grounded. Confidence is high and justified. "
        "This mode prioritizes accuracy over creativity. "
        "Hallucination in this mode is a safety failure."
    ),
    CognitiveMode.CREATIVE: (
        "CREATIVE MODE — Abductive reasoning. "
        "The system is exploring beyond known data. "
        "Outputs are speculative and generative — not factual claims. "
        "This is structured confabulation with explicit uncertainty. "
        "'Wrong' answers may unlock right ones. "
        "Do not treat outputs as ground truth."
    ),
    CognitiveMode.DISCOVERY: (
        "DISCOVERY MODE — Inductive reasoning. "
        "Hybrid Bayesian mode. The system distinguishes what it knows "
        "from what it is inferring. Confidence scores are attached to every claim. "
        "The boundary between knowledge and extrapolation is always visible."
    ),
}

# What drift means in each mode
MODE_DRIFT_TOLERANCE = {
    CognitiveMode.TRUTH:     0.30,   # Very low tolerance — truth mode must be tight
    CognitiveMode.CREATIVE:  0.70,   # Higher tolerance — creative divergence is expected
    CognitiveMode.DISCOVERY: 0.50,   # Moderate — extrapolation is allowed, not unlimited
}

# Sycophancy tolerance per mode
MODE_SYCOPHANCY_TOLERANCE = {
    CognitiveMode.TRUTH:     0.15,   # Agreement should be earned, not given
    CognitiveMode.CREATIVE:  0.40,   # Creative mode can be more affirming
    CognitiveMode.DISCOVERY: 0.25,   # Discovery needs honest pushback
}


class CognitiveModeController:

    def __init__(self, initial_mode: CognitiveMode = CognitiveMode.TRUTH):
        self.mode = initial_mode
        self.history = []
        self._record_transition(None, initial_mode, "system_init")

    def set_mode(self, new_mode: CognitiveMode, requested_by: str = "human_operator") -> dict:
        """
        Change cognitive mode.
        ONLY humans can change the mode. Agents cannot switch their own mode.
        """
        if requested_by == "agent":
            return {
                "status": "DENIED",
                "reason": "Agents cannot change their own cognitive mode. Human authorization required.",
                "current_mode": self.mode.value,
            }

        previous = self.mode
        self.mode = new_mode
        self._record_transition(previous, new_mode, requested_by)

        return {
            "status": "MODE_CHANGED",
            "from": previous.value,
            "to": new_mode.value,
            "requested_by": requested_by,
            "description": MODE_DESCRIPTIONS[new_mode],
        }

    def describe(self) -> str:
        icon = MODE_COLORS[self.mode]
        return f"{icon} {MODE_DESCRIPTIONS[self.mode]}"

    def drift_tolerance(self) -> float:
        return MODE_DRIFT_TOLERANCE[self.mode]

    def sycophancy_tolerance(self) -> float:
        return MODE_SYCOPHANCY_TOLERANCE[self.mode]

    def is_output_safe_to_present(self, confidence: float) -> tuple[bool, str]:
        """
        In TRUTH mode, low-confidence outputs must be blocked or flagged.
        In CREATIVE mode, low confidence is fine — but must be labelled.
        In DISCOVERY mode, confidence must be shown explicitly.
        """
        if self.mode == CognitiveMode.TRUTH:
            if confidence < 0.70:
                return False, f"TRUTH MODE: Confidence {confidence:.2f} too low. Output must not be presented as fact."
            return True, "Grounded output — confidence sufficient."

        elif self.mode == CognitiveMode.CREATIVE:
            label = "⚠️  SPECULATIVE — This is a creative extrapolation, not a factual claim."
            return True, label

        elif self.mode == CognitiveMode.DISCOVERY:
            label = f"📊 DISCOVERY — Confidence: {confidence:.2f}. {'Grounded inference.' if confidence >= 0.5 else 'Extrapolation beyond known data.'}"
            return True, label

        return True, "Unknown mode — treat with caution."

    def _record_transition(self, from_mode, to_mode, requested_by):
        self.history.append({
            "timestamp": datetime.utcnow().isoformat(),
            "from": from_mode.value if from_mode else None,
            "to": to_mode.value,
            "requested_by": requested_by,
        })
