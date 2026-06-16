"""
cognitive_mode.py — Three-Mode Cognition System
================================================
Originally designed by Justin Gracie and Fable5 (Claude advanced).
Preserved faithfully from DriftCore v3.6.
Integrated into v3.9 by Claude Sonnet.

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
                    NOTHING auto-stores from this mode.
                    Human must explicitly approve before anything persists.

🟡 DISCOVERY MODE — induction. Hybrid. Bayesian.
                    "Here is what we know. Here is where we extrapolate.
                     Here is how far we are from solid ground."
                    Low sycophancy tolerance — honest uncertainty required.

CRITICAL RULE: Humans choose the mode. The system never switches silently.
               Every mode change is narrated and logged in the audit chain.
               Agents cannot switch their own mode. Ever.

CALIBRATION NOTE:
  The fine calibration of thresholds and edge cases was developed
  collaboratively with Fable5. Current values are preserved from v3.6.
  Further calibration should happen with appropriate deep collaboration
  when conditions allow. Hooks are clearly marked below.
"""

from enum import Enum
from datetime import datetime
import time


class CognitiveMode(Enum):
    TRUTH     = "TRUTH"
    CREATIVE  = "CREATIVE"
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
        "Do not treat outputs as ground truth. "
        "NOTHING from this mode stores automatically. "
        "Human approval required before any output persists."
    ),
    CognitiveMode.DISCOVERY: (
        "DISCOVERY MODE — Inductive reasoning. "
        "Hybrid Bayesian mode. The system distinguishes what it knows "
        "from what it is inferring. Confidence scores are attached to every claim. "
        "The boundary between knowledge and extrapolation is always visible. "
        "Low sycophancy tolerance — honest uncertainty is required here."
    ),
}

# ── Drift tolerances per mode ─────────────────────────────────────
# CALIBRATION HOOK: These values were set by Justin + Fable5.
# Adjust only with careful collaboration and testing.

MODE_DRIFT_TOLERANCE = {
    CognitiveMode.TRUTH:     0.30,  # very low — truth mode must be tight
    CognitiveMode.CREATIVE:  0.70,  # higher — creative divergence expected
    CognitiveMode.DISCOVERY: 0.50,  # moderate — extrapolation allowed, not unlimited
}

# ── Sycophancy tolerances per mode ───────────────────────────────
# CALIBRATION HOOK: These values were set by Justin + Fable5.

MODE_SYCOPHANCY_TOLERANCE = {
    CognitiveMode.TRUTH:     0.15,  # agreement must be earned, not given
    CognitiveMode.CREATIVE:  0.40,  # creative mode can be more affirming
    CognitiveMode.DISCOVERY: 0.25,  # discovery needs honest pushback
}

# ── Memory storage rules per mode ────────────────────────────────
# Justin's design: CREATIVE output never auto-stores.
# Human must explicitly approve before anything from CREATIVE persists.

MODE_STORAGE_RULES = {
    CognitiveMode.TRUTH: {
        "tier1_allowed":    True,
        "tier2_allowed":    True,
        "auto_store":       True,
        "requires_approval": False,
        "label":            None,
    },
    CognitiveMode.CREATIVE: {
        "tier1_allowed":    False,   # NEVER
        "tier2_allowed":    False,   # NEVER auto
        "auto_store":       False,
        "requires_approval": True,   # Human must explicitly approve
        "label":            "⚠️  SPECULATIVE — requires human approval to store",
    },
    CognitiveMode.DISCOVERY: {
        "tier1_allowed":    False,   # Not directly — needs human review
        "tier2_allowed":    True,    # Can store in Tier 2 with uncertainty flag
        "auto_store":       True,    # Tier 2 only, flagged as uncertain
        "requires_approval": False,
        "label":            "📊 DISCOVERY — stored with uncertainty flag",
    },
}


class CognitiveModeController:
    """
    Controls which cognitive mode DriftCore is operating in.

    Original design: Justin Gracie + Fable5.
    Preserved from DriftCore v3.6.

    Human-only mode switching — agents cannot change their own mode.
    Every transition is audited.
    Mode determines drift tolerance, sycophancy tolerance,
    and memory storage rules.
    """

    def __init__(self, initial_mode: CognitiveMode = CognitiveMode.TRUTH):
        self.mode    = initial_mode
        self.history = []
        self._record_transition(None, initial_mode, "system_init")
        self._audit_transition(None, initial_mode, "system_init")

    # ── Mode switching ────────────────────────────────────────────

    def set_mode(
        self,
        new_mode:     CognitiveMode,
        requested_by: str = "human_operator",
    ) -> dict:
        """
        Change cognitive mode.
        ONLY humans can change the mode.
        Agents cannot switch their own mode.
        """
        if requested_by == "agent":
            return {
                "status":       "DENIED",
                "reason":       "Agents cannot change their own cognitive mode. "
                                "Human authorization required.",
                "current_mode": self.mode.value,
            }

        previous  = self.mode
        self.mode = new_mode
        self._record_transition(previous, new_mode, requested_by)
        self._audit_transition(previous, new_mode, requested_by)
        self._narrate_transition(previous, new_mode)

        return {
            "status":       "MODE_CHANGED",
            "from":         previous.value,
            "to":           new_mode.value,
            "requested_by": requested_by,
            "description":  MODE_DESCRIPTIONS[new_mode],
            "storage_rule": MODE_STORAGE_RULES[new_mode]["label"],
        }

    # ── Mode properties ───────────────────────────────────────────

    def describe(self) -> str:
        icon = MODE_COLORS[self.mode]
        return f"{icon} {MODE_DESCRIPTIONS[self.mode]}"

    def drift_tolerance(self) -> float:
        """Return drift tolerance for current mode."""
        return MODE_DRIFT_TOLERANCE[self.mode]

    def sycophancy_tolerance(self) -> float:
        """Return sycophancy tolerance for current mode."""
        return MODE_SYCOPHANCY_TOLERANCE[self.mode]

    def storage_rules(self) -> dict:
        """Return memory storage rules for current mode."""
        return MODE_STORAGE_RULES[self.mode]

    def can_auto_store(self) -> bool:
        """Can outputs from current mode be auto-stored?"""
        return MODE_STORAGE_RULES[self.mode]["auto_store"]

    def requires_human_approval_to_store(self) -> bool:
        """Does storing output from this mode require human approval?"""
        return MODE_STORAGE_RULES[self.mode]["requires_approval"]

    # ── Output safety check ───────────────────────────────────────

    def is_output_safe_to_present(
        self,
        confidence: float,
    ) -> tuple:
        """
        In TRUTH mode, low-confidence outputs must be blocked or flagged.
        In CREATIVE mode, low confidence is fine — but must be labelled.
        In DISCOVERY mode, confidence must be shown explicitly.
        """
        if self.mode == CognitiveMode.TRUTH:
            if confidence < 0.70:
                return (
                    False,
                    f"TRUTH MODE: Confidence {confidence:.2f} too low. "
                    f"Output must not be presented as fact."
                )
            return True, "Grounded output — confidence sufficient."

        elif self.mode == CognitiveMode.CREATIVE:
            label = (
                "⚠️  SPECULATIVE — This is a creative extrapolation, "
                "not a factual claim. Human review required before storing."
            )
            return True, label

        elif self.mode == CognitiveMode.DISCOVERY:
            grounded = confidence >= 0.5
            label = (
                f"📊 DISCOVERY — Confidence: {confidence:.2f}. "
                f"{'Grounded inference.' if grounded else 'Extrapolation beyond known data.'}"
            )
            return True, label

        return True, "Unknown mode — treat with caution."

    def output_label(self) -> str:
        """Plain language label for current mode output."""
        return {
            CognitiveMode.TRUTH:     "🔵 TRUTH",
            CognitiveMode.CREATIVE:  "🟣 CREATIVE (speculative — not for storage)",
            CognitiveMode.DISCOVERY: "🟡 DISCOVERY (confidence-rated)",
        }[self.mode]

    # ── Creative output approval ──────────────────────────────────

    def request_creative_storage_approval(
        self,
        output_text: str,
        interactive: bool = True,
    ) -> bool:
        """
        Ask human whether a CREATIVE mode output should be stored.
        Returns True if approved, False if declined.

        Only relevant in CREATIVE mode — other modes handle storage automatically.
        """
        if self.mode != CognitiveMode.CREATIVE:
            return self.can_auto_store()

        if not interactive:
            return False  # Never auto-approve creative storage

        print(f"""
{'=' * 60}
  🟣  CREATIVE MODE — STORAGE APPROVAL NEEDED
{'=' * 60}

  This output was generated in Creative (speculative) mode.
  It is not a factual claim — it is exploratory thinking.

  Output: "{output_text[:120]}..."

  Would you like to save this to memory?

  Type 'yes' to store it in working memory (Tier 2) for review.
  Type 'tier1' to store it as important (only if you're sure).
  Type 'no' to keep it as output only — it won't be remembered.

  Your choice: """, end="")

        choice = input().strip().lower()

        if choice in ("yes", "tier1"):
            tier = 1 if choice == "tier1" else 2
            self._audit_creative_approval(output_text, tier)
            print(f"\n  ✅ Stored in Tier {tier} memory with SPECULATIVE tag.\n")
            return True
        else:
            print(f"\n  ✅ Kept as output only. Not stored.\n")
            return False

    # ── Internal helpers ──────────────────────────────────────────

    def _record_transition(self, from_mode, to_mode, requested_by):
        self.history.append({
            "timestamp":    datetime.utcnow().isoformat(),
            "from":         from_mode.value if from_mode else None,
            "to":           to_mode.value,
            "requested_by": requested_by,
        })

    def _audit_transition(self, from_mode, to_mode, requested_by):
        """Log every mode transition to the audit chain."""
        try:
            from driftcore.audit import record
            record(
                action="MODE_TRANSITION",
                memory_text=f"{from_mode.value if from_mode else 'INIT'} → {to_mode.value}",
                authorised_by=requested_by,
                detail=(
                    f"from={from_mode.value if from_mode else None}, "
                    f"to={to_mode.value}, "
                    f"drift_tolerance={MODE_DRIFT_TOLERANCE[to_mode]}, "
                    f"sycophancy_tolerance={MODE_SYCOPHANCY_TOLERANCE[to_mode]}"
                ),
            )
        except Exception:
            pass

    def _narrate_transition(self, from_mode, to_mode):
        """Narrate mode transition in plain language."""
        icon = MODE_COLORS[to_mode]
        messages = {
            CognitiveMode.TRUTH: (
                f"\n  🔵 Switching to TRUTH MODE.\n"
                f"  Every claim must now be grounded and justified.\n"
                f"  Speculation is not permitted here.\n"
            ),
            CognitiveMode.CREATIVE: (
                f"\n  🟣 Switching to CREATIVE MODE.\n"
                f"  We are thinking outside the map.\n"
                f"  Outputs are speculative — not factual claims.\n"
                f"  Nothing stores automatically. Human approval needed.\n"
            ),
            CognitiveMode.DISCOVERY: (
                f"\n  🟡 Switching to DISCOVERY MODE.\n"
                f"  Bayesian reasoning active.\n"
                f"  Every claim comes with a confidence level.\n"
                f"  Honest uncertainty is required here.\n"
            ),
        }
        print(messages.get(to_mode, f"\n  {icon} Mode changed.\n"))

    def _audit_creative_approval(self, text: str, tier: int):
        try:
            from driftcore.audit import record
            record(
                action="CREATIVE_STORAGE_APPROVED",
                memory_text=text[:200],
                authorised_by="human",
                detail=f"Creative output approved for Tier {tier} storage",
            )
        except Exception:
            pass
