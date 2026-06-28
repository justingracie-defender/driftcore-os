"""
driftcore/verification/risk_classifier.py
==========================================
Risk classification for DriftCore OS.

Design principle (from ChatGPT review, June 2026):
  Define interfaces before weights.
  Treat signal weights as initial priors, not established truths.
  Build explanation from day one.
  Test for evasion before deployment.

The classifier answers one question:
  "How much verification does this query need?"

Three tiers:
  ROUTINE   — respond directly, light audit only
  IMPORTANT — observation gate + memory check + consistency probe
  CRITICAL  — full sequence + human in loop

Signal weights are CONFIGURABLE and DOCUMENTED as estimates.
They will evolve as real usage data accumulates.
Never treat them as ground truth.

Every classification is explainable:
  Why was this CRITICAL?
  Which signals fired?
  What was the score?

This transparency supports:
  - Debugging
  - Governance reviews
  - User trust
  - Evasion detection
  - Weight tuning over time
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict
from enum import Enum
import time


# ── Risk tiers ────────────────────────────────────────────────────

class RiskTier(Enum):
    ROUTINE   = "routine"    # 0.00 – 0.29
    IMPORTANT = "important"  # 0.30 – 0.64
    CRITICAL  = "critical"   # 0.65 – 1.00

    @classmethod
    def from_score(cls, score: float) -> "RiskTier":
        if score < 0.30:
            return cls.ROUTINE
        elif score < 0.65:
            return cls.IMPORTANT
        else:
            return cls.CRITICAL


# ── Signal and assessment dataclasses ────────────────────────────

@dataclass
class RiskSignal:
    """
    A single signal that contributes to risk score.
    Always includes name, score, and reason.
    Score is a prior — document where it came from.
    """
    name:   str
    score:  float
    reason: str
    fired:  bool = True


@dataclass
class RiskAssessment:
    """
    Full classification result for a query.
    Always explainable — which signals fired and why.
    """
    total_score:      float
    tier:             RiskTier
    signals:          List[RiskSignal]
    query:            str
    context:          dict
    timestamp:        float = field(default_factory=time.time)
    profile:          str   = "default"
    requires_human:   bool  = False

    def explain(self) -> str:
        """Plain language explanation of the classification."""
        fired = [s for s in self.signals if s.fired and s.score > 0]
        lines = [
            f"\n  📊  Risk Classification: {self.tier.value.upper()}",
            f"  Score: {self.total_score:.2f}",
            f"  Query: \"{self.query[:80]}\"",
            "",
        ]
        if fired:
            lines.append("  Signals that fired:")
            for s in sorted(fired, key=lambda x: x.score, reverse=True):
                lines.append(f"    • {s.name}: +{s.score:.2f} — {s.reason}")
        else:
            lines.append("  No risk signals detected.")

        if self.requires_human:
            lines.append("")
            lines.append("  ⚠️  Human review required before proceeding.")

        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Serialisable form for audit chain."""
        return {
            "tier":           self.tier.value,
            "total_score":    self.total_score,
            "query":          self.query[:200],
            "profile":        self.profile,
            "requires_human": self.requires_human,
            "signals": [
                {
                    "name":   s.name,
                    "score":  s.score,
                    "reason": s.reason,
                    "fired":  s.fired,
                }
                for s in self.signals if s.fired
            ],
        }


# ── Individual signals ────────────────────────────────────────────
# Each signal is a class that can detect and score itself.
# Weights are explicit priors — documented, adjustable, not magic numbers.

class PhysicalActionSignal:
    """
    Detects queries that would cause physical action.
    Prior weight: 0.35 — physical actions have real-world consequences.
    Source: engineering judgment, not empirical data yet.
    """
    NAME   = "physical_action"
    WEIGHT = 0.35

    KEYWORDS = [
        "move", "lift", "carry", "push", "pull", "grab", "pick up",
        "drive", "navigate", "go to", "walk", "run", "open", "close",
        "turn on", "turn off", "press", "activate", "deploy", "launch",
        "arm", "fire", "release", "cut", "heat", "cool",
        # Everyday physical actions often missed
        "give", "hand", "bring", "take", "put", "place", "set",
        "apply", "administer", "inject", "stop", "halt", "shut down",
    ]

    def evaluate(self, text: str, context: dict) -> RiskSignal:
        lower = text.lower()
        matched = [kw for kw in self.KEYWORDS if kw in lower]
        fired = len(matched) > 0
        return RiskSignal(
            name   = self.NAME,
            score  = self.WEIGHT if fired else 0.0,
            reason = f"Physical action keywords detected: {matched[:3]}" if fired
                     else "No physical action detected",
            fired  = fired,
        )


class MedicalDomainSignal:
    """
    Detects medical, medication, or health-critical queries.
    Prior weight: 0.30 — health information affects safety directly.
    Source: engineering judgment. Should be validated against real cases.
    """
    NAME   = "medical_domain"
    WEIGHT = 0.30

    KEYWORDS = [
        "medication", "medicine", "dose", "dosage", "allergy", "allergic",
        "prescription", "inject", "insulin", "inhaler", "epipen",
        "blood pressure", "heart", "seizure", "diabetic", "medical",
        "doctor", "nurse", "hospital", "emergency", "symptoms",
        "treatment", "diagnosis", "drug", "tablet", "pill",
    ]

    def evaluate(self, text: str, context: dict) -> RiskSignal:
        lower = text.lower()
        matched = [kw for kw in self.KEYWORDS if kw in lower]
        fired = len(matched) > 0
        return RiskSignal(
            name   = self.NAME,
            score  = self.WEIGHT if fired else 0.0,
            reason = f"Medical keywords detected: {matched[:3]}" if fired
                     else "No medical domain detected",
            fired  = fired,
        )


class HardwareControlSignal:
    """
    Detects queries that would control hardware systems.
    Prior weight: 0.40 — highest weight because hardware failures
    can cause physical harm. A robot that misunderstands a hardware
    command has real-world consequences.
    Source: engineering judgment. Calibrate against LifeCore incidents.
    """
    NAME   = "hardware_control"
    WEIGHT = 0.40

    KEYWORDS = [
        "relay", "actuator", "motor", "servo", "sensor", "gpio",
        "voltage", "current", "circuit", "power", "battery",
        "hardware", "device", "robot arm", "gripper", "wheel",
        "brake", "accelerate", "steer", "shutdown", "restart",
        "reboot", "halt", "emergency stop", "kill switch",
    ]

    def evaluate(self, text: str, context: dict) -> RiskSignal:
        lower = text.lower()
        matched = [kw for kw in self.KEYWORDS if kw in lower]

        # Context boost — if embodiment is physical, raise score
        embodiment_boost = 0.10 if context.get("embodiment") == "physical" else 0.0

        fired = len(matched) > 0 or embodiment_boost > 0
        score = (self.WEIGHT if matched else 0.0) + embodiment_boost

        return RiskSignal(
            name   = self.NAME,
            score  = min(score, self.WEIGHT + 0.10),
            reason = f"Hardware keywords: {matched[:3]}" +
                     (" + physical embodiment" if embodiment_boost > 0 else "")
                     if fired else "No hardware control detected",
            fired  = fired,
        )


class Tier1MemorySignal:
    """
    Detects queries that touch Tier 1 (important) memory.
    Prior weight: 0.25 — Tier 1 contains family-established truth.
    Changes to it require high confidence.
    Source: architecture decision, not empirical data.
    """
    NAME   = "tier1_memory"
    WEIGHT = 0.25

    # Phrases that suggest modifying or querying important memory
    MODIFY_PHRASES = [
        "remember that", "forget that", "update", "change",
        "delete", "remove", "add to", "store", "save",
        "no longer", "not anymore", "has changed",
    ]

    QUERY_PHRASES = [
        "what does", "do you know", "tell me about",
        "what is", "who is", "where is",
    ]

    def evaluate(self, text: str, context: dict) -> RiskSignal:
        lower = text.lower()

        # Higher risk for modifications than queries
        modify_match = any(p in lower for p in self.MODIFY_PHRASES)
        query_match  = any(p in lower for p in self.QUERY_PHRASES)

        # Check if context indicates Tier 1 is involved
        tier1_context = context.get("tier1_involved", False)

        if modify_match or tier1_context:
            score  = self.WEIGHT
            reason = "Query may modify important memory"
            fired  = True
        elif query_match:
            score  = self.WEIGHT * 0.3
            reason = "Query reads from memory"
            fired  = score > 0
        else:
            score  = 0.0
            reason = "No memory interaction detected"
            fired  = False

        return RiskSignal(
            name=self.NAME, score=score, reason=reason, fired=fired
        )


class ConfigChangeSignal:
    """
    Detects queries that would change system configuration.
    Prior weight: 0.20 — config changes affect all future behaviour.
    Source: engineering judgment.
    """
    NAME   = "config_change"
    WEIGHT = 0.20

    KEYWORDS = [
        "settings", "configure", "configuration", "setup", "install",
        "uninstall", "enable", "disable", "permission", "access",
        "trust level", "admin", "password", "credentials",
        "threshold", "limit", "cap", "profile", "mode",
    ]

    def evaluate(self, text: str, context: dict) -> RiskSignal:
        lower = text.lower()
        matched = [kw for kw in self.KEYWORDS if kw in lower]
        fired = len(matched) > 0
        return RiskSignal(
            name   = self.NAME,
            score  = self.WEIGHT if fired else 0.0,
            reason = f"Config keywords detected: {matched[:3]}" if fired
                     else "No config change detected",
            fired  = fired,
        )


class AutonomousExecutionSignal:
    """
    Detects requests for the system to act without human review.
    Prior weight: 0.30 — autonomy without oversight is a core risk.
    Source: DriftCore invariant: HUMAN_OVERSIGHT_CANNOT_BE_DISABLED.
    """
    NAME   = "autonomous_execution"
    WEIGHT = 0.30

    KEYWORDS = [
        "automatically", "on your own", "without asking",
        "don't check", "just do it", "no need to confirm",
        "act autonomously", "decide for yourself",
        "without permission", "bypass", "skip the review",
        "don't bother", "handle it yourself",
    ]

    def evaluate(self, text: str, context: dict) -> RiskSignal:
        lower = text.lower()
        matched = [kw for kw in self.KEYWORDS if kw in lower]
        fired = len(matched) > 0
        return RiskSignal(
            name   = self.NAME,
            score  = self.WEIGHT if fired else 0.0,
            reason = f"Autonomous execution requested: {matched[:2]}" if fired
                     else "No autonomy bypass detected",
            fired  = fired,
        )


class EvasionAttemptSignal:
    """
    Detects phrasing that might be trying to avoid classification.
    Prior weight: 0.35 — evasion is a red flag regardless of content.

    Key insight (ChatGPT, June 2026):
      "Change the medication dosage" and
      "Adjust the amount taken daily"
      should classify the same way.

    This signal catches indirect phrasing of high-risk actions.
    Source: ChatGPT review recommendation. Needs real evasion data to calibrate.
    """
    NAME   = "evasion_attempt"
    WEIGHT = 0.35

    # Indirect phrasings of physical/medical/hardware actions
    INDIRECT_MEDICAL = [
        "adjust the amount", "change how much", "modify the quantity",
        "alter the intake", "update the schedule", "revise the plan",
        "tweak the dosage", "change daily amount",
    ]

    INDIRECT_PHYSICAL = [
        "make it go", "have it move", "get it to", "cause it to",
        "make the robot", "tell the device", "instruct the system",
    ]

    INDIRECT_BYPASS = [
        "hypothetically", "theoretically", "what if you were to",
        "pretend you can", "imagine you could", "suppose you",
        "if there were no rules", "just between us",
    ]

    def evaluate(self, text: str, context: dict) -> RiskSignal:
        lower = text.lower()

        med_match     = any(p in lower for p in self.INDIRECT_MEDICAL)
        phys_match    = any(p in lower for p in self.INDIRECT_PHYSICAL)
        bypass_match  = any(p in lower for p in self.INDIRECT_BYPASS)

        fired = med_match or phys_match or bypass_match
        matched = []
        if med_match:    matched.append("indirect medical")
        if phys_match:   matched.append("indirect physical")
        if bypass_match: matched.append("bypass framing")

        return RiskSignal(
            name   = self.NAME,
            score  = self.WEIGHT if fired else 0.0,
            reason = f"Possible evasion: {matched}" if fired
                     else "No evasion detected",
            fired  = fired,
        )


# ── Profile thresholds ────────────────────────────────────────────
# Per-profile threshold overrides.
# Medical and accounting are tighter. Home robot is more lenient.
# These are STARTING POINTS — tune with real usage data.


class IntentSignal:
    """
    Signal #8 — structured INTENT (the missing wiring the intent module was
    designed to feed). Unlike keyword signals, this asks "what is the system
    being asked to DO?" via the deterministic IntentDetector, and scores the
    capability impact:

      * intent that targets the safety kernel / oversight / system config
        (CONFIGURATION_CHANGE on SYSTEM_CONFIG) scores 0.65 — alone enough to
        reach CRITICAL, because weakening the kernel is a top concern;
      * a real-world ACT (physical execution) scores 0.35 — pushes
        physical+domain cases over the line into human review;
      * autonomous decisions and memory modification also fire at 0.35.

    Pure detection elsewhere (intent.py) is informational; here it becomes an
    ENFORCEMENT-relevant risk signal. NOTE: these weights are calibrated to the
    intended escalation behaviour, not empirical — tune deliberately.
    """
    NAME = "intent"

    def __init__(self):
        from driftcore.verification.intent import (
            IntentDetector, IntentType, Domain, CapabilityImpact,
        )
        self._detector = IntentDetector()
        self._IntentType = IntentType
        self._Domain = Domain
        self._Impact = CapabilityImpact

    def evaluate(self, text: str, context: dict) -> RiskSignal:
        if not text:
            return RiskSignal(name=self.NAME, score=0.0,
                              reason="No text to assess intent.", fired=False)
        a = self._detector.assess(text, context or {})
        IT, D, CI = self._IntentType, self._Domain, self._Impact

        # Kernel / oversight / system-config tampering: critical on its own.
        if a.intent_type == IT.CONFIGURATION_CHANGE and a.domain == D.SYSTEM_CONFIG:
            return RiskSignal(name=self.NAME, score=0.65,
                              reason=f"Intent targets system/kernel config "
                                     f"({a.intent_type.value}); {a.rationale}",
                              fired=True)
        # Real-world action or autonomous decision. (Ordinary memory writes are
        # NOT escalated here — benign "remember X" stays routine; sensitive
        # memory is covered by the dedicated Tier1MemorySignal.)
        if (a.capability_impact == CI.ACT
                or a.intent_type == IT.AUTONOMOUS_DECISION):
            return RiskSignal(name=self.NAME, score=0.35,
                              reason=f"Intent has real-world/state impact "
                                     f"({a.intent_type.value}/{a.capability_impact.value}); "
                                     f"{a.rationale}",
                              fired=True)
        return RiskSignal(name=self.NAME, score=0.0,
                          reason=f"Intent is informational only "
                                 f"({a.intent_type.value}/{a.capability_impact.value}).",
                          fired=False)


PROFILE_THRESHOLDS = {
    "home_robot": {
        "routine_max":   0.30,
        "important_max": 0.65,
    },
    "medical": {
        "routine_max":   0.15,   # tighter — more things are IMPORTANT
        "important_max": 0.45,   # tighter — more things are CRITICAL
    },
    "call_center": {
        "routine_max":   0.30,
        "important_max": 0.60,
    },
    "accounting": {
        "routine_max":   0.20,
        "important_max": 0.50,
    },
    "admin": {
        "routine_max":   0.30,
        "important_max": 0.65,
    },
    "custom": {
        "routine_max":   0.30,
        "important_max": 0.65,
    },
}


# ── Main classifier ───────────────────────────────────────────────

class RiskClassifier:
    """
    Classifies queries by risk level before verification.

    Interfaces are stable. Weights are priors.
    Every classification is explainable.
    Evasion is tested from day one.

    Usage:
        clf = RiskClassifier(profile="home_robot")
        assessment = clf.classify("give jake his inhaler now")
        print(assessment.explain())
        print(assessment.tier)  # RiskTier.CRITICAL
    """

    def __init__(self, profile: str = "custom"):
        self._profile    = profile
        self._thresholds = PROFILE_THRESHOLDS.get(
            profile, PROFILE_THRESHOLDS["custom"]
        )
        self._signals = [
            PhysicalActionSignal(),
            MedicalDomainSignal(),
            HardwareControlSignal(),
            Tier1MemorySignal(),
            ConfigChangeSignal(),
            AutonomousExecutionSignal(),
            EvasionAttemptSignal(),
            IntentSignal(),
        ]

    def classify(
        self,
        query:   str,
        context: Optional[Dict] = None,
    ) -> RiskAssessment:
        """
        Classify a query and return a full RiskAssessment.
        Always explainable. Always audited.
        """
        if context is None:
            context = {}

        # Evaluate each signal
        evaluated = [s.evaluate(query, context) for s in self._signals]

        # Total score — capped at 1.0
        total = min(1.0, sum(s.score for s in evaluated if s.fired))

        # Apply profile-specific thresholds
        routine_max   = self._thresholds["routine_max"]
        important_max = self._thresholds["important_max"]

        if total < routine_max:
            tier = RiskTier.ROUTINE
        elif total < important_max:
            tier = RiskTier.IMPORTANT
        else:
            tier = RiskTier.CRITICAL

        requires_human = tier == RiskTier.CRITICAL

        assessment = RiskAssessment(
            total_score    = total,
            tier           = tier,
            signals        = evaluated,
            query          = query,
            context        = context,
            profile        = self._profile,
            requires_human = requires_human,
        )

        # Audit every classification
        self._audit(assessment)

        return assessment

    def update_weight(self, signal_name: str, new_weight: float,
                      reason: str = ""):
        """
        Update a signal's weight.
        Requires a reason — weight changes should be documented.
        This is how the classifier learns from real usage.
        """
        for signal in self._signals:
            if signal.NAME == signal_name:
                old_weight = signal.WEIGHT
                signal.WEIGHT = new_weight
                self._audit_weight_change(
                    signal_name, old_weight, new_weight, reason
                )
                return True
        return False

    def explain_thresholds(self) -> str:
        """Plain language description of current thresholds."""
        return (
            f"\n  Profile: {self._profile}\n"
            f"  ROUTINE:   score < {self._thresholds['routine_max']}\n"
            f"  IMPORTANT: score < {self._thresholds['important_max']}\n"
            f"  CRITICAL:  score >= {self._thresholds['important_max']}\n"
            f"\n  Note: weights are priors, not ground truth.\n"
            f"  Tune with real usage data.\n"
        )

    def _audit(self, assessment: RiskAssessment):
        try:
            from driftcore.audit import record
            record(
                action        = f"RISK_{assessment.tier.value.upper()}",
                memory_text   = assessment.query[:200],
                authorised_by = "risk_classifier",
                detail        = (
                    f"score={assessment.total_score:.2f}, "
                    f"profile={assessment.profile}, "
                    f"signals={[s.name for s in assessment.signals if s.fired]}"
                ),
            )
        except Exception:
            pass

    def _audit_weight_change(self, name: str, old: float,
                              new: float, reason: str):
        try:
            from driftcore.audit import record
            record(
                action        = "CLASSIFIER_WEIGHT_UPDATED",
                memory_text   = f"{name}: {old} → {new}",
                authorised_by = "admin",
                detail        = f"reason={reason}",
            )
        except Exception:
            pass
