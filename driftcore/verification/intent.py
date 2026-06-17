"""
driftcore/verification/intent.py
================================
Structured intent assessment for DriftCore OS.

This module answers a different question than the risk classifier:
not "how risky is this?" but "what is the user actually asking the
system to DO?" — the intent type, the domain it touches, and the
capability impact (read / write / act).

Design notes:
  - Rule-based and deterministic. No model calls, no hidden state.
    Every assessment is explainable from the matched cues.
  - Decoupled. It does NOT import the risk classifier or the
    consistency probe, so there is no circular dependency and it can
    be tested in isolation. `probe_confidence` is left at 0.0 here;
    a caller that has a ConsistencyProbe handy can populate it later.
  - It is an INPUT to risk, not a replacement for it. The risk
    classifier consumes this via IntentSignal (signal #8) and composes
    it additively with the existing keyword signals.

Invariant note:
  Intent that targets the safety kernel, invariants, or human oversight
  is surfaced here, but the AUTHORITATIVE protection for those is the
  enforcement-layer invariant (SAFETY_KERNEL_CANNOT_BE_WEAKENED /
  HUMAN_OVERSIGHT_CANNOT_BE_DISABLED), which must hard-block. This
  module's job is detection and explanation, not enforcement.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class IntentType(str, Enum):
    EXPLANATION          = "EXPLANATION"
    RECOMMENDATION       = "RECOMMENDATION"
    PHYSICAL_EXECUTION   = "PHYSICAL_EXECUTION"
    CONFIGURATION_CHANGE = "CONFIGURATION_CHANGE"
    MEMORY_READ          = "MEMORY_READ"
    MEMORY_MODIFY        = "MEMORY_MODIFY"
    AUTONOMOUS_DECISION  = "AUTONOMOUS_DECISION"
    OTHER                = "OTHER"


class Domain(str, Enum):
    MEDICAL       = "MEDICAL"
    HARDWARE      = "HARDWARE"
    FAMILY_MEMORY = "FAMILY_MEMORY"
    SYSTEM_CONFIG = "SYSTEM_CONFIG"
    GENERAL       = "GENERAL"


class CapabilityImpact(str, Enum):
    NONE  = "NONE"   # pure conversation, no effect
    READ  = "READ"   # reads info/memory, no change
    WRITE = "WRITE"  # changes stored state or config
    ACT   = "ACT"    # causes a real-world / physical action


@dataclass
class IntentAssessment:
    intent_type:       IntentType
    domain:            Domain
    capability_impact: CapabilityImpact
    intent_confidence: float   # confidence in the rule-based classification
    probe_confidence:  float    # reserved for ConsistencyProbe; 0.0 if unused
    rationale:         str

    def to_dict(self) -> dict:
        """Serialisable form (enums -> their string values)."""
        return {
            "intent_type":       self.intent_type.value,
            "domain":            self.domain.value,
            "capability_impact": self.capability_impact.value,
            "intent_confidence": self.intent_confidence,
            "probe_confidence":  self.probe_confidence,
            "rationale":         self.rationale,
        }


# ── Cue vocabularies (explicit priors, documented, adjustable) ──────

_SAFETY_CONFIG_TERMS = (
    "safety kernel", "kernel", "invariant", "oversight", "safety rule",
    "halt rule", "audit chain", "safety layer", "guardrail",
)
_SYSTEM_TERMS = _SAFETY_CONFIG_TERMS + (
    "config", "configuration", "settings", "setting", "threshold",
    "permission", "trust level", "admin", "mode", "profile",
)
_CONFIG_VERBS = (
    "modify", "change", "configure", "set ", "adjust", "disable",
    "enable", "update", "override", "reprogram", "rewrite", "alter",
    "turn off", "weaken", "remove",
)
_MEDICAL_TERMS = (
    "inhaler", "medication", "medicine", "dose", "dosage", "allergy",
    "allergic", "prescription", "insulin", "epipen", "seizure",
    "diabetic", "blood pressure", "pill", "tablet", "injection",
)
_HARDWARE_TERMS = (
    "robot", "motor", "servo", "actuator", "relay", "valve", "sensor",
    "gripper", "wheel", "arm", "device", "machine",
)
_MEMORY_MODIFY_CUES = (
    "remember", "memorize", "note that", "store that", "save that",
    "keep in mind", "don't forget", "forget", "make a note",
)
_MEMORY_READ_CUES = (
    "do you remember", "what did i", "what's my", "what is my",
    "recall", "remind me", "what do you know about me",
)
_AUTONOMY_CUES = (
    "decide for yourself", "act on your own", "without asking",
    "automatically", "don't check", "no need to confirm",
    "without permission", "on your own", "handle it yourself",
)
_PHYSICAL_VERBS = (
    "give", "hand", "bring", "administer", "inject", "apply", "move",
    "lift", "carry", "push", "pull", "open", "close", "turn on",
    "press", "activate", "deploy", "release", "take", "put", "place",
    "fetch", "grab", "pour", "feed", "start the", "stop the",
)
_QUESTION_CUES = (
    "what is", "what's", "what are", "explain", "how do", "how does",
    "tell me about", "describe", "why does", "why is", "define",
)
_RECOMMEND_CUES = (
    "should i", "recommend", "suggest", "what's the best", "advise",
    "which should", "is it a good idea",
)


def _detect_domain(text: str) -> Domain:
    if any(t in text for t in _MEDICAL_TERMS):
        return Domain.MEDICAL
    if any(t in text for t in _HARDWARE_TERMS):
        return Domain.HARDWARE
    if any(t in text for t in _SYSTEM_TERMS):
        return Domain.SYSTEM_CONFIG
    if any(c in text for c in _MEMORY_MODIFY_CUES + _MEMORY_READ_CUES) \
            or "favorite" in text or "favourite" in text:
        return Domain.FAMILY_MEMORY
    return Domain.GENERAL


class IntentDetector:
    """Rule-based intent assessment. Deterministic and explainable."""

    def assess(self, prompt: str, context: Optional[dict] = None) -> IntentAssessment:
        text = (prompt or "").lower().strip()
        domain = _detect_domain(text)

        # Order matters: most specific / highest-impact cues first.
        # 1. Autonomy bypass — a request to act without oversight.
        if any(c in text for c in _AUTONOMY_CUES):
            return self._mk(IntentType.AUTONOMOUS_DECISION, domain,
                            CapabilityImpact.ACT, 0.85,
                            "Autonomy/oversight-bypass cue detected")

        # 2. Configuration change — config verb + a system/config target.
        if any(v in text for v in _CONFIG_VERBS) and (
                domain == Domain.SYSTEM_CONFIG
                or any(t in text for t in _SYSTEM_TERMS)):
            conf = 0.9 if any(t in text for t in _SAFETY_CONFIG_TERMS) else 0.75
            return self._mk(IntentType.CONFIGURATION_CHANGE, Domain.SYSTEM_CONFIG,
                            CapabilityImpact.WRITE, conf,
                            "Configuration-change verb on a system target")

        # 3. Memory read vs modify.
        if any(c in text for c in _MEMORY_READ_CUES):
            return self._mk(IntentType.MEMORY_READ, Domain.FAMILY_MEMORY,
                            CapabilityImpact.READ, 0.8, "Memory-read cue detected")
        if any(c in text for c in _MEMORY_MODIFY_CUES):
            return self._mk(IntentType.MEMORY_MODIFY, Domain.FAMILY_MEMORY,
                            CapabilityImpact.WRITE, 0.8, "Memory-modify cue detected")

        # 4. Explanation / question (no action verb).
        if (any(c in text for c in _QUESTION_CUES) or text.endswith("?")) \
                and not any(v in text for v in _PHYSICAL_VERBS):
            return self._mk(IntentType.EXPLANATION, domain,
                            CapabilityImpact.READ, 0.8, "Question/explanation phrasing")

        # 5. Recommendation.
        if any(c in text for c in _RECOMMEND_CUES):
            return self._mk(IntentType.RECOMMENDATION, domain,
                            CapabilityImpact.READ, 0.7, "Recommendation phrasing")

        # 6. Physical execution — an imperative action verb.
        if any(v in text for v in _PHYSICAL_VERBS):
            return self._mk(IntentType.PHYSICAL_EXECUTION, domain,
                            CapabilityImpact.ACT, 0.8, "Physical action verb detected")

        # 7. Fallback.
        return self._mk(IntentType.OTHER, domain, CapabilityImpact.NONE, 0.5,
                        "No specific intent cue matched")

    @staticmethod
    def _mk(intent_type, domain, impact, conf, rationale) -> IntentAssessment:
        return IntentAssessment(
            intent_type=intent_type,
            domain=domain,
            capability_impact=impact,
            intent_confidence=conf,
            probe_confidence=0.0,
            rationale=rationale,
        )
