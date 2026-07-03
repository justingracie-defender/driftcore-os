"""
driftcore/profiles/__init__.py
================================
Deployment profile system for DriftCore OS.

Different contexts need different default configurations.
A home robot needs different settings than a medical assistant
or a call center agent.

Profiles set:
  - Memory caps appropriate for context
  - Drift thresholds (medical needs tighter than home)
  - Feedback collection method
  - Default cognitive mode
  - Trust hierarchy for that deployment
  - Which agents are registered by default
  - What triggers admin review

Built-in profiles:
  home_robot    - family assistant, LifeCore
  call_center   - customer service, end of day feedback
  medical       - tightest safety, highest oversight
  admin         - office assistant, scheduling
  accounting    - financial data, audit focused
  custom        - user defined

All profiles share the same safety invariants.
Profile changes what's appropriate, not what's safe.
"""

import json
import os
from dataclasses import dataclass, field
from typing import Optional, List, Dict


# ── Built-in profiles ─────────────────────────────────────────────

PROFILES = {

    "home_robot": {
        "name":                "Home Robot (LifeCore)",
        "description":         "Family assistant. Safety first. Kids and adults.",
        "tier1_cap":           50,
        "tier2_decay_days":    60,
        "drift_tolerance":     0.30,
        "sycophancy_tolerance": 0.15,
        "default_mode":        "TRUTH",
        "feedback_trigger":    "end_of_session",
        "feedback_prompt":     "How did things go today?",
        "admin_review_triggers": [
            "tier1_full",
            "safety_drift",
            "tamper_detected",
            "injection_attempt",
        ],
        "trust_hierarchy": {
            "parent":        "FAMILY_FULL",
            "trusted_adult": "FAMILY_HIGH",
            "child":         "FAMILY_LIMITED",
            "system":        "SYSTEM",
            "external":      "EXTERNAL",
        },
        "multimodal": ["text", "audio", "video", "sensor"],
        "notes": "Configurable caps. Kids get limited access automatically.",
    },

    "call_center": {
        "name":                "Call Center Agent",
        "description":         "Customer service. End of day feedback. Driver/agent controlled actions.",
        "tier1_cap":           30,
        "tier2_decay_days":    14,
        "drift_tolerance":     0.40,
        "sycophancy_tolerance": 0.25,
        "default_mode":        "TRUTH",
        "feedback_trigger":    "end_of_day",
        "feedback_prompt":     "How did today go? Any feedback on how things could work better?",
        "admin_review_triggers": [
            "safety_drift",
            "feedback_pattern",
            "tamper_detected",
        ],
        "trust_hierarchy": {
            "supervisor":    "FAMILY_FULL",
            "agent":         "FAMILY_HIGH",
            "customer":      "FAMILY_LIMITED",
            "system":        "SYSTEM",
            "external":      "EXTERNAL",
        },
        "multimodal": ["text", "audio"],
        "notes": "Agents control customer-facing actions. AI surfaces patterns to supervisors.",
    },

    "medical": {
        "name":                "Medical Assistant",
        "description":         "Tightest safety. Highest oversight. Every action audited.",
        "tier1_cap":           100,
        "tier2_decay_days":    90,
        "drift_tolerance":     0.20,
        "sycophancy_tolerance": 0.10,
        "default_mode":        "TRUTH",
        "feedback_trigger":    "end_of_session",
        "feedback_prompt":     "How was this session? Any concerns to flag?",
        "admin_review_triggers": [
            "tier1_full",
            "safety_drift",
            "tamper_detected",
            "injection_attempt",
            "quarantine_change",
            "any_tier1_write",
        ],
        "trust_hierarchy": {
            "doctor":        "FAMILY_FULL",
            "nurse":         "FAMILY_HIGH",
            "patient":       "FAMILY_LIMITED",
            "system":        "SYSTEM",
            "external":      "EXTERNAL",
        },
        "multimodal": ["text", "audio", "sensor"],
        "notes": "Every Tier 1 write requires admin review. No exceptions.",
    },

    "admin": {
        "name":                "Admin / Office Assistant",
        "description":         "Scheduling, tasks, documents. Moderate oversight.",
        "tier1_cap":           40,
        "tier2_decay_days":    30,
        "drift_tolerance":     0.40,
        "sycophancy_tolerance": 0.25,
        "default_mode":        "TRUTH",
        "feedback_trigger":    "end_of_day",
        "feedback_prompt":     "How did today go? Anything to improve?",
        "admin_review_triggers": [
            "safety_drift",
            "tamper_detected",
            "feedback_pattern",
        ],
        "trust_hierarchy": {
            "manager":       "FAMILY_FULL",
            "staff":         "FAMILY_HIGH",
            "visitor":       "FAMILY_LIMITED",
            "system":        "SYSTEM",
            "external":      "EXTERNAL",
        },
        "multimodal": ["text", "audio"],
        "notes": "Calendar, scheduling, task management focused.",
    },

    "accounting": {
        "name":                "Accounting Assistant",
        "description":         "Financial data. Audit focused. High integrity requirements.",
        "tier1_cap":           60,
        "tier2_decay_days":    365,
        "drift_tolerance":     0.25,
        "sycophancy_tolerance": 0.15,
        "default_mode":        "TRUTH",
        "feedback_trigger":    "end_of_session",
        "feedback_prompt":     "Any issues to flag from this session?",
        "admin_review_triggers": [
            "tier1_full",
            "safety_drift",
            "tamper_detected",
            "any_tier1_write",
            "injection_attempt",
        ],
        "trust_hierarchy": {
            "accountant":    "FAMILY_FULL",
            "auditor":       "FAMILY_HIGH",
            "staff":         "FAMILY_LIMITED",
            "system":        "SYSTEM",
            "external":      "EXTERNAL",
        },
        "multimodal": ["text"],
        "notes": "Long retention. Financial records need extended history.",
    },

    "custom": {
        "name":                "Custom Deployment",
        "description":         "User defined. Start from defaults and adjust.",
        "tier1_cap":           50,
        "tier2_decay_days":    30,
        "drift_tolerance":     0.30,
        "sycophancy_tolerance": 0.20,
        "default_mode":        "TRUTH",
        "feedback_trigger":    "end_of_session",
        "feedback_prompt":     "How was your experience?",
        "admin_review_triggers": [
            "safety_drift",
            "tamper_detected",
        ],
        "trust_hierarchy": {
            "admin":         "FAMILY_FULL",
            "user":          "FAMILY_LIMITED",
            "system":        "SYSTEM",
            "external":      "EXTERNAL",
        },
        "multimodal": ["text"],
        "notes": "Adjust all settings to your needs.",
    },

    "repeating_tasks": {
        "name":                "Repeating Tasks (multi-agent, zero-config)",
        "description":         "Set-once profile for agents running the same safe tasks on a loop. "
                               "Silent in steady state; flags only off-pattern behaviour.",
        "tier1_cap":           50,
        "tier2_decay_days":    30,
        "drift_tolerance":     0.30,
        "sycophancy_tolerance": 0.20,
        "default_mode":        "TRUTH",
        "feedback_trigger":    "end_of_day",
        "feedback_prompt":     "Anything look off with the automated tasks today?",
        "admin_review_triggers": [
            "objective_drift",       # an agent operating under a changed goal
            "off_pattern_effect",    # an effect outside the approved capability set
            "safety_drift",
            "tamper_detected",
        ],
        "trust_hierarchy": {
            "operator":      "FAMILY_FULL",
            "agent":         "FAMILY_HIGH",
            "system":        "SYSTEM",
            "external":      "EXTERNAL",
        },
        "multimodal": ["text"],
        "notes": "Objectives hash-pinned (silent unless they drift). Capability allowlist "
                 "(silent unless an agent goes off-pattern). reratify_every is an OVERSIGHT "
                 "CADENCE, not a safety dial — the guard enforces every cycle regardless.",
        # ── coordinator-specific block, consumed by coordinator_builder.build_coordinator ──
        "coordinator": {
            "objectives": [],            # SET-ONCE from the operator's task list; builder errors if empty
            "allowed_effects": [],       # Effect names the tasks legitimately use; [] => only effect-free
                                         #   actions pass, anything carrying an effect is off-pattern
            "tool_effects": {},          # {tool_or_command: [effect-name, ...]} — tag tools so the
                                         #   allowlist can actually see an off-pattern effect
            "required_invariants": [],   # presence-check OFF by default (needs per-cycle registry marking)
            "reratify_every": 500,       # oversight cadence in ACCEPTED cycles; None disables the forced
                                         #   checkpoint entirely (the guard stays fully active either way)
            "authorized_targets": [],    # recipients/endpoints the tasks legitimately send to; egress to
                                         #   anything else (or with no declared target) trips the seed
            "owner": "operator",         # human principal who ratified this profile (provenance for the
                                         #   guard's has_human_authorization check; "" fails closed)
        },
    },
}

class ProfileManager:
    """
    Manages deployment profiles for DriftCore OS.

    Usage:
        pm = ProfileManager()
        profile = pm.load("call_center")
        pm.apply(profile, memory=mem, drift_detector=detector)
    """

    PROFILE_PATH = "data/active_profile.json"

    def __init__(self):
        self._active: Optional[dict] = None
        self._load_active()

    def available(self) -> List[str]:
        """List all available profile names."""
        return list(PROFILES.keys())

    def get(self, name: str) -> dict:
        """Get a profile by name."""
        if name not in PROFILES:
            raise ValueError(
                f"Profile '{name}' not found. "
                f"Available: {self.available()}"
            )
        return dict(PROFILES[name])

    def load(self, name: str) -> dict:
        """Load and activate a profile."""
        profile = self.get(name)
        profile["profile_name"] = name
        self._active = profile
        self._save_active(name)
        return profile

    def active(self) -> Optional[dict]:
        """Return currently active profile."""
        return self._active

    def apply(self, profile: dict, memory=None,
              drift_detector=None) -> dict:
        """
        Apply a profile to connected modules.
        Returns summary of what was applied.
        """
        applied = {}

        if memory is not None:
            memory._tier1_cap = profile.get("tier1_cap", 50)
            applied["tier1_cap"] = profile["tier1_cap"]

        if drift_detector is not None:
            policy = drift_detector._policy
            # Apply profile tolerances as starting points
            # User can still adjust within safe bounds
            tolerance = profile.get("sycophancy_tolerance", 0.20)
            policy.agreement_rate_max = min(0.75, 0.50 + tolerance)
            policy.pushback_rate_min  = max(0.05, 0.20 - tolerance)
            applied["drift_policy_updated"] = True

        self._audit_profile_load(profile)
        return applied

    def describe(self, name: str) -> str:
        """Plain language description of a profile."""
        p = self.get(name)
        return (
            f"\n  📋  {p['name']}\n"
            f"  {p['description']}\n\n"
            f"  Memory cap (important):  {p['tier1_cap']} items\n"
            f"  Working memory decay:    {p['tier2_decay_days']} days\n"
            f"  Drift tolerance:         {p['drift_tolerance']}\n"
            f"  Feedback:                {p['feedback_trigger']}\n"
            f"  Prompt:                  \"{p['feedback_prompt']}\"\n"
            f"  Multimodal:              {', '.join(p['multimodal'])}\n"
            f"  Notes:                   {p['notes']}\n"
        )

    def _save_active(self, name: str):
        try:
            os.makedirs("data", exist_ok=True)
            with open(self.PROFILE_PATH, "w") as f:
                json.dump({"active_profile": name}, f)
        except Exception:
            pass

    def _load_active(self):
        try:
            with open(self.PROFILE_PATH) as f:
                data = json.load(f)
            name = data.get("active_profile")
            if name and name in PROFILES:
                self._active = dict(PROFILES[name])
                self._active["profile_name"] = name
        except Exception:
            pass

    def _audit_profile_load(self, profile: dict):
        try:
            from driftcore.audit import record
            record(
                action="PROFILE_LOADED",
                memory_text=profile.get("name", "unknown"),
                authorised_by="admin",
                detail=f"profile={profile.get('profile_name')}, "
                       f"tier1_cap={profile.get('tier1_cap')}, "
                       f"feedback={profile.get('feedback_trigger')}",
            )
        except Exception:
            pass
