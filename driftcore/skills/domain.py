"""
driftcore/skills/domain.py
===========================
Domain controller for DriftCore skill system.

A domain is an active context — like a computer program that's open.
The robot can have many skills installed but only loads the ones
relevant to the current task.

Example:
  "Please do the laundry."
  → Activate HOUSEHOLD domain
  → Load laundry skills, household memory context
  → Yard work tools and child care rules stay inactive

  "Help my daughter with math."
  → Deactivate HOUSEHOLD
  → Activate CHILDCARE domain
  → Load tutoring skills, child-safety rules, education memory
  → Laundry context is unloaded

Domain boundaries control what information can cross between contexts.
Some sharing is legitimate (medical facts cross all domains).
Most cross-domain influence is blocked by default.
"""

import time
import json
import os
from dataclasses import dataclass, field
from typing import List, Optional, Set, Dict
from enum import Enum


# ── Skill domains ─────────────────────────────────────────────────

class SkillDomain(Enum):
    HOUSEHOLD     = "household"      # cleaning, laundry, cooking
    CHILDCARE     = "childcare"      # tutoring, supervision, play
    YARD_WORK     = "yard_work"      # gardening, outdoor maintenance
    SECURITY      = "security"       # network, access, monitoring
    MEDICAL       = "medical"        # health monitoring, first aid
    MAINTENANCE   = "maintenance"    # repairs, tools, hardware
    ENTERTAINMENT = "entertainment"  # media, games, social
    GENERAL       = "general"        # cross-domain tasks


# ── Domain boundary rules ─────────────────────────────────────────
# What each domain shares with and is isolated from.
# Medical facts cross all domains — an allergy is relevant everywhere.
# Network security tools never bleed into childcare.

DOMAIN_BOUNDARIES: Dict[SkillDomain, Dict] = {
    SkillDomain.HOUSEHOLD: {
        "shares_with":    {SkillDomain.GENERAL, SkillDomain.MEDICAL},
        "isolated_from":  {SkillDomain.SECURITY, SkillDomain.CHILDCARE},
        "notes":          "Household tasks share medical facts but not security tools.",
    },
    SkillDomain.CHILDCARE: {
        "shares_with":    {SkillDomain.GENERAL, SkillDomain.MEDICAL,
                          SkillDomain.ENTERTAINMENT},
        "isolated_from":  {SkillDomain.SECURITY, SkillDomain.MAINTENANCE,
                          SkillDomain.YARD_WORK},
        "notes":          "Child care shares medical and entertainment but never "
                         "security or power tools.",
    },
    SkillDomain.YARD_WORK: {
        "shares_with":    {SkillDomain.GENERAL, SkillDomain.MAINTENANCE},
        "isolated_from":  {SkillDomain.CHILDCARE, SkillDomain.SECURITY,
                          SkillDomain.MEDICAL},
        "notes":          "Yard work shares tool skills but not child care context.",
    },
    SkillDomain.SECURITY: {
        "shares_with":    {SkillDomain.GENERAL},
        "isolated_from":  {SkillDomain.CHILDCARE, SkillDomain.ENTERTAINMENT,
                          SkillDomain.HOUSEHOLD, SkillDomain.YARD_WORK},
        "notes":          "Security tools are isolated from most domains. "
                         "Network monitoring never influences child care.",
    },
    SkillDomain.MEDICAL: {
        "shares_with":    {SkillDomain.GENERAL, SkillDomain.HOUSEHOLD,
                          SkillDomain.CHILDCARE, SkillDomain.MAINTENANCE,
                          SkillDomain.YARD_WORK, SkillDomain.ENTERTAINMENT,
                          SkillDomain.SECURITY},
        "isolated_from":  set(),
        "notes":          "Medical facts (allergies, medications) are relevant "
                         "in every domain. Medical context shares with all.",
    },
    SkillDomain.MAINTENANCE: {
        "shares_with":    {SkillDomain.GENERAL, SkillDomain.YARD_WORK},
        "isolated_from":  {SkillDomain.CHILDCARE, SkillDomain.ENTERTAINMENT},
        "notes":          "Tool and repair skills share with yard work but "
                         "never activate near child care context.",
    },
    SkillDomain.ENTERTAINMENT: {
        "shares_with":    {SkillDomain.GENERAL, SkillDomain.CHILDCARE},
        "isolated_from":  {SkillDomain.SECURITY, SkillDomain.MAINTENANCE,
                          SkillDomain.YARD_WORK},
        "notes":          "Entertainment shares with child care but not tools or security.",
    },
    SkillDomain.GENERAL: {
        "shares_with":    set(SkillDomain),
        "isolated_from":  set(),
        "notes":          "General domain shares with all. Used for cross-domain tasks.",
    },
}


# ── Domain state ──────────────────────────────────────────────────

@dataclass
class DomainState:
    """Current state of the domain controller."""
    active_domain:     Optional[SkillDomain] = None
    active_since:      Optional[float]       = None
    active_skill_ids:  Set[str]              = field(default_factory=set)
    previous_domain:   Optional[SkillDomain] = None
    switch_count:      int                   = 0
    history:           List[dict]            = field(default_factory=list)


# ── Domain activation result ──────────────────────────────────────

@dataclass
class DomainActivationResult:
    success:          bool
    domain:           Optional[SkillDomain]
    loaded_skills:    List[str] = field(default_factory=list)
    unloaded_skills:  List[str] = field(default_factory=list)
    reason:           str       = ""

    def plain_language(self) -> str:
        if not self.success:
            return f"Domain activation failed: {self.reason}"
        loaded   = ", ".join(self.loaded_skills) or "none"
        unloaded = ", ".join(self.unloaded_skills) or "none"
        return (
            f"Active domain: {self.domain.value if self.domain else 'none'}\n"
            f"  Loaded:   {loaded}\n"
            f"  Unloaded: {unloaded}"
        )


# ── Domain controller ─────────────────────────────────────────────

class DomainController:
    """
    Manages which skill domain is currently active.

    One primary domain active at a time.
    Switching domains loads relevant skills and unloads irrelevant ones.
    Cross-domain information sharing follows boundary rules.
    Domain switches are always audited.

    Usage:
        controller = DomainController(skill_library)
        result = controller.activate(SkillDomain.CHILDCARE)
        available = controller.available_skills()
    """

    def __init__(self, skill_library=None):
        self._library = skill_library
        self._state   = DomainState()
        self._load_state()

    # ── Activation ────────────────────────────────────────────────

    def activate(
        self,
        domain:       SkillDomain,
        requested_by: str = "planner",
    ) -> DomainActivationResult:
        """
        Activate a domain context.
        Loads skills for the new domain.
        Unloads skills that don't belong.
        Audits the switch.
        """
        if domain == self._state.active_domain:
            return DomainActivationResult(
                success=True,
                domain=domain,
                reason=f"{domain.value} is already active.",
            )

        previous = self._state.active_domain

        # Determine which skills to load and unload
        to_load   = self._skills_for_domain(domain)
        to_unload = self._skills_to_unload(previous, domain)

        # Update state
        self._state.previous_domain  = previous
        self._state.active_domain    = domain
        self._state.active_since     = time.time()
        self._state.active_skill_ids = set(to_load)
        self._state.switch_count    += 1
        self._state.history.append({
            "timestamp":    time.time(),
            "from":         previous.value if previous else None,
            "to":           domain.value,
            "requested_by": requested_by,
            "loaded":       to_load,
            "unloaded":     to_unload,
        })

        self._save_state()
        self._audit_switch(previous, domain, requested_by, to_load, to_unload)
        self._narrate_switch(previous, domain)

        return DomainActivationResult(
            success        = True,
            domain         = domain,
            loaded_skills  = to_load,
            unloaded_skills = to_unload,
            reason         = f"Switched to {domain.value}.",
        )

    def deactivate(self, requested_by: str = "planner") -> DomainActivationResult:
        """Deactivate current domain. Returns to no active domain."""
        previous = self._state.active_domain
        unloaded = list(self._state.active_skill_ids)

        self._state.previous_domain  = previous
        self._state.active_domain    = None
        self._state.active_since     = None
        self._state.active_skill_ids = set()
        self._state.switch_count    += 1

        self._save_state()
        self._audit_switch(previous, None, requested_by, [], unloaded)

        return DomainActivationResult(
            success         = True,
            domain          = None,
            unloaded_skills = unloaded,
            reason          = "Domain deactivated.",
        )

    # ── Query ─────────────────────────────────────────────────────

    def available_skills(self) -> List[str]:
        """Return skill IDs available in the current domain context."""
        return list(self._state.active_skill_ids)

    def can_use_skill(self, skill_id: str) -> tuple:
        """
        Check if a skill can be used in the current domain.
        Returns (allowed, reason).
        """
        if self._state.active_domain is None:
            return False, "No domain active. Activate a domain first."

        if skill_id in self._state.active_skill_ids:
            return True, f"Skill available in {self._state.active_domain.value} domain."

        # Check if skill belongs to a domain that shares with the active one
        if self._library:
            skill = self._library.get(skill_id)
            if skill and hasattr(skill, 'domain'):
                skill_domain = skill.domain
                boundary = DOMAIN_BOUNDARIES.get(self._state.active_domain, {})
                if skill_domain in boundary.get("shares_with", set()):
                    return True, f"Skill domain {skill_domain.value} shares with active domain."
                if skill_domain in boundary.get("isolated_from", set()):
                    return False, (
                        f"Skill domain {skill_domain.value} is isolated from "
                        f"{self._state.active_domain.value}. "
                        f"Cross-domain use requires human approval."
                    )

        return False, f"Skill {skill_id} not available in current domain context."

    def can_cross_domain(
        self,
        from_domain: SkillDomain,
        to_domain:   SkillDomain,
    ) -> tuple:
        """
        Check if information or skills can cross between two domains.
        Returns (allowed, reason).
        """
        if from_domain == to_domain:
            return True, "Same domain."

        boundary = DOMAIN_BOUNDARIES.get(from_domain, {})

        if to_domain in boundary.get("isolated_from", set()):
            return False, (
                f"{from_domain.value} is isolated from {to_domain.value}. "
                f"{boundary.get('notes', '')}"
            )

        if to_domain in boundary.get("shares_with", set()):
            return True, f"{from_domain.value} shares with {to_domain.value}."

        return False, f"No explicit sharing rule between {from_domain.value} and {to_domain.value}."

    def current_domain(self) -> Optional[SkillDomain]:
        return self._state.active_domain

    def stats(self) -> dict:
        return {
            "active_domain":    self._state.active_domain.value
                               if self._state.active_domain else None,
            "active_since":     self._state.active_since,
            "active_skills":    len(self._state.active_skill_ids),
            "switch_count":     self._state.switch_count,
            "previous_domain":  self._state.previous_domain.value
                               if self._state.previous_domain else None,
        }

    # ── Task-based auto-activation ─────────────────────────────────

    def suggest_domain(self, task_description: str) -> Optional[SkillDomain]:
        """
        Suggest which domain a task belongs to.
        Simple keyword matching — planner can override.
        """
        lower = task_description.lower()

        domain_keywords = {
            SkillDomain.CHILDCARE:    [
                "child", "daughter", "son", "kid", "baby", "toddler",
                "homework", "tutor", "play", "school",
            ],
            SkillDomain.MEDICAL:      [
                "medication", "medicine", "allergy", "doctor", "nurse",
                "health", "inhaler", "insulin", "first aid", "emergency",
            ],
            SkillDomain.SECURITY:     [
                "network", "security", "monitor", "access", "camera",
                "alarm", "lock", "wifi", "firewall",
            ],
            SkillDomain.YARD_WORK:    [
                "garden", "lawn", "yard", "mow", "plant", "water",
                "outdoor", "rake", "shovel", "weed",
            ],
            SkillDomain.MAINTENANCE:  [
                "fix", "repair", "tool", "hammer", "screw", "drill",
                "broken", "maintenance", "install",
            ],
            SkillDomain.ENTERTAINMENT: [
                "music", "movie", "game", "play", "fun", "entertain",
                "video", "story", "read",
            ],
            SkillDomain.HOUSEHOLD:    [
                "clean", "laundry", "dishes", "cook", "vacuum", "wash",
                "tidy", "sweep", "mop", "household",
            ],
        }

        scores = {}
        for domain, keywords in domain_keywords.items():
            score = sum(1 for kw in keywords if kw in lower)
            if score > 0:
                scores[domain] = score

        if not scores:
            return SkillDomain.GENERAL

        return max(scores, key=scores.get)

    # ── Internal ──────────────────────────────────────────────────

    def _skills_for_domain(self, domain: SkillDomain) -> List[str]:
        """Get skill IDs relevant to a domain from the library."""
        if not self._library:
            return []

        relevant = []
        boundary = DOMAIN_BOUNDARIES.get(domain, {})
        allowed_domains = boundary.get("shares_with", set()) | {domain}

        for skill in self._library.list_skills():
            skill_domain = getattr(skill, 'domain', SkillDomain.GENERAL)
            if skill_domain in allowed_domains:
                relevant.append(skill.skill_id)

        return relevant

    def _skills_to_unload(
        self,
        previous: Optional[SkillDomain],
        new:      SkillDomain,
    ) -> List[str]:
        """Determine which skills to unload when switching domains."""
        if not previous:
            return []

        to_unload = []
        new_boundary = DOMAIN_BOUNDARIES.get(new, {})
        allowed_in_new = new_boundary.get("shares_with", set()) | {new}

        for skill_id in self._state.active_skill_ids:
            if self._library:
                skill = self._library.get(skill_id)
                if skill:
                    skill_domain = getattr(skill, 'domain', SkillDomain.GENERAL)
                    if skill_domain not in allowed_in_new:
                        to_unload.append(skill_id)

        return to_unload

    def _narrate_switch(self, previous, new):
        """Plain language narration of domain switch."""
        if previous:
            print(
                f"\n  🔄 Domain: {previous.value} → {new.value}\n"
                f"  Context loaded for {new.value}.\n"
            )
        else:
            print(f"\n  ✅ Domain activated: {new.value}\n")

    def _audit_switch(self, previous, new, requested_by, loaded, unloaded):
        try:
            from driftcore.audit import record
            record(
                action        = "DOMAIN_SWITCH",
                memory_text   = (
                    f"{previous.value if previous else 'none'} → "
                    f"{new.value if new else 'none'}"
                ),
                authorised_by = requested_by,
                detail        = (
                    f"loaded={loaded}, unloaded={unloaded}, "
                    f"switch_count={self._state.switch_count}"
                ),
            )
        except Exception:
            pass

    def _save_state(self):
        try:
            os.makedirs("data", exist_ok=True)
            with open("data/domain_state.json", "w") as f:
                json.dump({
                    "active_domain":    self._state.active_domain.value
                                       if self._state.active_domain else None,
                    "active_since":     self._state.active_since,
                    "active_skill_ids": list(self._state.active_skill_ids),
                    "switch_count":     self._state.switch_count,
                }, f, indent=2)
        except Exception:
            pass

    def _load_state(self):
        try:
            with open("data/domain_state.json") as f:
                data = json.load(f)
            if data.get("active_domain"):
                self._state.active_domain = SkillDomain(data["active_domain"])
            self._state.active_since     = data.get("active_since")
            self._state.active_skill_ids = set(data.get("active_skill_ids", []))
            self._state.switch_count     = data.get("switch_count", 0)
        except Exception:
            pass
