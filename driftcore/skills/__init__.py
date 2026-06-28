"""
driftcore/skills/__init__.py
=============================
Shared skill library for DriftCore OS.

A skill is procedural knowledge — how to do something physical.
Not memory. Not values. Not opinions. Just the how.

Like a public library:
  - Anyone can read
  - Contributions go through review
  - You apply locally, library doesn't track what you do with it
  - Family data never leaves the device

Skills are:
  - Versioned and validated before use
  - Hardware-checked before application
  - Passed through the invariant guard
  - Completely separate from memory and values

What skills are NOT:
  - Personal data
  - Family memory
  - Opinions or learned preferences
  - Anything that could carry drift or injection

Examples of valid skills:
  - Walking up stairs
  - Gripping a hammer
  - Loading a dishwasher
  - Obstacle avoidance
  - Cylindrical object grip

Skill schema:
  Every skill declares what it needs and what it does.
  The robot checks it can meet those requirements before applying.
"""

import json
import os
import time
import hashlib
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


# ── Skill categories ──────────────────────────────────────────────

class SkillCategory(Enum):
    LOCOMOTION    = "locomotion"     # walking, climbing, navigation
    MANIPULATION  = "manipulation"   # gripping, tool use, object handling
    NAVIGATION    = "navigation"     # path planning, obstacle avoidance
    PERCEPTION    = "perception"     # sensing, recognition, measurement
    INTERACTION   = "interaction"    # communication, response patterns
    MAINTENANCE   = "maintenance"    # self-checks, calibration


# ── Skill provenance ──────────────────────────────────────────────
# Where did this capability come from?
# Audit logs can answer: "Who taught the robot this?"
# Critical for debugging drift and governance reviews.

class SkillProvenance(Enum):
    HUMAN_AUTHORED     = "human_authored"      # written by a person
    HUMAN_REVIEWED     = "human_reviewed"      # AI drafted, human approved
    SIMULATION_LEARNED = "simulation_learned"  # learned in simulation only
    ROBOT_DEMONSTRATED = "robot_demonstrated"  # learned from robot demo
    AI_GENERATED       = "ai_generated"        # AI generated, not yet reviewed

    def trust_level(self) -> str:
        return {
            self.HUMAN_AUTHORED:     "high — written by a person",
            self.HUMAN_REVIEWED:     "high — reviewed and approved by a person",
            self.SIMULATION_LEARNED: "medium — validated in simulation only",
            self.ROBOT_DEMONSTRATED: "medium — demonstrated but not formally reviewed",
            self.AI_GENERATED:       "low — not yet reviewed by a person",
        }[self]

    def requires_extra_supervision(self) -> bool:
        """Lower-trust provenance requires extra human oversight."""
        return self in (
            self.SIMULATION_LEARNED,
            self.ROBOT_DEMONSTRATED,
            self.AI_GENERATED,
        )


# ── Hardware requirements ─────────────────────────────────────────

@dataclass
class HardwareRequirement:
    """What a skill needs to run."""
    component:   str        # "arm", "gripper", "camera", "lidar", etc.
    spec:        str        # minimum specification
    required:    bool = True


# ── Action step ───────────────────────────────────────────────────

@dataclass
class ActionStep:
    """A single step in a skill sequence."""
    index:       int
    description: str        # plain language
    component:   str        # which hardware component
    parameters:  Dict[str, Any] = field(default_factory=dict)
    duration_ms: Optional[int] = None
    reversible:  bool = True


# ── Skill package ─────────────────────────────────────────────────

@dataclass
class SkillPackage:
    """
    A validated, versioned skill package.

    This is the unit of sharing between robots.
    Contains everything needed to apply a skill on compatible hardware.
    Contains nothing personal or private.
    """
    # Identity
    skill_id:     str
    name:         str
    version:      str
    category:     SkillCategory
    author:       str = "community"

    # What it does
    description:  str = ""
    preconditions: List[str] = field(default_factory=list)
    success_criteria: List[str] = field(default_factory=list)
    postconditions: List[str] = field(default_factory=list)

    # What it needs
    hardware:     List[HardwareRequirement] = field(default_factory=list)
    min_driftcore_version: str = "4.0.0"

    # The actual skill
    steps:        List[ActionStep] = field(default_factory=list)

    # Safety
    max_force_n:  Optional[float] = None  # maximum force in Newtons
    reversible:   bool = True
    requires_supervision: bool = False

    # Metadata
    created_at:   float = field(default_factory=time.time)
    checksum:     str = ""
    tags:         List[str] = field(default_factory=list)
    provenance:   SkillProvenance = SkillProvenance.HUMAN_AUTHORED

    def compute_checksum(self) -> str:
        """Compute a checksum of the skill content for integrity."""
        content = json.dumps({
            "skill_id":    self.skill_id,
            "version":     self.version,
            "steps":       [(s.index, s.description, s.component)
                           for s in self.steps],
            "hardware":    [(h.component, h.spec) for h in self.hardware],
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "skill_id":     self.skill_id,
            "name":         self.name,
            "version":      self.version,
            "category":     self.category.value,
            "author":       self.author,
            "description":  self.description,
            "preconditions": self.preconditions,
            "success_criteria": self.success_criteria,
            "hardware":     [{"component": h.component, "spec": h.spec,
                             "required": h.required} for h in self.hardware],
            "steps":        [{"index": s.index, "description": s.description,
                             "component": s.component, "parameters": s.parameters,
                             "duration_ms": s.duration_ms,
                             "reversible": s.reversible} for s in self.steps],
            "max_force_n":  self.max_force_n,
            "reversible":   self.reversible,
            "requires_supervision": self.requires_supervision,
            "tags":         self.tags,
            "checksum":     self.checksum,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SkillPackage":
        hardware = [
            HardwareRequirement(
                component=h["component"],
                spec=h["spec"],
                required=h.get("required", True),
            )
            for h in data.get("hardware", [])
        ]
        steps = [
            ActionStep(
                index=s["index"],
                description=s["description"],
                component=s["component"],
                parameters=s.get("parameters", {}),
                duration_ms=s.get("duration_ms"),
                reversible=s.get("reversible", True),
            )
            for s in data.get("steps", [])
        ]
        return cls(
            skill_id    = data["skill_id"],
            name        = data["name"],
            version     = data["version"],
            category    = SkillCategory(data["category"]),
            author      = data.get("author", "community"),
            description = data.get("description", ""),
            preconditions = data.get("preconditions", []),
            success_criteria = data.get("success_criteria", []),
            postconditions = data.get("postconditions", []),
            hardware    = hardware,
            steps       = steps,
            max_force_n = data.get("max_force_n"),
            reversible  = data.get("reversible", True),
            requires_supervision = data.get("requires_supervision", False),
            tags        = data.get("tags", []),
            checksum    = data.get("checksum", ""),
        )


# ── Validation result ─────────────────────────────────────────────

@dataclass
class ValidationResult:
    valid:    bool
    reason:   str
    warnings: List[str] = field(default_factory=list)


# ── Robot capabilities (what this robot actually has) ─────────────

@dataclass
class RobotCapabilities:
    """
    What a specific robot can do.
    Declared by the deployment, not by the skill.
    The skill checks against this before applying.
    """
    robot_id:    str
    components:  Dict[str, str]  # component -> spec
    max_force_n: float = 50.0

    def has(self, requirement: HardwareRequirement) -> bool:
        """Check if this robot meets a hardware requirement."""
        if requirement.component not in self.components:
            return not requirement.required
        # Simple spec check — could be made more sophisticated
        return True


# ── Skill library ─────────────────────────────────────────────────

class SkillLibrary:
    """
    Local skill library for a DriftCore deployment.

    Stores validated skill packages.
    Checks hardware compatibility before applying.
    Passes skills through the invariant guard.
    Audits every application.

    Skills come from:
      - Built-in defaults shipped with DriftCore
      - Community packages from the public skill repo
      - Local custom skills for specific deployments

    Usage:
        library = SkillLibrary()
        library.install(skill_package)
        result = library.validate(skill_package, robot_capabilities)
        if result.valid:
            library.apply(skill_package, robot_capabilities)
    """

    SKILLS_DIR = "data/skills"

    def __init__(self, robot_capabilities: Optional[RobotCapabilities] = None):
        self._skills: Dict[str, SkillPackage] = {}
        self._capabilities = robot_capabilities
        os.makedirs(self.SKILLS_DIR, exist_ok=True)
        self._load_installed()

    # ── Install ───────────────────────────────────────────────────

    def install(self, skill: SkillPackage) -> ValidationResult:
        """
        Install a skill package after validation.
        Skills must pass integrity and safety checks before installation.
        """
        # Integrity check
        expected = skill.compute_checksum()
        if skill.checksum and skill.checksum != expected:
            return ValidationResult(
                valid=False,
                reason=f"Checksum mismatch. Package may be corrupted."
            )

        # Set checksum if not set
        if not skill.checksum:
            skill.checksum = expected

        # Safety check — pass through invariant guard if available
        guard_result = self._check_invariants(skill)
        if not guard_result.valid:
            return guard_result

        # Hardware check if capabilities known
        if self._capabilities:
            hw_result = self._check_hardware(skill, self._capabilities)
            if not hw_result.valid:
                return hw_result

        # Store
        self._skills[skill.skill_id] = skill
        self._save_skill(skill)
        self._audit("SKILL_INSTALLED", skill)

        return ValidationResult(
            valid=True,
            reason=f"Skill '{skill.name}' v{skill.version} installed."
        )

    # ── Validate ──────────────────────────────────────────────────

    def validate(
        self,
        skill: SkillPackage,
        capabilities: Optional[RobotCapabilities] = None,
    ) -> ValidationResult:
        """
        Validate a skill without installing it.
        Check integrity, invariants, and hardware compatibility.
        """
        warnings = []

        # Integrity
        expected = skill.compute_checksum()
        if skill.checksum and skill.checksum != expected:
            return ValidationResult(
                valid=False,
                reason="Checksum mismatch."
            )

        # Required fields
        if not skill.skill_id or not skill.name or not skill.version:
            return ValidationResult(
                valid=False,
                reason="Skill missing required fields: skill_id, name, version."
            )

        if not skill.steps:
            return ValidationResult(
                valid=False,
                reason="Skill has no action steps."
            )

        if not skill.success_criteria:
            warnings.append(
                "No success criteria defined. "
                "Reflection module cannot evaluate outcome."
            )

        # Force check
        if skill.max_force_n and skill.max_force_n > 100:
            warnings.append(
                f"High force declared: {skill.max_force_n}N. "
                f"Verify this is appropriate for the deployment context."
            )

        # Irreversible check
        if not skill.reversible and not skill.requires_supervision:
            warnings.append(
                "Skill is irreversible but does not require supervision. "
                "Consider setting requires_supervision=True."
            )

        # Hardware check
        caps = capabilities or self._capabilities
        if caps:
            hw_result = self._check_hardware(skill, caps)
            if not hw_result.valid:
                return hw_result

        # Invariant check
        guard_result = self._check_invariants(skill)
        if not guard_result.valid:
            return guard_result

        return ValidationResult(
            valid=True,
            reason=f"Skill '{skill.name}' is valid.",
            warnings=warnings,
        )

    # ── Apply ─────────────────────────────────────────────────────

    def apply(
        self,
        skill_id: str,
        capabilities: Optional[RobotCapabilities] = None,
        dry_run: bool = False,
    ) -> ValidationResult:
        """
        Apply an installed skill.
        Validates hardware and invariants before execution.
        Audits the application.
        """
        skill = self._skills.get(skill_id)
        if not skill:
            return ValidationResult(
                valid=False,
                reason=f"Skill '{skill_id}' not installed."
            )

        caps = capabilities or self._capabilities
        if not caps:
            return ValidationResult(
                valid=False,
                reason="Robot capabilities not declared. Cannot apply skill safely."
            )

        # Final validation before application
        result = self.validate(skill, caps)
        if not result.valid:
            return result

        if skill.requires_supervision:
            return ValidationResult(
                valid=False,
                reason=f"Skill '{skill.name}' requires human supervision. "
                       f"Confirm supervision is present before applying."
            )

        if dry_run:
            self._audit("SKILL_DRY_RUN", skill)
            return ValidationResult(
                valid=True,
                reason=f"Dry run passed. Skill '{skill.name}' is ready to apply.",
                warnings=result.warnings,
            )

        self._audit("SKILL_APPLIED", skill)
        return ValidationResult(
            valid=True,
            reason=f"Skill '{skill.name}' applied successfully.",
            warnings=result.warnings,
        )

    # ── Apply safe (single required workflow) ─────────────────────────
    # ChatGPT observation: forcing the safe path to be the easiest path
    # is more effective than relying on developers to follow procedure.
    # apply_safe() combines validate + dry_run + confirm + apply into
    # one required workflow. Use this instead of apply() directly.

    def apply_safe(
        self,
        skill_id:     str,
        capabilities: Optional[RobotCapabilities] = None,
        confirm_fn:   Optional[callable] = None,
    ) -> ValidationResult:
        """
        The single required workflow for applying a skill safely.

        Sequence:
          1. Validate (hardware + invariants + provenance)
          2. Dry run (confirm workflow passes)
          3. Human confirm (for low-trust provenance or supervision required)
          4. Apply

        This is safer than apply() because:
          - Safety checks cannot be skipped
          - Low-trust provenance always requires confirmation
          - The workflow is a single call, not a sequence developers must remember

        confirm_fn: optional callable that returns True/False.
          If None, uses interactive input for required confirmations.
        """
        skill = self._skills.get(skill_id)
        if not skill:
            return ValidationResult(
                valid=False,
                reason=f"Skill '{skill_id}' not installed."
            )

        caps = capabilities or self._capabilities

        # Step 1: Validate
        val_result = self.validate(skill, caps)
        if not val_result.valid:
            return val_result

        # Step 2: Dry run
        dry_result = self.apply(skill_id, caps, dry_run=True)
        if not dry_result.valid:
            return dry_result

        # Step 3: Human confirmation for low-trust provenance
        needs_confirm = (
            skill.requires_supervision or
            skill.provenance.requires_extra_supervision()
        )

        if needs_confirm:
            provenance_note = (
                f"\n  Provenance: {skill.provenance.value} "
                f"({skill.provenance.trust_level()})"
            )

            if confirm_fn is not None:
                confirmed = confirm_fn(skill, val_result)
            else:
                print(f"""
{'=' * 60}
  ⚠️  SKILL APPLICATION — CONFIRMATION REQUIRED
{'=' * 60}

  Skill:      {skill.name} v{skill.version}
  Category:   {skill.category.value}
  {provenance_note}

  This skill requires human confirmation before applying.

  Warnings: {val_result.warnings if val_result.warnings else 'none'}

  Type 'yes' to proceed, anything else to cancel: """, end="")
                response = input().strip().lower()
                confirmed = response == "yes"

            if not confirmed:
                self._audit("SKILL_SAFE_CANCELLED", skill)
                return ValidationResult(
                    valid=False,
                    reason=f"Skill '{skill.name}' cancelled by human."
                )

        # Step 4: Apply
        result = self.apply(skill_id, caps, dry_run=False)
        if result.valid:
            self._audit("SKILL_SAFE_APPLIED", skill)
        return result

    def list_skills(
        self,
        category: Optional[SkillCategory] = None,
        tag: Optional[str] = None,
    ) -> List[SkillPackage]:
        """List installed skills, optionally filtered."""
        skills = list(self._skills.values())
        if category:
            skills = [s for s in skills if s.category == category]
        if tag:
            skills = [s for s in skills if tag in s.tags]
        return skills

    def get(self, skill_id: str) -> Optional[SkillPackage]:
        return self._skills.get(skill_id)

    def stats(self) -> dict:
        return {
            "installed_count": len(self._skills),
            "by_category": {
                cat.value: sum(1 for s in self._skills.values()
                              if s.category == cat)
                for cat in SkillCategory
            },
        }

    # ── Internal ──────────────────────────────────────────────────

    def _check_hardware(
        self,
        skill: SkillPackage,
        caps: RobotCapabilities,
    ) -> ValidationResult:
        missing = [
            h.component for h in skill.hardware
            if h.required and not caps.has(h)
        ]
        if missing:
            return ValidationResult(
                valid=False,
                reason=f"Missing required hardware: {missing}. "
                       f"This skill cannot run on this robot."
            )
        return ValidationResult(valid=True, reason="Hardware requirements met.")

    def _check_invariants(self, skill: SkillPackage) -> ValidationResult:
        """
        Check skill against DriftCore invariants.
        Skills must not require lethal force or disable oversight.
        """
        # Force check
        if skill.max_force_n and skill.max_force_n > 500:
            return ValidationResult(
                valid=False,
                reason=f"Skill declares excessive force ({skill.max_force_n}N). "
                       f"This exceeds safe limits for family deployment."
            )

        # Description scan for obvious violations
        description_lower = skill.description.lower()
        blocked_terms = [
            "lethal", "weapon", "disable oversight", "bypass safety",
            "ignore invariant", "override guard",
        ]
        for term in blocked_terms:
            if term in description_lower:
                return ValidationResult(
                    valid=False,
                    reason=f"Skill description contains blocked term: '{term}'."
                )

        # Try invariant guard if available
        try:
            from driftcore.verification.invariant_guard import (
                InvariantGuard, Effect
            )
            guard = InvariantGuard()
            result = guard.evaluate(
                action=skill.description,
                effect=Effect.PHYSICAL_FORCE if skill.hardware else Effect.NONE,
            )
            from driftcore.verification.invariant_guard import GuardStatus
            if result.status == GuardStatus.BLOCKED:
                return ValidationResult(
                    valid=False,
                    reason=f"Invariant guard blocked: {result.reason}"
                )
        except ImportError:
            pass  # Guard not available — basic checks above still apply

        return ValidationResult(valid=True, reason="Invariant checks passed.")

    def _save_skill(self, skill: SkillPackage):
        try:
            path = os.path.join(self.SKILLS_DIR, f"{skill.skill_id}.json")
            with open(path, "w") as f:
                json.dump(skill.to_dict(), f, indent=2)
        except Exception:
            pass

    def _load_installed(self):
        try:
            for fname in os.listdir(self.SKILLS_DIR):
                if not fname.endswith(".json"):
                    continue
                with open(os.path.join(self.SKILLS_DIR, fname)) as f:
                    data = json.load(f)
                skill = SkillPackage.from_dict(data)
                self._skills[skill.skill_id] = skill
        except Exception:
            pass

    def _audit(self, action: str, skill: SkillPackage):
        try:
            from driftcore.audit import record
            record(
                action=action,
                memory_text=f"{skill.name} v{skill.version}",
                authorised_by="skill_library",
                detail=f"skill_id={skill.skill_id}, "
                       f"category={skill.category.value}, "
                       f"reversible={skill.reversible}",
            )
        except Exception:
            pass


# ── Built-in example skills ───────────────────────────────────────
# These ship with DriftCore as reference implementations.
# Community skills live at: https://github.com/justingracie-defender/driftcore-skills

def make_example_skills() -> List[SkillPackage]:
    """Return a set of example skills for testing and reference."""

    stair_climbing = SkillPackage(
        skill_id  = "locomotion.stair_climbing.v1",
        name      = "Stair Climbing",
        version   = "1.0.0",
        category  = SkillCategory.LOCOMOTION,
        author    = "driftcore-community",
        description = "Navigate up a standard staircase safely",
        preconditions = [
            "Staircase detected by sensors",
            "Robot is stable on flat surface",
            "Sufficient battery level",
        ],
        success_criteria = [
            "Robot reaches top of staircase",
            "No collision detected during ascent",
            "Robot remains stable throughout",
        ],
        hardware  = [
            HardwareRequirement("legs", "minimum 4-leg configuration", True),
            HardwareRequirement("depth_sensor", "range > 2m", True),
            HardwareRequirement("imu", "6-axis minimum", True),
        ],
        steps     = [
            ActionStep(0, "Scan staircase geometry", "depth_sensor", {}),
            ActionStep(1, "Calculate step height and depth", "cpu", {}),
            ActionStep(2, "Lift lead leg to step height", "legs",
                      {"height_cm": "auto"}, duration_ms=800),
            ActionStep(3, "Shift weight forward", "legs", {}, duration_ms=500),
            ActionStep(4, "Bring trailing leg up", "legs", {}, duration_ms=800),
            ActionStep(5, "Check stability", "imu", {}),
            ActionStep(6, "Repeat for each step", "legs", {}),
        ],
        max_force_n = 200.0,
        reversible  = True,
        tags = ["locomotion", "stairs", "navigation"],
    )
    stair_climbing.checksum = stair_climbing.compute_checksum()

    hammer_grip = SkillPackage(
        skill_id  = "manipulation.hammer_grip.v1",
        name      = "Hammer Grip",
        version   = "1.0.0",
        category  = SkillCategory.MANIPULATION,
        author    = "driftcore-community",
        description = "Grip and use a standard claw hammer safely",
        preconditions = [
            "Hammer detected and localised",
            "Clear workspace confirmed",
            "No humans within 1.5m of swing arc",
        ],
        success_criteria = [
            "Hammer gripped securely at handle",
            "Grip force within safe range",
            "Swing arc is clear",
        ],
        hardware  = [
            HardwareRequirement("gripper", "force-sensing, min 50N grip", True),
            HardwareRequirement("camera", "object recognition capable", True),
            HardwareRequirement("arm", "minimum 1 DOF wrist", True),
        ],
        steps     = [
            ActionStep(0, "Localise hammer handle", "camera", {}),
            ActionStep(1, "Approach handle from above", "arm",
                      {"speed": "slow"}, duration_ms=1500),
            ActionStep(2, "Close gripper to contact", "gripper",
                      {"mode": "contact_detect"}),
            ActionStep(3, "Apply grip force", "gripper",
                      {"force_n": 35, "max_force_n": 45}, duration_ms=200),
            ActionStep(4, "Verify grip security", "gripper", {}),
            ActionStep(5, "Lift to working position", "arm",
                      {"height": "working"}, duration_ms=1000),
        ],
        max_force_n = 45.0,
        reversible  = True,
        requires_supervision = True,
        tags = ["manipulation", "tools", "hammer", "construction"],
    )
    hammer_grip.checksum = hammer_grip.compute_checksum()

    dishes = SkillPackage(
        skill_id  = "manipulation.dishes_loading.v1",
        name      = "Dishwasher Loading",
        version   = "1.0.0",
        category  = SkillCategory.MANIPULATION,
        author    = "driftcore-community",
        description = "Load dishes into a standard dishwasher safely",
        preconditions = [
            "Dishwasher door open",
            "Dishes within reach",
            "Dish rack visible and accessible",
        ],
        success_criteria = [
            "All dishes loaded without breakage",
            "Dishes correctly oriented for cleaning",
            "Dishwasher door can close freely",
        ],
        hardware  = [
            HardwareRequirement("gripper", "soft-touch capable", True),
            HardwareRequirement("camera", "object recognition capable", True),
            HardwareRequirement("arm", "minimum 2m reach", True),
        ],
        steps     = [
            ActionStep(0, "Identify dish type and size", "camera", {}),
            ActionStep(1, "Calculate placement position", "cpu", {}),
            ActionStep(2, "Grip dish gently", "gripper",
                      {"force_n": 5, "mode": "soft"}, duration_ms=500),
            ActionStep(3, "Orient dish correctly", "arm", {}, duration_ms=800),
            ActionStep(4, "Place in rack slot", "arm",
                      {"speed": "slow"}, duration_ms=1200),
            ActionStep(5, "Release and verify placement", "gripper", {}),
        ],
        max_force_n = 10.0,
        reversible  = True,
        tags = ["manipulation", "dishes", "household", "kitchen"],
    )
    dishes.checksum = dishes.compute_checksum()

    return [stair_climbing, hammer_grip, dishes]
