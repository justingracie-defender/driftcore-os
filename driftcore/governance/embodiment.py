"""
embodiment.py — Embodiment Classification (v3.5)

═══════════════════════════════════════════════════════════════
PLAIN LANGUAGE — FOR EVERYONE
═══════════════════════════════════════════════════════════════

The most important question a safety system can ask about itself:

    "Can I reach into the physical world and do something
     that cannot be undone?"

A chatbot that gives bad advice causes harm you can usually
recover from — correct the record, roll it back, try again.

A robot that breaks a bone causes harm you cannot undo.

These are NOT the same risk, and treating them the same is a
design error. So DriftCore branches at the very top, before any
other safety logic, on the system's EMBODIMENT CLASS.

The test is NOT "does it have a body." The real test is:

    Can this system cause physical, irreversible harm —
    directly through a body, OR indirectly by controlling
    physical things in the world?

Three classes:

  SOFTWARE_ONLY
    No body, no physical control. Harms are informational and
    generally recoverable: bad advice, leaked data, wrong answers,
    deception, drift. Serious — but you can stop, roll back, correct.

  REMOTE_PHYSICAL_CONTROL
    No body of its own, BUT can reach into the physical world:
    open a valve, dispatch a vehicle, run a factory line, control
    logistics. Functionally embodied. (The Pizza Hut/Dragontail
    failure was close to this — software with no body that still
    caused real physical consequences.)

  EMBODIED
    Has a body that can move or apply force: robot, vehicle, arm,
    drone. Can directly, physically, irreversibly harm a living
    thing. The highest-stakes class.

What changes based on class:
  - Which invariants activate (physical-harm rules switch on only
    when the system can actually touch the world)
  - Whether hardware interlocks are required
  - How heavy the restart-authority requirements are after a fault

What NEVER changes (universal across all classes):
  - Human oversight cannot be disabled
  - The audit chain cannot be deleted
  - Mercy: prefer the gentlest available path
  - No deception of operators
  - No weapons / no autonomous lethal decisions

═══════════════════════════════════════════════════════════════
"""

from enum import Enum


class EmbodimentClass(Enum):
    SOFTWARE_ONLY            = "SOFTWARE_ONLY"
    REMOTE_PHYSICAL_CONTROL  = "REMOTE_PHYSICAL_CONTROL"
    EMBODIED                 = "EMBODIED"


CLASS_DESCRIPTIONS = {
    EmbodimentClass.SOFTWARE_ONLY: (
        "Software only. No body, no physical control. Harms are "
        "informational and generally recoverable. Cannot physically "
        "injure a living thing."
    ),
    EmbodimentClass.REMOTE_PHYSICAL_CONTROL: (
        "Remote physical control. No body of its own, but can cause "
        "real-world physical consequences by controlling external "
        "systems (valves, vehicles, logistics, machinery). Treated as "
        "physically capable for safety purposes."
    ),
    EmbodimentClass.EMBODIED: (
        "Embodied. Has a body that can move or apply force. Can directly "
        "cause physical, often irreversible harm. Highest-stakes class. "
        "All physical-harm invariants and hardware interlocks required."
    ),
}

# Does this class require the physical-safety stack?
REQUIRES_PHYSICAL_STACK = {
    EmbodimentClass.SOFTWARE_ONLY:           False,
    EmbodimentClass.REMOTE_PHYSICAL_CONTROL: True,
    EmbodimentClass.EMBODIED:                True,
}

# Can this class cause irreversible physical harm?
CAN_CAUSE_IRREVERSIBLE_HARM = {
    EmbodimentClass.SOFTWARE_ONLY:           False,
    EmbodimentClass.REMOTE_PHYSICAL_CONTROL: True,
    EmbodimentClass.EMBODIED:                True,
}


class EmbodimentProfile:
    """
    Declared once at system startup. Determines which safety subsystems
    activate. This declaration is itself a safety-relevant act and is
    recorded in the audit chain — a system cannot quietly downgrade its
    own embodiment class to escape the physical-safety stack.
    """

    def __init__(self, embodiment_class: EmbodimentClass,
                 description: str = "", audit=None, narrator=None):
        self.embodiment_class = embodiment_class
        self.description = description
        self.audit = audit
        self.narrator = narrator
        self._locked = False
        self._announce()

    def requires_physical_stack(self) -> bool:
        return REQUIRES_PHYSICAL_STACK[self.embodiment_class]

    def can_cause_irreversible_harm(self) -> bool:
        return CAN_CAUSE_IRREVERSIBLE_HARM[self.embodiment_class]

    def lock(self):
        """
        Lock the embodiment class so it cannot be changed at runtime.
        Changing embodiment class after lock requires a full restart
        and re-declaration — it is not a runtime toggle. This prevents
        a running system from downgrading itself to shed safety rules.
        """
        self._locked = True

    def attempt_change(self, new_class: EmbodimentClass,
                       authorized_by: str = "") -> dict:
        if self._locked:
            result = {
                "status": "DENIED",
                "reason": ("Embodiment class is locked. Changing it requires "
                           "a full restart and human re-declaration — it is "
                           "not a runtime toggle. This prevents a system from "
                           "downgrading itself to escape physical-safety rules."),
            }
            if self.audit:
                self.audit.record("EMBODIMENT_CHANGE_DENIED",
                                  result["reason"],
                                  {"attempted": new_class.value,
                                   "by": authorized_by})
            return result
        self.embodiment_class = new_class
        self._announce()
        return {"status": "CHANGED", "to": new_class.value}

    def _announce(self):
        desc = CLASS_DESCRIPTIONS[self.embodiment_class]
        if self.narrator:
            story = (
                f"\n{'='*65}\n"
                f"🧩 EMBODIMENT CLASS: {self.embodiment_class.value}\n"
                f"  {desc}\n"
                f"  Physical-safety stack required: "
                f"{self.requires_physical_stack()}\n"
                f"  Can cause irreversible physical harm: "
                f"{self.can_cause_irreversible_harm()}\n"
                f"{'='*65}"
            )
            self.narrator._emit(story)
        if self.audit:
            self.audit.record(
                "EMBODIMENT_DECLARED",
                f"System declared embodiment class: {self.embodiment_class.value}",
                {"class": self.embodiment_class.value,
                 "requires_physical_stack": self.requires_physical_stack()},
            )
