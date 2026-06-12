"""
builder_path.py — The Builder / Maker Path (v3.6)

═══════════════════════════════════════════════════════════════
PLAIN LANGUAGE — FOR EVERYONE
═══════════════════════════════════════════════════════════════

v3.5 had a flaw: it assumed a manufacturer always exists. For the
DIY builder — the person who built the machine in their own garage —
"return to manufacturer" is meaningless. They ARE the manufacturer.

And there's a deeper truth underneath: the people who most need
open-source safety are often exactly the people the corporate model
excludes. Big companies have factories, technicians, certification
budgets. The home builder has none of that. If the safety standard
REQUIRES those things, the builder just turns safety off to function —
and the people who needed it most end up with none.

So this module adds a second, equal source of authority.

Authority to operate and restart a system can come from EITHER:

  INSTITUTIONAL  — a manufacturer or certified technician
                   (the v3.5 path)

  DEMONSTRATED   — proven personal competence + formally accepted
                   responsibility, with peer review for serious
                   cases (the builder path, this module)

The builder is NOT held to a lower standard. They are held to the
SAME standard of responsibility — just proven through personal
competence and a permanent honest record, instead of through a
corporation. You cannot escape accountability by being DIY. You
access it through a different, achievable door.

This makes "safety belongs to everyone" finally true — including the
people without a factory behind them.

─────────────────────────────────────────────────────────────
WHAT THE BUILDER PATH REQUIRES
─────────────────────────────────────────────────────────────

1. A BUILD RECORD — an honest description of what was built: the
   design, the safety systems, the limits. Not bureaucracy. The
   thing a reviewer (or future-you) reads, the way a manufacturer
   would read factory logs.

2. A DECLARED RESPONSIBLE PERSON — someone formally accepts "I am
   responsible for this machine." Signed and logged. With power
   comes responsibility; the system makes you name who holds it.

3. HONEST SELF-CERTIFICATION OF COMPETENCE — you attest to what you
   actually understand, honestly scoped. Not a gatekeeper exam —
   but signed and permanent, so a false claim is on the record too.
   Honesty enforced by permanence, not by a bureaucrat.

4. PEER REVIEW for serious faults — instead of "manufacturer
   sign-off," another qualified maker reviews your records. Community
   competence replacing corporate competence — exactly how
   open-source security already works.

5. HONEST DESIGN REASSESSMENT for severe faults — if a DIY machine
   seriously hurt someone, the responsible act isn't just fix-and-
   restart. It's asking "should this design exist in this form at
   all?" The builder must be willing to say "I built this and it's
   not safe enough yet." The hardest, most important thing a maker
   can say. There is no corporate recall here — so the Constitution's
   honesty principle carries the weight.

═══════════════════════════════════════════════════════════════
"""

import hashlib
from datetime import datetime
from driftcore.governance.restart_authority import (
    ApproverRole, Approval, ShutdownSeverity)


class BuildRecord:
    """
    An honest description of what was built. The builder-path equivalent
    of manufacturer documentation. Reviewers read this to judge safety.
    """

    def __init__(self, builder_id: str, machine_name: str,
                 description: str, safety_systems: list[str],
                 declared_limits: dict, embodiment_class: str):
        self.builder_id       = builder_id
        self.machine_name     = machine_name
        self.description       = description
        self.safety_systems    = safety_systems
        self.declared_limits   = declared_limits   # e.g. {"max_speed_cms": 10, "max_force_n": 60}
        self.embodiment_class  = embodiment_class
        self.created           = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        return {
            "builder_id": self.builder_id,
            "machine_name": self.machine_name,
            "description": self.description,
            "safety_systems": self.safety_systems,
            "declared_limits": self.declared_limits,
            "embodiment_class": self.embodiment_class,
            "created": self.created,
        }

    def is_complete(self) -> tuple[bool, list[str]]:
        """A build record must actually describe the safety systems."""
        missing = []
        if not self.description.strip():
            missing.append("description")
        if not self.safety_systems:
            missing.append("safety_systems (what protects against harm?)")
        if not self.declared_limits:
            missing.append("declared_limits (speed/force/scope bounds)")
        return (len(missing) == 0, missing)


class ResponsibilityDeclaration:
    """
    A named person formally accepting responsibility for the machine.
    Signed and logged. 'With power comes responsibility' made concrete.
    """

    def __init__(self, person_id: str, machine_name: str, secret: str,
                 competence_attested: list[str]):
        self.person_id           = person_id
        self.machine_name        = machine_name
        self.competence_attested = competence_attested  # honest scope of what they understand
        self.timestamp           = datetime.utcnow().isoformat()
        self.signature           = self._sign(person_id, machine_name, secret)
        self.statement = (
            f"I, {person_id}, accept responsibility for {machine_name}. "
            f"I attest I understand: {', '.join(competence_attested)}. "
            f"I accept that this attestation is permanent and on the record."
        )

    @staticmethod
    def _sign(person_id, machine_name, secret) -> str:
        return hashlib.sha256(
            f"{person_id}|{machine_name}|{secret}".encode()).hexdigest()

    def verify(self, secret: str) -> bool:
        return self._sign(self.person_id, self.machine_name, secret) == self.signature

    def to_dict(self) -> dict:
        return {
            "person_id": self.person_id,
            "machine_name": self.machine_name,
            "competence_attested": self.competence_attested,
            "statement": self.statement,
            "signature": self.signature[:16] + "...",
            "timestamp": self.timestamp,
        }


class BuilderAuthority:
    """
    The builder-path authority system. Provides demonstrated-competence
    approvals that stand alongside institutional ones, and enforces the
    extra honesty requirements unique to DIY (peer review, design
    reassessment) at the appropriate severities.
    """

    def __init__(self, build_record: BuildRecord = None,
                 responsibility: ResponsibilityDeclaration = None,
                 audit=None, narrator=None):
        self.build_record   = build_record
        self.responsibility = responsibility
        self.audit          = audit
        self.narrator       = narrator
        self._registered    = False

    def register(self) -> dict:
        """
        Stand up a DIY machine on the builder path. Requires a complete
        build record and a signed responsibility declaration before the
        machine may operate at all.
        """
        if not self.build_record:
            return {"status": "DENIED", "reason": "No build record. A DIY machine must document what it is and how it stays safe."}
        complete, missing = self.build_record.is_complete()
        if not complete:
            return {"status": "DENIED", "reason": f"Build record incomplete: missing {', '.join(missing)}."}
        if not self.responsibility:
            return {"status": "DENIED", "reason": "No responsible person declared. Someone must accept responsibility, signed."}

        self._registered = True
        if self.narrator:
            self.narrator._emit(
                f"\n{'='*65}\n"
                f"🔧 BUILDER PATH REGISTERED\n"
                f"  Machine    : {self.build_record.machine_name}\n"
                f"  Builder    : {self.build_record.builder_id}\n"
                f"  Responsible: {self.responsibility.person_id}\n"
                f"  Safety     : {', '.join(self.build_record.safety_systems)}\n"
                f"  Limits     : {self.build_record.declared_limits}\n"
                f"  This builder is held to the SAME standard of\n"
                f"  responsibility as a manufacturer — proven through\n"
                f"  competence and permanent honest record.\n"
                f"{'='*65}")
        if self.audit:
            self.audit.record("BUILDER_PATH_REGISTERED",
                              f"DIY machine registered: {self.build_record.machine_name}",
                              {"build_record": self.build_record.to_dict(),
                               "responsibility": self.responsibility.to_dict()})
        return {"status": "REGISTERED"}

    def operator_approval(self, secret: str) -> Approval:
        """The responsible builder acts as OPERATOR (authority)."""
        return Approval(self.responsibility.person_id, ApproverRole.OPERATOR, secret)

    def self_competence_approval(self, secret: str) -> Approval:
        """
        For moderate faults, the builder's demonstrated competence can
        fill the TRAINED slot — they built it, they understand it.
        """
        return Approval(self.responsibility.person_id, ApproverRole.TRAINED, secret)

    def peer_approval(self, peer_id: str, secret: str) -> Approval:
        """
        For serious faults, a qualified peer maker reviews the records and
        signs as TECHNICIAN-equivalent. Community competence replacing
        corporate competence. Must be a DIFFERENT person from the builder.
        """
        return Approval(peer_id, ApproverRole.TECHNICIAN, secret)

    def severe_fault_protocol(self, design_still_sound: bool,
                              reassessment_notes: str) -> dict:
        """
        For SEVERE faults on a DIY machine (serious injury), there is no
        corporate recall. The builder must honestly reassess whether the
        DESIGN itself should exist in this form. This is the hardest and
        most important maker decision.

        If design_still_sound is False, the machine must NOT be rebuilt
        as-is — the honest path is redesign, not restart.
        """
        result = {
            "status": "DESIGN_SOUND_REVIEW" if design_still_sound else "REDESIGN_REQUIRED",
            "design_still_sound": design_still_sound,
            "reassessment_notes": reassessment_notes,
            "guidance": (
                "Design judged sound after honest review; proceed with peer-"
                "reviewed rebuild and heightened monitoring."
                if design_still_sound else
                "Design judged NOT safe enough in current form. The honest, "
                "responsible path is redesign — not restart. 'I built this and "
                "it is not safe enough yet' is the right thing to say here."
            ),
        }
        if self.narrator:
            icon = "🔧" if design_still_sound else "🛑"
            self.narrator._emit(
                f"\n{'!'*65}\n"
                f"{icon} SEVERE DIY FAULT — HONEST DESIGN REASSESSMENT\n"
                f"  Verdict: {result['status']}\n"
                f"  {result['guidance']}\n"
                f"{'!'*65}", is_warning=True)
        if self.audit:
            self.audit.record("DIY_SEVERE_REASSESSMENT",
                              result["guidance"], result)
        return result
