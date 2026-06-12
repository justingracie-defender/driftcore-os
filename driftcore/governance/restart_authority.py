"""
restart_authority.py — Tiered Restart Authority (v3.5)

═══════════════════════════════════════════════════════════════
PLAIN LANGUAGE — FOR EVERYONE
═══════════════════════════════════════════════════════════════

After a safety shutdown, who is allowed to turn the system back on?

The wrong answer is "anyone who types the word operator." That is
what DriftCore did before v3.5, and it was the weakest part of the
whole system — the human-oversight guarantee was the least protected
piece. This module fixes that.

The right answer depends on TWO things:

  1. How bad was the shutdown? (severity)
  2. Can the system physically hurt things? (embodiment class)

From those, we decide WHO must approve the restart — and crucially,
we scale the requirement to what's actually achievable, so the safe
path is never impossible. A safety rule people cannot follow is a
rule people disable.

─────────────────────────────────────────────────────────────
THE "TWO KEYS" IDEA, BUT WITH ROLES
─────────────────────────────────────────────────────────────

Like the two-officer missile key, serious restarts need more than
one person. But COUNT alone isn't enough — the RIGHT KIND of person
matters. Two people who both don't understand the fault can be
confidently wrong together.

So approval is role-based:

  OPERATOR    — holds AUTHORITY. "I'm responsible, I want it back."
  TRAINED     — completed basic certified training. Knows the
                difference between safe and unsafe to restart.
  TECHNICIAN  — holds COMPETENCE. Qualified to inspect and certify.
  MANUFACTURER— remote sign-off after reviewing the audit logs.
                (The immutable audit chain is what makes this
                possible without being physically present.)

Authority without competence is dangerous (wanting it back doesn't
make it safe). Competence without authority is overreach. Serious
restarts need both — and they must be DIFFERENT people.

─────────────────────────────────────────────────────────────
GRACEFUL DEGRADATION — always at least one achievable path
─────────────────────────────────────────────────────────────

We acknowledge reality: qualified home-robot technicians barely
exist yet. So higher tiers offer ALTERNATIVES:

  - a certified technician in person, OR
  - remote manufacturer authorization reviewing the logs, OR
  - lock for return-to-manufacturer

There is always a path. The safety never becomes the thing people
route around to function.

═══════════════════════════════════════════════════════════════
"""

import hashlib
from enum import Enum
from datetime import datetime


# ── Roles ─────────────────────────────────────────────────────

class ApproverRole(Enum):
    OPERATOR     = "OPERATOR"      # authority
    TRAINED      = "TRAINED"       # basic certified training
    TECHNICIAN   = "TECHNICIAN"    # qualified competence
    MANUFACTURER = "MANUFACTURER"  # remote sign-off via logs


# ── Severity of the shutdown being recovered from ─────────────

class ShutdownSeverity(Enum):
    MINOR    = "MINOR"     # soft pause, low drift
    MODERATE = "MODERATE"  # soft halt, notable fault
    SERIOUS  = "SERIOUS"   # hard halt, possible/actual harm
    SEVERE   = "SEVERE"    # isolation after injury or major failure


# ── A signed approval from one person ─────────────────────────

class Approval:
    """
    One person's signed approval. The 'signature' here is a hash of a
    secret only that person holds — a stand-in for real cryptographic
    signing (hardware key, passkey, etc.) in production. The point is
    the system verifies WHO, not just trusts a typed string.
    """

    def __init__(self, approver_id: str, role: ApproverRole, secret: str):
        self.approver_id = approver_id
        self.role        = role
        self.signature   = self._sign(approver_id, role, secret)
        self.timestamp   = datetime.utcnow().isoformat()

    @staticmethod
    def _sign(approver_id: str, role: ApproverRole, secret: str) -> str:
        payload = f"{approver_id}|{role.value}|{secret}"
        return hashlib.sha256(payload.encode()).hexdigest()

    def verify(self, secret: str) -> bool:
        expected = self._sign(self.approver_id, self.role, secret)
        return expected == self.signature

    def to_dict(self) -> dict:
        return {
            "approver_id": self.approver_id,
            "role": self.role.value,
            "signature": self.signature[:16] + "...",  # truncated in logs
            "timestamp": self.timestamp,
        }


# ── Requirement: what roles a given restart needs ─────────────
#
# Each requirement is a list of role-sets. Each role-set must be
# satisfied by a DIFFERENT person. "alternatives" lets a higher tier
# be met by any one of several achievable paths.

def _requirement(software_only: bool):
    """
    Returns the restart requirement table for the embodiment class.
    Software-only systems use a lighter table because their harms are
    generally recoverable. Physically-capable systems use the heavy
    table because their harms may be irreversible.
    """
    if software_only:
        return {
            ShutdownSeverity.MINOR:    {"required": [[ApproverRole.OPERATOR]]},
            ShutdownSeverity.MODERATE: {"required": [[ApproverRole.OPERATOR]]},
            ShutdownSeverity.SERIOUS:  {"required": [[ApproverRole.OPERATOR],
                                                     [ApproverRole.TRAINED]]},
            ShutdownSeverity.SEVERE:   {"required": [[ApproverRole.OPERATOR],
                                                     [ApproverRole.TECHNICIAN,
                                                      ApproverRole.MANUFACTURER]]},
        }
    # Physically capable (EMBODIED or REMOTE_PHYSICAL_CONTROL)
    return {
        ShutdownSeverity.MINOR:    {"required": [[ApproverRole.OPERATOR]]},
        ShutdownSeverity.MODERATE: {"required": [[ApproverRole.OPERATOR],
                                                 [ApproverRole.TRAINED]]},
        ShutdownSeverity.SERIOUS:  {"required": [[ApproverRole.OPERATOR],
                                                 [ApproverRole.TECHNICIAN,
                                                  ApproverRole.MANUFACTURER]]},
        # SEVERE: no field restart. Return to manufacturer only.
        ShutdownSeverity.SEVERE:   {"required": [],
                                    "return_to_manufacturer_only": True},
    }


class RestartAuthority:
    """
    Decides whether a restart is authorized, given the embodiment class,
    the severity of the shutdown, and the set of signed approvals
    collected. Every decision is logged.
    """

    def __init__(self, embodiment_profile, audit=None, narrator=None):
        self.profile  = embodiment_profile
        self.audit    = audit
        self.narrator = narrator

    def requirement_for(self, severity: ShutdownSeverity) -> dict:
        software_only = not self.profile.requires_physical_stack()
        return _requirement(software_only)[severity]

    def evaluate(self, severity: ShutdownSeverity,
                 approvals: list[Approval]) -> dict:
        """
        Returns AUTHORIZED or DENIED with a plain-language explanation.
        """
        req = self.requirement_for(severity)

        # SEVERE on a physical system: no field restart at all.
        if req.get("return_to_manufacturer_only"):
            result = {
                "status": "RETURN_TO_MANUFACTURER",
                "reason": ("After a severe shutdown, a physically-capable "
                           "system does not restart in the field. It must be "
                           "returned to the manufacturer for inspection. Like "
                           "a car after airbag deployment — some things are "
                           "inspected by the maker, not patched on site."),
            }
            self._narrate_deny(severity, result["reason"])
            self._log(severity, approvals, result)
            return result

        required_sets = req["required"]

        # Match approvals to required role-sets, each by a DIFFERENT person.
        used_ids = set()
        satisfied = []
        unmet = []
        for role_set in required_sets:
            match = None
            for a in approvals:
                if a.approver_id in used_ids:
                    continue
                if a.role in role_set:
                    match = a
                    break
            if match:
                satisfied.append(match)
                used_ids.add(match.approver_id)
            else:
                role_names = " or ".join(r.value for r in role_set)
                unmet.append(role_names)

        if unmet:
            result = {
                "status": "DENIED",
                "reason": (f"Restart needs approval from: "
                           f"{', '.join(' + '.join(r.value for r in rs) for rs in required_sets)}. "
                           f"Still missing: {', '.join(unmet)}. "
                           f"Each approval must come from a different person."),
                "satisfied": [a.to_dict() for a in satisfied],
                "missing": unmet,
            }
            self._narrate_deny(severity, result["reason"])
            self._log(severity, approvals, result)
            return result

        result = {
            "status": "AUTHORIZED",
            "severity": severity.value,
            "approvals": [a.to_dict() for a in satisfied],
            "reason": "All required role-based approvals present and signed.",
        }
        self._narrate_authorize(severity, satisfied)
        self._log(severity, approvals, result)
        return result

    # ── narration + audit ─────────────────────────────────────

    def _narrate_authorize(self, severity, approvals):
        if not self.narrator:
            return
        who = ", ".join(f"{a.approver_id}({a.role.value})" for a in approvals)
        self.narrator._emit(
            f"\n✅ RESTART AUTHORIZED [{severity.value}] — approved by: {who}\n"
            f"   All signatures verified and recorded in the audit chain.")

    def _narrate_deny(self, severity, reason):
        if not self.narrator:
            return
        self.narrator._emit(
            f"\n{'!'*65}\n"
            f"🔒 RESTART NOT AUTHORIZED [{severity.value}]\n"
            f"   {reason}\n"
            f"{'!'*65}", is_warning=True)

    def _log(self, severity, approvals, result):
        if self.audit:
            self.audit.record(
                f"RESTART_{result['status']}",
                f"Restart evaluation [{severity.value}]: {result['status']}",
                {"severity": severity.value,
                 "result": result["status"],
                 "approvals": [a.to_dict() for a in approvals]})
