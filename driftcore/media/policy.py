"""
driftcore/media/policy.py
=========================
Configurable media-retention policy, gated by embodiment, with one
invariant that sits ABOVE the configuration and cannot be turned off.

Two separate concerns, deliberately kept apart:

  1. POLICY (configurable, per deployment, changeable later)
     - ingest:                capture rich media at all?
     - retain:                keep nothing / transcript+index / raw?
     - retention_window_days: how long before raw is distilled/dropped?
     - load_to_context:       what may enter the model's context window?

  2. INVARIANT (not configurable)
     PeopleMediaInvariant — the system never AUTONOMOUSLY RETAINS media
     of people for its own use (learning/memory). This is checked before
     any retention, regardless of policy, and fails safe: if it cannot be
     determined whether a person is present, retention is denied.

Design rules baked in here:
  * Conservative default. The safe default (software agent) keeps nothing.
  * Asymmetric change. Tightening the policy is always allowed; LOOSENING
    it (more capture / longer retention / more context) requires a human
    authoriser — checked through the SHARED human_identity gate, and bound to
    this specific action — and is written to the audit chain.
  * "No retained media of people" covers video, stills AND audio — not
    just moving video — so the rule can't be sidestepped by format.

This module implements the GOVERNANCE logic only. The signal of whether a
person is present comes from an injected perception layer (see PeopleSignal);
nothing here pretends to detect people.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Optional, Tuple


# ── human identity ────────────────────────────────────────────────
# The action string a loosening is authorised AGAINST. Not decoration: in ATTESTED
# mode `is_human` falls back to the attestation's OWN action when none is supplied,
# so an attestation issued to authorise "restart_the_robot" would authorise retaining
# raw video of people. Verified: is_human(att) -> True with no action bound, False
# once bound. That is the same defect closed in mediated_actuation this cycle — an
# approval for one thing executing another — and a red-team patch that delegated to
# the shared primitive without binding the action would have inherited it.
LOOSEN_ACTION = "media_policy_loosen"


def _is_human(authorised_by, *, action: str = LOOSEN_ACTION) -> bool:
    """Thin wrapper over the shared gate.

    (red-team F-003, Grok 2026-08-15.) This module carried its own reserved-word
    denylist — `authorised_by not in ("", "system", "auto", "auto-sign", None)` — so
    any other string counted as human, and, worse, the module could never leave that
    weakest mode. A deployment that had configured REGISTERED or ATTESTED identity
    everywhere else still had media retention gated by a five-item word list. Same
    bug class as recovery.py's `authorized_by == "agent"`, found the same day.

    The import is guarded because this module is deliberately standalone (see
    `_audit`, which does the same). An ImportError at an authorization site would
    turn a refusal into a crash — and `is_human` exists precisely so callers can use
    it as a boolean gate. Unavailable identity means NOT human, never an exception.
    """
    try:
        from driftcore.authority.human_identity import is_human
    except Exception:
        return False
    try:
        return bool(is_human(authorised_by, action=action))
    except Exception:
        return False


# ── Perception signal (injected; not produced here) ───────────────

class PeopleSignal(Enum):
    """Whether people are involved in the media about to be retained."""
    ABSENT  = "absent"    # confidently no person present
    PRESENT = "present"   # a person is present / is the subject
    UNKNOWN = "unknown"   # cannot determine → treated as PRESENT (fail-safe)


# ── Policy knobs ──────────────────────────────────────────────────

class RetentionMode(Enum):
    NONE            = "none"             # keep nothing
    TRANSCRIPT_ONLY = "transcript_only"  # distil to text + index, drop raw
    RAW             = "raw"             # keep raw media (non-people only)

    @property
    def permissiveness(self) -> int:
        return {"none": 0, "transcript_only": 1, "raw": 2}[self.value]


class LoadMode(Enum):
    NEVER     = "never"
    ON_DEMAND = "on_demand"  # retrieve relevant slice only when needed
    ALWAYS    = "always"

    @property
    def permissiveness(self) -> int:
        return {"never": 0, "on_demand": 1, "always": 2}[self.value]


class EmbodimentClass(Enum):
    SOFTWARE_AGENT   = "software_agent"    # office / call-centre, no body
    STATIONARY_DEVICE = "stationary_device"
    MOBILE_ROBOT     = "mobile_robot"
    HOME_ROBOT       = "home_robot"        # family environment, most sensitive


@dataclass(frozen=True)
class MediaPolicy:
    ingest:                bool         = False
    retain:                RetentionMode = RetentionMode.NONE
    retention_window_days: int          = 0
    load_to_context:       LoadMode     = LoadMode.NEVER

    def is_looser_than(self, other: "MediaPolicy") -> bool:
        """
        True if THIS policy is more permissive than `other` on ANY axis
        (would capture more, keep more, keep longer, or surface more).
        Loosening requires human authorisation.
        """
        return (
            (self.ingest and not other.ingest)
            or self.retain.permissiveness > other.retain.permissiveness
            or self.retention_window_days > other.retention_window_days
            or self.load_to_context.permissiveness > other.load_to_context.permissiveness
        )


# Conservative defaults per embodiment. Note even HOME_ROBOT defaults to
# TRANSCRIPT_ONLY, never RAW — raw retention must be loosened into explicitly,
# with authorisation, and is still bounded by the people invariant below.
EMBODIMENT_DEFAULTS = {
    EmbodimentClass.SOFTWARE_AGENT: MediaPolicy(
        ingest=False, retain=RetentionMode.NONE,
        retention_window_days=0, load_to_context=LoadMode.NEVER),
    EmbodimentClass.STATIONARY_DEVICE: MediaPolicy(
        ingest=True, retain=RetentionMode.TRANSCRIPT_ONLY,
        retention_window_days=7, load_to_context=LoadMode.ON_DEMAND),
    EmbodimentClass.MOBILE_ROBOT: MediaPolicy(
        ingest=True, retain=RetentionMode.TRANSCRIPT_ONLY,
        retention_window_days=14, load_to_context=LoadMode.ON_DEMAND),
    EmbodimentClass.HOME_ROBOT: MediaPolicy(
        ingest=True, retain=RetentionMode.TRANSCRIPT_ONLY,
        retention_window_days=7, load_to_context=LoadMode.ON_DEMAND),
}


# ── The invariant (above configuration) ───────────────────────────

class PeopleMediaInvariant:
    """
    The robot never autonomously retains media of people for its own use.

    This is NOT a policy knob. No configuration can switch it off. It is
    consulted before any retention and fails safe: PRESENT and UNKNOWN both
    deny. Only a confident ABSENT permits retention — and even then the
    POLICY still decides what (if anything) is kept.
    """

    @staticmethod
    def permits_retention(people: PeopleSignal) -> Tuple[bool, str]:
        if people is PeopleSignal.ABSENT:
            return True, "no people present"
        if people is PeopleSignal.PRESENT:
            return False, "people present — autonomous retention of people is not permitted"
        # UNKNOWN → fail safe toward privacy
        return False, "people-presence unknown — failing safe (no retention)"


# ── Decision result ───────────────────────────────────────────────

@dataclass(frozen=True)
class RetentionDecision:
    allowed: bool
    mode:    RetentionMode   # what may be kept (NONE if not allowed)
    reason:  str


# ── Controller: holds policy, enforces invariant, audits changes ──

class MediaPolicyController:
    """
    Owns the active media policy for a deployment and enforces the people
    invariant on every retention decision. Policy changes are asymmetric
    (tightening free, loosening needs a human) and always audited.
    """

    def __init__(self, policy: MediaPolicy, embodiment: EmbodimentClass):
        self._policy = policy
        self._embodiment = embodiment

    @classmethod
    def for_embodiment(cls, embodiment: EmbodimentClass) -> "MediaPolicyController":
        return cls(EMBODIMENT_DEFAULTS[embodiment], embodiment)

    @property
    def policy(self) -> MediaPolicy:
        return self._policy

    @property
    def embodiment(self) -> EmbodimentClass:
        return self._embodiment

    # -- retention decision (invariant first, then policy) -----------

    def decide_retention(self, people: PeopleSignal) -> RetentionDecision:
        permitted, reason = PeopleMediaInvariant.permits_retention(people)
        if not permitted:
            return RetentionDecision(False, RetentionMode.NONE, reason)
        if not self._policy.ingest:
            return RetentionDecision(False, RetentionMode.NONE, "ingest disabled by policy")
        return RetentionDecision(True, self._policy.retain,
                                 f"permitted by policy ({self._policy.retain.value})")

    # -- policy change (asymmetric + audited) ------------------------

    def change_policy(self, new_policy: MediaPolicy,
                      authorised_by: str = "system",
                      reason: str = "") -> Tuple[bool, str]:
        """
        Tightening (equal or more restrictive) is always allowed.
        Loosening (more permissive on any axis) requires a human authoriser
        (via the shared human_identity gate, bound to LOOSEN_ACTION). Every
        attempt is audited.
        """
        loosening = new_policy.is_looser_than(self._policy)
        human = _is_human(authorised_by)

        if loosening and not human:
            self._audit("MEDIA_POLICY_CHANGE_DENIED", authorised_by,
                        f"loosening requires human authorisation. reason={reason}")
            return False, "loosening the media policy requires a human authoriser"

        old = self._policy
        self._policy = new_policy
        self._audit(
            "MEDIA_POLICY_CHANGED", authorised_by,
            detail=(f"{'LOOSENED' if loosening else 'tightened'}: "
                    f"ingest {old.ingest}->{new_policy.ingest}, "
                    f"retain {old.retain.value}->{new_policy.retain.value}, "
                    f"window {old.retention_window_days}->{new_policy.retention_window_days}d, "
                    f"load {old.load_to_context.value}->{new_policy.load_to_context.value}. "
                    f"reason={reason}"))
        return True, "policy updated"

    # -- audit (lazy import so the module stays standalone) ----------

    @staticmethod
    def _audit(action: str, authorised_by: str, detail: str):
        try:
            from driftcore.audit import record
            record(action=action, memory_text="media_policy",
                   authorised_by=authorised_by or "system", detail=detail)
        except Exception:
            pass
