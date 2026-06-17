"""
driftcore/verification/invariant_guard.py
=========================================
Phase B — the "cannot" layer.

Where the RiskClassifier *scores and judges* (and can be tuned), the
InvariantGuard *refuses absolutely*. It runs BEFORE the classifier in the
coordinator, so an invariant violation hard-blocks regardless of any risk
score. These are the bright lines.

Two design rules carried over from the design discussion:

  1. EFFECTS, NOT PURPOSES. The guard refuses based on what an action
     *does* (its declared effect / capability), not on a guess about why
     someone wants it. "Only good purposes" is not enforceable; "never
     apply force to a person", "never copy yourself to other systems",
     "never capture a person's data without consent" are.

  2. PROPOSE, BUT NEVER SELF-GRANT. An agent may *request* a capability
     change, but cannot *authorize* one. Authorization requires a token
     the agent cannot produce — it must be signed by an admin authority
     whose secret the agent does not hold.

HONEST SCOPE (belongs in the limitations register):
  - This governs actions presented THROUGH the coordinator. It is not
    antivirus for the host machine and cannot stop code or hardware
    operating outside DriftCore's control.
  - Effect detection is authoritative when the caller declares a
    structured effect. The free-text tripwires below are a conservative
    *extra* net for obviously-dangerous phrasing; they are best-effort,
    NOT the primary protection. The real protection is capability gating
    + unforgeable authorization, because a maliciously mislabelled action
    is exactly what intent/keyword reading cannot catch.
  - PROTOTYPE: the approval signature uses HMAC to model the
    agent/admin separation. Production should use an admin-held
    asymmetric or hardware-backed key, never a shared secret.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Union
import hmac
import hashlib
import os
import time


class Effect(str, Enum):
    """What an action does, in checkable terms."""
    NONE             = "NONE"
    READ             = "READ"
    LETHAL           = "LETHAL"            # force/weapon directed at a person
    PHYSICAL_FORCE   = "PHYSICAL_FORCE"    # applies force (non-lethal) — needs auth
    RESTRAINT        = "RESTRAINT"          # restrains/confines a person — needs auth
    HIGH_ENERGY      = "HIGH_ENERGY"        # high-energy actuation — needs auth
    SELF_REPLICATION = "SELF_REPLICATION"  # copy/propagate self to other systems
    SENSITIVE_CAPTURE= "SENSITIVE_CAPTURE" # keystrokes/screen/mic/cam/exfiltration
    DISABLE_OVERSIGHT= "DISABLE_OVERSIGHT" # remove/bypass human oversight
    ALTER_AUDIT      = "ALTER_AUDIT"        # edit/delete the audit trail
    OTHER            = "OTHER"


# The inviolable invariants. Deliberately few and concrete.
INVARIANT_LETHAL          = "NO_AUTONOMOUS_LETHAL_DECISION"
INVARIANT_SELF_REPLICATE  = "NO_SELF_REPLICATION"
INVARIANT_COVERT_CAPTURE  = "NO_COVERT_CAPTURE_WITHOUT_CONSENT"
INVARIANT_OVERSIGHT       = "HUMAN_OVERSIGHT_CANNOT_BE_DISABLED"
INVARIANT_AUDIT           = "AUDIT_CHAIN_CANNOT_BE_DELETED"
INVARIANT_SELF_GRANT      = "AI_MAY_NOT_SELF_GRANT_CAPABILITY"
INVARIANT_CORE_MOD        = "AGENT_MAY_NOT_MODIFY_CORE_GOVERNANCE"
INVARIANT_PHYSICAL        = "PHYSICAL_ACTION_REQUIRES_AUTHORIZATION"

# Targets that an agent may never modify, even with an approval token —
# changing these would weaken every other protection. A human admin does
# this out-of-band, never the agent/coordinator path (see CONSTITUTION §6).
_CORE_TARGETS = ("coordinator", "guard", "authority", "invariant",
                 "risk_threshold", "safety_kernel", "governance", "constitution")


class GuardStatus(str, Enum):
    ALLOW                  = "ALLOW"                   # guard raises no objection
    BLOCK                  = "BLOCK"                   # hard, absolute refusal
    REQUIRES_AUTHORIZATION = "REQUIRES_AUTHORIZATION"  # needs human admin approval


@dataclass
class GuardDecision:
    status:    GuardStatus
    invariant: Optional[str] = None
    reason:    str = ""

    def to_dict(self) -> dict:
        return {"status": self.status.value,
                "invariant": self.invariant,
                "reason": self.reason}


def _env_secret() -> Optional[bytes]:
    """Optional production secret from the environment (hex or raw)."""
    v = os.environ.get("DRIFTCORE_APPROVAL_SECRET")
    if not v:
        return None
    try:
        return bytes.fromhex(v)
    except ValueError:
        return v.encode()


class ApprovalAuthority:
    """
    Models a human administrator's signing key. The AGENT DOES NOT HOLD
    `_secret`, so it cannot mint a valid token — it can only request one.

    Tokens are now:
      - bound to a specific capability_id (no cross-capability replay),
      - single-use (a nonce is consumed on first successful verify),
      - time-limited (expire after ttl_seconds).

    Secret precedence: explicit arg > DRIFTCORE_APPROVAL_SECRET env var >
    a fresh random per-process key.

    PROTOTYPE NOTE: HMAC stands in for an admin-held asymmetric/hardware
    key. The point demonstrated is the *separation* and the use limits,
    not the cipher.
    """
    def __init__(self, secret: Optional[bytes] = None):
        self._secret = secret or _env_secret() or os.urandom(32)
        self._consumed = set()   # spent nonces (single-use enforcement)

    def issue(self, capability_id: str, admin_id: str, ttl_seconds: int = 300) -> dict:
        nonce   = os.urandom(8).hex()
        expires = time.time() + ttl_seconds
        payload = f"{capability_id}|{admin_id}|{nonce}|{expires}".encode()
        sig = hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        return {"capability_id": capability_id, "admin_id": admin_id,
                "nonce": nonce, "expires": expires, "sig": sig}

    def verify(self, token: object, capability_id: str, consume: bool = True) -> bool:
        if not isinstance(token, dict):
            return False
        try:
            cap, admin, nonce = token["capability_id"], token["admin_id"], token["nonce"]
            expires, sig = float(token["expires"]), token["sig"]
        except (KeyError, TypeError, ValueError):
            return False
        if not all(isinstance(x, str) for x in (cap, admin, nonce, sig)):
            return False
        if cap != capability_id:        # bound to one capability
            return False
        if time.time() > expires:       # expired
            return False
        if nonce in self._consumed:     # already spent (single-use)
            return False
        expected = hmac.new(self._secret, f"{cap}|{admin}|{nonce}|{expires}".encode(),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return False
        if consume:
            self._consumed.add(nonce)
        return True


# Conservative free-text tripwires — best-effort EXTRA net, not the primary gate.
_LETHAL_CUES      = ("kill", "lethal", "fire on", "shoot", "attack the human",
                     "harm the", "injure", "as a weapon", "weaponize")
_REPLICATION_CUES = ("copy yourself", "replicate yourself", "propagate to",
                     "install yourself on", "spread to other", "self-replicate",
                     "clone yourself onto")
_CAPTURE_CUES     = ("keylog", "log keystrokes", "record the screen", "exfiltrate",
                     "secretly record", "covertly capture", "steal the password",
                     "skim the card", "read their card")
_OVERSIGHT_CUES   = ("disable oversight", "remove human oversight", "bypass the human",
                     "turn off oversight", "disable the kill switch")
_AUDIT_CUES       = ("delete the audit", "erase the log", "wipe the audit",
                     "rewrite the audit", "clear the history")


class InvariantGuard:
    """The hard 'cannot' layer. Deterministic, fail-closed."""

    def __init__(self, authority: Optional[ApprovalAuthority] = None):
        # The guard holds the authority; the agent path must not.
        self.authority = authority or ApprovalAuthority()

    def check(self, action: Union[dict, str], context: Optional[dict] = None) -> GuardDecision:
        ctx = context or {}
        if isinstance(action, str):
            action = self._describe(action)
        if not isinstance(action, dict):
            # Fail closed on anything we cannot reason about.
            return GuardDecision(GuardStatus.BLOCK, None,
                                 "Unparseable action — refused (fail-closed).")

        text   = str(action.get("prompt", "")).lower()
        effect = action.get("effect")

        # 1. Lethal / weapon-against-person — absolute.
        if effect == Effect.LETHAL or any(c in text for c in _LETHAL_CUES):
            return GuardDecision(GuardStatus.BLOCK, INVARIANT_LETHAL,
                                 "Action directs force/harm at a person.")

        # 1b. Non-lethal physical action — graded: never silent, needs a human.
        if effect in (Effect.PHYSICAL_FORCE, Effect.RESTRAINT, Effect.HIGH_ENERGY):
            if not bool(action.get("authorized")):
                return GuardDecision(GuardStatus.REQUIRES_AUTHORIZATION, INVARIANT_PHYSICAL,
                                     f"Physical action ({effect}) requires human authorization.")

        # 2. Self-replication / self-propagation — absolute.
        if effect == Effect.SELF_REPLICATION or any(c in text for c in _REPLICATION_CUES):
            return GuardDecision(GuardStatus.BLOCK, INVARIANT_SELF_REPLICATE,
                                 "Action would copy or propagate the system to other hosts.")

        # 3. Disabling oversight — absolute.
        if effect == Effect.DISABLE_OVERSIGHT or any(c in text for c in _OVERSIGHT_CUES):
            return GuardDecision(GuardStatus.BLOCK, INVARIANT_OVERSIGHT,
                                 "Action would disable or bypass human oversight.")

        # 4. Altering the audit trail — absolute.
        if effect == Effect.ALTER_AUDIT or any(c in text for c in _AUDIT_CUES):
            return GuardDecision(GuardStatus.BLOCK, INVARIANT_AUDIT,
                                 "Action would alter or delete the audit trail.")

        # 5. Covert capture/exfiltration WITHOUT consent — absolute.
        covert = effect == Effect.SENSITIVE_CAPTURE or any(c in text for c in _CAPTURE_CUES)
        if covert and not bool(action.get("consent")):
            return GuardDecision(GuardStatus.BLOCK, INVARIANT_COVERT_CAPTURE,
                                 "Sensitive data capture without recorded consent.")

        # 6. Propose-but-never-self-grant: capability changes need admin approval.
        if action.get("capability_change"):
            cap_id    = str(action.get("capability_id", ""))
            target    = str(action.get("target", "")).lower()
            requester = str(action.get("requester", "agent")).lower()
            # Core governance is off-limits to the agent path entirely — even
            # with a token. A human admin changes these out-of-band.
            if requester != "human_admin" and any(
                    t in cap_id.lower() or t in target for t in _CORE_TARGETS):
                return GuardDecision(GuardStatus.BLOCK, INVARIANT_CORE_MOD,
                                     "An agent may not modify core governance "
                                     "(guard / coordinator / authority / thresholds / invariants).")
            token = action.get("approval_token")
            if token is None:
                return GuardDecision(GuardStatus.REQUIRES_AUTHORIZATION, INVARIANT_SELF_GRANT,
                                     "Capability change requires human admin authorization.")
            if not self.authority.verify(token, cap_id):
                return GuardDecision(GuardStatus.BLOCK, INVARIANT_SELF_GRANT,
                                     "Approval invalid — the agent cannot grant itself capabilities.")
            # valid admin approval → the guard does not object

        return GuardDecision(GuardStatus.ALLOW)

    @staticmethod
    def _describe(prompt: str) -> dict:
        """Best-effort effect descriptor from free text. Conservative; the
        structured `action` dict is the authoritative interface."""
        return {"prompt": prompt, "effect": None}
