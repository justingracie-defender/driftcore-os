"""
driftcore/authority/human_identity.py
=====================================
STATUS: PROPOSED (stdlib-only). WHO COUNTS AS A HUMAN.

WHY THIS EXISTS. Three modules — `skills/governance.py`, `authority/resolver.py` and
`recovery/store.py` — each carried an identical private helper:

    def _is_human(authorised_by):
        return authorised_by not in ("", "system", "auto", "auto-sign",
                                     "agent", "reflection", None)

That is a RESERVED-WORD BLACKLIST, and it means every one of these returns True:

    _is_human("mallory")          -> True
    _is_human("planner_agent_7")  -> True
    _is_human("operator")         -> True

A planner that can choose the string it passes can therefore self-authorize through skill
governance, authority override, and recovery/restore. This was found by external review,
and it sits UNDERNEATH the parts of the system that check credentials properly: the
actuation wall verifies signed grants correctly, and then a different path accepts the
word "operator" as a person.

Human sovereignty is the load-bearing idea in this architecture. If "human" means "a
string that isn't on a six-item denylist", the sovereignty is decorative.

────────────────────────────────────────────────────────────────────────────────────────
THREE MODES, and a deployment can tell which one it is in.

  ATTESTED   — an attestation verifier is configured. `authorised_by` must present a
               valid HMAC-signed HumanAttestation. This is the real check: a label alone
               never suffices, so an agent cannot self-authorize by picking a name.

  REGISTERED — one or more human principals have been registered by name. Only those
               names count. No attestation, so it does not prove WHO acted, but an agent
               cannot invent a principal that was never registered. Fail-closed against
               unknown labels.

  LABEL_ONLY — nothing configured. Falls back to the legacy denylist. THIS IS INSECURE
               and is reported as such by `mode()` and `status()`. It exists only so that
               existing deployments do not change behaviour silently on upgrade; it is
               not a safe configuration and must not be used where a planner controls
               the `authorised_by` value.

Registering a single principal, or a single key, moves the whole process out of
LABEL_ONLY. Deployment checks should assert `mode() != "LABEL_ONLY"`.

HONEST LIMITS:
  * An attestation proves a HOLDER OF THE KEY approved this action. It does not prove a
    human was awake, understood, or was not coerced. Key custody is the boundary.
  * Attestations are HMAC — symmetric. Anyone who can read the key can mint one. Real
    deployments should move to asymmetric signatures with hardware-held keys.
  * This module governs IDENTITY only. Whether that human was ALLOWED to authorize this
    particular action is the authority resolver's job, not this one's.
"""
from __future__ import annotations

import hashlib
import hmac
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional, Set

# The legacy denylist. Retained ONLY for LABEL_ONLY mode, and named honestly.
_NON_HUMAN_LABELS = ("", "system", "auto", "auto-sign", "agent", "reflection")


@dataclass(frozen=True)
class HumanAttestation:
    """A signed statement that a specific human principal approved a specific action.

    Mirrors `signed_permission.Grant` deliberately: same shape, same failure modes, same
    reasoning. A nonce makes it single-use; `action` binds it so an attestation for one
    action cannot be replayed onto another.
    """
    principal: str
    action: str
    issued_at: float
    expires_at: float
    nonce: str
    sig: str

    @staticmethod
    def _payload(principal: str, action: str, issued_at: float,
                 expires_at: float, nonce: str) -> bytes:
        # Field-separated so that ("ab","c") and ("a","bc") cannot collide.
        return "\x1f".join([principal, action, f"{issued_at:.6f}",
                            f"{expires_at:.6f}", nonce]).encode("utf-8")

    @classmethod
    def issue(cls, key: bytes | str, *, principal: str, action: str,
              ttl_seconds: float, nonce: str,
              now: Optional[float] = None) -> "HumanAttestation":
        if not principal or not isinstance(principal, str):
            raise ValueError("principal must be a non-empty string")
        if not action or not isinstance(action, str):
            raise ValueError("action must be a non-empty string")
        if not nonce or not isinstance(nonce, str):
            raise ValueError("nonce must be a non-empty string")
        if not (0 < float(ttl_seconds) <= 86400):
            # No unbounded attestations: an approval that never expires is a standing
            # grant nobody remembers issuing.
            raise ValueError("ttl_seconds must be in (0, 86400]")
        t = time.time() if now is None else float(now)
        exp = t + float(ttl_seconds)
        k = key.encode("utf-8") if isinstance(key, str) else key
        sig = hmac.new(k, cls._payload(principal, action, t, exp, nonce),
                       hashlib.sha256).hexdigest()
        return cls(principal=principal, action=action, issued_at=t,
                   expires_at=exp, nonce=nonce, sig=sig)


class HumanIdentityVerifier:
    """Holds human principal keys and verifies attestations. Thread-safe."""

    def __init__(self) -> None:
        self._keys: Dict[str, bytes] = {}
        self._used: Set[str] = set()
        self._lock = threading.RLock()

    def register_principal(self, principal: str, key: bytes | str) -> None:
        if not principal or not isinstance(principal, str):
            raise ValueError("principal must be a non-empty string")
        if principal in _NON_HUMAN_LABELS:
            raise ValueError(
                f"{principal!r} is a reserved non-human label and cannot be registered "
                f"as a human principal")
        k = key.encode("utf-8") if isinstance(key, str) else key
        if not k:
            raise ValueError("key must be non-empty")
        with self._lock:
            self._keys[principal] = k

    def verify(self, att: HumanAttestation, *, action: str,
               now: Optional[float] = None) -> str:
        """Return the principal name if the attestation is valid; raise otherwise.
        Every failure is an exception — there is no falsy 'not verified' return that a
        caller could accidentally treat as success."""
        if not isinstance(att, HumanAttestation):
            raise PermissionError("not a HumanAttestation")
        t = time.time() if now is None else float(now)
        with self._lock:
            key = self._keys.get(att.principal)
            if key is None:
                raise PermissionError(f"unknown human principal {att.principal!r}")
            expect = hmac.new(key, HumanAttestation._payload(
                att.principal, att.action, att.issued_at, att.expires_at, att.nonce),
                hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expect, att.sig):
                raise PermissionError("attestation signature invalid")
            if t >= att.expires_at:
                raise PermissionError("attestation expired")
            if t < att.issued_at - 1:
                raise PermissionError("attestation not yet valid")
            if att.action != action:
                raise PermissionError(
                    f"attestation is for action {att.action!r}, not {action!r}")
            if att.nonce in self._used:
                raise PermissionError(f"attestation nonce already used: {att.nonce!r}")
            self._used.add(att.nonce)
            return att.principal

    def known_principals(self) -> Set[str]:
        with self._lock:
            return set(self._keys)


# ── process-wide policy ──
_lock = threading.RLock()
_verifier: Optional[HumanIdentityVerifier] = None
_registered: Set[str] = set()


def set_verifier(v: Optional[HumanIdentityVerifier]) -> None:
    """Install an attestation verifier. Once set, `is_human` requires a valid
    attestation and a bare label NEVER suffices."""
    global _verifier
    with _lock:
        _verifier = v


def register_human_principal(principal: str) -> None:
    """Register a known human principal by name. Registering even ONE moves the process
    out of LABEL_ONLY: from then on, only registered names count as human."""
    if not principal or principal in _NON_HUMAN_LABELS:
        raise ValueError(f"{principal!r} cannot be a human principal")
    with _lock:
        _registered.add(principal)


def reset_policy() -> None:
    """Test hook: clear verifier and registry."""
    global _verifier
    with _lock:
        _verifier = None
        _registered.clear()


def mode() -> str:
    with _lock:
        if _verifier is not None:
            return "ATTESTED"
        if _registered:
            return "REGISTERED"
        return "LABEL_ONLY"


def status() -> dict:
    m = mode()
    return {
        "mode": m,
        "registered_principals": sorted(_registered),
        "secure": m != "LABEL_ONLY",
        "note": (
            "LABEL_ONLY is INSECURE: any string not on a six-item denylist counts as a "
            "human, so a caller that chooses its own `authorised_by` self-authorizes. It "
            "exists only so existing deployments do not change behaviour silently on "
            "upgrade. Register a principal or install a verifier. Deployment checks "
            "should assert mode() != 'LABEL_ONLY'."
            if m == "LABEL_ONLY" else
            "REGISTERED rejects labels that were never registered, but does not prove WHO "
            "acted — only ATTESTED does that."
            if m == "REGISTERED" else
            "ATTESTED: a valid signed attestation is required; a bare label never "
            "suffices. Key custody is the trust boundary."),
    }


def is_human(authorised_by: Optional[object], *, action: Optional[str] = None,
             now: Optional[float] = None) -> bool:
    """Does `authorised_by` represent a human?

    ATTESTED   → must be a valid HumanAttestation for `action` (a bare string is False).
    REGISTERED → must be a registered principal name.
    LABEL_ONLY → legacy denylist (INSECURE — see status()).

    Never raises: callers use this as a boolean gate, and an exception escaping here
    would turn a refusal into a crash at an authorization site.
    """
    with _lock:
        v, reg = _verifier, set(_registered)

    if isinstance(authorised_by, HumanAttestation):
        if v is None:
            return False          # attestations are meaningless with no verifier
        try:
            v.verify(authorised_by, action=action or authorised_by.action, now=now)
            return True
        except Exception:
            return False

    if v is not None:
        # Strongest mode: a label alone is never a human.
        return False
    if reg:
        return isinstance(authorised_by, str) and authorised_by in reg
    return (isinstance(authorised_by, str)
            and authorised_by not in _NON_HUMAN_LABELS)
