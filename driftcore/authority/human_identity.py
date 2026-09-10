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

    def __init__(self, used_nonces: Optional[Set[str]] = None) -> None:
        self._keys: Dict[str, bytes] = {}
        # (red-team, Grok 2026-08-14) An in-memory set means a restart RE-ARMS every
        # outstanding attestation: the approvals a human spent before the crash become
        # spendable again. Any container supporting `in` and `.add()` works here, so a
        # deployment can pass an ExpiringNonceStore / SqliteNonceStore and get the
        # durable, clock-guarded burn those modules already provide.
        #
        # HONEST LIMIT: the check and the add are atomic WITHIN this process because
        # both happen under `self._lock`. A durable store shared by SEVERAL processes
        # is not covered — these are two statements, not one transaction, and the store
        # exposes no reserve primitive. Single-process durable: yes. Multi-process
        # linearisable: no, and it must not be claimed.
        self._used: Set[str] = set() if used_nonces is None else used_nonces
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
        # (external red-team, Grok, 2026-09-01) Registering a principal HERE changes
        # what counts as a human without touching the module-level policy, so
        # policy_generation() versioned the verifier HANDLE and not its CONTENTS.
        # Confirmed live: adding a principal, and overwriting an existing
        # principal's key, both left the counter unmoved while safe_halt's
        # compare-and-swap was trusting it. Bump it from inside the mutation.
        global _generation
        with _lock:
            _generation += 1
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
            # Prefer an ATOMIC claim when the backing store offers one. `in` followed
            # by `.add()` is two statements: `self._lock` makes them indivisible
            # inside THIS process, but two processes sharing a durable store both see
            # the nonce absent and both proceed — one approval, two physical actions.
            # A store exposing `consume()` lets the database pick the winner.
            # (red-team, ChatGPT 2026-08-14)
            consume = getattr(self._used, "consume", None)
            if callable(consume):
                if not consume(att.nonce):
                    raise PermissionError(
                        f"attestation nonce already used: {att.nonce!r}")
            else:
                if att.nonce in self._used:
                    raise PermissionError(
                        f"attestation nonce already used: {att.nonce!r}")
                self._used.add(att.nonce)
            return att.principal

    def known_principals(self) -> Set[str]:
        with self._lock:
            return set(self._keys)


# ── process-wide policy ──
_lock = threading.RLock()
_verifier: Optional[HumanIdentityVerifier] = None
_registered: Set[str] = set()
# (red-team #3, 2026-09-01) This policy is process-global and PUBLICLY mutable —
# set_verifier() and register_human_principal() can change what counts as a human
# while another thread is midway through an authorization that already consulted it.
# Demonstrated: a SOFT halt release was permitted under LABEL_ONLY, the process moved
# to REGISTERED before the release committed, and the halt was cleared by a principal
# that the policy in force at commit time REFUSES — and logged as a verified human
# release. A caller that must not act on a stale policy snapshots this counter before
# deciding and compares it before committing. It is a version, not a lock: it does not
# prevent the change, it makes the change detectable.
_generation = 0

# (2026-09-06) UNCONFIGURED IS NOT PERMISSIVE.
#
# `mode()` returned LABEL_ONLY whenever nothing was configured, and LABEL_ONLY
# says yes to any name not on a six-word denylist — `agent_7`, `planner` and
# `mallory` all passed. That default is the floor every other gate in this project
# stands on, and it sat underneath five separate findings in one review.
#
# The sibling module already had this right: `EgressGuard` with no policy returns
# BLOCK_UNDECLARED and says "unconfigured is not permissive." Identity had the
# same situation and the opposite default.
_label_only_declared_by: Optional[str] = None


def declare_label_only(declared_by: str) -> None:
    """Accept that identity will not be verified in this process.

    CLAIM label-only-must-be-declared: LABEL_ONLY is reachable only through this
    call, so an unconfigured process refuses rather than trusting a name.

    `declared_by` is recorded, not checked — there is nobody to check it against
    yet, which is exactly the state being declared. Its purpose is that the
    decision has an author instead of being nobody's.
    """
    if not isinstance(declared_by, str) or not declared_by.strip():
        raise ValueError(
            "declare_label_only requires a non-empty declared_by. Accepting that "
            "identity will not be verified is a decision, and a decision with no "
            "author is how a default becomes a policy nobody chose.")
    global _label_only_declared_by, _generation
    with _lock:
        # (cold pass, 2026-09-09) IDENTITY STRENGTH ONLY INCREASES.
        #
        # Confirmed by execution: under ATTESTED a bare name is correctly refused,
        # and in-process code that called reset_policy() then declare_label_only()
        # got the same bare name accepted. The agent downgraded its own identity
        # floor and every gate standing on it.
        #
        # `reset_policy` and `set_verifier` were always in-process reachable, so
        # that half is a pre-existing limitation of running the checks inside the
        # address space being checked — the same one `mediated_actuation` exists
        # to escape, and not something a function here can fix.
        #
        # What IS fixable is the clean downgrade path this module added. Declaring
        # label-only over an installed verifier or registry is refused, so the
        # weakening now requires tearing those down first — a louder act that
        # leaves `mode()` visibly UNCONFIGURED in between. Same rule as
        # `narrowing_channel`: it may tighten and never quietly loosen.
        if _verifier is not None or _registered:
            raise PermissionError(
                f"refusing to declare label-only while identity is already "
                f"{'ATTESTED' if _verifier is not None else 'REGISTERED'}. "
                f"Declaring that identity goes unverified is a DOWNGRADE, and a "
                f"downgrade is not something a running process talks itself into.")
        _label_only_declared_by = declared_by
        _generation += 1


def undeclare_label_only() -> None:
    """Withdraw the declaration, returning the process to UNCONFIGURED.

    Separate from `reset_policy` deliberately: withdrawing consent to run
    unverified is a decision and must not be a side effect of clearing a registry.
    """
    global _label_only_declared_by, _generation
    with _lock:
        _label_only_declared_by = None
        _generation += 1


def policy_generation() -> int:
    """Monotonic version of the process-wide identity policy.

    Advances when the installed verifier changes, when a principal is registered
    (module-level or on an installed `HumanIdentityVerifier`), and on reset. Compare a
    value taken before an authorization decision against one taken before the
    resulting mutation: if they differ, the decision was made under rules that no
    longer hold.

    It versions the mutations routed through this module and through
    `HumanIdentityVerifier.register_principal`. It CANNOT see a change made by any
    other route — a custom verifier that consults an external store, a key rotated
    outside this class, a registry mutated directly. The counter is only as complete
    as the set of mutators that bump it, and a caller trusting it is trusting that
    set. An earlier version of this line claimed it advanced on EVERY change to what
    counts as a human; that was false, and it was false in the direction that made a
    compare-and-swap built on it look sound.
    """
    with _lock:
        return _generation


def set_verifier(v: Optional[HumanIdentityVerifier]) -> None:
    """Install an attestation verifier. Once set, `is_human` requires a valid
    attestation and a bare label NEVER suffices."""
    global _verifier, _generation
    with _lock:
        _verifier = v
        _generation += 1


def register_human_principal(principal: str) -> None:
    """Register a known human principal by name. Registering even ONE moves the process
    out of LABEL_ONLY: from then on, only registered names count as human."""
    if not principal or principal in _NON_HUMAN_LABELS:
        raise ValueError(f"{principal!r} cannot be a human principal")
    global _generation
    with _lock:
        _registered.add(principal)
        _generation += 1


def reset_policy() -> None:
    """Test hook: clear verifier, registry AND any label-only declaration.

    (external red-team, Grok, 2026-09-09) This cleared the verifier and registry
    and left `_label_only_declared_by` standing. Executed: declare label-only,
    register a principal (mode REGISTERED), call reset_policy() — and the process
    lands back in LABEL_ONLY carrying a STALE declaration authored by whoever
    declared first. `is_human("mallory")` is True again. A test hook plus one
    leftover declaration restores the exact floor this module was changed to
    remove.

    Clearing everything lands in UNCONFIGURED, which refuses. A caller that wants
    label-only declares it again — which is the honest sequence, because after a
    reset nobody has declared anything.
    """
    global _verifier, _generation, _label_only_declared_by
    with _lock:
        _verifier = None
        _registered.clear()
        _label_only_declared_by = None
        _generation += 1


def mode() -> str:
    with _lock:
        if _verifier is not None:
            return "ATTESTED"
        if _registered:
            return "REGISTERED"
        if _label_only_declared_by is None:
            return "UNCONFIGURED"
        return "LABEL_ONLY"


def require_secure_mode(*, context: str = "production") -> str:
    """Refuse to proceed in LABEL_ONLY. Call at deployment startup.

    `status()` already reports `secure: False` for LABEL_ONLY, and the module
    already documents that deployments SHOULD assert this. Red team (ChatGPT,
    2026-08) made the correct objection: honest documentation is not
    enforcement, and the entire original vulnerability returns if someone
    deploys without registering a principal or installing a verifier.

    So this is the assertion, in the library, callable as one line — an
    unconfigured deployment stops at startup rather than running with string
    authorization and finding out later.
    """
    m = mode()
    # (external red-team, Grok, 2026-09-09) This tested only for LABEL_ONLY and
    # so RETURNED "UNCONFIGURED" — green-lighting the exact state introduced to be
    # fail-closed. Identity was made to refuse; the function a deployment calls to
    # refuse a bad boot was not updated to know about the new mode.
    #
    # A mode enum that grows and a classifier that does not is how "we could not
    # check" starts reading as "we checked" again, one layer up.
    if m in ("LABEL_ONLY", "UNCONFIGURED"):
        raise InsecureAuthorizationMode(
            f"{context} refuses to start in LABEL_ONLY mode: human authorization "
            f"would be a string comparison, on boundaries that include "
            f"declassifying a secret and widening a physical envelope. Install a "
            f"HumanIdentityVerifier (ATTESTED) or register principals "
            f"(REGISTERED) before starting.")
    return m


class InsecureAuthorizationMode(RuntimeError):
    """Raised when a deployment would run with string-only human authorization."""


def status() -> dict:
    m = mode()
    return {
        "mode": m,
        "registered_principals": sorted(_registered),
        # Secure means identity can actually be established: a registry or a
        # verifier. UNCONFIGURED has neither and reported secure=True.
        "secure": m in ("REGISTERED", "ATTESTED"),
        "note": (
            "LABEL_ONLY is INSECURE: any string not on a six-item denylist counts as a "
            "human, so a caller that chooses its own `authorised_by` self-authorizes. It "
            "exists only so existing deployments do not change behaviour silently on "
            "upgrade. Register a principal or install a verifier. Deployment checks "
            "should assert mode() != 'LABEL_ONLY'."
            if m in ("LABEL_ONLY", "UNCONFIGURED") else
            "REGISTERED rejects labels that were never registered, but does not prove WHO "
            "acted — only ATTESTED does that."
            if m == "REGISTERED" else
            "ATTESTED: a valid signed attestation is required; a bare label never "
            "suffices. Key custody is the trust boundary."),
    }


def is_human(authorised_by: Optional[object], *, action: Optional[str] = None,
             now: Optional[float] = None,
             attestation_required: bool = False) -> bool:
    """Does `authorised_by` represent a human?

    ATTESTED   → must be a valid HumanAttestation for `action` (a bare string is False).
    REGISTERED → must be a registered principal name.
    LABEL_ONLY → legacy denylist (INSECURE — see status()).

    `attestation_required` pins the site to ATTESTED regardless of deployment mode.
    A call site that clears a SAFETY HOLD must pass it: the deployment mode is set by
    whoever configured the process, and an unconfigured process is exactly where an
    e-stop release matters most. Under LABEL_ONLY, `release(authorized_by="poppy")`
    cleared a halt and logged Poppy as the releasing human (red-team, verified by
    execution 2026-08-31: the Law Zero item-2 fix removed the default principal but
    left the type, so every string outside a six-word denylist still passed).

    Takes the literal `True`, not anything truthy — a safety opt-in that accepts `1`
    or `"yes"` can be switched on by a value that was never meant as consent.

    Never raises: callers use this as a boolean gate, and an exception escaping here
    would turn a refusal into a crash at an authorization site.
    """
    with _lock:
        v, reg = _verifier, set(_registered)

    if attestation_required is True:
        # Fail-closed, mirroring BreachResponse.acknowledge: with no way to verify a
        # human we do not clear. Better a system stuck safe than one that cleared
        # itself. Only a verified attestation passes; a label never does.
        if v is None or not isinstance(authorised_by, HumanAttestation):
            return False
    elif attestation_required is not False:
        # Neither literal True nor literal False: the caller's intent is unknown at a
        # site that decides authorisation. Refuse rather than guess.
        return False

    if isinstance(authorised_by, HumanAttestation):
        if v is None:
            return False          # attestations are meaningless with no verifier
        # CLAIM attestation-cannot-self-bind: an attestation is verified against
        # the action the CALLER names. A caller that names none is refused rather
        # than having the token supply its own.
        #
        # (external red-team, 2026-09-04) This was
        # `action=action or authorised_by.action`. With `action` omitted, the
        # attestation verified against ITSELF: whatever it claimed to be for was
        # what it was checked for, so a token issued for `declassify` satisfied a
        # call site that forgot to say what it was authorising. Confirmed by
        # execution — cross-action substitution was refused when `action=` was
        # passed and accepted when it was not.
        #
        # Same class as "truthiness is not consent", one level up: OMISSION IS
        # NOT BINDING. The earlier sweep that cleared action-binding always
        # passed `action=`, which proved the binding works and never tested the
        # case where a caller forgets — the property was checked in the
        # configuration that could not fail.
        if action is None:
            # Not "use the token's own action". A caller that names nothing gets
            # nothing. The three `_is_human` helpers each supply a module-level
            # default so no call site silently omits one; that binding is COARSER
            # than per-operation and is deliberately a first step. Making it
            # per-operation is a 23-caller migration across 28 files, measured,
            # and is its own piece of work rather than a change to slip in
            # alongside this one.
            return False
        try:
            v.verify(authorised_by, action=action, now=now)
            return True
        except Exception:
            return False

    if v is not None:
        # Strongest mode: a label alone is never a human.
        return False
    if reg:
        return isinstance(authorised_by, str) and authorised_by in reg
    if _label_only_declared_by is None:
        # UNCONFIGURED. The denylist below cannot establish that a caller is human,
        # only that they avoided six words. Returning True from it when nobody
        # chose that policy is "we could not check" reading as "we checked".
        return False

    return (isinstance(authorised_by, str)
            and authorised_by not in _NON_HUMAN_LABELS)
