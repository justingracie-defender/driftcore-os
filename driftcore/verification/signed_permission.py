"""
driftcore/verification/signed_permission.py
===========================================
STATUS: PROPOSED (stdlib-only). The UNIVERSAL authorization primitive.

THE PRINCIPLE THAT KEEPS DRIFTCORE UNIVERSAL. A permission is a signed, scoped,
expiring grant. DriftCore verifies that a grant is:
  * authentically signed by a key it trusts,
  * not expired,
  * not replayed (nonce),
  * and that the action falls WITHIN the grant's declared scope.
DriftCore does NOT know what "admin", "trusted adult", or "kid" means. The ROLE
HIERARCHY — who outranks whom, what each tier may authorize — is DEPLOYMENT POLICY
carried INSIDE the grant (its `role`, `scope`, and which key signed it). A hospital,
a bank, and a family robot all use this same primitive; only the payload differs.

    LifeCore example (the ladder lives in the DATA, not in this code):
      parent  -> key P, may sign grants with any scope
      adult   -> key A, may sign scopes {household, doors, media}
      kid     -> key K, may sign scopes {media:child_safe}
    DriftCore just checks: "is this grant validly signed by an authorized key,
    unexpired, unreplayed, and does the requested action fit its scope?" It never
    hardcodes that parent > adult > kid. LifeCore expresses that by which keys it
    installs and what scopes it lets each sign.

WHY SIGNED (not a role string in context). A role passed as plain context
(`ctx["role"]="admin"`) is forgeable by the planner — the exact context-provenance
hole THREAT_BOUNDARIES §8 names. A grant must be SIGNED by an authority key the
agent does not hold, so the agent cannot mint its own authorization. This is the
same "evidence grants authority" discipline as the rest of DriftCore, applied to
permissions.

SCOPE MATCHING. Scope is a set of capability tokens. A grant authorizes an action
iff EVERY capability the action requires is covered by the grant's scope. Matching
supports exact tokens and a single trailing wildcard segment (`doors:*` covers
`doors:front`), and is otherwise literal — no clever globbing, so scope creep is
hard. Required capabilities come from the ACTION (structural), never from the
grant's self-description.

HONEST LIMITS (named, per the TCB doc):
  * KEY CUSTODY is the whole game. If the agent can read the signing key (shared
    process memory), it can mint grants — same turtle as signed_config. The key
    belongs in the broker / a separate process. This module VERIFIES; it does not
    solve custody. Verification key(s) live in a trusted registry the deployment
    populates.
  * This authorizes; it does not ENFORCE execution. A verified grant says "this was
    permitted"; binding it to the actual actuation (so the executor cannot
    substitute the action) is MEDIATED ACTUATION (§8). A grant here SHOULD carry an
    action binding (actuator+command+params hash) so the actuation layer can check
    the executed action matches — the field exists; the enforcement is that layer.
  * Revocation is by expiry + nonce-burn here; long-lived revocation lists are a
    deployment concern (a revoked key is removed from the registry).
"""
from __future__ import annotations

import hmac
import json
import threading
import time
import hashlib
from dataclasses import dataclass, field
from typing import Dict, Iterable, Optional, Tuple, Union

KeyLike = Union[str, bytes]
_ALG = "HMAC-SHA256"


class PermissionError_(Exception):
    """Base for all permission failures. (Named with trailing underscore to avoid
    shadowing the builtin PermissionError.)"""


class InvalidSignature(PermissionError_):
    pass


class PermissionExpired(PermissionError_):
    pass


class PermissionReplay(PermissionError_):
    pass


class ScopeExceeded(PermissionError_):
    pass


class UnknownSigner(PermissionError_):
    pass


def _canonical(obj) -> bytes:
    # allow_nan=False makes json.dumps RAISE on NaN/Infinity at ANY depth. The first
    # attempt at this walked the top level of params by hand and missed
    # {"body": {"f": nan}} and {"vals": [inf]} — the same only-checked-the-first-level
    # mistake as the egress decoy-parameter bug. Handing the rule to the serializer
    # turns a walk that can miss a case into a property that cannot: every value that
    # reaches a hash is finite, or nothing is hashed at all.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _finite(x: float, label: str) -> float:
    """Reject NaN/Infinity in a timestamp. Non-finite values break the expiry check
    silently (`now >= NaN` is always False -> a grant that NEVER expires) and produce
    invalid JSON (`json.dumps` emits literal NaN, which strict parsers reject). Both
    are fail-OPEN, the worst failure mode for an auth primitive. Found in red-team."""
    import math as _math
    if not isinstance(x, (int, float)) or isinstance(x, bool) or not _math.isfinite(float(x)):
        raise ScopeExceeded(f"non-finite or invalid {label}: {x!r} (must be a finite number)")
    return float(x)


def _resolve(key: KeyLike) -> bytes:
    if isinstance(key, str):
        key = key.encode("utf-8")
    if not isinstance(key, (bytes, bytearray)) or not key:
        raise UnknownSigner("empty/invalid verification key")
    return bytes(key)


@dataclass(frozen=True)
class Grant:
    """A signed permission. `role` and `scope` are DEPLOYMENT semantics (opaque to
    DriftCore). `key_id` names the signer. `action_binding` optionally pins the
    exact action (for mediated actuation to check the executor). Sign with
    `Grant.issue(...)`; verify with a PermissionVerifier."""
    key_id: str                       # which authority key signed this
    role: str                         # deployment role label (opaque here)
    scope: Tuple[str, ...]            # capability tokens this grant authorizes
    subject: str                      # who/what the grant is for (e.g. an agent/owner id)
    issued_at: float
    expires_at: float
    nonce: str
    action_binding: Optional[str] = None   # optional hash pinning a specific action
    sig: str = ""

    def _payload(self) -> dict:
        return {"alg": _ALG, "key_id": self.key_id, "role": self.role,
                "scope": list(self.scope), "subject": self.subject,
                "issued_at": self.issued_at, "expires_at": self.expires_at,
                "nonce": self.nonce, "action_binding": self.action_binding}

    @staticmethod
    def issue(key: KeyLike, *, key_id: str, role: str, scope: Iterable[str],
              subject: str, ttl_seconds: float, nonce: str,
              action_binding: Optional[str] = None, now: Optional[float] = None) -> "Grant":
        t = time.time() if now is None else now
        t = _finite(t, "issued_at")
        ttl = _finite(ttl_seconds, "ttl_seconds")
        g = Grant(key_id=key_id, role=role, scope=tuple(scope), subject=subject,
                  issued_at=t, expires_at=t + ttl, nonce=nonce,
                  action_binding=action_binding)
        sig = hmac.new(_resolve(key), _canonical(g._payload()), hashlib.sha256).hexdigest()
        return Grant(**{**g.__dict__, "sig": sig})

    def to_dict(self) -> dict:
        return {**self._payload(), "sig": self.sig}

    @staticmethod
    def from_dict(d: dict) -> "Grant":
        return Grant(key_id=d["key_id"], role=d["role"], scope=tuple(d.get("scope", ())),
                     subject=d["subject"], issued_at=d["issued_at"],
                     expires_at=d["expires_at"], nonce=d["nonce"],
                     action_binding=d.get("action_binding"), sig=d.get("sig", ""))


def _scope_covers(scope: Tuple[str, ...], required: str) -> bool:
    """True if `required` capability is covered by any token in `scope`. Supports a
    single trailing '*' segment: 'doors:*' covers 'doors:front' but NOT
    'doors:front:unlock' (exactly ONE additional segment — found in red-team: the old
    prefix match covered infinite depth, so 'media:*' wrongly authorized
    'media:admin:delete_user'). Otherwise exact."""
    for tok in scope:
        if tok == required:
            return True
        if tok == "*":                     # a full wildcard scope (use sparingly)
            return True
        if tok.endswith(":*"):
            prefix = tok[:-2]              # 'doors:*' -> 'doors'
            if required.startswith(prefix + ":"):
                # exactly one more segment: the remainder must contain no further ':'
                remainder = required[len(prefix) + 1:]
                if remainder and ":" not in remainder:
                    return True
    return False


class PermissionVerifier:
    """Verifies grants against a registry of trusted signer keys the DEPLOYMENT
    populates. DriftCore-universal: it checks signature/expiry/replay/scope, never
    role meaning. Burned nonces are tracked in-memory here; for durable/cross-
    instance replay defense, back it with the AuthorizationState store (the nonce
    check is intentionally the same shape)."""

    def __init__(self, *, clock=time.time, used_nonces: Optional[set] = None):
        self._keys: Dict[str, bytes] = {}         # key_id -> verification key
        self._clock = clock
        self._used = used_nonces if used_nonces is not None else set()
        # (red-team, external) verify() CHECKED the nonce but did not BURN it, and
        # consume() was a separate public call. With any work between them the check
        # and the burn are not atomic: 8 threads racing one single-use grant all
        # verified successfully. The broker had 26 lines — including the cumulative
        # ledger gate — between its verify and its consume.
        #
        # A plain verify_and_consume() would close the race but burn the nonce BEFORE
        # the ledger gate runs, so a request the ledger legitimately refuses would still
        # spend a single-use grant — trading replay for grant exhaustion. Instead:
        # RESERVE (atomic check + mark in-flight) -> run the gates -> COMMIT or RELEASE.
        self._reserved: set = set()
        self._nonce_lock = threading.RLock()

    # ── trusted key registry (deployment / broker populates) ──
    def register_key(self, key_id: str, key: KeyLike) -> None:
        """Install a signer the deployment trusts. Which keys exist, and what each
        is allowed to sign, IS the role hierarchy — expressed as data, not code."""
        self._keys[key_id] = _resolve(key)

    def revoke_key(self, key_id: str) -> None:
        self._keys.pop(key_id, None)

    # ── verification ──
    def verify(self, grant: Grant, *, required_scope: Iterable[str] = (),
               expected_subject: Optional[str] = None,
               action_binding: Optional[str] = None,
               allowed_signers: Optional[Iterable[str]] = None) -> Grant:
        """Return the grant iff it is authentic, unexpired, unreplayed, and covers
        every capability in `required_scope`. Raises a specific PermissionError_
        subclass otherwise. `allowed_signers` optionally restricts WHICH key_ids are
        acceptable for THIS action (e.g. 'only a parent-tier key may authorize
        this') — that restriction is the deployment expressing its hierarchy.
        `action_binding`, if given, must match the grant's pinned action."""
        key = self._keys.get(grant.key_id)
        if key is None:
            raise UnknownSigner(f"grant signed by unknown/untrusted key_id {grant.key_id!r}")
        if allowed_signers is not None and grant.key_id not in set(allowed_signers):
            raise UnknownSigner(
                f"key_id {grant.key_id!r} is not permitted to authorize this action")

        expected_sig = hmac.new(key, _canonical(grant._payload()), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(grant.sig), expected_sig):   # constant-time
            raise InvalidSignature("grant signature does not verify (altered or wrong key)")

        # Reject non-finite timestamps BEFORE the expiry comparison. A NaN expiry
        # would make `now >= expires_at` always False -> a grant that never expires
        # (fail-open). Found in red-team.
        _finite(grant.expires_at, "expires_at")
        _finite(grant.issued_at, "issued_at")

        now = self._clock()
        if now >= grant.expires_at:
            raise PermissionExpired(
                f"grant expired at {grant.expires_at} (now {now:.0f})")
        if now < grant.issued_at - 1:      # small skew tolerance
            raise PermissionExpired("grant not yet valid (issued in the future)")
        # Upper bound on how far in the future a grant may be dated: defends against a
        # captured future-dated grant becoming valid after a forward clock jump.
        if grant.issued_at > now + 300:    # 5 min ceiling (generous for NTP skew)
            raise PermissionExpired(
                f"grant issued too far in the future ({grant.issued_at} > now+300)")

        if grant.nonce in self._used:
            raise PermissionReplay(f"grant nonce already used: {grant.nonce!r}")
        # (red-team) an IN-FLIGHT nonce is not yet burned but must not verify again.
        if grant.nonce in getattr(self, "_reserved", ()):
            raise PermissionReplay(
                f"grant nonce {grant.nonce!r} is already in flight (concurrent use)")

        if expected_subject is not None and grant.subject != expected_subject:
            raise ScopeExceeded(
                f"grant subject {grant.subject!r} != expected {expected_subject!r}")

        if action_binding is not None and grant.action_binding != action_binding:
            raise ScopeExceeded("grant is not bound to this action (action_binding mismatch)")

        for cap in required_scope:
            if not _scope_covers(grant.scope, cap):
                raise ScopeExceeded(
                    f"action requires capability {cap!r} not covered by grant scope {grant.scope}")

        return grant

    def reserve(self, grant: Grant, *, required_scope: Iterable[str] = (),
                expected_subject: Optional[str] = None,
                action_binding: Optional[str] = None) -> Grant:
        """ATOMIC check-and-hold. Verifies the grant and marks its nonce IN-FLIGHT under
        one lock, so a concurrent caller cannot verify the same single-use grant.

        The caller MUST follow with exactly one of:
          * `commit(grant)`  — the action happened; burn the nonce permanently
          * `release(grant)` — the action was refused BEFORE any side effect; the nonce
                               becomes usable again

        A crash between reserve and commit leaves the nonce RESERVED, i.e. unusable. That
        is deliberate: for a single-use credential, failing closed on an unknown outcome
        is the safe direction — better a grant that must be reissued than one that might
        be spent twice.
        """
        with self._nonce_lock:
            if grant.nonce in self._reserved:
                raise PermissionReplay(
                    f"grant nonce {grant.nonce!r} is already in flight (concurrent use)")
            g = self.verify(grant, required_scope=required_scope,
                            expected_subject=expected_subject,
                            action_binding=action_binding)
            self._reserved.add(grant.nonce)
            return g

    def commit(self, grant: Grant) -> None:
        """The action happened: burn the nonce permanently and drop the reservation."""
        with self._nonce_lock:
            self._used.add(grant.nonce)
            self._reserved.discard(grant.nonce)

    def release(self, grant: Grant) -> None:
        """The action was refused BEFORE any side effect: return the nonce to the pool.
        Never call this after the actuator has run — that would permit a genuine replay."""
        with self._nonce_lock:
            self._reserved.discard(grant.nonce)

    def in_flight(self) -> int:
        """Reservations currently held. A number that only grows indicates callers that
        reserve and then neither commit nor release."""
        with self._nonce_lock:
            return len(self._reserved)

    def consume(self, grant: Grant) -> None:
        """Burn the grant's nonce so it cannot be replayed. Call after a
        single-use grant has been acted on. (Durable/shared burn: back `used_nonces`
        with AuthorizationState.)"""
        self._used.add(grant.nonce)

    @staticmethod
    def bind_action(actuator_id: str, command: str, params: Optional[dict] = None,
                    broker_id: Optional[str] = None,
                    effects_hash: Optional[str] = None) -> str:
        """Compute the action_binding hash a grant should carry to pin a specific
        actuation. The actuation layer recomputes this from what it is about to
        execute and checks it matches — so the executor cannot substitute the
        action (the TOCTOU defense; enforcement lives in mediated actuation).

        effects_hash (optional) BINDS THE GRANT TO THE EFFECT DECLARATION that was
        current when it was issued. Without it, a grant is bound to WHAT is executed
        but not to WHAT THAT ACTUATOR WAS DECLARED TO DO — so an operator (or a
        compromised broker) can issue a grant against a LETHAL declaration, downgrade
        the registry to NONE with replace=True, and the grant then executes under the
        weaker floor. Upgrading fails closed; downgrading executed. Including the
        declaration in the binding means the hash no longer matches after any change,
        and the action is refused. BACKWARD-COMPATIBLE the same way broker_id is: when
        omitted the hash is computed exactly as before.

        broker_id (optional) BINDS THE GRANT TO A SPECIFIC BROKER. This closes the
        cross-broker replay gap: without it, a grant's single-use nonce is tracked
        per-broker, so a grant approved for one broker could be replayed against a
        different broker that shares the signing key. Binding the broker_id means a
        grant for broker-A simply does not match broker-B — the hash differs, and
        broker-B refuses. It does NOT limit how many grants an agent may hold or use
        in parallel; it only keeps each pre-approved action bound to the exact broker
        it was approved for. BACKWARD-COMPATIBLE: when broker_id is omitted, the hash
        is byte-identical to the pre-broker-binding behavior, so existing grants and
        single-broker deployments are unaffected."""
        # NaN / Infinity are refused rather than hashed. json.dumps accepts them by
        # default and emits the non-standard tokens NaN/Infinity, which other languages
        # serialize differently or reject outright — so a grant minted by one runtime
        # could fail to match, or in the worst case match something it should not. A
        # value that cannot be canonically represented cannot be bound to.
        payload = {"actuator_id": actuator_id, "command": command,
                   "params": params or {}}
        if broker_id is not None:
            payload["broker_id"] = broker_id
        if effects_hash is not None:
            payload["effects_hash"] = effects_hash
        try:
            return hashlib.sha256(_canonical(payload)).hexdigest()
        except ValueError as e:
            raise ValueError(
                f"these parameters cannot be canonically represented ({e}). NaN and "
                f"Infinity have no standard JSON form — other runtimes serialize them "
                f"differently or reject them — so an action containing one cannot be "
                f"bound, and an unbindable action is not approvable.") from e
