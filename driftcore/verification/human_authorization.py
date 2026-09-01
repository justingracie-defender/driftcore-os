"""
human_authorization.py — make "a human approved this" a checkable fact.

WHY THIS EXISTS
---------------
Before this module, `mediated_actuation` proved something narrower than the safety
case implied. A `Grant` is signed with an operator KEY, and the wall checks the
signature. So the wall's real statement is:

    "something holding the signing key authorised this exact action"

not

    "a human authorised this exact action".

Those come apart in every case that matters. A stolen key, a key left in a config
file, an automation minting its own grants, or an agent that reached the key store
all produce a grant that verifies perfectly and looks approved. The action binding
was excellent at pinning WHAT executes and silent on WHO agreed to it.

The repo already had the right primitive — `driftcore/authority/human_identity.py`,
with signed `HumanAttestation`s, registered principals, bounded TTLs and single-use
nonces. It was wired into physical_envelope, information_flow, skills governance,
restart_authority and recovery — and NOT into the wall, the one place where the
consequence is physical. This module is the join, and it deliberately reuses that
primitive rather than growing a third weaker copy of it (the lesson from two modules
that each reinvented `_is_human()` as a string comparison).

THE PROTOCOL
------------
Three stages, each failing closed.

  1. EFFECT IDENTITY. `effect_id()` is the canonical hash of the exact executable
     effect: actuator, command, every parameter (so target, force and duration are
     covered whenever they travel in params), broker, the effect declaration
     including implementation identity, and the safety envelope digest.
     It is `PermissionVerifier.bind_action` with the attestation omitted — the SAME
     canonicalisation the wall already uses, not a parallel one that could drift.

  2. THE HUMAN SIGNS THAT IDENTITY. The attestation's `action` field IS the
     effect_id. This is the structural weld: the human's HMAC covers a hash of the
     effect, target, parameters, duration, device, declaration and envelope. A
     human who approved a 20N grip on a cup has not approved a 900N grip on a
     knife, because that is a different effect_id and the signature will not verify
     against it.

  3. THE GRANT PINS THE APPROVAL. `attestation_digest()` goes into the grant's
     `action_binding`, so grant and attestation are a matched pair. A key holder
     cannot pair their grant with some other valid attestation, and an attestation
     cannot be re-used under a differently-scoped grant.

WHAT THIS DOES NOT DO — read before quoting it in a safety case
---------------------------------------------------------------
* REPRESENTATION IS AUTHORITY, and this is deliberate. The effect identity is a hash
  of the canonical JSON of the Python object as given. So `{"force_n": 20}` and
  `{"force_n": 20.0}` are DIFFERENT approvals, as are `True` and `1`, and as are two
  strings that differ only by Unicode normalisation. Key ORDER is neutralised; value
  representation is not. The consequence an integrator must plan for: whatever is
  signed must be reproduced exactly at request time, and a UI layer that helpfully
  coerces `20` to `20.0` will produce approvals that never verify.
  This is the safe failure direction — a mismatch refuses — and the alternative is
  worse: any normalisation inside the gate is a rule about what counts as "the same
  action", and that rule would be applied by code the human never saw. If a
  deployment needs numeric semantic equality, it belongs in an audited normalisation
  step BEFORE the human signs, never inside this module. (red-team, Grok 2026-08-14)
* It does not prove a human UNDERSTOOD the action. It proves a registered principal's
  key signed this exact effect identity. Whether the approval surface showed them
  something faithful is an integration property this cannot reach. Rendering an
  effect_id back into something a person can actually read is the deployer's job and
  is where a deceptive approval would live.
* It does not prove the human was PRESENT. A principal key sitting in a script is a
  human-shaped automation. That is the same class of problem as the operator key and
  it moves the trust to key custody — which is exactly where it should be, and no
  further.
* Envelope binding pins a DIGEST. DriftCore holds no physical values (see §0b of
  000_AI_START_HERE.md): it cannot tell you 60N is sane for a kitchen. It can tell
  you the envelope in force at execution is byte-identical to the one in force at
  approval, and refuse when it is not.
* An attestation is single-use by nonce, enforced by HumanIdentityVerifier. The
  crypto check is therefore run LATE in the broker pipeline, after the gates that
  can refuse for unrelated reasons, so a ledger refusal does not burn a human's
  approval. The structural pairing check runs early because it has no side effect.
  This ordering is deliberate; see the wiring in mediated_actuation._handle.

Run: python3 test_human_authorization.py
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Optional

from driftcore.verification.signed_permission import PermissionVerifier
from driftcore.authority.human_identity import (
    HumanAttestation, HumanIdentityVerifier)


class HumanApprovalError(PermissionError):
    """Raised when an action is not provably backed by a human approval.

    A subclass of PermissionError so a caller that already fails closed on
    PermissionError does not silently let this through as a different exception.
    """


def _canonical_bytes(obj: Any) -> bytes:
    """Same canonical form the binding uses: sorted keys, no NaN, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def envelope_digest(declaration: Optional[Mapping[str, Any]]) -> Optional[str]:
    """Digest of the safety constraints in force, whatever they are.

    DriftCore does not interpret this. It is deliberately opaque: a mapping the
    deployment (LifeCore, or an industrial integrator) declares, hashed. The
    property being bought is not "the envelope is correct" — DriftCore cannot know
    that — it is "the envelope at execution is the envelope at approval".

    None in, None out, so an unconfigured deployment keeps byte-identical bindings
    rather than being silently pinned to the digest of an empty dict. Whether a
    missing envelope is ACCEPTABLE is the gate's decision, not this function's.
    """
    if declaration is None:
        return None
    if not isinstance(declaration, Mapping):
        raise HumanApprovalError(
            "envelope declaration must be a mapping; a bare string or number cannot "
            "be canonically compared and would bind to nothing checkable")
    try:
        return hashlib.sha256(_canonical_bytes(dict(declaration))).hexdigest()
    except ValueError as e:
        raise HumanApprovalError(
            f"envelope declaration cannot be canonically represented ({e}). An "
            f"envelope containing NaN or Infinity cannot be bound to, and an "
            f"unbindable envelope is not approvable.") from e


def effect_id(actuator_id: str, command: str, params: Optional[dict] = None,
              *, broker_id: Optional[str] = None,
              effects_hash: Optional[str] = None,
              envelope_hash: Optional[str] = None,
              subject: Optional[str] = None) -> str:
    """The canonical identity of the exact executable effect — what a human signs.

    Note what is NOT a parameter here: `attestation_hash`. The human signs the
    effect; the grant then pins the human. Folding the attestation into the thing
    the attestation covers would be circular.
    """
    if not actuator_id or not isinstance(actuator_id, str):
        raise HumanApprovalError("actuator_id must be a non-empty string")
    if not command or not isinstance(command, str):
        raise HumanApprovalError("command must be a non-empty string")
    # bind_action raises ValueError for a value that has no canonical form (NaN,
    # Infinity). A bare ValueError escapes a caller that fails closed on
    # PermissionError and surfaces as a generic broker error with the reason lost —
    # the "refused for an unrecorded reason" pattern this repo has fixed before. It
    # is a refusal, so it is raised as one, message intact.
    try:
        return PermissionVerifier.bind_action(
            actuator_id, command, params, broker_id=broker_id,
            effects_hash=effects_hash, envelope_hash=envelope_hash, subject=subject)
    except (ValueError, TypeError) as e:
        # ValueError: NaN / Infinity. TypeError: an object with no JSON form at all.
        # Both mean the same thing — this action has no canonical identity, so it
        # cannot be approved — and both must arrive as a refusal, not as a stray
        # exception a fail-closed caller never sees.
        raise HumanApprovalError(
            f"these parameters cannot be canonically represented, so this action "
            f"has no stable identity to approve: {e}") from e


def attestation_digest(att: HumanAttestation) -> str:
    """Pin ONE attestation instance.

    Covers the principal, the effect identity they signed, the validity window, the
    nonce and the signature. Including `sig` is what makes this an instance pin
    rather than a description: two attestations that agree on every visible field
    but were signed by different keys are different approvals, and a grant bound to
    one must not accept the other.
    """
    if not isinstance(att, HumanAttestation):
        raise HumanApprovalError(
            "attestation_digest requires a HumanAttestation; a dict or a bare "
            "string is the exact substitution this exists to refuse")
    payload = {"principal": att.principal, "action": att.action,
               "issued_at": float(att.issued_at), "expires_at": float(att.expires_at),
               "nonce": att.nonce, "sig": att.sig}
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


class HumanApprovalGate:
    """Verifies that an action is backed by a human approval bound to THAT action.

    Opt-in and inert when not configured: a broker constructed without one behaves
    exactly as before. Constructed WITH one, every actuation must present an
    attestation — there is no per-request opt-out, because a gate a caller can
    decline is not a gate.
    """

    def __init__(self, verifier: HumanIdentityVerifier, *,
                 require_envelope: bool = False) -> None:
        if not isinstance(verifier, HumanIdentityVerifier):
            raise HumanApprovalError(
                "HumanApprovalGate requires a real HumanIdentityVerifier holding "
                "registered principal keys. Accepting a duck-typed stand-in here "
                "would reintroduce the string-comparison authorisation this "
                "module exists to remove.")
        if not verifier.known_principals():
            raise HumanApprovalError(
                "no human principals are registered, so no attestation could ever "
                "verify. A gate that can only refuse is a misconfiguration, not a "
                "safety property — register a principal or do not install the gate.")
        self._verifier = verifier
        self._require_envelope = bool(require_envelope)

    @property
    def require_envelope(self) -> bool:
        return self._require_envelope

    def pair_digest(self, attestation: Any) -> str:
        """Structural half: the digest to fold into the grant's action_binding.

        NO cryptographic verification and NO side effect, so this is safe to run
        before the gates that may refuse for unrelated reasons. It answers only
        "is this grant bound to this attestation object", which is a hash
        comparison. Validity is `verify()`'s job.
        """
        att = self._coerce(attestation)
        return attestation_digest(att)

    def verify(self, attestation: Any, *, actuator_id: str, command: str,
               params: Optional[dict] = None, broker_id: Optional[str] = None,
               effects_hash: Optional[str] = None,
               envelope_hash: Optional[str] = None,
               subject: Optional[str] = None,
               now: Optional[float] = None) -> str:
        """Cryptographic half: prove a registered human signed THIS effect.

        Returns the principal name. Raises on every failure — there is no falsy
        return a caller could mistake for success. BURNS the attestation nonce, so
        call this once, late, and only on a request that is otherwise going to act.
        """
        att = self._coerce(attestation)

        if self._require_envelope and envelope_hash is None:
            raise HumanApprovalError(
                "this gate requires the safety envelope to be bound and none was "
                "supplied. Unconfigured is not permissive: without it, an approval "
                "given under a 20N envelope stays valid after the envelope is "
                "widened, which is the whole failure being closed.")

        expected = effect_id(actuator_id, command, params, broker_id=broker_id,
                             effects_hash=effects_hash, envelope_hash=envelope_hash,
                             subject=subject)

        # human_identity does the crypto, the expiry, the principal lookup and the
        # single-use nonce, and it raises on an action mismatch. Delegating rather
        # than re-implementing is the point: this module adds the BINDING, not a
        # second opinion about signatures.
        try:
            return self._verifier.verify(att, action=expected, now=now)
        except PermissionError as e:
            raise HumanApprovalError(
                f"no valid human approval for this exact action: {e}") from e

    @staticmethod
    def _coerce(attestation: Any) -> HumanAttestation:
        """Accept a HumanAttestation or the dict form that crosses the socket.

        STRICT, not tolerant. An earlier version called `str()` on the identity
        fields, which meant "if it can be turned into a string I will accept it" —
        on a boundary whose entire purpose is that caller-controlled representation
        must not silently become authority. A list, an object with a __str__, or a
        number now stops here instead of becoming a principal name. The safest parser
        is boring. (red-team, ChatGPT 2026-08-14)
        """
        if isinstance(attestation, HumanAttestation):
            return attestation
        if isinstance(attestation, Mapping):
            required = ("principal", "action", "issued_at", "expires_at",
                        "nonce", "sig")
            missing = [f for f in required if f not in attestation]
            if missing:
                raise HumanApprovalError(
                    f"attestation is missing required field(s): {', '.join(missing)}")
            for f in ("principal", "action", "nonce", "sig"):
                v = attestation[f]
                if not isinstance(v, str):
                    raise HumanApprovalError(
                        f"attestation field {f!r} must already be a string, not "
                        f"{type(v).__name__}. Converting it here would let the "
                        f"sender choose the representation and the verifier choose "
                        f"the meaning.")
                if not v:
                    raise HumanApprovalError(f"attestation field {f!r} is empty")
            for f in ("issued_at", "expires_at"):
                v = attestation[f]
                # bool is an int subclass and is never a timestamp.
                if isinstance(v, bool) or not isinstance(v, (int, float)):
                    raise HumanApprovalError(
                        f"attestation field {f!r} must be a number, not "
                        f"{type(v).__name__}")
                if v != v or v in (float("inf"), float("-inf")):
                    raise HumanApprovalError(
                        f"attestation field {f!r} is not finite. A validity window "
                        f"that cannot be canonically represented is not a window.")
            if float(attestation["expires_at"]) <= float(attestation["issued_at"]):
                raise HumanApprovalError(
                    "attestation expires no later than it was issued, so it "
                    "authorises nothing for any instant")
            return HumanAttestation(
                principal=attestation["principal"], action=attestation["action"],
                issued_at=float(attestation["issued_at"]),
                expires_at=float(attestation["expires_at"]),
                nonce=attestation["nonce"], sig=attestation["sig"])
        raise HumanApprovalError(
            f"an attestation must be a signed HumanAttestation, not "
            f"{type(attestation).__name__}. A bare label is never a human.")


class CanonicalAction:
    """One object that produces BOTH the text a human reads and the identity they sign.

    (red-team, ChatGPT 2026-08-14.) The gap this closes was previously named in this
    module as an integration property and left there: nothing stopped an approval
    surface from displaying "grip the cup gently" while signing the effect identity of
    a 900N grip on a knife. The cryptography would be perfect and the human would have
    been shown a lie — an authorization failure that no HMAC can detect.

    The structural answer is not another hash. It is to remove the second generation
    path: the display string and the effect identity must be derived from the SAME
    object, so there is no independent description that can drift from the command.
    An approval surface that renders `describe()` and signs `identity()` cannot show
    one action and authorise another, because both come from these fields.

    WHAT IS STILL NOT CLOSED, and must not be claimed: a UI is free to ignore
    `describe()` and print whatever it likes. This makes fidelity the DEFAULT and the
    cheap path rather than an achievement, which is the most a library can do from
    here. Proving what pixels a human saw is outside any process boundary DriftCore
    controls.

    `describe()` is deliberately plain and complete rather than tidy. Every field that
    enters the identity appears in the text, because a description that omits a
    parameter is how "grip cup" ends up meaning "grip cup for ten minutes".
    """

    __slots__ = ("actuator_id", "command", "params", "broker_id", "effects_hash",
                 "envelope_hash", "subject", "envelope")

    def __init__(self, actuator_id: str, command: str,
                 params: Optional[dict] = None, *,
                 broker_id: Optional[str] = None,
                 effects_hash: Optional[str] = None,
                 envelope: Optional[Mapping[str, Any]] = None,
                 subject: Optional[str] = None) -> None:
        self.actuator_id = actuator_id
        self.command = command
        self.params = dict(params or {})
        self.broker_id = broker_id
        self.effects_hash = effects_hash
        self.envelope = None if envelope is None else dict(envelope)
        self.envelope_hash = envelope_digest(self.envelope)
        self.subject = subject

    def identity(self) -> str:
        """The effect_id the human's signature will cover."""
        return effect_id(self.actuator_id, self.command, self.params,
                         broker_id=self.broker_id, effects_hash=self.effects_hash,
                         envelope_hash=self.envelope_hash, subject=self.subject)

    def describe(self) -> str:
        """Human-readable, generated from the SAME fields as `identity()`."""
        lines = [f"Action:    {self.command} on {self.actuator_id}"]
        if self.subject:
            lines.append(f"Subject:   {self.subject}")
        if self.params:
            lines.append("Parameters:")
            for k in sorted(self.params):
                v = self.params[k]
                # repr, not str: the representation IS the approval. A UI showing
                # 20 for a value signed as "20" would be a different approval.
                lines.append(f"    {k} = {v!r}")
        else:
            lines.append("Parameters: (none)")
        if self.envelope is not None:
            lines.append("Under safety envelope:")
            for k in sorted(self.envelope):
                lines.append(f"    {k} = {self.envelope[k]!r}")
        if self.broker_id:
            lines.append(f"Broker:    {self.broker_id}")
        if self.effects_hash:
            lines.append(f"Effects:   {self.effects_hash}")
        lines.append(f"Identity:  {self.identity()}")
        return "\n".join(lines)

    def approve_with(self, key: "bytes | str", *, principal: str,
                     ttl_seconds: float, nonce: str,
                     now: Optional[float] = None) -> HumanAttestation:
        """Sign exactly what `describe()` rendered."""
        return HumanAttestation.issue(key, principal=principal,
                                      action=self.identity(),
                                      ttl_seconds=ttl_seconds, nonce=nonce, now=now)


def approve(key: bytes | str, *, principal: str, actuator_id: str, command: str,
            params: Optional[dict] = None, ttl_seconds: float,
            nonce: str, broker_id: Optional[str] = None,
            effects_hash: Optional[str] = None,
            envelope_hash: Optional[str] = None,
            subject: Optional[str] = None,
            now: Optional[float] = None) -> HumanAttestation:
    """Issue a human approval bound to one exact action.

    The convenience form of stage 2, so a deployment does not have to know that the
    attestation's `action` field must carry an effect_id. "A control nobody can use
    is a control nobody has" — the same reason declaration_hash was made public.
    """
    return HumanAttestation.issue(
        key, principal=principal,
        action=effect_id(actuator_id, command, params, broker_id=broker_id,
                         effects_hash=effects_hash, envelope_hash=envelope_hash,
                         subject=subject),
        ttl_seconds=ttl_seconds, nonce=nonce, now=now)
