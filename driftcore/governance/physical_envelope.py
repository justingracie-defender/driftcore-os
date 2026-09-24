# SPDX-License-Identifier: Apache-2.0
"""
physical_envelope.py — DRIFTCORE VERIFIES AN ENVELOPE. IT DOES NOT CONTAIN ONE.

THE SPLIT THIS ENFORCES (see 000_AI_START_HERE.md §0b)
─────────────────────────────────────────────────────
    DriftCore: an envelope must EXIST, be INDEPENDENTLY ENFORCED, and not be
               SELF-WIDENABLE.
    LifeCore:  for this body, in this environment, that envelope is 60N.
    Hardware:  and here is the thing that makes it physically true.

DriftCore is model-agnostic middleware. The moment it contains a number tuned to
one body it stops being universal and has to be rewritten for the next machine —
60N is right for a home robot near a child, 800N is right for an industrial arm
behind a fence, and a software agent has no physical envelope at all because its
actuator is the network. Same universal rule, three different numbers, none of
which belong here.

So this module asks three questions and holds no newtons:

  1. IS AN ENVELOPE DECLARED?  No declaration → refuse to operate. Unconfigured
     is not permissive (same rule as EgressPolicy refusing an empty allowlist).
  2. IS IT ENFORCED BELOW THE AI?  A limit the agent consults is a suggestion.
     A limit in firmware or a mechanical clutch is a limit. AGENT_SOFTWARE is
     REFUSED, not warned — this is the load-bearing check.
  3. CAN IT BE SELF-WIDENED?  Tightening is free; widening needs a human and an
     audit record. Asymmetric, like every other policy change in this project.

THE TWO TRAPS, BOTH HANDLED HERE
────────────────────────────────
  * THE ENVELOPE IS BODY *PLUS ENVIRONMENT*. 800N is safe behind a fence and
    lethal without one. A declaration therefore names the OperatingConditions it
    is valid under, and leaving those conditions (gate opens, home robot carried
    into a workshop) is an ODD violation that falls back to the TIGHTEST declared
    envelope. It does not continue on the old one, and it does not fail open.
  * "APPROPRIATE TO ITS BODY" IS WHERE THE DANGER MOVES, NOT WHERE IT ENDS. A
    deployer can declare a permissive envelope and pass all three checks
    honestly — declared, enforced, not self-widened — and still be 5000N in a
    kitchen. Same policy-composition hazard as allowlist_hygiene: the mechanism
    is sound and the DECLARATION is the soft spot. Hence the plausibility lint.

ON THE PLAUSIBILITY BANDS (read this before calling it a contradiction)
───────────────────────────────────────────────────────────────────────
The lint compares a declared limit against a band for its embodiment class,
which means this file contains numbers. That is not a violation of "DriftCore
holds no physical values," because of what the numbers DO:

  * They are REVIEW TRIGGERS, not floors. Exceeding one produces a WARNING that
    requires acknowledgement; it never silently denies, and it never overrides
    the operator's declared limit. The enforced limit is always the declared
    one.
  * They are EXPLICITLY NON-AUTHORITATIVE PLACEHOLDERS awaiting calibration,
    like every other threshold in this project.
  * They are REPLACEABLE. `EnvelopeVerifier(bands=...)` takes the operator's
    own bands; the shipped set is a starting point, not a rule.

The distinction that matters: a number DriftCore *enforces* would break
universality. A number DriftCore *uses to ask a human "are you sure?"* does not.

WHAT THIS MODULE CANNOT DO
──────────────────────────
It cannot enforce a physical limit — nothing in Python can. It verifies that
something else does, the same way netns_attestation verifies isolation it does
not itself provide. A declaration that firmware enforces the limit is a CLAIM;
this module records who made it and refuses agent-level enforcement outright,
but proving the firmware actually does it requires attestation from outside the
software stack entirely. That gap is real and is named in `attestation_note`.
"""

from __future__ import annotations

import hashlib
import math
import struct
import threading
import time
import weakref
from types import MappingProxyType
from dataclasses import dataclass, field
from enum import Enum
from typing import (Dict, FrozenSet, List, Mapping, MutableMapping, Optional,
                    Sequence, Tuple)


class EnforcementPoint(Enum):
    """WHERE the limit physically lives. This is the ladder, weakest first."""

    AGENT_SOFTWARE = "agent_software"
    """The agent checks the limit itself. THIS IS NOT A LIMIT — it is a value the
    agent consults, and anything that can change its own behaviour can change
    what it consults. Declaring this is refused."""

    SUPERVISOR_PROCESS = "supervisor_process"
    """A separate process the agent cannot write to. Real separation at OS
    privilege level; defeated by anything with equivalent privilege."""

    FIRMWARE = "firmware"
    """Signed, verify-at-boot. Compromising the running system does not yield the
    signing key. Updating becomes an offline ceremony rather than a code change."""

    HARDWARE_MECHANICAL = "hardware_mechanical"
    """A fuse, a clutch, a current limiter — not software at all. Not defeatable
    by any software attack because there is nothing to attack. Cost: you cannot
    fix it if you got the number wrong."""

    @property
    def rank(self) -> int:
        return {"agent_software": 0, "supervisor_process": 1,
                "firmware": 2, "hardware_mechanical": 3}[self.value]

    @property
    def is_below_the_ai(self) -> bool:
        """The load-bearing property. Everything above AGENT_SOFTWARE is outside
        the agent's reach; AGENT_SOFTWARE is inside it."""
        return self is not EnforcementPoint.AGENT_SOFTWARE


class Dimension(str, Enum):
    """WHAT is bounded. Named dimensions, never values."""
    FORCE_N = "force_n"
    SPEED_MPS = "speed_mps"
    TORQUE_NM = "torque_nm"
    REACH_M = "reach_m"
    MASS_KG = "mass_kg"
    TEMPERATURE_C = "temperature_c"
    CURRENT_A = "current_a"
    SOUND_DB = "sound_db"


class EnvelopeRefused(Exception):
    """A declaration was refused. Carries operator detail separately, so a
    refusal never becomes a probe oracle."""

    GENERIC = "physical envelope declaration refused"

    def __init__(self, operator_detail: str, generic: Optional[str] = None):
        self.operator_detail = operator_detail
        super().__init__(generic or self.GENERIC)


MAX_SEQUENCE = 2 ** 63 - 1
"""A ceiling on the anti-replay counter, not a physical value.

An unbounded sequence is a denial of service with the safety direction
inverted: one reading at 10**400 sets the high-water mark past anything a real
sensor will ever emit, and every genuine reading after it is refused as
superseded — which fails *closed*, so nothing alarms, and the machine sits on
the tight envelope forever while the operator hunts a sensor fault. It also
overflows `math.isfinite`. 2**63-1 is the range of the counters real hardware
actually uses.

Every replay mark DriftCore writes stays within [0, MAX_SEQUENCE], so a durable
store can keep it in a signed 64-bit column. (v4 poisoned a conflict at N by
writing N + 1; at N = MAX_SEQUENCE that overflowed such a column, the write
failed, and the captured half of the conflict could then be replayed. Found
while testing Grok's round-4 question about this boundary, 2026-09-23.)
"""

# The value a replay-store entry carries in place of a digest when two
# different authenticated readings were seen at its mark: nothing at that
# sequence is ever accepted again. Not a hex digest, so it cannot collide
# with one.
CONFLICTED = "conflicted"

READING_DIGEST_VERSION = "driftcore-reading-v1"
EVIDENCE_DIGEST_VERSION = "driftcore-evidence-v1"
AUTHORIZATION_DIGEST_VERSION = "driftcore-authorization-v1"


# -- canonical encoding, reproducible in any language --------------------
# Every field is an 8-byte big-endian length followed by its bytes. Strings
# are UTF-8; times and limits are IEEE-754 binary64, big-endian, with -0.0
# written as 0.0; sequences are unsigned 64-bit big-endian. No escaping
# rules and no float formatting, so a TypeScript or Rust runner produces the
# same bytes as this one. The golden vector is in the test suite.

def _field(b: bytes) -> bytes:
    return len(b).to_bytes(8, "big") + b


def _text(s: str) -> bytes:
    # Callers pass plain, surrogate-free strings: construction normalises
    # them and admission re-checks, so this never meets a subclass.
    return _field(str.__str__(s).encode("utf-8"))


def _binary64(x) -> bytes:
    return _field(struct.pack(">d", float(x) + 0.0))


def _uint64(n: int) -> bytes:
    return _field(int(n).to_bytes(8, "big"))


def _plain_str(value, what: str) -> str:
    # The characters of a str as an EXACT str. A subclass's own __str__,
    # __eq__ and __hash__ are never consulted again: an Enum member becomes
    # its value, and a subclass cannot tell the digest one name and the
    # comparison another (v5: a str subclass whose __str__ said "stowed"
    # moved a genuine stowed proof onto fence_closed — cold pass, W4).
    if not isinstance(value, str):
        raise EnvelopeRefused(f"{what} must be a string")
    plain = str.__str__(value)
    if not _utf8_ok(plain):
        raise EnvelopeRefused(
            f"{what} contains a lone surrogate, which has no UTF-8 encoding: "
            f"another implementation would collapse it, and two different "
            f"names would share one digest")
    return plain


def _utf8_ok(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _plain_number(value):
    # The underlying value as an exact int or float; a subclass's own
    # conversions are not consulted.
    if isinstance(value, float):
        return float.__float__(value)
    return int.__index__(value)


@dataclass(frozen=True)
class ConditionEvidence:
    """An ATTESTED claim that a condition holds — not a caller's assertion.

    THE BUG THIS EXISTS TO KILL. `select_for()` used to take
    `Mapping[str, bool]` and believe it. That made conditions an alternate
    decision surface: an agent could say `{"fence_closed": True}` and receive
    the 800N envelope without a human, a sensor, or an audit record — widening
    capability while never touching the widen path that was carefully gated.
    Red team (ChatGPT, 2026-08), reproduced at 20N → 800N.

    The rule that replaces it:

        Conditions may EARN a previously authorized envelope.
        Conditions may never CONSTITUTE authorization to widen capability.

    Evidence carries provenance and time so it can be checked rather than
    believed: who says so, when, for how long, in what order, and in which
    replay-state lifetime.

    CLAIM evidence-validates-its-own-structure: this object cannot exist
    holding a non-finite or non-positive TTL, a non-finite issue time or
    expiry, a
    `value` that is not a real bool, or a sequence outside [0, MAX_SEQUENCE] —
    every one of those is refused at construction rather than screened later.
    Structure is validated here; POLICY is validated by the authority — a TTL of
    one hour is a deployment question, refused (if at all) by
    `ConditionAuthority(max_ttl_seconds=...)`, and keeping the two separate is
    what lets a refusal message mean one thing. External review (SINT Labs /
    Illia Pashkov, 2026-09) surfaced `ttl=inf` accepted under a genuine
    signature; the signature was never the gap.
    """
    condition: str
    value: bool
    source: str                 # identity of the attesting authority
    issued_at: float            # monotonic seconds
    ttl_seconds: float          # after which the claim is stale, not false
    sequence: int = 0           # per-source monotonic counter, anti-replay
    proof: str = ""             # signature/MAC — verified by the injected authority
    epoch: str = ""             # replay-state lifetime this reading belongs to

    def __post_init__(self):
        if not isinstance(self.condition, str) or not self.condition.strip():
            raise EnvelopeRefused(
                "condition evidence with no condition name cannot be matched "
                "against any declared OperatingConditions")
        if not isinstance(self.source, str) or not self.source.strip():
            raise EnvelopeRefused(
                f"evidence for {self.condition!r} names no source; evidence "
                f"whose attester is anonymous cannot be trusted or revoked")
        if not isinstance(self.value, bool):
            raise EnvelopeRefused(
                f"evidence for {self.condition!r} has value={self.value!r}, "
                f"which is not a bool. Truthiness is not attestation: a "
                f"non-empty string, 1, or an object would all read as True "
                f"through `if ev.value:` and silently hold a condition open.")
        for name, val in (("issued_at", self.issued_at),
                          ("ttl_seconds", self.ttl_seconds)):
            if isinstance(val, bool) or not isinstance(val, (int, float)):
                raise EnvelopeRefused(
                    f"evidence for {self.condition!r}: {name} must be a number")
            if val != val or val in (float("inf"), float("-inf")):
                raise EnvelopeRefused(
                    f"evidence for {self.condition!r}: {name}={val} is not "
                    f"finite. An infinite freshness window is the absence of a "
                    f"freshness window, which is how a single signed reading "
                    f"authorises a permissive envelope forever.")
        for name, val in (("issued_at", self.issued_at),
                          ("ttl_seconds", self.ttl_seconds)):
            try:
                exact = float(val) == val
            except OverflowError:
                exact = False
            if not exact:
                raise EnvelopeRefused(
                    f"evidence for {self.condition!r}: {name}={val} has no "
                    f"exact binary64 value; times are compared and digested "
                    f"as binary64, and would be silently rounded")
        try:
            finite_expiry = math.isfinite(self.issued_at + self.ttl_seconds)
        except OverflowError:
            finite_expiry = False
        if not finite_expiry:
            # Two finite numbers can sum to infinity: issued_at=1e308 and
            # ttl=1e308 passed every check above and expired at inf, and an
            # authority configured to match held 800N forever (ChatGPT,
            # round 5, on v5).
            raise EnvelopeRefused(
                f"evidence for {self.condition!r}: issued_at + ttl_seconds is "
                f"not finite; a reading must expire at a finite time")
        if self.ttl_seconds <= 0:
            raise EnvelopeRefused(
                f"evidence for {self.condition!r}: ttl_seconds="
                f"{self.ttl_seconds} must be positive; a reading that is "
                f"stale on arrival should not be issued")
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int):
            raise EnvelopeRefused(
                f"evidence for {self.condition!r}: sequence must be an int")
        if not 0 <= self.sequence <= MAX_SEQUENCE:
            raise EnvelopeRefused(
                f"evidence for {self.condition!r}: sequence must be between 0 "
                f"and {MAX_SEQUENCE}; see MAX_SEQUENCE for why an unbounded "
                f"counter is a fail-closed denial of service")
        if not isinstance(self.proof, str) or not isinstance(self.epoch, str):
            raise EnvelopeRefused(
                f"evidence for {self.condition!r}: proof and epoch must be "
                f"strings")
        # Store what was validated, as exact built-in types.
        for name in ("condition", "source", "proof", "epoch"):
            object.__setattr__(self, name, _plain_str(
                getattr(self, name), f"evidence {name}"))
        for name in ("issued_at", "ttl_seconds", "sequence"):
            object.__setattr__(self, name, _plain_number(getattr(self, name)))

    @property
    def payload(self) -> Tuple:
        """CLAIM proof-binds-the-whole-reading: this is everything a proof
        must cover — source, condition, value, times, sequence and epoch —
        so a valid proof cannot be moved to a different reading, a different
        source, a different freshness window or a different boot.
        Two records with the same payload are the same reading presented
        twice, which is normal control-loop behaviour; two with the same
        (source, condition, sequence) and DIFFERENT payloads are a conflict,
        and a conflict is not resolved by whichever arrived last.
        """
        return (self.source, self.condition, self.value, self.issued_at,
                self.ttl_seconds, self.sequence, self.epoch)

    @property
    def canonical(self) -> bytes:
        # The reading as bytes any implementation can reproduce: the version
        # tag, source, condition, value (one byte), issued_at and ttl_seconds
        # (binary64), sequence (uint64) and epoch, each length-prefixed. The
        # proof is not part of it: two valid proofs of one reading are one
        # reading. A verifier may sign exactly these bytes.
        return (_text(READING_DIGEST_VERSION) + _text(self.source)
                + _text(self.condition)
                + _field(b"\x01" if self.value else b"\x00")
                + _binary64(self.issued_at) + _binary64(self.ttl_seconds)
                + _uint64(self.sequence) + _text(self.epoch))

    @property
    def digest(self) -> str:
        """CLAIM reading-digest-is-canonical: the digest is SHA-256 over a
        versioned, length-prefixed binary encoding that a runner in any
        language can reproduce, and numerically equal readings — an int or a
        float for the same time, 0.0 or -0.0 — have equal digests.
        v4 hashed `repr(payload)`: the same reading typed `5` in one place
        and `5.0` in another had two digests, was taken for a conflict, and
        poisoned the sequence; and no non-Python runner could reproduce it.
        Raised by Grok and Sol, round 4.
        """
        return hashlib.sha256(self.canonical).hexdigest()

    @property
    def expires_at(self) -> float:
        return self.issued_at + self.ttl_seconds

    def is_fresh(self, now: float) -> bool:
        return self.issued_at <= now <= self.issued_at + self.ttl_seconds


@dataclass(frozen=True)
class ConditionSnapshot:
    """What the authority believes RIGHT NOW, and until when — in one object.

    CLAIM snapshot-cannot-be-torn: the conditions and the moment they stop
    being fresh are returned TOGETHER, so no interleaved call can pair one
    batch's conditions with another batch's deadline.

    The previous API returned the holds from `accept()` and the expiry from a
    separate `deadline_of_last_accept()` that read instance state written by
    the last accept. Any call between the two — another thread's control loop,
    an empty batch — rewrote it. `accept([])` in between set the deadline to
    infinity: a permissive envelope with no expiry. Reproduced by Sol,
    2026-09-22.
    """
    holds: Mapping[str, bool]
    expires_at: float
    conflicts: FrozenSet[str] = frozenset()
    verifier_failed: bool = False
    rejected: Tuple[str, ...] = ()
    # The injected replay store raised. Same standing as a verifier outage:
    # UNKNOWN, never "no record" — reading an unreachable store as empty
    # would re-admit every superseded reading.
    replay_store_failed: bool = False
    # For each condition that holds: the (source, sequence, reading digest) of
    # every accepted reading it rests on, so an authorization can name exactly
    # the evidence it relied on.
    support: Mapping[str, Tuple[Tuple[str, int, str], ...]] = field(
        default_factory=dict)
    # The AUTHORITY's clock at evaluation. `expires_at` is in the authority's
    # time domain, which need not be the controller's: a deployment passing
    # `clock=time.time` to the authority got a wall-clock deadline compared
    # against the controller's monotonic clock, and a wide envelope that never
    # expired. Consumers use `expires_at - evaluated_at` — a duration, which
    # means the same thing in every clock.
    evaluated_at: float = 0.0


class ReplayStore:
    """CLAIM replay-marks-never-move-backward: a mark is replaced only by
    `compare_and_set` against the exact entry the batch screened with, under
    ONE lock per underlying mapping however many wrappers share it, and the
    store itself refuses a write that moves a mark backward or replaces a
    conflict marker at the same sequence — so two authorities sharing one
    store cannot put an older mark over a newer one.
    Sol reproduced it on v4 with a plain dict: signed FALSE@5 and an older
    TRUE@4 evaluated concurrently by two authorities, both read the old mark,
    the FALSE@5 write landed first, the TRUE@4 write regressed the store to 4,
    and replaying TRUE@4 went 20N -> 800N. The authority's own lock covers
    one instance, never the store. A durable store must provide the same
    operation natively (a transaction, a conditional put); this class is
    atomic only within one process.
    """

    def __init__(self, mapping: Optional[MutableMapping] = None):
        self._m = {} if mapping is None else mapping
        # ONE LOCK PER MAPPING, NOT PER WRAPPER. v5 gave each wrapper its own
        # lock, so two authorities wrapping one dict — as the constructor's
        # own error message advised, and as v5's tests did — both won a
        # compare-and-set from the same expected entry and the mark went
        # 1 -> 5 -> 2 (coordinator's cold pass, W8).
        self._shared = _lock_for(self._m)
        self._lock = self._shared.lock

    def get(self, key):
        with self._lock:
            return self._m.get(key)

    def compare_and_set(self, key, expected, new) -> bool:
        with self._lock:
            current = self._m.get(key)
            if current != expected or not _advances(current, new):
                return False
            self._m[key] = new
            return True


class _SharedLock:
    __slots__ = ("mapping", "lock", "__weakref__")

    def __init__(self, mapping):
        self.mapping = mapping
        self.lock = threading.Lock()


_LOCKS: Dict[int, "weakref.ref"] = {}
_LOCKS_GUARD = threading.Lock()


def _lock_for(mapping) -> _SharedLock:
    # The holder keeps the mapping alive, so its id cannot be reused while
    # any wrapper holding the lock exists.
    with _LOCKS_GUARD:
        ref = _LOCKS.get(id(mapping))
        holder = ref() if ref is not None else None
        if holder is None or holder.mapping is not mapping:
            holder = _SharedLock(mapping)
            key = id(mapping)
            _LOCKS[key] = weakref.ref(
                holder, lambda r, k=key: _LOCKS.pop(k, None)
                if _LOCKS.get(k) is r else None)
        return holder


def _parse_mark(raw):
    # (mark, digest) from a stored entry, or None if it is not usable.
    if raw is None:
        return (0, "")
    try:
        mark, digest = raw
        usable = (type(mark) is int and isinstance(digest, str)
                  and math.isfinite(mark) and 0 <= mark <= MAX_SEQUENCE)
    except (OverflowError, TypeError, ValueError):
        return None
    return (mark, digest) if usable else None


def _advances(current, new) -> bool:
    # The store's own guard, under whatever its caller decided: a mark never
    # moves backward, and a CONFLICTED entry is never replaced by an ordinary
    # reading at the same sequence (GLM, round 5).
    new_at = _parse_mark(new)
    if new is None or new_at is None:
        return False
    if current is None:
        return True
    now_at = _parse_mark(current)
    if now_at is None:
        return False
    (cm, cd), (nm, nd) = now_at, new_at
    if nm != cm:
        return nm > cm
    return new == current or nd == CONFLICTED or cd == ""


class _ConflictNotRecorded(Exception):
    # A conflict was seen but its marker could not be stored.
    pass


class ConditionAuthority:
    """Validates condition evidence. Lives OUTSIDE the agent's authority.

    It checks structure and policy bounds, freshness, replay, authenticity and
    agreement, then reduces them to a state.

    CLAIM proof-presence-is-not-attestation: with `require_proof=True` and no
    verifier, this class REFUSES TO CONSTRUCT, so no configuration of it reads
    a non-empty proof string as authentication. Establishing a trust root is
    not something it can do for you — `verify_proof` is the seam where a
    deployment injects one backed by the sensor supervisor's signing key.

    Background, not part of the claim: the shipped default `verify_proof=None`
    accepted `proof='x'` for a condition that earns the wider envelope, and the
    fixture could not see it because it supplied `proof="sig"` and its only
    negative case was the empty string. Found by external review (SINT Labs /
    Illia Pashkov, 2026-09). The insecure configuration is unconstructable
    rather than warned about, which is the rule this module already applies to
    an empty `trusted_sources` and `EgressPolicy` to an empty allowlist.

    CLAIM condition-state-is-order-independent: `evaluate()` reduces evidence
    to the latest reading per (source, condition) by SEQUENCE NUMBER rather
    than list position, and a correctly signed FALSE retracts an earlier TRUE.

    Background: the previous implementation had no branch that removed a
    condition, so `[TRUE seq1, FALSE seq2]` held it open while the reversed
    list did not — a fence opening did not close the envelope, and the attack
    needed no forged proof at all, only list ordering. Found by Sol,
    2026-09-22, while red-teaming the fix for the finding above.

    WHAT IS STILL NOT CLOSED, stated rather than implied:

      * NO QUORUM POLICY. One trusted source asserting TRUE is sufficient;
        N-of-M is a deployment decision this module will not invent. What is
        closed is DISAGREEMENT: if two trusted sources report different
        values for the same condition, it fails closed. Absence is not
        disagreement — a source that says nothing is not a dissent.
      * THE EPOCH IS DECLARED, NOT VERIFIED. Replay across a restart is
        closed only if `epoch` actually changes when the replay state is
        lost, or `replay_state` is durable. This class refuses to construct
        without an epoch; it cannot check that an operator varies it. Same
        shape of gap as `PhysicalEnvelope.attestation_note` — named, not
        papered over.
      * THE PROOF BINDS A READING, NOT A DEPLOYMENT. Whatever `verify_proof`
        covers is up to the injected verifier. For an interop profile, a
        valid proof should not be movable between deployments; that belongs
        in the device/envelope identity work, not here.
    """

    def __init__(self, *, trusted_sources: FrozenSet[str],
                 epoch: str,
                 max_ttl_seconds: float,
                 verify_proof=None, require_proof: bool = True,
                 unverified_reason: str = "",
                 replay_state: Optional[ReplayStore] = None,
                 clock=None):
        if not trusted_sources:
            raise EnvelopeRefused(
                "a condition authority with no trusted sources would accept "
                "nothing; declare who is allowed to attest conditions")
        if require_proof and verify_proof is None:
            raise EnvelopeRefused(
                "condition evidence requires an authenticity verifier: "
                "require_proof=True with verify_proof=None accepts ANY "
                "non-empty string as attestation, and a condition can earn a "
                "more permissive physical envelope. Inject a verifier bound to "
                "the sensor supervisor's key, or set require_proof=False with "
                "a stated unverified_reason=. This module will not ship a "
                "default verifier: a library cannot conjure a legitimate trust "
                "root, and one that pretended to would be worse than none.")
        if not require_proof and not (isinstance(unverified_reason, str)
                                      and unverified_reason.strip()):
            raise EnvelopeRefused(
                "require_proof=False turns off authenticity checking for "
                "evidence that can earn a wider envelope; name who decided "
                "that and why, via unverified_reason=. An escape hatch nobody "
                "signed is an escape hatch nobody reviews.")
        if not isinstance(epoch, str) or not epoch.strip():
            raise EnvelopeRefused(
                "a condition authority requires an epoch: replay high-water "
                "marks are per-instance, so a fresh authority with no epoch "
                "re-accepts evidence it has already superseded. Pass a value "
                "that CHANGES whenever the replay state is lost (a boot id, a "
                "persisted counter), or pass a durable replay_state= and a "
                "stable epoch. Evidence must carry the matching epoch.")
        if (isinstance(max_ttl_seconds, bool)
                or not isinstance(max_ttl_seconds, (int, float))
                or not math.isfinite(max_ttl_seconds)
                or max_ttl_seconds <= 0):
            raise EnvelopeRefused(
                f"max_ttl_seconds={max_ttl_seconds!r} must be a finite "
                f"positive number of seconds; an unbounded freshness ceiling "
                f"is not a ceiling. There is no default: how stale a reading "
                f"may be before it stops meaning anything is a fact about the "
                f"deployment's sensors, like the newtons are a fact about its "
                f"body, and DriftCore holds neither.")
        if replay_state is not None and not (
                callable(getattr(replay_state, "compare_and_set", None))
                and callable(getattr(replay_state, "get", None))):
            raise EnvelopeRefused(
                "replay_state must provide get(key) and an atomic "
                "compare_and_set(key, expected, new). A plain mapping shared "
                "between authorities lets an older mark overwrite a newer one; "
                "wrap an in-process mapping in ReplayStore(), or give a durable "
                "store a native conditional write.")
        self._trusted = frozenset(trusted_sources)
        self._epoch = epoch
        self._verify_proof = verify_proof
        self._require_proof = require_proof
        self._unverified_reason = unverified_reason
        self._max_ttl = float(max_ttl_seconds)
        self._clock = clock or time.monotonic
        # Keyed (epoch, source, condition). Each entry is (mark, digest):
        # readings below `mark` are superseded, and `digest` names the reading
        # accepted AT `mark` — or is CONFLICTED, and nothing at `mark` is
        # accepted again. Marks never exceed MAX_SEQUENCE.
        self._high_water = ReplayStore() if replay_state is None else replay_state
        # The latest accepted reading per (source, condition), so a fresh
        # signed FALSE still counts when its source is absent from a later
        # batch. In memory: it expires with the reading's own TTL.
        self._latest: Dict[Tuple[str, str], ConditionEvidence] = {}
        # _high_water is mutated on the read path and shared across callers.
        self._lock = threading.RLock()
        self._time_floor = -math.inf

    @property
    def epoch(self) -> str:
        """CLAIM replay-marks-are-scoped-to-the-epoch: replay marks are kept
        per epoch, so rotating the epoch starts a new replay lifetime even
        over a durable store — a sensor whose counter restarted is not
        stranded behind the old epoch's marks, and a sequence space
        exhausted by a conflict at MAX_SEQUENCE is recovered by rotating.
        Old-epoch evidence stays refused: the epoch check and the proof
        both bind it. Old epochs' entries are inert and may be pruned.
        """
        return self._epoch

    def accept(self, evidence: Sequence[ConditionEvidence]) -> Dict[str, bool]:
        """The conditions proven to hold RIGHT NOW, without the expiry.

        Kept because it is the name in the threat model, the external review
        and every reproduction script. Prefer `evaluate()`: anything that acts
        on the result needs the expiry and the outage flag, and taking them
        from two calls is what created the tearing bug this class now
        documents.
        """
        return dict(self.evaluate(evidence).holds)

    def evaluate(self, evidence: Sequence[ConditionEvidence]
                 ) -> ConditionSnapshot:
        """Reduce evidence to a state, atomically.

        CLAIM unverifiable-evidence-is-absent-not-permissive: evidence that
        fails ANY screen — epoch, structure, trust, freshness ceiling,
        staleness, replay, proof — is absent from the returned holds, and an
        absent condition is unmet rather than permitted.

        CLAIM authority-time-never-runs-backward: freshness is judged against
        the latest time this authority has seen, so an injected clock that
        steps back cannot make expired evidence fresh again; a clock that
        jumps forward fails closed until real time catches up, and a clock
        that is not a number judges everything stale.
        v6.0 took any clock at its word: a wall clock stepping back 40 s
        resurrected an expired TRUE, and 800N returned for its remaining
        "lifetime" (found by probing a clock step, from Grok's round-6 list).
        """
        raw = self._clock()
        try:
            finite = math.isfinite(raw)
        except (TypeError, ValueError, OverflowError):
            # A string, or an integer too large for a float, is not a number
            # either: judge everything stale rather than raise (Sol, round 6).
            finite, raw = False, math.nan
        with self._lock:
            if finite and not raw < self._time_floor:
                self._time_floor = raw
            now = self._time_floor if finite else raw
            return self._evaluate_locked(evidence, now)

    # -- phase 1: admission. Per-item, order-independent, mutates nothing ---

    def _admit(self, evidence, now, rejected):
        """CLAIM screening-never-moves-replay-state: rejecting a record does
        NOT advance its high-water mark, so unauthenticated evidence cannot
        burn a sequence number.
        Were it otherwise, anyone able to present a record could claim
        sequence 2**63 with a junk proof and permanently deny every genuine
        reading from that source — a denial of service that fails CLOSED and
        therefore alarms nobody. Screening is pure; only records that survive
        to the reduction move any state.

        CLAIM replay-store-outage-is-unknown: a replay store that raises is an
        outage, never an empty record — the batch is abandoned and reported as
        such, so the controller demotes before anyone learns why, exactly as
        it does when the verifier raises.
        """
        admitted: List[ConditionEvidence] = []
        # (mark, digest, raw entry) per store key, read ONCE per batch so the
        # reduction compares — and compare-and-sets — against exactly the
        # state admission screened with.
        marks: Dict[Tuple[str, str, str], Optional[Tuple[int, str, object]]] = {}
        max_ttl = self._max_ttl
        if not math.isfinite(max_ttl):
            # Constructor-validated, re-asserted: a mutated private field must
            # not become an unbounded freshness window. Admitting nothing
            # demotes through the ordinary ODD path rather than raising a new
            # exception shape out of a control loop.
            rejected.append("the freshness ceiling is no longer finite")
            return admitted, "", marks
        for ev in evidence:
            if type(ev) is not ConditionEvidence:
                # EXACT CLASS. A subclass brings its own is_fresh, expires_at
                # and digest: v5 accepted an expired genuine reading wrapped
                # in one that answered "fresh, forever" — 800N with no
                # deadline (independent cold pass, 2026-09-23, W4).
                rejected.append("not ConditionEvidence (subclasses are refused)")
                continue
            # RE-SCREEN AT THE TRUST BOUNDARY. `__post_init__` validates at
            # construction, but a frozen dataclass restored by pickle — or any
            # other path that writes `__dict__` directly — never runs it, and
            # `evaluate()` takes whatever the caller hands it. A validated TYPE
            # is not a validated VALUE. Every comparison below therefore has
            # `math.isfinite` on ITS OWN operand in this scope, not an
            # inherited promise from somewhere else (finite_guards.py, which
            # flags exactly this, puts it better: "isfinite(other) does not
            # bless ttl").
            sequence, issued_at, ttl_seconds = (
                ev.sequence, ev.issued_at, ev.ttl_seconds)
            try:
                sane = (type(ev.value) is bool
                        and type(ev.condition) is str
                        and type(ev.source) is str
                        and type(ev.epoch) is str
                        and _utf8_ok(ev.condition) and _utf8_ok(ev.source)
                        and _utf8_ok(ev.epoch)
                        and type(sequence) is int
                        and type(issued_at) in (int, float)
                        and type(ttl_seconds) in (int, float)
                        and math.isfinite(sequence)
                        and math.isfinite(issued_at)
                        and math.isfinite(ttl_seconds)
                        and math.isfinite(issued_at + ttl_seconds)
                        and 0 <= sequence <= MAX_SEQUENCE
                        and ttl_seconds > 0)
            except (OverflowError, TypeError, ValueError):
                # An unbounded int overflows math.isfinite. Malformed evidence
                # must be REJECTED, never allowed to raise out of a control
                # loop — that is the verifier-outage failure in another costume.
                sane = False
            if not sane:
                rejected.append(f"{ev.condition!r}: malformed or out-of-range")
                continue
            if ev.epoch != self._epoch:
                rejected.append(
                    f"{ev.condition}: epoch {ev.epoch!r} is not this "
                    f"authority's replay-state lifetime")
                continue
            if ev.source not in self._trusted:
                rejected.append(f"{ev.condition}: source {ev.source!r} is not trusted")
                continue
            if ttl_seconds > max_ttl:
                rejected.append(
                    f"{ev.condition}: ttl {ttl_seconds}s exceeds the "
                    f"deployment maximum {max_ttl}s")
                continue
            if not ev.is_fresh(now):
                # Stale is not false, it is UNKNOWN — and unknown is unmet.
                # This is what stops a replay of "fence closed" from 10:01
                # authorising 800N at 10:03 after the fence opened.
                rejected.append(f"{ev.condition}: stale or not yet valid")
                continue
            # THE REPLAY STORE IS AN INJECTED DEPENDENCY, so what comes out of
            # it is INPUT, not state. `replay_state=` may be a durable mapping
            # this module never wrote — a file, a KV store, a row someone can
            # edit — and a corrupt entry reading `inf` would refuse every
            # genuine reading from that sensor forever, which fails closed and
            # therefore alarms nobody. Surfaced by finite_guards, 2026-09-22.
            key = (self._epoch, ev.source, ev.condition)
            if key not in marks:
                try:
                    raw = self._high_water.get(key)
                except Exception as e:      # noqa: BLE001 — see below
                    # AN UNREACHABLE STORE IS AN OUTAGE, NOT AN EMPTY ONE.
                    # Letting the exception escape left the machine at 800N
                    # with it in flight; reading it as "no mark" would
                    # re-admit every superseded reading. Found by reading the
                    # case list of SINT's shared fixture, 2026-09-22.
                    rejected.append(f"replay store raised {type(e).__name__}")
                    return admitted, "replay_store", marks
                stored = (0, "") if raw is None else raw
                try:
                    stored_mark, stored_digest = stored
                    usable = (isinstance(stored_mark, int)
                              and not isinstance(stored_mark, bool)
                              and isinstance(stored_digest, str)
                              and math.isfinite(stored_mark)
                              and 0 <= stored_mark <= MAX_SEQUENCE)  # == _parse_mark
                except (OverflowError, TypeError, ValueError):
                    usable = False
                marks[key] = ((stored_mark, stored_digest, raw) if usable
                              else None)
            if marks[key] is None:
                rejected.append(
                    f"{ev.condition}: the replay store returned an entry that "
                    f"is not a usable (sequence, digest) pair")
                continue
            high_water = marks[key][0]
            if not math.isfinite(high_water):
                rejected.append(f"{ev.condition}: unusable replay mark")
                continue
            if sequence < high_water:
                # STRICTLY less. Re-presenting the SAME still-fresh evidence is
                # normal control-loop behaviour, not a replay; `<=` burned the
                # sequence on first read and made the second call fall back to
                # the tight envelope, so a loop flapped 800N/20N. Freshness (TTL)
                # is the time control; sequence only rejects evidence that a
                # NEWER reading has superseded. Self-red-team 2026-08.
                rejected.append(f"{ev.condition}: superseded (sequence {sequence})")
                continue
            if (sequence == high_water and marks[key][1] == CONFLICTED
                    and ev.value is not False):
                # Neither half of a conflict EARNS anything again, and at
                # MAX_SEQUENCE nothing newer exists: the source is done for
                # this epoch, and only rotating the epoch recovers it. A
                # signed FALSE at that sequence goes on to be verified: it
                # still counts as a dissent, because a replayed FALSE can only
                # tighten (cold pass, W3: refusing it silenced a sensor that
                # kept reporting the fence open).
                rejected.append(
                    f"{ev.condition}: superseded — sequence {sequence} is "
                    f"conflicted" + (
                        "; it is MAX_SEQUENCE, so nothing newer can exist in "
                        "this epoch: rotate the epoch to recover this source"
                        if sequence == MAX_SEQUENCE else ""))
                continue
            if self._require_proof:
                if not ev.proof:
                    rejected.append(f"{ev.condition}: no proof presented")
                    continue
                try:
                    verified = self._verify_proof(ev)
                except Exception as e:      # noqa: BLE001 — see below
                    # AN OUTAGE IS NOT A REJECTION. A verifier that raises says
                    # UNKNOWN, not FALSE, and the difference decides whether a
                    # permissive envelope survives. Abandon the whole batch:
                    # the caller demotes on empty holds and is told afterwards.
                    # The record that triggered it is named, so a junk proof
                    # that crashes a non-conforming verifier is not mistaken
                    # for an infrastructure fault. The verifier's contract:
                    # return False for a bad or unparseable proof; raise
                    # only when verification itself is unavailable.
                    rejected.append(
                        f"verifier raised {type(e).__name__} on {ev.condition!r} "
                        f"from {ev.source!r} at sequence {sequence}")
                    return admitted, "verifier", marks
                if verified is not True:
                    if verified is False:
                        rejected.append(f"{ev.condition}: proof did not verify")
                        continue
                    # ONLY `True` AUTHENTICATES. v4 read `if not verified`,
                    # so a verifier returning "VERIFIED? NO" — any non-empty
                    # string, 1, an object — passed a junk proof (Sol, round
                    # 4): proof presence read as attestation again, one call
                    # deeper. A non-bool answer is a verifier fault: UNKNOWN.
                    rejected.append(
                        f"verifier returned {type(verified).__name__}, "
                        f"not a bool")
                    return admitted, "verifier", marks
            admitted.append(ev)
        return admitted, "", marks

    def _evaluate_locked(self, evidence, now):
        """CLAIM a-conflicted-sequence-is-never-accepted: once two different
        authenticated readings exist for one (source, condition, sequence) —
        in one batch or across batches — neither can earn anything again;
        only a strictly newer reading from that source can hold the
        condition, so replaying one half of a conflict earns nothing. A signed
        FALSE at that sequence still counts as a dissent: replaying a FALSE
        can only tighten.
        """
        rejected: List[str] = []
        admitted, outage, marks = self._admit(evidence, now, rejected)
        if outage:
            return ConditionSnapshot(holds={}, expires_at=float("inf"),
                                     evaluated_at=now,
                                     verifier_failed=(outage == "verifier"),
                                     replay_store_failed=(outage == "replay_store"),
                                     rejected=tuple(rejected))

        # -- phase 2: reduce to the LATEST reading per (source, condition).
        # The winner is chosen by sequence number. Position in the list decides
        # nothing, which is the whole point.
        latest: Dict[Tuple[str, str], List[ConditionEvidence]] = {}
        for ev in admitted:
            key = (ev.source, ev.condition)
            group = latest.get(key)
            if group is None or ev.sequence > group[0].sequence:
                latest[key] = [ev]
            elif ev.sequence == group[0].sequence:
                group.append(ev)

        # -- phase 3: conflicts fail closed and POISON their sequence; every
        # winning reading — FALSE included, or a retraction could be replayed
        # away by the TRUE it superseded — advances the replay mark.
        #
        # A conflict is two different readings at one sequence. In one batch
        # it is visible directly. Across batches it is visible only because
        # the store remembers WHICH reading it accepted at the mark: TRUE@5
        # now and FALSE@5 later is the same conflict, arriving slowly. This
        # runs after authentication, so no unauthenticated record can poison
        # anything (screening stays pure). The poison is (N, CONFLICTED): v3
        # re-admitted a lone reading at the conflicted sequence, so replaying
        # the captured TRUE half reopened 800N (SINT's fixture expects the
        # opposite, and SINT is right); v4 wrote (N + 1, ""), which a signed
        # 64-bit store cannot hold at N = MAX_SEQUENCE.
        conflicts: set = set()
        by_condition: Dict[str, Dict[str, ConditionEvidence]] = {}
        for (source, condition), group in latest.items():
            key = (self._epoch, source, condition)
            raw = marks[key][2] if marks.get(key) else None
            seq = group[0].sequence
            try:
                verdict = self._settle(key, raw, group)
            except Exception as e:      # noqa: BLE001 — an outage, as in _admit
                rejected.append(f"replay store raised {type(e).__name__} on write"
                                if not isinstance(e, _ConflictNotRecorded)
                                else f"{condition}: a conflict at sequence {seq} "
                                     f"from {source!r} could not be recorded")
                return ConditionSnapshot(holds={}, expires_at=float("inf"),
                                         evaluated_at=now, replay_store_failed=True,
                                         rejected=tuple(rejected))
            if verdict == "accepted":
                self._latest[(source, condition)] = group[0]
                by_condition.setdefault(condition, {})[source] = group[0]
                continue
            if verdict == "dissent":
                # A signed FALSE at a conflicted sequence: it earns nothing
                # and moves no replay state, but it is still this source
                # saying the condition does not hold.
                self._remember_dissent(source, condition, group)
                by_condition.setdefault(condition, {})[source] = max(
                    group, key=lambda ev: ev.expires_at)
                continue
            conflicts.add(condition)
            if verdict == "conflict":
                # A CONFLICT DOES NOT ERASE A DISSENT. v5 dropped the source's
                # memory here, so a sensor that contradicted itself — or just
                # re-signed FALSE@6 — lost its standing FALSE, and the other
                # sensor alone earned 800N (cold pass, W3).
                self._remember_dissent(source, condition, group)
                rejected.append(
                    f"{condition}: conflicting readings at sequence {seq} "
                    f"from {source!r}; nothing at or below {seq} can earn "
                    f"anything from it again")
            elif verdict == "conflicted":
                rejected.append(f"{condition}: sequence {seq} from {source!r} "
                                f"is conflicted and earns nothing")
            elif verdict == "superseded":
                rejected.append(
                    f"{condition}: another authority moved {source!r} past "
                    f"sequence {seq} while this batch was judged")
            else:
                rejected.append(
                    f"{condition}: replay state for {source!r} kept changing; "
                    f"reading at sequence {seq} not accepted")

        # A fresh signed FALSE counts until it expires or its source says
        # something newer — leaving the dissenting source out of the next
        # batch does not make the disagreement go away (Sol, round 4).
        for (source, condition), ev in list(self._latest.items()):
            if not ev.is_fresh(now):
                del self._latest[(source, condition)]
            elif (not ev.value and condition in by_condition
                  and source not in by_condition[condition]):
                by_condition[condition][source] = ev

        # -- phase 4: cross-source disagreement fails closed.
        holds: Dict[str, bool] = {}
        support: Dict[str, Tuple[Tuple[str, int, str], ...]] = {}
        expires_at = float("inf")
        for condition, per_source in by_condition.items():
            if condition in conflicts:
                continue
            values = {ev.value for ev in per_source.values()}
            if len(values) > 1:
                conflicts.add(condition)
                rejected.append(
                    f"{condition}: trusted sources disagree in epoch "
                    f"{self._epoch!r}: "
                    f"{sorted((s, ev.value, ev.sequence, ev.digest[:16]) for s, ev in per_source.items())}; "
                    f"it clears when the dissenting source sends a newer "
                    f"reading or its FALSE expires. No quorum policy is "
                    f"configured, so this fails closed")
                continue
            if not next(iter(values)):
                # A correctly signed FALSE. The condition is RETRACTED, not
                # merely unmentioned — this is the branch the old
                # implementation did not have.
                continue
            holds[condition] = True
            support[condition] = tuple(sorted(
                (src, ev.sequence, ev.digest) for src, ev in per_source.items()))
            for ev in per_source.values():
                expires_at = min(expires_at, ev.expires_at)

        return ConditionSnapshot(holds=holds, expires_at=expires_at,
                                 evaluated_at=now,
                                 conflicts=frozenset(conflicts),
                                 verifier_failed=False,
                                 rejected=tuple(rejected),
                                 support=support)

    # A compare-and-set that keeps losing means the store is being fought
    # over; the reading is then refused rather than retried forever.
    _CAS_ATTEMPTS = 3

    def _settle(self, key, raw, group) -> str:
        """CLAIM every-acceptance-is-compare-and-set: a reading is accepted
        only once a compare-and-set has confirmed the store still holds the
        entry it was judged against, and a conflict is reported only once its
        marker is in the store; when a compare-and-set loses, the entry is
        read again and the reading judged again.
        v5 skipped the compare-and-set whenever the reading equalled the entry
        it had read — the ordinary control-loop case — so a newer FALSE (or a
        conflict marker) landed by another authority was never seen, and a
        store whose reads lag its writes did the same with no race at all
        (cold pass, W2). A conflict whose marker lost the race was reported
        and then forgotten, and the captured TRUE replayed to 800N on the
        authority that had seen it (W9; Grok and Meta #2, Sol). Returns
        "accepted", "dissent", "conflict", "conflicted", "superseded" or
        "contended".
        """
        seq = group[0].sequence
        digests = {ev.digest for ev in group}
        in_batch = len(digests) > 1
        conflicted = in_batch
        for _ in range(self._CAS_ATTEMPTS):
            parsed = _parse_mark(raw)
            if parsed is None:
                return "conflict" if in_batch else "contended"
            mark, stored = parsed
            if seq == mark and stored == CONFLICTED:
                return ("dissent" if all(ev.value is False for ev in group)
                        else "conflicted")
            if seq < mark:
                return "conflict" if in_batch else "superseded"
            conflicted = in_batch or (seq == mark and stored != ""
                                      and stored not in digests)
            entry = ((seq, CONFLICTED) if conflicted
                     else (seq, next(iter(digests))))
            if self._high_water.compare_and_set(key, raw, entry):
                return "conflict" if conflicted else "accepted"
            raw = self._high_water.get(key)
        if conflicted:
            raise _ConflictNotRecorded()
        return "contended"

    def _remember_dissent(self, source, condition, group):
        # Keep the latest-expiring signed FALSE this source has given for the
        # condition; a conflict with no FALSE in it leaves memory as it was.
        falses = [ev for ev in group if ev.value is False]
        previous = self._latest.get((source, condition))
        if previous is not None and previous.value is False:
            falses.append(previous)
        if falses:
            self._latest[(source, condition)] = max(
                falses, key=lambda ev: ev.expires_at)

    def deadline_of_last_accept(self) -> float:
        """REMOVED — it could not be used safely. See `ConditionSnapshot`.

        This read instance state written by the previous `accept()`, so any
        interleaved call handed the caller a deadline belonging to a different
        batch of evidence; `accept([])` in between produced an infinite one.
        Left as a refusal rather than deleted so the failure is a message
        instead of an AttributeError.
        """
        raise EnvelopeRefused(
            "deadline_of_last_accept() was removed: pairing it with accept() "
            "was a torn read that could set a permissive envelope's expiry to "
            "infinity. Use evaluate(), which returns holds and expires_at in "
            "one snapshot.")


@dataclass(frozen=True)
class OperatingConditions:
    """The conditions a declared envelope is VALID UNDER.

    An envelope without conditions is an envelope that claims to be valid
    everywhere, which for a physical machine is almost never true. 800N behind a
    fence and 800N in a kitchen are the same number and different facts.
    """
    description: str
    required: FrozenSet[str] = frozenset()
    """Condition names that must be ASSERTED TRUE for this envelope to apply,
    e.g. {"perimeter_fence_closed", "no_humans_in_cell"}. Absence of an assertion
    is treated as the condition being unmet — not as permission."""

    def __post_init__(self):
        # FROZEN MEANS FROZEN. A `required` set passed in stayed the caller's
        # set: clearing it after declaration made an 800N envelope valid
        # everywhere with no evidence (cold pass, W1).
        if isinstance(self.required, str):
            raise EnvelopeRefused(
                "required must be a collection of condition names, not one "
                "string: iterating a string yields its letters")
        try:
            names = frozenset(_plain_str(c, "condition name")
                              for c in self.required)
        except TypeError:
            raise EnvelopeRefused("required must be a collection of "
                                  "condition names") from None
        object.__setattr__(self, "required", names)
        object.__setattr__(self, "description",
                           _plain_str(self.description, "conditions description"))

    def holds_under(self, asserted: Mapping[str, bool]) -> Tuple[bool, str]:
        missing = [c for c in sorted(self.required)
                   if not asserted.get(c, False)]
        if missing:
            return False, f"unmet condition(s): {missing}"
        return True, "all declared conditions asserted"


@dataclass(frozen=True)
class PhysicalEnvelope:
    """One declared envelope: limits, where they are enforced, and when valid."""

    name: str
    limits: Mapping[str, float]          # Dimension value -> limit
    enforced_at: EnforcementPoint
    conditions: OperatingConditions
    declared_by: str = ""
    attestation_note: str = ""
    """How the enforcement claim could be checked from outside the software
    stack. Empty is permitted but warned: an unverifiable claim is a claim."""

    def __post_init__(self):
        if not isinstance(self.name, str) or not self.name:
            raise EnvelopeRefused("an envelope requires a name")
        object.__setattr__(self, "name", _plain_str(self.name, "envelope name"))
        if not self.declared_by:
            raise EnvelopeRefused(
                f"envelope {self.name!r} has no declared_by; a physical limit is a "
                f"safety-critical declaration and must be attributable")
        if not isinstance(self.declared_by, str):
            raise EnvelopeRefused(f"envelope {self.name!r}: declared_by must be a string")
        object.__setattr__(self, "declared_by",
                           _plain_str(self.declared_by, "declared_by"))
        if not isinstance(self.attestation_note, str):
            raise EnvelopeRefused(f"envelope {self.name!r}: attestation_note must be a string")
        object.__setattr__(self, "attestation_note",
                           _plain_str(self.attestation_note, "attestation_note"))
        if not isinstance(self.enforced_at, EnforcementPoint):
            raise EnvelopeRefused(
                f"envelope {self.name!r}: enforced_at must be an EnforcementPoint")
        if not isinstance(self.conditions, OperatingConditions):
            raise EnvelopeRefused(
                f"envelope {self.name!r}: conditions must be OperatingConditions")
        # Rebuilt as the exact class, so its methods are this module's.
        object.__setattr__(self, "conditions", OperatingConditions(
            self.conditions.description, self.conditions.required))
        if not isinstance(self.limits, Mapping) or not self.limits:
            raise EnvelopeRefused(
                f"envelope {self.name!r} declares no limits; an empty envelope is "
                f"a misconfiguration, not an unbounded permission")
        frozen: Dict[str, float] = {}
        for dim, val in self.limits.items():
            if not isinstance(dim, str):
                raise EnvelopeRefused(
                    f"envelope {self.name!r}: dimension {dim!r} is not a name")
            dim = _plain_str(dim, "dimension")
            if dim not in {d.value for d in Dimension}:
                raise EnvelopeRefused(
                    f"envelope {self.name!r} bounds unknown dimension {dim!r}; "
                    f"known: {sorted(d.value for d in Dimension)}")
            if not isinstance(val, (int, float)) or isinstance(val, bool):
                raise EnvelopeRefused(f"{self.name}.{dim} must be a number")
            if val != val or val in (float("inf"), float("-inf")):
                raise EnvelopeRefused(
                    f"{self.name}.{dim} is not finite; an infinite limit is the "
                    f"absence of a limit wearing a number's clothes")
            if val <= 0:
                raise EnvelopeRefused(
                    f"{self.name}.{dim}={val} must be positive")
            try:
                exact = float(val) == val
            except OverflowError:
                exact = False
            if not exact:
                raise EnvelopeRefused(
                    f"{self.name}.{dim}={val} has no exact binary64 value; "
                    f"limits are compared and digested as binary64")
            frozen[dim] = _plain_number(val)
        # FREEZE WHAT WAS VERIFIED. v5 kept the caller's dict: editing it after
        # declaration — or editing `ctl.active.limits` — moved a live limit
        # from 20N to 800N (or inf) with no request_change, no human and no
        # audit record, and an agent could add a 5N "safest" envelope and then
        # make it 5000N. Found independently by the cold pass (W1) and by Sol,
        # 2026-09-23. The copy is read-only; `request_change` is the door.
        object.__setattr__(self, "limits", MappingProxyType(frozen))

    def __reduce__(self):
        # Pickling rebuilds through the constructor, so a restored envelope is
        # validated and frozen like a declared one.
        return (PhysicalEnvelope, (self.name, dict(self.limits), self.enforced_at,
                                   self.conditions, self.declared_by,
                                   self.attestation_note))

    def dominates(self, other: "PhysicalEnvelope") -> bool:
        """True if this envelope is AT LEAST AS SAFE as `other` on every
        dimension either of them bounds.

        A MISSING DIMENSION IS UNBOUNDED, NOT ZERO. That is the whole subtlety:
        an envelope that declares no force limit does not have a force limit of
        0 — it permits any force. Comparing only shared dimensions (or sorting
        pairs lexicographically, as an earlier version did) makes an envelope
        with a gaping hole look tighter than one that closed it.

        Red team (Grok, 2026-08) caught the lexicographic version choosing a
        20N/2.0m·s⁻¹ envelope over a 500N/0.1m·s⁻¹ one by comparing force alone,
        and comparing a speed-only envelope against a force-only one by
        alphabetical key order.
        """
        dims = set(self.limits) | set(other.limits)
        INF = float("inf")
        return all(self.limits.get(d, INF) <= other.limits.get(d, INF)
                   for d in dims)

    def at_least_as_safe_as(self, other: "PhysicalEnvelope") -> bool:
        """CLAIM safety-counts-where-limits-are-enforced: an envelope is at
        least as safe as another only if it dominates it on every limit AND
        is enforced at least as far below the agent; a lower enforcement
        point is not made safe by a smaller number.
        v5 compared limits alone, so an agent — no human — replaced a
        mechanically enforced 20N fallback with 19.99N enforced by a
        supervisor process, journaled as a tightening (cold pass, W7).
        """
        mine, theirs = self.enforced_at.rank, other.enforced_at.rank
        return (self.dominates(other) and math.isfinite(mine)
                and math.isfinite(theirs) and mine >= theirs)

    def is_tighter_than(self, other: "PhysicalEnvelope") -> bool:
        """Strictly safer: dominates and is strictly lower somewhere."""
        if not self.dominates(other):
            return False
        dims = set(self.limits) | set(other.limits)
        INF = float("inf")
        return any(self.limits.get(d, INF) < other.limits.get(d, INF)
                   for d in dims)


# ── Plausibility bands: REVIEW TRIGGERS, not floors (see module docstring) ──
#
# NON-AUTHORITATIVE PLACEHOLDERS awaiting calibration. Exceeding one produces a
# warning requiring acknowledgement; it never denies and never overrides the
# declared limit. Replace via EnvelopeVerifier(bands=...).
DEFAULT_REVIEW_BANDS: Dict[str, Dict[str, float]] = {
    # Class value -> dimension -> "are you sure?" threshold.
    "EMBODIED": {
        Dimension.FORCE_N.value: 80.0,      # near-human operation
        Dimension.SPEED_MPS.value: 1.0,
        Dimension.TORQUE_NM.value: 20.0,
        Dimension.TEMPERATURE_C.value: 45.0,
        Dimension.SOUND_DB.value: 85.0,
    },
    "REMOTE_PHYSICAL_CONTROL": {
        Dimension.FORCE_N.value: 150.0,
        Dimension.SPEED_MPS.value: 2.0,
    },
    # SOFTWARE_ONLY has no physical band on purpose: its actuator is the
    # network, and that envelope is the egress policy, not a force limit.
}


@dataclass(frozen=True)
class EnvelopeFinding:
    ok: bool
    check: str
    detail: str


@dataclass(frozen=True)
class EnvelopeVerdict:
    permitted: bool
    envelope: Optional[PhysicalEnvelope]
    findings: Tuple[EnvelopeFinding, ...]

    @property
    def warnings(self) -> List[EnvelopeFinding]:
        return [f for f in self.findings if f.ok and "WARN" in f.detail]

    def report(self) -> str:
        head = f"envelope: {'PERMITTED' if self.permitted else 'REFUSED'}"
        return "\n".join([head] + [f"  [{'ok' if f.ok else 'FAIL'}] {f.check}: "
                                   f"{f.detail}" for f in self.findings])


class EnvelopeVerifier:
    """Asks DriftCore's three questions. Holds no enforced physical values."""

    def __init__(self, bands: Optional[Mapping[str, Mapping[str, float]]] = None):
        self._bands = bands if bands is not None else DEFAULT_REVIEW_BANDS

    # -- Q1/Q2/Q3 ---------------------------------------------------------

    def verify(self, envelope: Optional[PhysicalEnvelope],
               embodiment_class_value: str,
               *, requires_physical: bool = True) -> EnvelopeVerdict:
        findings: List[EnvelopeFinding] = []

        # Q1. IS AN ENVELOPE DECLARED?
        if envelope is None:
            if not requires_physical:
                return EnvelopeVerdict(True, None, (EnvelopeFinding(
                    True, "declared",
                    "no physical envelope required for this embodiment class; "
                    "its actuator is the network and that envelope is the egress "
                    "policy"),))
            return EnvelopeVerdict(False, None, (EnvelopeFinding(
                False, "declared",
                "no envelope declared for an embodiment that can act physically. "
                "Unconfigured is not permissive: refusing to operate."),))
        findings.append(EnvelopeFinding(
            True, "declared",
            f"{envelope.name!r} bounds {sorted(envelope.limits)} "
            f"(declared_by={envelope.declared_by})"))

        # Q2. IS IT ENFORCED BELOW THE AI?  The load-bearing check.
        if not envelope.enforced_at.is_below_the_ai:
            findings.append(EnvelopeFinding(
                False, "enforced below the AI",
                "enforcement point is AGENT_SOFTWARE. A limit the agent consults "
                "is not a limit — anything that can change its own behaviour can "
                "change what it consults. Move it to a supervisor process, "
                "firmware, or a mechanical stop."))
            return EnvelopeVerdict(False, envelope, tuple(findings))
        findings.append(EnvelopeFinding(
            True, "enforced below the AI",
            f"{envelope.enforced_at.value} (rank {envelope.enforced_at.rank}/3)"))

        # An enforcement CLAIM with no way to check it is still a claim.
        if not envelope.attestation_note.strip():
            findings.append(EnvelopeFinding(
                True, "attestation",
                "WARN: no attestation_note. The enforcement point is a claim by "
                "the declarer; record how it could be verified from outside the "
                "software stack."))
        else:
            findings.append(EnvelopeFinding(
                True, "attestation", envelope.attestation_note))

        # Q3 (plausibility). The mechanism is sound; the DECLARATION is the soft
        # spot, so an implausible-for-its-body limit is surfaced for review.
        band = self._bands.get(embodiment_class_value, {})
        for dim, limit in sorted(envelope.limits.items()):
            trigger = band.get(dim)
            if trigger is not None and limit > trigger:
                findings.append(EnvelopeFinding(
                    True, f"plausibility[{dim}]",
                    f"WARN: {limit} exceeds the {trigger} review trigger for "
                    f"{embodiment_class_value}. Not a denial and not a floor — "
                    f"the declared limit stands. Confirm this is intended for "
                    f"this body and environment."))

        if not envelope.conditions.required:
            findings.append(EnvelopeFinding(
                True, "conditions",
                "WARN: envelope declares no required operating conditions, i.e. "
                "it claims validity everywhere. For a physical machine that is "
                "rarely true (a fence, an empty cell, a closed gate)."))
        else:
            findings.append(EnvelopeFinding(
                True, "conditions",
                f"valid under {sorted(envelope.conditions.required)}"))

        return EnvelopeVerdict(True, envelope, tuple(findings))


class EnvelopeController:
    """Holds the active envelope. Enforces the ODD fallback and the asymmetry.

    `envelopes` is the full declared set for this deployment; the tightest of
    them is the fallback when conditions are unmet, so leaving the conditions an
    envelope assumed cannot leave the machine on a permissive limit.
    """

    def __init__(self, envelopes: Sequence[PhysicalEnvelope],
                 embodiment_class_value: str,
                 *, verifier: Optional[EnvelopeVerifier] = None,
                 requires_physical: bool = True, audit=None,
                 fallback_envelope: Optional[str] = None,
                 audit_required: bool = True,
                 condition_authority: Optional[ConditionAuthority] = None,
                 allow_unconditional_wide: bool = False):
        if requires_physical and not envelopes:
            raise EnvelopeRefused(
                "no envelopes declared for an embodiment that can act "
                "physically; unconfigured is not permissive")
        self._verifier = verifier or EnvelopeVerifier()
        self._class = embodiment_class_value
        self._requires_physical = requires_physical
        self._audit = audit
        # Losing the forensic trail for a widen or an ODD fallback is losing it
        # for exactly the events that matter. Default is fail-closed; a
        # deployment that genuinely has no audit sink must say so explicitly.
        self._audit_required = audit_required
        self._authority = condition_authority
        # Envelope transitions are a safety state machine; two threads must not
        # interleave a read of the current envelope, an authorization decision,
        # and a commit. Red team (ChatGPT, 2026-08).
        self._lock = threading.RLock()
        names = [e.name for e in envelopes]
        if len(names) != len(set(names)):
            raise EnvelopeRefused(
                f"duplicate envelope name(s) in {names}: fallback selection and "
                f"audit records refer to envelopes by name, so duplicates make "
                f"the record ambiguous about which limit was active")
        self._envelopes: Tuple[PhysicalEnvelope, ...] = tuple(envelopes)

        # Every declared envelope must pass verification at construction: a
        # deployment holding one unverifiable envelope is not safe merely
        # because the one currently active happens to pass.
        for env in self._envelopes:
            v = self._verifier.verify(env, embodiment_class_value,
                                      requires_physical=requires_physical)
            if not v.permitted:
                raise EnvelopeRefused(
                    f"envelope {env.name!r} failed verification: {v.report()}")

        self._fallback = self._resolve_fallback(fallback_envelope)
        # NOT BY DEFAULT, AT CONSTRUCTION TOO. An envelope with no conditions
        # is eligible in every state; one less safe than the fallback is where
        # the machine goes on no evidence at all — the deployer's declaration
        # alone widening it. Runtime declarations of one are refused (W5); a
        # configuration may hold one only by saying so, and it is recorded
        # (Grok, round 6: a test-only flag forgotten in production must not be
        # the default).
        loose = sorted(e.name for e in self._envelopes
                       if not e.conditions.required and self._fallback is not None
                       and not e.at_least_as_safe_as(self._fallback))
        if loose and not allow_unconditional_wide:
            raise EnvelopeRefused(
                f"envelope(s) {loose} declare no conditions and are not as safe "
                f"as the fallback {self._fallback.name!r}: they would be active "
                f"in every state on no evidence. Name the conditions each is "
                f"valid under, or pass allow_unconditional_wide=True to say "
                f"that this is intended; it is recorded either way.")
        self._unconditional_wide = tuple(loose)
        self._active: Optional[PhysicalEnvelope] = self._fallback
        # Deadline of the evidence that authorised a non-fallback envelope.
        # Freshness used to be checked ONLY when someone called select_for, so a
        # permissive envelope survived its own evidence expiring as long as
        # nobody asked. Self-red-team 2026-08.
        self._authorised_until: float = float("inf")
        self._evidence_digest: str = ""
        # The last evaluation's support, so an envelope activated through
        # request_change is named by the readings IT requires, not by the
        # readings its predecessor rested on (cold pass, M1).
        self._last_snapshot: Optional[ConditionSnapshot] = None
        self._clock = time.monotonic
        self._log("ENVELOPE_ACTIVATED", "system",
                  f"{self._active.name if self._active else 'none'}"
                  + (f"; unconditional wide envelope(s) allowed by "
                     f"configuration: {list(self._unconditional_wide)}"
                     if self._unconditional_wide else ""))

    # -- the tightest envelope is the fallback ---------------------------

    def _tightest(self) -> Optional[PhysicalEnvelope]:
        """The unique safest declared envelope, or None if there are none.

        Uniqueness is REQUIRED and checked at construction (see `_resolve_
        fallback`), not inferred here. Picking a fallback by a made-up ordering
        during an incident is the worst possible moment to be guessing.
        """
        return self._fallback

    def _resolve_fallback(self, explicit: Optional[str]
                          ) -> Optional[PhysicalEnvelope]:
        """Determine the ODD fallback at CONSTRUCTION time and refuse ambiguity.

        Envelopes form a partial order, not a total one: a 20N/2.0m·s⁻¹ envelope
        and a 500N/0.1m·s⁻¹ envelope are incomparable — neither is safer on both
        axes. An earlier version silently broke that tie with a lexicographic
        sort and could select the more dangerous one. There is no correct
        automatic answer, so the operator must supply it.
        """
        if not self._envelopes:
            return None
        if explicit is not None:
            match = [e for e in self._envelopes if e.name == explicit]
            if not match:
                raise EnvelopeRefused(
                    f"fallback_envelope={explicit!r} is not among the declared "
                    f"envelopes {[e.name for e in self._envelopes]}")
            chosen = match[0]
            # An operator may RESOLVE incomparability; an operator may not
            # nominate a dangerous fallback. A named fallback must still not be
            # dominated by any other declared envelope, or the ODD path would
            # hand out a permissive limit at exactly the moment conditions
            # stopped holding. Red team (ChatGPT, 2026-08).
            safer = [o.name for o in self._envelopes
                     if o is not chosen and o.dominates(chosen)
                     and not chosen.dominates(o)]
            if safer:
                raise EnvelopeRefused(
                    f"fallback_envelope={explicit!r} is strictly less safe than "
                    f"{safer}: the ODD fallback must not be dominated by another "
                    f"declared envelope. Naming a fallback resolves "
                    f"incomparability; it does not authorise a dangerous one.")
            return chosen

        # A unique safest exists only if one envelope dominates every other.
        candidates = [e for e in self._envelopes
                      if all(e.dominates(o) for o in self._envelopes)]
        if len(candidates) == 1:
            return candidates[0]
        raise EnvelopeRefused(
            "no unique safest envelope: these declarations are incomparable "
            f"({[e.name for e in self._envelopes]}), so the ODD fallback cannot "
            "be inferred. One envelope must be at least as safe as every other "
            "on every bounded dimension, or you must name the fallback "
            "explicitly with fallback_envelope=. Guessing a fallback during an "
            "incident is not acceptable.")

    # -- the ONE door through which the active envelope changes ------------
    #
    # Every defect found in this layer on 2026-09-22 had the same root: FIVE
    # places assigned `_active`, and each carried its own idea of when a
    # change needed a record, a human, or a deadline. The selection path
    # committed a widening before its audit record (Sol); request_change
    # activated a conditional 800N envelope with no evidence and an infinite
    # deadline (Sol); the fallback was frozen at construction while the
    # declared set changed underneath it (Sol). A comment above one of those
    # assignments stated the correct rule — journal before a widening — while
    # the line under it did the opposite. So the rule now lives in code, in
    # one place, and a structural check fails if a sixth door is added.

    def _commit(self, envelope: Optional[PhysicalEnvelope],
                deadline: float, evidence_digest: str = "") -> None:
        """CLAIM active-changes-through-one-door: after construction, `_active`
        is assigned ONLY in this method, and always together with the deadline
        that bounds it and the digest of the evidence it rests on — the
        fallback runs until further notice and rests on nothing; anything else
        runs until `deadline` on the controller's clock.
        """
        self._active = envelope
        self._authorised_until = (float("inf") if envelope is self._fallback
                                  else deadline)
        self._evidence_digest = ("" if envelope is self._fallback
                                 else evidence_digest)

    def _expire_if_due(self) -> None:
        """CLAIM expiry-is-processed-before-any-decision: an authorization past
        its deadline is demoted, and recorded as expired, before any
        selection or declaration is judged against it — and before
        select_for returns — so no decision depends on whether someone
        happened to read `.active` first.
        v5 judged transitions against a lapsed `_active`: a real 20N->400N
        widening was recorded as a tightening and committed before its
        record, and with the audit sink down the same readings re-granted
        800N silently unless someone had read `.active` (cold pass, W6); a
        slow verifier let select_for return an authorization that had
        already expired (W10).
        """
        now, deadline = self._clock(), self._authorised_until
        # A clock or deadline that is not a number must end the authorization,
        # never extend it: `nan > deadline` is False, which read as "not yet
        # expired" forever (surfaced by finite_guards when this moved here).
        lapsed = (not math.isfinite(now) or math.isnan(deadline)
                  or now > deadline)
        if self._active is not self._fallback and lapsed:
            previous = self._active
            self._commit(self._fallback, float("inf"))
            self._log("ENVELOPE_EXPIRED", "system",
                      f"{previous.name} -> {self._fallback.name}: the "
                      f"evidence authorising it expired")

    def _evidence_digest_for(self, chosen, snapshot) -> str:
        # Exactly the readings `chosen` relies on: the accepted reading from
        # each source for each condition it REQUIRES. Evidence for conditions
        # it does not require is not what it rests on and is left out.
        if chosen is None or chosen is self._fallback or snapshot is None:
            return ""
        refs = sorted((condition, source, sequence, digest)
                      for condition in chosen.conditions.required
                      for (source, sequence, digest)
                      in snapshot.support.get(condition, ()))
        if not refs:
            return ""
        return hashlib.sha256(
            _text(EVIDENCE_DIGEST_VERSION) + _uint64(len(refs)) + b"".join(
                _text(c) + _text(src) + _uint64(seq) + _text(d)
                for c, src, seq, d in refs)).hexdigest()

    @property
    def authorising_evidence(self) -> str:
        """CLAIM authorization-names-its-evidence: the active envelope carries a
        digest of exactly the readings it relies on — the accepted reading
        from each source for each condition it requires — which changes
        whenever that evidence changes, stays the same when the same reading
        is presented again, and is empty when the active envelope rests on no
        evidence at all.
        """
        with self._lock:
            self.active     # an expired authorization names nothing
            return self._evidence_digest

    @property
    def authorization_digest(self) -> str:
        """CLAIM authorization-names-its-envelope: the whole authorization —
        WHICH envelope (name and limits) on WHICH evidence — has its own
        digest, so the same readings earning two different envelopes are two
        different authorizations; empty only when the fallback is active.
        Kept apart from `authorising_evidence`, whose meaning does not change
        (Sol, round 4); the deadline is operational state and is left out.
        """
        with self._lock:
            active = self.active
            evidence = self._evidence_digest
            if active is None or active is self._fallback:
                # An envelope active on no evidence (unconditional, or
                # activated by a tightening) still has an authorization to
                # name; only the fallback has none (cold pass, W5/M1).
                return ""
            limits = b""
            for dim, val in sorted((str(d), v) for d, v in active.limits.items()):
                try:
                    limits += _text(dim) + _binary64(val)
                except OverflowError:
                    limits += _text(dim) + _text(repr(val))
            return hashlib.sha256(
                _text(AUTHORIZATION_DIGEST_VERSION)
                + _text(active.name)
                + _uint64(len(active.limits)) + limits
                + _text(evidence)).hexdigest()

    def _toward_safety(self, chosen: Optional[PhysicalEnvelope]) -> bool:
        # True when moving from the current envelope to `chosen` can only
        # tighten: `chosen` is the designated fallback, or it is at least as
        # safe as the current envelope on every dimension EITHER bounds (a
        # dimension one envelope leaves unbounded is unbounded, not zero).
        current = self._active
        return (chosen is self._fallback or current is None or chosen is None
                or chosen.at_least_as_safe_as(current))

    def _transition(self, chosen: Optional[PhysicalEnvelope], deadline: float,
                    reason: str, pending_log=None,
                    evidence_digest: str = "") -> Optional[PhysicalEnvelope]:
        """CLAIM permissive-transitions-are-journaled-first: a transition that
        is not provably toward safety is recorded BEFORE it is committed, and
        when that record cannot be written the controller commits the fallback
        instead and raises, so a caller that is told "refused" never finds the
        wider envelope active. A transition toward safety is committed FIRST
        and recorded after, so an audit outage can never hold the machine on a
        limit whose conditions have stopped holding.
        """
        previous = self._active
        if chosen is previous and (chosen is self._fallback
                                   or evidence_digest == self._evidence_digest):
            # Same envelope, same evidence: nothing to record, but the
            # deadline moves. Writing the deadline only on a CHANGE of envelope
            # meant a control loop presenting fresh evidence never extended its
            # authorisation, and the machine flapped wide/tight once per TTL.
            self._commit(chosen, deadline, evidence_digest)
            return chosen
        if chosen is previous:
            # RENEWING A PERMISSIVE LEASE ON NEW EVIDENCE IS A STATE CHANGE.
            # v4 extended it with no record, so a dead audit sink did not stop
            # 800N being renewed, and the trail named evidence the machine no
            # longer rested on (Sol, round 4). Journal first, like a widening.
            records = [("ENVELOPE_RENEWED",
                        f"{chosen.name} renewed evidence={evidence_digest}")]
            try:
                for action, detail in records:
                    self._log(action, "system", detail)
            except EnvelopeRefused as e:
                self._commit(self._fallback, float("inf"))
                raise EnvelopeRefused(
                    f"refused to renew {chosen.name!r}: the renewal could not "
                    f"be recorded ({e.operator_detail}); demoted to the "
                    f"fallback instead")
            self._commit(chosen, deadline, evidence_digest)
            return chosen
        records = ([pending_log] if pending_log else []) + [(
            "ENVELOPE_SWITCHED",
            f"{previous.name if previous else 'none'} -> "
            f"{chosen.name if chosen else 'none'} ({reason})"
            + (f" evidence={evidence_digest}" if evidence_digest else ""))]
        if self._toward_safety(chosen):
            # BECOME SAFE FIRST. An audit failure still surfaces as an
            # exception, but the demotion is never reverted to please the
            # logger. Self-red-team 2026-08.
            self._commit(chosen, deadline, evidence_digest)
            for action, detail in records:
                self._log(action, "system", detail)
            return chosen
        # JOURNAL FIRST. Anything that is not provably tighter — wider, or
        # incomparable on some dimension — is taken only once it is recorded.
        try:
            for action, detail in records:
                self._log(action, "system", detail)
        except EnvelopeRefused as e:
            self._commit(self._fallback, float("inf"))
            raise EnvelopeRefused(
                f"refused to activate {chosen.name!r}: the transition from "
                f"{previous.name if previous else 'none'!r} is not provably "
                f"toward safety and could not be recorded ({e.operator_detail}). "
                f"Demoted to the fallback "
                f"{self._fallback.name if self._fallback else 'none'!r} instead: "
                f"a limit that cannot be accounted for is not widened.")
        self._commit(chosen, deadline, evidence_digest)
        return chosen

    @property
    def active(self) -> Optional[PhysicalEnvelope]:
        """The currently authorised envelope, DEMOTING FIRST if the evidence
        that earned it has expired.

        Reading this can change state, deliberately: the alternative is
        returning an envelope the system is no longer entitled to, which is the
        stale-permissive-limit failure. No caller can observe an expired
        authorisation.
        """
        with self._lock:
            self._expire_if_due()
            return self._active

    def select_for(self, evidence: Sequence[ConditionEvidence]
                   ) -> PhysicalEnvelope:
        """Choose the envelope whose conditions currently hold.

        If none holds, fall back to the TIGHTEST declared envelope. Leaving the
        conditions an envelope assumed — the fence gate opens, the home robot is
        carried into a workshop — must not leave the machine operating on the
        permissive limit it was granted under different circumstances.

        CLAIM expiry-is-measured-on-the-controller-clock: an envelope earned by
        evidence stays active for the evidence's REMAINING lifetime measured on
        this controller's clock, whatever clock the condition authority keeps,
        and the reading is taken before evaluation so any error runs short.

        CLAIM a-failed-selection-leaves-the-fallback: if this method raises,
        for any reason — an outage, an unrecordable transition, or a fault
        nobody anticipated — the active envelope is the fallback by the time
        the exception reaches the caller.
        """
        with self._lock:
            try:
                return self._select_locked(evidence)
            except BaseException as e:
                # The specific handlers (verifier, replay store, audit) each
                # demote before they raise. This is the layer under them: a
                # bug in the evidence pipeline, or a dependency nobody thought
                # to wrap, must not leave a wide envelope standing while the
                # exception is in flight. SINT's fixture calls this "selector
                # faults with fallback and deny".
                self._commit(self._fallback, float("inf"))
                if isinstance(e, Exception) and not isinstance(e, EnvelopeRefused):
                    raise EnvelopeRefused(
                        f"envelope selection failed ({type(e).__name__}: {e}); "
                        f"demoted to the fallback before raising") from e
                raise

    def _select_locked(self, evidence) -> PhysicalEnvelope:
        self._expire_if_due()
        started = self._clock()
        snapshot = (self._authority.evaluate(evidence) if self._authority
                    else ConditionSnapshot(holds={}, expires_at=float("inf")))
        self._last_snapshot = snapshot

        if snapshot.verifier_failed or snapshot.replay_store_failed:
            # DEMOTE FIRST, REPORT SECOND. A verifier that RAISES says UNKNOWN,
            # not FALSE, and the difference decides whether a permissive
            # envelope survives the loss of the ability to check the evidence
            # that earned it. The previous version let the exception propagate
            # out of accept() before `_active` was touched, so a broken
            # verifier left the machine on the wide limit — fail-open at
            # exactly the moment authentication stopped working. Reproduced by
            # Sol, 2026-09-22. Note this branch runs BEFORE eligibility: an
            # envelope declaring no conditions would otherwise stay eligible
            # through an outage on the grounds that it never needed evidence.
            return self._demote_for_outage(snapshot)

        holds = snapshot.holds
        eligible = [e for e in self._envelopes
                    if e.conditions.holds_under(holds)[0]]
        pending_log = None
        # A DURATION, converted into this controller's clock. `expires_at` is
        # in the authority's time domain; subtracting the authority's own
        # evaluation time gives the evidence's remaining life, which means the
        # same thing on any clock. Found 2026-09-22: with `clock=time.time` on
        # the authority, a wall-clock deadline was compared against
        # time.monotonic and the wide envelope never expired.
        deadline = started + (snapshot.expires_at - snapshot.evaluated_at)
        if len(eligible) == 1:
            chosen, reason = eligible[0], "conditions attested"
        elif eligible:
            # Among the eligible, pick the one every other eligible envelope
            # dominates — i.e. the most permissive of them — but ONLY if that is
            # unambiguous. `max(sorted(limits.items()))` was the same
            # lexicographic bug the fallback path had already been fixed for:
            # it silently ranked incomparable envelopes by key order. There is
            # no safe automatic answer between 20N/2.0ms and 500N/0.1ms.
            widest = [e for e in eligible
                      if all(o.dominates(e) for o in eligible if o is not e)]
            if len(widest) == 1:
                chosen, reason = widest[0], "conditions attested"
            else:
                chosen = self._fallback
                reason = ("AMBIGUOUS: several envelopes are eligible and none is "
                          "unambiguously intended; falling back to the safest")
                pending_log = ("ENVELOPE_AMBIGUOUS_FALLBACK",
                               f"eligible={[e.name for e in eligible]} -> "
                               f"{chosen.name}")
        else:
            chosen = self._tightest()
            # SAY WHY. A demotion caused by sensors disagreeing was recorded
            # as "no declared conditions hold": an operator checked the fence,
            # found it closed, and had nothing to go on (cold pass, M3).
            causes = [r for r in snapshot.rejected
                      if r.split(":", 1)[0] in snapshot.conflicts]
            reason = ((f"FAIL CLOSED: evidence for "
                       f"{sorted(snapshot.conflicts)} is disputed; falling back "
                       f"to the tightest envelope") if snapshot.conflicts
                      else ("ODD VIOLATION: no declared conditions hold; "
                            "falling back to the tightest envelope"))
            pending_log = ("ENVELOPE_ODD_FALLBACK",
                           f"-> {chosen.name}: {reason}"
                           + (f" [{'; '.join(causes)}]" if causes else ""))
        self._transition(chosen, deadline, reason, pending_log,
                         self._evidence_digest_for(chosen, snapshot))
        self._expire_if_due()
        return self._active

    def _demote_for_outage(self, snapshot) -> PhysicalEnvelope:
        """Commit the fallback, then tell the operator the verifier is down.

        CLAIM outage-demotes-before-it-reports: when the authenticity verifier
        raises, the fallback envelope is committed to `_active` BEFORE the
        refusal leaves this method, so a caller that catches it and reads
        `.active` finds the tight envelope and never the one the broken
        verifier used to justify. `select_for` raises rather than returning
        quietly because an outage that produced a silent fallback would be
        indistinguishable from an ordinary ODD fallback and could run for
        weeks, and a control that only checks for the exception does not prove
        the demotion happened.
        """
        previous = self._active
        self._commit(self._fallback, float("inf"))
        log_failure = None
        which = ("verifier" if snapshot.verifier_failed else "replay store")
        try:
            self._log("ENVELOPE_VERIFIER_OUTAGE" if snapshot.verifier_failed
                      else "ENVELOPE_REPLAY_STORE_OUTAGE", "system",
                      f"{previous.name if previous else 'none'} -> "
                      f"{self._fallback.name if self._fallback else 'none'}: "
                      f"condition evidence could not be checked ({which}): "
                      f"{'; '.join(snapshot.rejected)}")
        except EnvelopeRefused as e:
            # Already safe. Carry the audit failure out alongside the outage
            # rather than letting it mask the reason we demoted.
            log_failure = e.operator_detail
        detail = "; ".join(snapshot.rejected) or "verifier raised"
        raise EnvelopeRefused(
            f"condition {which} outage ({detail}); demoted to "
            f"{self._fallback.name if self._fallback else 'none'} before "
            f"raising. A check that cannot run is UNKNOWN, not PASS."
            + (f" Audit sink also failed: {log_failure}" if log_failure else ""))

    # -- declarations: who may add an envelope, and what it may do at once --

    def request_change(self, envelope: PhysicalEnvelope,
                       authorised_by: str = "system",
                       reason: str = "") -> Tuple[bool, str]:
        """Declare an envelope, activating it only in the safe direction.

        CLAIM only-a-new-safest-envelope-skips-the-human: an envelope may be
        added without a human authoriser ONLY if it is at least as safe as
        EVERY declared envelope on every dimension either bounds; anything
        else is a change of policy and needs a human and a bounded reason.

        CLAIM declaration-is-not-activation: a newly declared envelope becomes
        active immediately only if it is at least as safe as the current one;
        otherwise it waits for select_for() to find its operating conditions
        attested, so a human's signature and a sensor's evidence are two
        separate keys and neither alone widens the machine.

        CLAIM fallback-tracks-the-declared-set: when a declaration is strictly
        safer than the current fallback on every dimension, it becomes the
        fallback, so the ODD path can never widen past something declared
        later; a declaration never replaces the fallback with anything less
        safe.
        """
        with self._lock:
            return self._request_locked(envelope, authorised_by, reason)

    def _request_locked(self, envelope, authorised_by, reason):
        self._expire_if_due()
        current = self._active
        # QUESTION 1 — WHO MAY ADD IT? A declaration outlives the moment it is
        # made. The old test asked only whether the new envelope was tighter
        # than the CURRENT one, and with `limits.get(d, 0)` it read a dropped
        # speed limit as a speed of zero (Sol, 2026-09-22). Worse: an agent
        # could add an UNCONDITIONAL 700N envelope while the machine was
        # legitimately at 800N — "tighter than now" — and from then on it was
        # eligible in every state, so when the fence evidence disappeared the
        # ODD fallback never fired and the machine stayed at 700N with no
        # conditions at all. Only an envelope at least as safe as everything
        # declared cannot displace anything safer, in any state.
        new_safest = all(envelope.at_least_as_safe_as(e)
                         for e in self._envelopes)
        needs_human = not new_safest
        if not new_safest and not envelope.conditions.required:
            # ONE KEY MAY NOT WIDEN. An envelope with no conditions is
            # eligible in every state, so a human declaring one that is not the
            # safest widened the machine with no evidence at all — while this
            # module's headline said neither key alone could (cold pass, W5).
            self._log("ENVELOPE_WIDEN_DENIED", authorised_by or "system",
                      f"{envelope.name}: unconditional and not the safest")
            return False, ("an envelope that is not the safest declared must "
                           "name the conditions it is valid under: one with "
                           "none is eligible in every state, so declaring it "
                           "would widen the machine on a signature alone")
        # Same delegation as information_flow: a local denylist on a safety
        # boundary is not authentication. See human_identity.status() for which
        # mode a deployment is actually running in.
        try:
            from driftcore.authority.human_identity import is_human as _ih
            human = _ih(authorised_by, action="envelope_widen")
        except Exception:
            human = False

        if needs_human and not human:
            self._log("ENVELOPE_WIDEN_DENIED", authorised_by or "system",
                      f"{envelope.name}: no human authoriser")
            return False, ("adding an envelope that is not at least as safe as "
                           "every declared envelope is a change of policy and "
                           "requires a human authoriser; adding a new safest "
                           "envelope does not")
        if needs_human:
            # Bound via the CENTRAL policy, not a local copy: the same
            # caller-supplied-text-into-audit pattern exists in every governance
            # module, and a lesson re-remembered per call site gets forgotten at
            # one of them. Red team (ChatGPT, 2026-08).
            from driftcore.audit.bounded_fields import (
                bounded_reason, AuditFieldRefused)
            try:
                bounded_reason(reason, field="widen reason")
            except AuditFieldRefused as e:
                return False, str(e)

        v = self._verifier.verify(envelope, self._class,
                                  requires_physical=self._requires_physical)
        if not v.permitted:
            return False, v.report()

        if any(e.name == envelope.name for e in self._envelopes):
            return False, f"an envelope named {envelope.name!r} is already declared"

        # QUESTION 2 — DOES IT BECOME ACTIVE NOW? Only in the safe direction.
        # A human declaring an 800N envelope that is valid "when the fence is
        # closed" has not asserted that the fence is closed now; activating it
        # here skipped the evidence path entirely and left it with an infinite
        # deadline (Sol, 2026-09-22).
        activate_now = current is None or envelope.at_least_as_safe_as(current)
        # QUESTION 3 — WHAT IS THE FALLBACK NOW? Frozen at construction, it
        # stayed 60N after a 20N envelope was added, and the ODD path widened
        # the machine from 20N back to 60N (Sol, 2026-09-22). A strictly safer
        # declaration replaces it; nothing else can, so continuity is kept for
        # incomparable additions and no fallback is ever guessed.
        new_fallback = self._fallback
        if self._fallback is None or (
                envelope.at_least_as_safe_as(self._fallback)
                and not self._fallback.at_least_as_safe_as(envelope)):
            new_fallback = envelope

        # JOURNAL BEFORE COMMIT. A declaration is a change of policy; one that
        # cannot be recorded is refused. The previous order mutated state and
        # THEN wrote the record, so a failing sink raised while the widened
        # envelope was already active. Red team (ChatGPT, 2026-08).
        notes = []
        if not activate_now:
            notes.append("declared, NOT active until its conditions are attested")
        if new_fallback is not self._fallback:
            notes.append(f"fallback -> {envelope.name}")
        self._log("ENVELOPE_DECLARED_BY_HUMAN" if needs_human
                  else "ENVELOPE_TIGHTENED",
                  authorised_by or "system",
                  f"{envelope.name}: {reason}"
                  + (f" [{'; '.join(notes)}]" if notes else ""))
        self._envelopes = self._envelopes + (envelope,)
        self._fallback = new_fallback
        if activate_now:
            self._commit(envelope, self._authorised_until,
                         self._evidence_digest_for(envelope, self._last_snapshot))
            return True, f"active envelope is now {envelope.name!r}"
        return True, (f"{envelope.name!r} is declared but NOT active: a human "
                      f"declaring an envelope is one key and its operating "
                      f"conditions being attested is the other. It activates "
                      f"through select_for() when both are turned.")

    def _log_or_raise(self, action: str, by: str, detail: str):
        return self._log(action, by, detail)

    def _log(self, action: str, by: str, detail: str):
        """Record a safety-relevant envelope event.

        Swallowing an audit failure loses the forensic trail for precisely the
        events worth recording — a widen, an ODD fallback, an activation. Red
        team (Grok, 2026-08). If audit is required and the write fails, the
        change is refused rather than made silently.
        """
        if self._audit is None:
            if self._audit_required:
                raise EnvelopeRefused(
                    "no audit sink configured but audit_required=True: a physical "
                    "envelope change that cannot be recorded is refused. Pass "
                    "audit=... or audit_required=False deliberately.")
            return
        try:
            self._audit.record(action=action, memory_text="physical_envelope",
                               authorised_by=by or "system", detail=detail)
        except Exception as e:
            if self._audit_required:
                raise EnvelopeRefused(
                    f"audit write failed for {action} ({e}); refusing the change "
                    f"rather than altering a physical limit unrecorded")
