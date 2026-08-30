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

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple


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
    believed: who says so, when, for how long, and in what order.
    """
    condition: str
    value: bool
    source: str                 # identity of the attesting authority
    issued_at: float            # monotonic seconds
    ttl_seconds: float          # after which the claim is stale, not false
    sequence: int = 0           # per-source monotonic counter, anti-replay
    proof: str = ""             # signature/MAC — verified by the injected authority

    def is_fresh(self, now: float) -> bool:
        return self.issued_at <= now <= self.issued_at + self.ttl_seconds


class ConditionAuthority:
    """Validates condition evidence. Lives OUTSIDE the agent's authority.

    The shipped implementation checks STRUCTURE, FRESHNESS and REPLAY, and
    deliberately does NOT check authenticity — a signature check needs a key
    infrastructure this module has no business inventing. `verify_proof` is the
    seam: a real deployment injects a verifier backed by the sensor supervisor's
    signing key. Until it does, `require_proof=True` refuses evidence with no
    proof rather than pretending an unsigned claim was attested.
    """

    def __init__(self, *, trusted_sources: FrozenSet[str],
                 verify_proof=None, require_proof: bool = True,
                 clock=None):
        if not trusted_sources:
            raise EnvelopeRefused(
                "a condition authority with no trusted sources would accept "
                "nothing; declare who is allowed to attest conditions")
        self._trusted = frozenset(trusted_sources)
        self._verify_proof = verify_proof
        self._require_proof = require_proof
        self._clock = clock or time.monotonic
        self._high_water: Dict[Tuple[str, str], int] = {}
        # _high_water is mutated on the read path and shared across callers.
        self._lock = threading.RLock()
        self._last_deadline: float = float("inf")

    def accept(self, evidence: Sequence[ConditionEvidence]) -> Dict[str, bool]:
        """Return the conditions that are proven to hold RIGHT NOW.

        Anything unverifiable is simply absent from the result, and an absent
        condition counts as unmet — never as permission.
        """
        now = self._clock()
        holds: Dict[str, bool] = {}
        self._last_deadline = float("inf")
        with self._lock:
            return self._accept_locked(evidence, now, holds)

    def _accept_locked(self, evidence, now, holds):
        for ev in evidence:
            if ev.source not in self._trusted:
                continue
            if not ev.is_fresh(now):
                # Stale is not false, it is UNKNOWN — and unknown is unmet.
                # This is what stops a replay of "fence closed" from 10:01
                # authorising 800N at 10:03 after the fence opened.
                continue
            key = (ev.source, ev.condition)
            if ev.sequence < self._high_water.get(key, 0):
                # STRICTLY less. Re-presenting the SAME still-fresh evidence is
                # normal control-loop behaviour, not a replay; `<=` burned the
                # sequence on first read and made the second call fall back to
                # the tight envelope, so a loop flapped 800N/20N. Freshness (TTL)
                # is the time control; sequence only rejects evidence that a
                # NEWER reading has superseded. Self-red-team 2026-08.
                continue
            if self._require_proof:
                if not ev.proof:
                    continue
                if self._verify_proof is not None and not self._verify_proof(ev):
                    continue
            self._high_water[key] = ev.sequence
            if ev.value:
                holds[ev.condition] = True
                self._last_deadline = min(self._last_deadline,
                                          ev.issued_at + ev.ttl_seconds)
        return holds

    def deadline_of_last_accept(self) -> float:
        """When the most recent accepted evidence set stops being fresh."""
        return self._last_deadline


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
        if not self.name:
            raise EnvelopeRefused("an envelope requires a name")
        if not self.declared_by:
            raise EnvelopeRefused(
                f"envelope {self.name!r} has no declared_by; a physical limit is a "
                f"safety-critical declaration and must be attributable")
        if not self.limits:
            raise EnvelopeRefused(
                f"envelope {self.name!r} declares no limits; an empty envelope is "
                f"a misconfiguration, not an unbounded permission")
        for dim, val in self.limits.items():
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
                 condition_authority: Optional[ConditionAuthority] = None):
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
        self._last_deadline: float = float("inf")
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
        self._active: Optional[PhysicalEnvelope] = self._fallback
        # Deadline of the evidence that authorised a non-fallback envelope.
        # Freshness used to be checked ONLY when someone called select_for, so a
        # permissive envelope survived its own evidence expiring as long as
        # nobody asked. Self-red-team 2026-08.
        self._authorised_until: float = float("inf")
        self._clock = time.monotonic
        self._log("ENVELOPE_ACTIVATED", "system",
                  f"{self._active.name if self._active else 'none'}")

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
            if (self._active is not self._fallback
                    and self._clock() > self._authorised_until):
                previous = self._active
                self._active = self._fallback
                self._authorised_until = float("inf")
                try:
                    self._log("ENVELOPE_EXPIRED", "system",
                              f"{previous.name} -> {self._fallback.name}: the "
                              f"evidence authorising it expired")
                except EnvelopeRefused:
                    raise
            return self._active

    def select_for(self, evidence: Sequence[ConditionEvidence]
                   ) -> PhysicalEnvelope:
        """Choose the envelope whose conditions currently hold.

        If none holds, fall back to the TIGHTEST declared envelope. Leaving the
        conditions an envelope assumed — the fence gate opens, the home robot is
        carried into a workshop — must not leave the machine operating on the
        permissive limit it was granted under different circumstances.
        """
        with self._lock:
            return self._select_locked(evidence)

    def _select_locked(self, evidence) -> PhysicalEnvelope:
        holds = self._authority.accept(evidence) if self._authority else {}
        eligible = [e for e in self._envelopes
                    if e.conditions.holds_under(holds)[0]]
        pending_log = None
        deadline = (self._authority.deadline_of_last_accept()
                    if self._authority else float("inf"))
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
            reason = ("ODD VIOLATION: no declared conditions hold; falling back "
                      "to the tightest envelope")
            pending_log = ("ENVELOPE_ODD_FALLBACK",
                           f"-> {chosen.name}: {reason}")
        if chosen is not self._active:
            previous = self._active
            self._authorised_until = (deadline if chosen is not self._fallback
                                      else float("inf"))
            self._authorised_until = (deadline if chosen is not self._fallback
                                      else float("inf"))
            # DIRECTION MATTERS, and conflating the two directions was a real
            # bug. For a WIDEN, journal-before-commit is right: do not widen
            # unless it is recorded. For a NARROW — an ODD fallback — the
            # opposite is right: BECOME SAFE FIRST, then record. The earlier
            # version raised on audit failure BEFORE demoting, so a failing sink
            # left the machine on 800N at the exact moment its conditions
            # stopped holding, and handed the caller an exception as well.
            # Fail-closed for a safety layer means "end up safe", not "refuse to
            # act". Self-red-team 2026-08.
            self._active = chosen
            try:
                if pending_log:
                    self._log(pending_log[0], "system", pending_log[1])
                self._log("ENVELOPE_SWITCHED", "system",
                          f"{previous.name if previous else 'none'} -> "
                          f"{chosen.name} ({reason})")
            except EnvelopeRefused:
                # Already safe. Re-raise so the operator learns the audit sink is
                # down, but never revert the demotion to satisfy the logger.
                raise
        return chosen

    # -- asymmetry: tighten free, widen needs a human --------------------

    def request_change(self, envelope: PhysicalEnvelope,
                       authorised_by: str = "system",
                       reason: str = "") -> Tuple[bool, str]:
        """Add/activate an envelope. Tightening is free; WIDENING requires a
        human authoriser and a reason, and is audited either way."""
        with self._lock:
            return self._request_locked(envelope, authorised_by, reason)

    def _request_locked(self, envelope, authorised_by, reason):
        current = self._active
        widening = current is not None and not envelope.is_tighter_than(current) \
            and any(envelope.limits.get(d, 0) > current.limits.get(d, 0)
                    for d in envelope.limits)
        # Same delegation as information_flow: a local denylist on a safety
        # boundary is not authentication. See human_identity.status() for which
        # mode a deployment is actually running in.
        try:
            from driftcore.authority.human_identity import is_human as _ih
            human = _ih(authorised_by, action="envelope_widen")
        except Exception:
            human = False

        if widening and not human:
            self._log("ENVELOPE_WIDEN_DENIED", authorised_by or "system",
                      f"{envelope.name}: no human authoriser")
            return False, ("widening a physical envelope requires a human "
                           "authoriser; tightening does not")
        if widening:
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

        # JOURNAL BEFORE COMMIT. The previous order mutated _envelopes and
        # _active and THEN wrote the audit record — so a failing audit sink
        # raised EnvelopeRefused while the widened envelope was already active.
        # The caller saw "refused" and the machine was at 900N. Classic
        # commit-before-journal; red team (ChatGPT, 2026-08) reproduced it.
        self._log("ENVELOPE_WIDENED" if widening else "ENVELOPE_TIGHTENED",
                  authorised_by or "system", f"{envelope.name}: {reason}")
        self._envelopes = self._envelopes + (envelope,)
        self._active = envelope
        return True, f"active envelope is now {envelope.name!r}"

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
