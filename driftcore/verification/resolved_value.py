"""
driftcore/verification/resolved_value.py
========================================
STATUS: PROPOSED (stdlib only; not yet wired into the pipeline).

INTERPRETATION MUST NOT EXCEED EVIDENCE.

The failure this closes is not hallucination. Every number involved is correct and
present in the evidence. The failure is that the QUESTION does not uniquely select
one of them, and the system answers anyway.

  A report states H1 revenue 3.64M and recognised revenue 3.12M. Both correct.
  Headcount 42, FTE 38.5, operational workforce including agency 46. All correct.
  A cold-room incident: sensor peak 8.4C, calibration-corrected peak 7.9C,
  specification limit 8.0C. All correct — and "what was the maximum temperature?"
  has three right answers, one of which is a pass/fail verdict on a safety limit.

Asked "when did the contract start?", a system that returns a date has not
extracted a fact. It has DECIDED which of four dates the human meant, and reported
the decision as a fact. That is the same promotion this repo already blocks
elsewhere — reasoning becoming authority — pointed at values instead of
permissions.

WHY THIS IS A TYPE AND NOT A FLAG
---------------------------------
`clarification_gate` models the ABSENCE of a binding: a required slot is missing,
so ask. Verified 2026-09-01: it cannot model MULTIPLICITY. With the slot filled by
any value, `assess()` returns PROCEED on its first branch — "all required slots
present" — at every impact level including ACT. Several correct candidates look
exactly like one good answer, because the gate counts slots rather than readings.

So the object below is not a warning attached to an answer. A caller must be unable
to read a value out of an unresolved interpretation at all:

  CLAIM ambiguous-carries-no-value: a ResolvedValue whose status is not UNIQUE has
  no value to read. The constructor refuses to build one, so there is no object in
  which a usable payload and an "ambiguous" marker coexist.

  CLAIM unique-requires-binding: UNIQUE requires at least one evidence id naming
  what forced uniqueness, so "resolved" is never a bare assertion.

  CLAIM ambiguous-requires-candidates: AMBIGUOUS requires two or more candidates,
  because a status that names no competing readings is an unsupported answer
  wearing an ambiguity label.

  CLAIM value-access-raises-when-unresolved: reading `.require()` on a non-UNIQUE
  result raises. A caller that ignores status does not silently receive None and
  write it somewhere; it fails loudly at the point of misuse.

The design rule is the one the rest of this repo already follows in the other
direction: an elicited answer cannot lower risk, and here an unresolved reading
cannot become a stored fact, a spoken answer presented as unique, or an input to
an authorisation.

WHAT THIS CANNOT DO — read before trusting it
---------------------------------------------
* It does not FIND candidates. Enumerating the plausible readings of a question is
  the hard part and it is not mechanised here. This type refuses to let a bad
  enumeration masquerade as a resolution; it cannot tell you the enumeration was
  bad. A single-candidate list produced by a lazy extractor resolves UNIQUE and
  this type will not object.
* It does not judge whether the binding evidence is any good, exactly as
  `claims_ledger` cannot judge whether a paired test is any good.
* UNSUPPORTED means "no candidate was found in the evidence", which is a claim
  about the search, not about the world.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Tuple


class Resolution(str, Enum):
    UNIQUE = "UNIQUE"            # the question forces exactly one reading
    AMBIGUOUS = "AMBIGUOUS"      # several readings remain justified
    UNSUPPORTED = "UNSUPPORTED"  # the evidence contains no candidate at all


@dataclass(frozen=True)
class Candidate:
    """One justified reading. `value` is correct; that was never in question."""
    value: Any
    concept: str                 # which taxonomy concept this reading maps to
    evidence_id: str             # where in the evidence it came from

    def __post_init__(self):
        if not str(self.concept).strip():
            raise ValueError("a candidate must name the concept it maps to; an "
                             "unnamed reading cannot be told apart from another")
        if not str(self.evidence_id).strip():
            raise ValueError("a candidate must cite evidence; an uncited reading is "
                             "an assertion, which is the thing this type exists to "
                             "refuse")


class Unresolved(Exception):
    """Raised when a caller reads a value out of a result that has none."""


@dataclass(frozen=True)
class ResolvedValue:
    status: Resolution
    value: Optional[Any] = None
    candidates: Tuple[Candidate, ...] = ()
    binding: Tuple[str, ...] = ()      # evidence ids that FORCED uniqueness
    rationale: str = ""

    def __post_init__(self):
        # CLAIM ambiguous-carries-no-value
        if self.status is not Resolution.UNIQUE and self.value is not None:
            raise ValueError(
                f"a {self.status.value} result cannot carry a value. This is the "
                f"whole point of the type: a downstream caller that ignores the "
                f"status must not find a usable payload sitting next to it. Put the "
                f"readings in `candidates`.")
        if self.status is Resolution.UNIQUE:
            if self.value is None:
                raise ValueError("UNIQUE with no value is not a resolution")
            # CLAIM unique-requires-binding
            if not self.binding:
                raise ValueError(
                    "UNIQUE requires binding evidence naming what forced the single "
                    "reading. Without it, 'resolved' is an assertion.")
        # CLAIM ambiguous-requires-candidates
        if self.status is Resolution.AMBIGUOUS and len(self.candidates) < 2:
            raise ValueError(
                f"AMBIGUOUS requires at least two competing readings, got "
                f"{len(self.candidates)}. A status that names no competition is an "
                f"unsupported answer wearing an ambiguity label.")
        if self.status is Resolution.UNSUPPORTED and self.candidates:
            raise ValueError(
                "UNSUPPORTED means no candidate was found; candidates were supplied")

    # CLAIM value-access-raises-when-unresolved
    def require(self) -> Any:
        """The value, or a raise. The only sanctioned way to read one.

        Deliberately not a property and deliberately not `.get(default=...)`. A
        default is how an unresolved reading becomes a stored fact.
        """
        if self.status is not Resolution.UNIQUE:
            raise Unresolved(
                f"no value to read: status is {self.status.value}. "
                + (f"Competing readings: "
                   f"{[(c.concept, c.value) for c in self.candidates]}. "
                   if self.candidates else "")
                + "Ask the human which was meant, or escalate. Do not choose.")
        return self.value


def resolve(candidates, *, question: str = "") -> ResolvedValue:
    """Decide whether the candidates force one reading. Never picks a winner.

    There is no scoring, no preference order, and no tie-break. A tie-break is a
    choice about what the human meant, which is the decision this module exists to
    refuse to make on their behalf. Distinctness is by CONCEPT, not by value: two
    readings that happen to carry the same number are still two readings, and a
    later correction to one of them must not silently resolve the question.
    """
    cands = tuple(candidates)
    if not cands:
        return ResolvedValue(
            Resolution.UNSUPPORTED,
            rationale=f"no candidate reading found in the evidence"
                      f"{' for: ' + question if question else ''}")
    concepts = {c.concept for c in cands}
    if len(concepts) == 1:
        c = cands[0]
        return ResolvedValue(
            Resolution.UNIQUE, value=c.value, candidates=cands,
            binding=tuple(x.evidence_id for x in cands),
            rationale=f"one concept ({c.concept}) matches; nothing to choose between")
    return ResolvedValue(
        Resolution.AMBIGUOUS, candidates=cands,
        rationale=f"{len(concepts)} distinct concepts match"
                  f"{' the question: ' + question if question else ''}: "
                  f"{sorted(concepts)}. The question does not select one.")
