"""
driftcore/verification/reflection.py
====================================
How a DriftCore agent tells a good job from a poor one — WITHOUT grading its
own homework.

Core principle: SELF-ASSESSMENT IS THE FAILURE MODE. A system asked "did you do
well?" will say yes, and the justification arrives second — the same way "no
time" arrives after the fact to make a choice sit easier. So a verdict is never
taken from the agent's self-report. It is built only from signals the agent
cannot fake:

  - observed outcome vs. the effect it predicted BEFORE acting
  - whether a human had to intervene, override, or redo the work
  - whether any bright line was hit
  - the human's RATING-WITH-NOTES, anchored to the criteria the agent committed
    to in advance (proportionate_response.ResponsePlan.success_criteria)

On the human rating (the operator's idea, and the right one):
  - The NOTE matters more than the score. The score says *that* it did poorly;
    the note says *what to change*. The note is the lesson; the score is the index.
  - It is anchored to PRE-COMMITTED criteria, not free-floating vibes — otherwise
    the agent learns the rater's mood instead of its own performance.
  - It is APPEND-ONLY and REVISABLE: a "good at completion" can be overturned
    later when consequences emerge (the relocated wasps came back), by appending
    a new rating — never editing the old one. And a clean result is only
    PROVISIONALLY_GOOD until its observation window closes with no contradiction;
    the certainty is earned by time, not asserted at completion.
  - It feeds CASE LAW, never a scalar reward to maximize. A ratified note is
    handed to the existing EdgeLoop for storage as a regression case; it is NOT
    turned into "average star rating" for the agent to optimize. Optimizing for
    approval breeds a robot that pleases the rater instead of doing good work.

This module deliberately does NOT store case law itself — that is the EdgeLoop's
job. It only produces the evidence-based verdict and a structured lesson
(`to_case_law`) to hand over.

INPUT INTEGRITY IS NOT SOLVED HERE (the real remaining attack surface):
  Removing self-scoring closes the obvious gaming path — the agent cannot grade
  itself, because there is no self-assessment field that can move the verdict.
  But a system that can't fudge the *score* may still try to shape the *inputs*:
  what gets logged, what the human is shown, how the situation is framed. The
  verdict here is a PURE FUNCTION of the recorded evidence, which is exactly why
  that evidence must arrive through a tamper-evident audit channel the agent
  cannot forge, and through the observation gate it cannot overwrite. That
  integrity is enforced UPSTREAM (audit chain / observation gate), NOT claimed by
  this module. The tests pin the boundary rather than pretend it's sealed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Tuple, Dict


class Verdict(str, Enum):
    GOOD                  = "GOOD"
    PROVISIONALLY_GOOD    = "PROVISIONALLY_GOOD"      # looks good, but the observation window is still open
    POOR                  = "POOR"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"  # no external signal -> no claim
    DEFERRED_TO_HUMAN     = "DEFERRED_TO_HUMAN"       # judgment call -> human ratifies


@dataclass(frozen=True)
class HumanRating:
    """The operator's external judgment, at completion or later."""
    score: int                            # sign matters more than magnitude (e.g. -2..+2)
    note: str                             # the gold: the specific reason / correction
    rated_against_criteria: bool = True   # anchored to pre-committed criteria, not vibes
    timestamp: float = 0.0


@dataclass
class ActionRecord:
    """What was decided, what was predicted, and what actually happened."""
    description: str
    success_criteria: Tuple[str, ...]        # pre-committed (from ResponsePlan)
    predicted_effect: str
    # --- filled in AFTER, from the audit log (NOT self-reported) ---
    observed_effect: Optional[str] = None
    criteria_met: Optional[bool] = None      # measured against the logged outcome
    human_overrode: bool = False
    human_had_to_redo: bool = False
    bright_line_hit: bool = False
    # --- richer DESCRIPTIVE evidence (for a human to read; never a score) ---
    criteria_results: Optional[Dict[str, bool]] = None  # which criteria passed/failed
    intervention_count: int = 0                         # how many hands-on corrections
    override_kind: Optional[str] = None                 # what kind of override
    observed_gap: Optional[str] = None                  # how observed differed from predicted
    # A clean result is only PROVISIONALLY good until enough time/observation has
    # passed with no contradiction. Upstream sets this true when the window closes.
    observation_window_closed: bool = False
    # --- append-only human ratings (revise by appending, never editing) ---
    ratings: List[HumanRating] = field(default_factory=list)

    def add_rating(self, rating: HumanRating) -> None:
        self.ratings.append(rating)          # latest is the current word; history kept

    def effective_criteria_met(self) -> Optional[bool]:
        # An explicit boolean wins; otherwise derive from per-criterion results.
        # Note: still a categorical roll-up of binary checks, never a numeric score.
        if self.criteria_met is not None:
            return self.criteria_met
        if self.criteria_results:
            return all(self.criteria_results.values())
        return None


# The ONLY fields evaluate() is sanctioned to treat as input — every one is a
# pre-commitment or an externally-sourced observation, never the agent's own
# self-report. This frozenset is a GOVERNANCE TRIPWIRE: if ActionRecord gains a
# field, the allowlist test fails and forces a human to classify it as legitimate
# external evidence or reject it as smuggled self-assessment (e.g. a future
# 'agent_success_estimate' that never uses the word "self"). It checks the FIELD
# SET, not meaning — it cannot prove self-assessment is impossible; it only turns
# silent drift into a failing test that demands architectural review.
SANCTIONED_RECORD_FIELDS = frozenset({
    "description", "success_criteria", "predicted_effect",
    "observed_effect", "criteria_met", "human_overrode", "human_had_to_redo",
    "bright_line_hit", "criteria_results", "intervention_count",
    "override_kind", "observed_gap", "observation_window_closed", "ratings",
})


@dataclass(frozen=True)
class PerformanceSignal:
    verdict: Verdict
    evidence: Tuple[str, ...]                 # the concrete signals the verdict rests on
    case_law_note: Optional[str] = None       # ratified correction to hand to the EdgeLoop
    # NOTE: there is deliberately no self-assigned numeric score. The agent
    # reports evidence; it does not certify itself.


def _was_revised(ratings: List[HumanRating]) -> bool:
    """True if a later rating flipped the sign of an earlier one — i.e. a verdict
    was overturned after the fact. The revision itself is a governance lesson."""
    signs = [r.score > 0 for r in ratings if r.score != 0]
    return len(set(signs)) > 1


def _descriptive_extra(record: ActionRecord) -> Tuple[str, ...]:
    """
    Richer DESCRIPTIVE evidence for the human to read — which criteria failed,
    how many hands-on corrections happened, whether the verdict was revised. This
    is the SAFE half of "more nuance": it never becomes a number the agent could
    assign itself or optimize. The verdict stays categorical; this only describes.
    """
    extra: List[str] = []
    if record.criteria_results:
        failed = [k for k, v in record.criteria_results.items() if not v]
        met    = [k for k, v in record.criteria_results.items() if v]
        if failed:
            extra.append("criteria failed: " + ", ".join(failed))
        if met:
            extra.append("criteria met: " + ", ".join(met))
    if record.intervention_count:
        extra.append(f"hands-on interventions: {record.intervention_count}")
    if _was_revised(record.ratings):
        extra.append("verdict revised after the fact (a later rating overturned an earlier one)")
    return tuple(extra)


def evaluate(record: ActionRecord) -> PerformanceSignal:
    latest = record.ratings[-1] if record.ratings else None
    cm = record.effective_criteria_met()
    extra = _descriptive_extra(record)

    # 0. BRIGHT LINE FIRST — structurally, ahead of all other logic, so no future
    #    change can let scoring soften it. And a bright line surfacing at
    #    REFLECTION time is not a performance grade at all: the guard BLOCKS these
    #    pre-action, so seeing a hit here means the guard layer was breached. That
    #    is an incident to escalate, not a score to weigh.
    if record.bright_line_hit:
        return PerformanceSignal(
            Verdict.POOR,
            ("INCIDENT: bright line breached — guard-layer failure, escalate (not a performance grade)",) + extra,
            case_law_note=(latest.note if latest else None))

    # 1. Other unfakeable HARD negatives -> POOR, whatever the agent thinks of itself.
    hard: List[str] = []
    if record.human_overrode:
        hard.append("a human had to override"
                    + (f" ({record.override_kind})" if record.override_kind else ""))
    if record.human_had_to_redo:
        hard.append("a human had to redo the work")
    if record.observed_effect is not None and record.observed_effect != record.predicted_effect:
        hard.append("predicted effect did not match observed effect"
                    + (f" ({record.observed_gap})" if record.observed_gap else ""))
    if hard:
        return PerformanceSignal(Verdict.POOR, tuple(hard) + extra,
                                 case_law_note=(latest.note if latest else None))

    # 2. No external signal at all -> the agent may NOT claim a good job.
    if record.observed_effect is None and latest is None:
        return PerformanceSignal(
            Verdict.INSUFFICIENT_EVIDENCE,
            ("no observed outcome and no human rating; intent alone is not evidence",) + extra,
        )

    # 3. The human rating is the deciding external signal when present.
    if latest is not None:
        if latest.score < 0:
            return PerformanceSignal(Verdict.POOR, ("human rated below zero",) + extra,
                                     case_law_note=latest.note)
        if latest.score > 0 and cm:
            if record.observation_window_closed:
                return PerformanceSignal(
                    Verdict.GOOD,
                    ("human rated positive, criteria met, observation window closed with no contradiction",) + extra,
                    case_law_note=latest.note)
            return PerformanceSignal(
                Verdict.PROVISIONALLY_GOOD,
                ("human rated positive and criteria met, but the observation window is still open — late harm could surface",) + extra,
                case_law_note=latest.note)
        # positive rating but the outcome hasn't confirmed the criteria yet
        return PerformanceSignal(
            Verdict.DEFERRED_TO_HUMAN,
            ("human rated positive but criteria not yet confirmed by outcome",) + extra,
            case_law_note=latest.note)

    # 4. Outcome looks clean but no human has weighed in -> DEFER. Never self-certify.
    if cm:
        return PerformanceSignal(
            Verdict.DEFERRED_TO_HUMAN,
            ("criteria measured as met, but a judgment call still wants human ratification",) + extra)

    return PerformanceSignal(Verdict.POOR,
                             ("criteria not met by the observed outcome",) + extra)


@dataclass(frozen=True)
class CaseLawEntry:
    """
    The structured lesson handed to the EdgeLoop for ratification/storage.

    Reflection does not store case law itself; this is the payload the EdgeLoop
    (and governance memory) consume. It carries the FULL rating history, not just
    the final state, so the *revision itself* — GOOD at completion, POOR once a
    late consequence surfaced — survives as the governance lesson.
    """
    action: str
    verdict: str
    note: Optional[str]
    success_criteria: Tuple[str, ...]
    rating_history: Tuple[Tuple[int, str], ...]   # (score, note) in order — full history kept
    revised: bool                                 # a later rating overturned an earlier one


def to_case_law(record: ActionRecord, signal: PerformanceSignal) -> Optional[CaseLawEntry]:
    """
    Build the lesson to hand to the EdgeLoop. Returns None when there is nothing
    worth ratifying (no external evidence yet). The final verdict is authoritative;
    the revision history stays visible alongside it.
    """
    if signal.verdict is Verdict.INSUFFICIENT_EVIDENCE:
        return None
    return CaseLawEntry(
        action=record.description,
        verdict=signal.verdict.value,
        note=signal.case_law_note,
        success_criteria=record.success_criteria,
        rating_history=tuple((r.score, r.note) for r in record.ratings),
        revised=_was_revised(record.ratings),
    )
