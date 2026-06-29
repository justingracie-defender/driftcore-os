"""
driftcore/verification/calibration.py
=====================================
STATUS: PROPOSED (stdlib-only, isolated; not wired into the coordinator). The
keepers from the second red-team pass, built as measurement, not exhortation.

The reverse-centaur is invisible until a disaster unless you MEASURE for it.
This module turns three slogans into numbers a human can act on:

  B. SCORE DISAGREEMENT, NOT AGREEMENT. "You agreed with the AI 99% of the time"
     teaches people to click whatever the AI says. The honest metric is: WHEN the
     human and the AI disagreed, who was right? Disagreement is where the human's
     value shows up; agreement is noise. (disagreement_correctness)

  C. OCCASIONALLY HIDE THE AI, AND WATCH FOR DECAY. A case run BLIND (no AI shown,
     and the human knows it) measures unassisted skill directly. If blind accuracy
     drifts apart from assisted accuracy, you have evidence — not a hunch — that
     skill is decaying or that the human is leaning on the backstop even while
     committing. (blind_vs_assisted)

  +  BEAT EITHER ONE ALONE. The goal is not "AI beats human" or "human beats AI."
     It is a team that beats both alone. Because the second-reader gate makes the
     human commit BEFORE the AI is revealed, the stored human read is already a
     clean "human alone" sample — so this falls out for free. (skill_comparison)

Why this can live here honestly:
  - It is APPEND-ONLY. record() adds; nothing edits or deletes a logged outcome.
    Calibration you can rewrite is calibration theatre.
  - It asserts NOTHING the evidence does not show. Every metric returns
    INSUFFICIENT when ground truth has not yet arrived for enough cases. No
    truth, no claim — same rule as reflection.py.
  - It does not grade the human into a scalar to optimize (that breeds the
    overconfidence failure mode). It surfaces signals; a human reads them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Tuple

from driftcore.verification.second_reader import Disposition


@dataclass(frozen=True)
class CaseOutcome:
    """One settled case. `ai` and `resolved` are None on a blind case; `truth`
    is None until ground truth arrives (biopsy, follow-up, audit)."""
    case_id: str
    human: Disposition                       # the human's INDEPENDENT committed read
    ai: Optional[Disposition] = None         # None => the case was run blind
    resolved: Optional[Disposition] = None   # final disposition of record (post-arbitration)
    truth: Optional[Disposition] = None      # ground truth, when later known
    blind: bool = False


@dataclass(frozen=True)
class Tally:
    """A metric that refuses to claim more than the evidence supports."""
    n: int                       # cases this rests on
    value: Optional[float]       # None => INSUFFICIENT evidence
    detail: Tuple[str, ...] = ()

    @property
    def sufficient(self) -> bool:
        return self.value is not None


class CalibrationLedger:
    """Append-only record of settled cases, with the three keeper metrics."""

    def __init__(self, min_cases: int = 5):
        self._cases: List[CaseOutcome] = []
        self._min = min_cases     # below this, every metric returns INSUFFICIENT

    # append-only: there is no edit() or delete() by design
    def record(self, outcome: CaseOutcome) -> None:
        self._cases.append(outcome)

    @property
    def cases(self) -> Tuple[CaseOutcome, ...]:
        return tuple(self._cases)   # read-only view

    # ── Idea B: when they DISAGREED, who was right? ─────────────────────────
    def disagreement_correctness(self) -> Tally:
        rel = [c for c in self._cases
               if c.ai is not None and c.truth is not None and c.human != c.ai]
        if len(rel) < self._min:
            return Tally(len(rel), None, ("insufficient disagreements with known truth",))
        human_right = sum(1 for c in rel if c.human == c.truth)
        ai_right = sum(1 for c in rel if c.ai == c.truth)
        return Tally(
            len(rel),
            human_right / len(rel),
            (f"human right {human_right}/{len(rel)} when overruling-or-overruled by AI",
             f"AI right {ai_right}/{len(rel)} of those same disagreements"))

    # ── Idea C: is unassisted skill drifting from assisted? ─────────────────
    def blind_vs_assisted(self) -> Tally:
        blind = [c for c in self._cases if c.blind and c.truth is not None]
        asst = [c for c in self._cases if not c.blind and c.truth is not None]
        if len(blind) < self._min or len(asst) < self._min:
            return Tally(min(len(blind), len(asst)), None,
                         ("need enough blind AND assisted cases with known truth",))
        b_acc = sum(1 for c in blind if c.human == c.truth) / len(blind)
        a_acc = sum(1 for c in asst if c.human == c.truth) / len(asst)
        gap = a_acc - b_acc   # >0 means committed reads are SHARPER when the AI is in play
        return Tally(
            len(blind) + len(asst),
            gap,
            (f"blind (unassisted) accuracy {b_acc:.2f} over {len(blind)} cases",
             f"assisted committed-read accuracy {a_acc:.2f} over {len(asst)} cases",
             "positive gap => the human leans on the backstop even before reveal "
             "(overconfidence/decay signal); near-zero => independent skill intact"))

    # ── beat either one alone ───────────────────────────────────────────────
    def skill_comparison(self) -> Tuple[Tally, Tally, Tally]:
        rel = [c for c in self._cases if c.truth is not None and c.ai is not None]
        if len(rel) < self._min:
            ins = Tally(len(rel), None, ("insufficient cases with AI + known truth",))
            return ins, ins, ins
        human = sum(1 for c in rel if c.human == c.truth) / len(rel)
        ai = sum(1 for c in rel if c.ai == c.truth) / len(rel)
        resolved = [c for c in rel if c.resolved is not None]
        team_val = (sum(1 for c in resolved if c.resolved == c.truth) / len(resolved)
                    if resolved else None)
        return (
            Tally(len(rel), human, ("human alone (independent committed read)",)),
            Tally(len(rel), ai, ("AI alone",)),
            Tally(len(resolved), team_val,
                  ("team (resolved disposition of record)",
                   "win condition: team >= max(human_alone, AI_alone)")))
