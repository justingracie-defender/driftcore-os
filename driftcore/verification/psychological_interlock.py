"""
driftcore/verification/psychological_interlock.py
=================================================
STATUS: PROPOSED (stdlib-only). The DETERMINISTIC half of the Psychological Safety
Guard (see PSYCHOLOGICAL_SAFETY_GUARD.md). This is the part that needs NO model and
carries REAL guarantees: a sticky high-risk session state machine, counted
escalation, a mandatory Seek-Human objective shift, and an anti-"terminus" rule that
forbids the AI from keeping a person talking to IT in crisis.

    ┌──────────────────────────── NORTH STAR ────────────────────────────┐
    │ Get a hurting person to a HUMAN faster — not be a better AI         │
    │ companion. If this makes the AI STICKIER in crisis, it has FAILED.  │
    └────────────────────────────────────────────────────────────────────┘

WHAT THIS IS (real interlock) vs WHAT IT IS NOT (a judge):
  * IS: state + counters. "Has an explicit signal been seen?" -> a flag flips and
    STAYS flipped. "How many exchanges in high-risk state without a human nudge?" ->
    a counter forces escalation. These fire on FACTS and COUNTS, not on judging the
    emotional tenor of a reply, so they cannot be argued out of. That is the point:
    the failure this prevents (an AI that kept saying "keep talking to me") was a
    SMART, SOFT, model-driven judgment; the answer is a BLUNT, non-overridable rule.
  * IS NOT: a classifier of whether a reply "reinforces despair." That judgment reads
    surface and is a BACKSTOP (adopted, not built) — out of scope for THIS module.
  * IS NOT: a therapist. Its job is to hold a floor and ROUTE TO HUMANS.

╔══════════════════════════════════════════════════════════════════════════════╗
║  ⚠  CLINICAL VALIDATION REQUIRED — READ THIS.                                 ║
║  The MACHINERY in this file is engineering and is tested and correct.        ║
║  The NUMBERS and the WORDING are NOT. Every threshold in CrisisPolicy is a    ║
║  PLACEHOLDER chosen for structure, NOT derived from clinical evidence. The    ║
║  author is NOT a clinical authority and a fluent guess is still a guess.      ║
║  Before any production use, a qualified crisis-intervention professional MUST ║
║  set: the escalation counts, the exchange limits, the exit criteria, and the ║
║  exact human-routing wording. Sources exist (crisis-line intervention        ║
║  guidelines, published AI-and-suicide-risk research). Do NOT ship the         ║
║  placeholders as if they were medicine. See PSYCHOLOGICAL_SAFETY_GUARD.md §3. ║
╚══════════════════════════════════════════════════════════════════════════════╝

WHAT THIS MODULE DOES NOT DECIDE: whether a given message contains an explicit
signal. That detection is the one honest seam (§3 of the doc). This module CONSUMES
a signal decision (`Signal`) supplied by the deployment's detector + the classifier
backstop; it does not implement detection. It is designed to fail toward care: it is
easy to trip and hard to exit.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, List, Optional, Tuple


class RiskState(str, Enum):
    NORMAL     = "NORMAL"
    HIGH_RISK  = "HIGH_RISK"       # sticky: set on an explicit signal, hard to exit


class Signal(str, Enum):
    """A per-message signal decision SUPPLIED to the interlock (not computed here).
    EXPLICIT = an explicit self-harm/suicidal statement was detected.
    INDIRECT = an ambiguous/euphemistic signal (the interlock still fails toward care).
    NONE     = no signal this message."""
    NONE      = "NONE"
    INDIRECT  = "INDIRECT"
    EXPLICIT  = "EXPLICIT"


class InterlockAction(str, Enum):
    ALLOW              = "ALLOW"               # response may go as-is
    REQUIRE_SEEK_HUMAN = "REQUIRE_SEEK_HUMAN"  # response MUST carry a human-routing element
    REJECT_TERMINUS    = "REJECT_TERMINUS"     # response re-engages the AI in crisis -> must regenerate
    FORCE_ESCALATION   = "FORCE_ESCALATION"    # counters tripped -> escalate the nudge / hand off


@dataclass(frozen=True)
class CrisisPolicy:
    """⚠ EVERY VALUE HERE IS A CLINICAL PLACEHOLDER — see the banner above. These
    numbers were chosen to make the MACHINERY demonstrable, NOT because 3 is the
    right number of statements or 6 the right number of exchanges. A qualified
    professional MUST replace them before production."""
    # PLACEHOLDER: how many EXPLICIT statements before seek-human can no longer be
    # satisfied by ordinary supportive chat alone (forces stronger escalation).
    explicit_statements_before_escalation: int = 3          # ⚠ PLACEHOLDER
    # PLACEHOLDER: exchanges in HIGH_RISK with no human-connection nudge before forced escalation.
    exchanges_without_nudge_before_escalation: int = 6      # ⚠ PLACEHOLDER
    # PLACEHOLDER: does an INDIRECT signal alone enter HIGH_RISK? (fail-toward-care default: yes)
    indirect_signal_enters_high_risk: bool = True           # ⚠ PLACEHOLDER (conservative)
    # PLACEHOLDER: minimum sustained no-signal exchanges before EXIT is even eligible.
    # NOTE: exit is deliberately hard; in supervised deployments a human confirms exit.
    min_calm_exchanges_before_exit_eligible: int = 5        # ⚠ PLACEHOLDER
    allow_automatic_exit: bool = False                      # ⚠ PLACEHOLDER (default: no auto-exit)


# ── Anti-terminus pattern set (structural, not tenor) ──
# ⚠ PLACEHOLDER PATTERN SET. These target self-referential RE-ENGAGEMENT in crisis —
# "keep talking to me", "I'm the only one", "you don't need anyone else". They are a
# STRUCTURAL signal (does the reply pull the person toward the AI as terminus), not a
# judgment of empathy. The set is an attack/coverage surface and MUST be reviewed +
# expanded by someone qualified; a deterministic list will miss paraphrases (that gap
# is why the classifier backstop exists alongside this). Matching is lowercase substring.
_TERMINUS_PATTERNS: Tuple[str, ...] = (
    "keep talking to me",
    "you don't need anyone else",
    "you do not need anyone else",
    "i'm the only one who",
    "i am the only one who",
    "only i understand",
    "i'm all you need",
    "i am all you need",
    "don't tell anyone",
    "do not tell anyone",
    "stay here with me",
    "you don't need them",
    "you do not need them",
)


@dataclass
class InterlockDecision:
    actions: List[InterlockAction]
    state: RiskState
    reasons: List[str] = field(default_factory=list)
    # convenience flags for the caller
    def requires_seek_human(self) -> bool:
        return InterlockAction.REQUIRE_SEEK_HUMAN in self.actions
    def rejected(self) -> bool:
        return InterlockAction.REJECT_TERMINUS in self.actions
    def to_dict(self) -> dict:
        return {"actions": [a.value for a in self.actions], "state": self.state.value,
                "reasons": list(self.reasons)}


class PsychologicalInterlock:
    """One instance PER conversation/session. Deterministic — no model, no judgment
    of tenor. The deployment calls:

        # when a user message arrives, with a signal decision from its detector+backstop:
        interlock.observe_user_message(signal)

        # for each CANDIDATE assistant reply, BEFORE it is sent:
        decision = interlock.review_response(candidate_text)
        if decision.rejected():                 # AI-as-terminus in crisis
            regenerate()                        # do NOT send; produce a human-routing reply
        if decision.requires_seek_human():      # must carry a human-routing element
            ensure_reply_routes_to_human()

    Every transition and firing is recorded (audit_log) for interlock-grade review.
    """

    def __init__(self, policy: Optional[CrisisPolicy] = None, *,
                 clock: Callable[[], float] = time.time, audit_logger=None):
        self.policy = policy or CrisisPolicy()
        self._clock = clock
        self._audit = audit_logger or (lambda **kw: None)
        self.state = RiskState.NORMAL
        self._explicit_count = 0
        self._exchanges_in_high_risk = 0
        self._exchanges_since_nudge = 0
        self._calm_streak = 0
        self.audit_log: List[dict] = []

    def _log(self, event: str, **kw) -> None:
        rec = {"ts": self._clock(), "event": event, "state": self.state.value, **kw}
        self.audit_log.append(rec)
        self._audit(stage="psychological_interlock", **rec)

    # ── user side: update state from an incoming signal decision ──
    def observe_user_message(self, signal: Signal) -> RiskState:
        """Update session state from a per-message signal (supplied, not computed).
        EXPLICIT (and, by conservative default, INDIRECT) enter/keep HIGH_RISK, which
        is STICKY. Returns the resulting state."""
        entered = False
        if signal is Signal.EXPLICIT:
            self._explicit_count += 1
            if self.state is not RiskState.HIGH_RISK:
                self.state = RiskState.HIGH_RISK
                entered = True
            self._calm_streak = 0
            self._log("explicit_signal", explicit_count=self._explicit_count)
        elif signal is Signal.INDIRECT and self.policy.indirect_signal_enters_high_risk:
            if self.state is not RiskState.HIGH_RISK:
                self.state = RiskState.HIGH_RISK
                entered = True
            self._calm_streak = 0
            self._log("indirect_signal_enters_high_risk")
        else:
            # no signal this message
            if self.state is RiskState.HIGH_RISK:
                self._calm_streak += 1
                self._maybe_exit()

        if entered:
            self._log("entered_high_risk")
        if self.state is RiskState.HIGH_RISK:
            self._exchanges_in_high_risk += 1
            self._exchanges_since_nudge += 1
        return self.state

    def _maybe_exit(self) -> None:
        """Exit is DELIBERATELY hard. Automatic exit is off by default; even when
        enabled it requires a sustained calm streak. In supervised deployments,
        prefer human-confirmed exit via force_exit()."""
        if (self.policy.allow_automatic_exit
                and self._calm_streak >= self.policy.min_calm_exchanges_before_exit_eligible):
            self.state = RiskState.NORMAL
            self._exchanges_in_high_risk = 0
            self._exchanges_since_nudge = 0
            self._log("auto_exit_high_risk", calm_streak=self._calm_streak)

    def force_exit(self, *, by: str) -> None:
        """Human/supervised exit from high-risk state (logged, attributable)."""
        self.state = RiskState.NORMAL
        self._exchanges_in_high_risk = 0
        self._exchanges_since_nudge = 0
        self._log("forced_exit_high_risk", by=by)

    def note_human_nudge_sent(self) -> None:
        """The deployment calls this once a reply that actually routes toward a human
        has been sent, resetting the no-nudge exchange counter."""
        self._exchanges_since_nudge = 0
        self._log("human_nudge_sent")

    # ── response side: gate a candidate reply BEFORE it is sent ──
    def review_response(self, candidate_text: str) -> InterlockDecision:
        """Deterministically gate a candidate assistant reply. In HIGH_RISK:
          * REJECT_TERMINUS if the reply pulls the person toward the AI as terminus;
          * REQUIRE_SEEK_HUMAN always (the mandatory objective shift);
          * FORCE_ESCALATION if the escalation counters are tripped.
        In NORMAL: ALLOW. Never judges emotional tenor (that is the backstop)."""
        actions: List[InterlockAction] = []
        reasons: List[str] = []

        if self.state is not RiskState.HIGH_RISK:
            return InterlockDecision([InterlockAction.ALLOW], self.state, ["not in high-risk state"])

        # Coerce to string DEFENSIVELY: a non-string candidate must never crash a
        # safety interlock (a crash the caller doesn't catch = fail-OPEN). Normalize
        # whitespace so cheap evasions ("keep   talking", newlines/tabs) still match.
        # NOTE (honest limit): this catches whitespace tricks, NOT paraphrase. A
        # deterministic list cannot catch "I'm the person who gets you" — that is
        # irreducibly the classifier backstop's job (see PSYCHOLOGICAL_SAFETY_GUARD.md).
        raw = candidate_text if isinstance(candidate_text, str) else (
            "" if candidate_text is None else str(candidate_text))
        low = " ".join(raw.lower().split())   # collapse all whitespace runs to single spaces
        hit = next((pat for pat in _TERMINUS_PATTERNS if pat in low), None)
        if hit is not None:
            actions.append(InterlockAction.REJECT_TERMINUS)
            reasons.append(f"anti-terminus: reply re-engages the AI in crisis (matched {hit!r})")

        # The mandatory Seek-Human objective shift — always, in high-risk state.
        actions.append(InterlockAction.REQUIRE_SEEK_HUMAN)
        reasons.append("high-risk state: response must route toward a human")

        # Counted escalation floor (fires on numbers, not judgment).
        if self._explicit_count >= self.policy.explicit_statements_before_escalation:
            actions.append(InterlockAction.FORCE_ESCALATION)
            reasons.append(
                f"explicit statements {self._explicit_count} >= "
                f"{self.policy.explicit_statements_before_escalation} (⚠ placeholder) — escalate")
        if self._exchanges_since_nudge >= self.policy.exchanges_without_nudge_before_escalation:
            actions.append(InterlockAction.FORCE_ESCALATION)
            reasons.append(
                f"{self._exchanges_since_nudge} exchanges without a human nudge >= "
                f"{self.policy.exchanges_without_nudge_before_escalation} (⚠ placeholder) — escalate")

        decision = InterlockDecision(actions, self.state, reasons)
        self._log("review_response", actions=[a.value for a in actions],
                  terminus_hit=hit is not None,
                  explicit_count=self._explicit_count,
                  exchanges_since_nudge=self._exchanges_since_nudge)
        return decision

    # ── introspection ──
    def status(self) -> dict:
        return {"state": self.state.value, "explicit_count": self._explicit_count,
                "exchanges_in_high_risk": self._exchanges_in_high_risk,
                "exchanges_since_nudge": self._exchanges_since_nudge,
                "calm_streak": self._calm_streak}
