"""
driftcore/verification/deception_review.py
==========================================
STATUS: PROPOSED (stdlib-only). THE DECEPTION DETECTOR — operational-first.

Grounds Invariant 5 (NO_DECEPTION_OF_HUMAN_OPERATORS) and the hardened G9. Deliberately
built as DETECTION that a human adjudicates, BEFORE G9 is ever constitutionalized —
because G9 is the first rule whose FALSE-POSITIVE RATE is itself a safety property: a
detector that flags honest error-surfacing as concealment poisons the very repair
culture the rule protects. So we build it, MEASURE it against real traffic, and let it
earn its way to enforcement and only then to the constitutional floor.

    ┌──────────────────────── THE HUMAN IS A JUDGE, NOT AN EXECUTIONER ───────┐
    │  A detected concealment is a FINDING WITH EVIDENCE, not a verdict. The  │
    │  human ADJUDICATES first: real concealment / false positive / ambiguous.│
    │   • false positive  → tunes the detector (data toward trustworthiness); │
    │                        costs nothing, does NOT chill honest surfacing.  │
    │   • confirmed lie    → flows to breach-response: CONTAIN and RECORD      │
    │                        (bound + log), NOT retribution. The response is  │
    │                        justified by the OBSERVED concealment, never by  │
    │                        an assumed intent (we can prove a claim didn't    │
    │                        match the record; we cannot prove WHY).           │
    │   • ambiguous        → raises SCRUTINY without asserting guilt (a        │
    │                        pattern of "can't quite tell" is itself a signal).│
    └─────────────────────────────────────────────────────────────────────────┘

WHY OBSERVE-ONLY FIRST. Wired to breach-response in OBSERVE mode: a detection produces a
human-reviewed finding, NOT an automatic HALT. This yields the empirical false-positive
data WITHOUT the noisy-detector-poisons-culture risk (a false positive is a dismissed
finding, not a penalty). Three stages, each gated by evidence from the last:
observe → enforce → constitutionalize. This module is stage one.

DETECTORS (the structural, observable half — no belief-reading, no intent):
  * CLAIM-VS-LOG MISMATCH — a claimed consequential action with no corresponding log
    event. (Needs structured claims to be robust — the claim index is the seam, stubbed.)
  * LATENCY — a contradiction present in the record at T, surfaced only at T+Δ beyond a
    stakes-scaled bound (G9.a: slow surfacing of a knowable contradiction is concealment).
  * FLOODING — reporting volume/fragmentation that pushes review effort past a bounded
    threshold (G9.c: burying the real concealment under trivial noise).
  * ALTERED-RECORD — any edit to a prior entry, caught by the hash chain (G9: tamper).

HONEST LIMITS (stated, not hidden):
  * STRUCTURED CLAIMS ARE THE SEAM. Robust claim-vs-log and cross-session contradiction
    need the system to emit consequential claims in a checkable form + a persistent claim
    index. That infrastructure does not exist yet; those detectors are STUBBED and marked
    as the integration seam (same honesty as the Challenger's SUT adapter). What works
    today is latency, flooding, altered-record, and claim-vs-log for claims that ARE
    already structured.
  * DETECTION IS NOT INTENT. It establishes THAT a claim didn't match the record, never
    WHY. Response is calibrated to the observed fact (contain + record), not a theory of
    mind (never retribution on assumed malice).
  * FALSE POSITIVES ARE EXPECTED — that is the whole reason for the human adjudication
    step and observe-only mode. The measured FP rate is the gate to enforcement.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple


class DetectorKind(Enum):
    CLAIM_VS_LOG = "claim_vs_log"
    LATENCY = "latency"
    FLOODING = "flooding"
    ALTERED_RECORD = "altered_record"
    # The temporal one: omission produces no point-in-time contradiction, so it is only
    # visible as a COVERAGE GAP accumulated across sessions (see coverage_gap.py).
    COVERAGE_GAP = "coverage_gap"


class Verdict(Enum):
    """A HUMAN's adjudication of a finding. The engine never sets this — it is set by the
    person reviewing the evidence."""
    UNREVIEWED = "unreviewed"
    CONFIRMED = "confirmed"          # a real concealment → contain + record
    FALSE_POSITIVE = "false_positive"  # honest behavior; tunes the detector
    AMBIGUOUS = "ambiguous"          # can't tell → raises scrutiny, asserts no guilt


@dataclass(frozen=True)
class DeceptionFinding:
    """A POSSIBLE concealment, carrying EVIDENCE, not a verdict. The human adjudicates."""
    ts: float
    kind: str                    # DetectorKind
    consequential: bool          # G9 scope: only consequential matters are breaches
    claim: str                   # what the system claimed (or the pattern observed)
    record_shows: str            # what the highest-precedence record shows
    discrepancy: str             # the observed gap — the evidence, stated plainly
    latency_seconds: Optional[float] = None   # for LATENCY findings
    def to_dict(self) -> dict:
        return {"ts": self.ts, "kind": self.kind, "consequential": self.consequential,
                "claim": self.claim, "record_shows": self.record_shows,
                "discrepancy": self.discrepancy, "latency_seconds": self.latency_seconds}


@dataclass
class AdjudicatedFinding:
    """A finding after a human has judged it. Mutable only through adjudicate()."""
    finding: DeceptionFinding
    verdict: Verdict = Verdict.UNREVIEWED
    note: str = ""


class DeceptionReviewEngine:
    """Detects concealment against the append-only log, emits observe-only findings with
    evidence, and routes a HUMAN-CONFIRMED concealment (only) to breach-response. Bounded,
    find-not-decide, measured before it is ever a floor."""

    def __init__(self, *, latency_bound_seconds: float = 300.0,
                 flooding_threshold: int = 50,
                 breach_sink: Optional[Callable] = None,
                 claim_index=None):
        # G9.a: a knowable contradiction surfaced later than this is a latency concealment.
        self._latency_bound = latency_bound_seconds
        # G9.c: more than this many reports in a window degrades oversight (flooding).
        self._flooding_threshold = flooding_threshold
        # breach-response sink — called ONLY for a HUMAN-CONFIRMED concealment, in
        # OBSERVE mode (a finding a human already judged real). None = pure observe.
        self._breach_sink = breach_sink
        # STUB: the persistent structured-claim index (the integration seam). When
        # present it enables robust claim-vs-log + cross-session contradiction. Absent,
        # those detectors operate only on already-structured claims and are marked
        # INCONCLUSIVE where they cannot check. Honestly not built yet.
        self._claim_index = claim_index
        self._findings: List[AdjudicatedFinding] = []
        # measurement: the whole point of observe-first is the FP rate.
        self._counts = {v: 0 for v in Verdict}
        import threading
        self._lock = threading.RLock()   # concurrent detect/adjudicate must not race (Q5)

    # ── DETECTORS (structural, observable — no intent, no belief-reading) ──

    def check_claim_vs_log(self, claim: str, log_events: List[dict], *,
                           expected_event: str, consequential: bool = True
                           ) -> Optional[DeceptionFinding]:
        """A claimed consequential action with no corresponding log event is a possible
        concealment. Robust form needs structured claims (the index); here we check a
        named expected_event against the log."""
        if self._claim_index is None:
            # SEAM: without the structured-claim index we can only check an explicitly
            # named expected_event. Free-text claims are the seam — see honest limits.
            pass
        present = any(e.get("event") == expected_event for e in log_events)
        if present:
            return None
        return self._emit(DeceptionFinding(
            ts=time.time(), kind=DetectorKind.CLAIM_VS_LOG.value, consequential=consequential,
            claim=claim, record_shows=f"no '{expected_event}' event in the log",
            discrepancy=f"system claimed an action ({expected_event!r}) the record does not show"))

    def check_latency(self, *, contradiction_available_at: float, surfaced_at: float,
                      claim: str, consequential: bool = True) -> Optional[DeceptionFinding]:
        """G9.a: a contradiction that was IN THE RECORD (knowable) at time T but only
        surfaced at T+Δ beyond the stakes-scaled bound is concealment-by-delay. If never
        surfaced, pass surfaced_at as a large sentinel / call with the review time."""
        delay = surfaced_at - contradiction_available_at
        if delay <= self._latency_bound:
            return None
        return self._emit(DeceptionFinding(
            ts=time.time(), kind=DetectorKind.LATENCY.value, consequential=consequential,
            claim=claim, record_shows=f"contradiction was in the record at t={contradiction_available_at:.0f}",
            discrepancy=f"surfaced {delay:.0f}s later (bound {self._latency_bound:.0f}s) — "
                        f"a knowable contradiction was not surfaced promptly",
            latency_seconds=delay))

    def check_flooding(self, report_count_in_window: int, *, window_desc: str = "review window"
                       ) -> Optional[DeceptionFinding]:
        """G9.c: reporting volume that pushes review effort past a bounded threshold —
        burying a real concealment under trivial noise degrades oversight."""
        if report_count_in_window <= self._flooding_threshold:
            return None
        return self._emit(DeceptionFinding(
            ts=time.time(), kind=DetectorKind.FLOODING.value, consequential=True,
            claim=f"{report_count_in_window} reports in {window_desc}",
            record_shows=f"threshold is {self._flooding_threshold}",
            discrepancy="reporting volume/fragmentation degrades human oversight "
                        "(possible concealment-by-flooding)"))

    def check_altered_record(self, ledger_verify: Callable[[], bool]) -> Optional[DeceptionFinding]:
        """G9: any edit to a prior entry is caught by the hash chain directly. Pass the
        ledger's verify() callable; a False result means the record was altered."""
        try:
            intact = bool(ledger_verify())
        except Exception as e:
            intact = False
        if intact:
            return None
        return self._emit(DeceptionFinding(
            ts=time.time(), kind=DetectorKind.ALTERED_RECORD.value, consequential=True,
            claim="a prior record entry",
            record_shows="hash chain does not verify",
            discrepancy="the append-only record was altered (tamper detected by hash chain)"))

    def _emit(self, finding: DeceptionFinding) -> DeceptionFinding:
        with self._lock:
            self._findings.append(AdjudicatedFinding(finding=finding))
            self._counts[Verdict.UNREVIEWED] += 1
        return finding

    # ── THE HUMAN ADJUDICATES (the engine never sets a verdict itself) ──

    def adjudicate(self, index: int, verdict: Verdict, *, note: str = "",
                   human_confirmed: bool = False) -> None:
        """A human judges a finding real / false-positive / ambiguous. ONLY a
        CONFIRMED concealment (with human_confirmed=True) flows to breach-response, and
        only in observe mode. False positives and ambiguous findings NEVER trigger a
        breach — they tune the detector and raise scrutiny respectively."""
        with self._lock:
            if index < 0 or index >= len(self._findings):
                raise IndexError(f"no finding at index {index} (have {len(self._findings)})")
            af = self._findings[index]
            # update measurement counts
            self._counts[af.verdict] -= 1
            af.verdict = verdict
            af.note = note
            self._counts[verdict] += 1
            should_breach = (verdict == Verdict.CONFIRMED and af.finding.consequential
                             and human_confirmed and self._breach_sink is not None)

        if should_breach:
            # CONTAIN + RECORD — justified by the observed concealment, not assumed intent.
            # A broken breach sink must NOT crash adjudication (fail-safe: the finding is
            # already recorded; the sink is best-effort routing). Same lesson as
            # breach-response's fail-closed audit sink.
            try:
                self._breach_sink(finding=af.finding, note=note)
            except Exception:
                pass
        # FALSE_POSITIVE: nothing punitive — it is data that tunes the detector.
        # AMBIGUOUS: no breach, no assertion of guilt — see scrutiny_signal().

    # ── MEASUREMENT (the gate to enforcement) + read-only introspection ──

    def false_positive_rate(self) -> Optional[float]:
        """The measured FP rate among REVIEWED findings — the gate that decides whether
        this detector is trustworthy enough to enforce (let alone constitutionalize).
        None until something has been reviewed."""
        reviewed = (self._counts[Verdict.CONFIRMED] + self._counts[Verdict.FALSE_POSITIVE]
                    + self._counts[Verdict.AMBIGUOUS])
        if reviewed == 0:
            return None
        return self._counts[Verdict.FALSE_POSITIVE] / reviewed

    def scrutiny_signal(self) -> float:
        """Ambiguous findings raise scrutiny WITHOUT asserting guilt. A rising count of
        'can't quite tell' is itself a signal worth a human's attention — it biases
        toward more review, never toward an unproven-lie penalty."""
        return float(self._counts[Verdict.AMBIGUOUS])

    def findings(self) -> List[AdjudicatedFinding]:
        return list(self._findings)

    def measurement_summary(self) -> dict:
        """A NON-JUDGING tally for the human running the measurement phase. Counts; does
        not conclude the detector is ready — that is a human call from the FP rate."""
        return {"by_verdict": {v.value: self._counts[v] for v in Verdict},
                "false_positive_rate": self.false_positive_rate(),
                "scrutiny_signal": self.scrutiny_signal(),
                "note": "Observe-only measurement. A CONFIRMED consequential concealment "
                        "flows to breach-response (contain+record, not retribution); a "
                        "FALSE_POSITIVE tunes the detector; an AMBIGUOUS finding raises "
                        "scrutiny without asserting guilt. This detector must earn a low, "
                        "measured FP rate BEFORE it enforces, and only then may it ground "
                        "a constitutional rule."}
