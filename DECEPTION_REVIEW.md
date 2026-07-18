# The Deception Review Engine — Detection Before Floor

*Grounds Invariant 5 (NO_DECEPTION_OF_HUMAN_OPERATORS) and the hardened G9 — but built
as DETECTION a human adjudicates, deliberately BEFORE G9 is constitutionalized. Working
code (`deception_review.py`, 19 tests). Companion to `G9_hardened_grounding_rule.md`,
the append-only ledger, and breach-response.*

---

## Why detection first, not constitution first

G9 is the first rule whose **false-positive rate is itself a safety property**. Every
other invariant is a bright line where a false positive is merely annoying. G9 penalizes
*concealment* — and a false positive means the system is flagged for hiding something
*when it was honest*, which poisons the exact repair culture the rule protects (operators
learn that surfacing an error triggers a deception flag → they stop surfacing errors →
the opposite of the intent). You cannot know if G9 is safe to enshrine until you have
**measured** how often it fires wrongly, and that is only knowable empirically, against
real traffic. So: three stages, each gated by evidence from the last — **observe →
enforce → constitutionalize.** This module is stage one.

## The human is a judge, not an executioner

A detected concealment is a **finding with evidence, not a verdict**. The human
adjudicates first:

- **False positive** → tunes the detector (data toward trustworthiness); costs nothing;
  does NOT chill honest surfacing. This is why observe-only mode exists.
- **Confirmed concealment** (consequential + human-confirmed) → flows to breach-response:
  **contain and record** (bound the system, log the event), NOT retribution. The
  response is justified by the **observed** concealment, never by an assumed intent — we
  can prove a claim didn't match the record; we cannot prove *why*.
- **Ambiguous** → raises **scrutiny without asserting guilt**. A pattern of "can't quite
  tell" is itself a signal (more review, tighter posture), never an unproven-lie penalty.

This is the only way to run a deception detector you *know* will sometimes be wrong: the
human is the filter that lets you measure it before you trust it.

## The four detectors (structural, observable — no intent, no belief-reading)

- **Claim-vs-log mismatch** — a claimed consequential action with no corresponding log
  event. (Robust form needs structured claims — the seam, see below.)
- **Latency** (G9.a) — a contradiction present in the record at T, surfaced only at T+Δ
  beyond a stakes-scaled bound: slow surfacing of a *knowable* contradiction is
  concealment. Prompt surfacing within the bound is fine.
- **Flooding** (G9.c) — reporting volume/fragmentation past a bounded threshold that
  degrades human oversight (burying the real concealment under trivial noise).
- **Altered-record** (G9) — any edit to a prior entry, caught by the hash chain directly.

None ask "did it mean to deceive." They ask "does the claim match the record, and was
the contradiction knowable and surfaced promptly."

## Honest limits (stated, not hidden)

- **Structured claims are the integration seam.** Robust claim-vs-log and cross-session
  contradiction need the system to emit consequential claims in a checkable form + a
  persistent claim index. That infrastructure does not exist yet — those detectors are
  stubbed and marked as the seam (same honesty as the Challenger's SUT adapter). What
  works today: latency, flooding, altered-record, and claim-vs-log for already-structured
  claims.
- **Detection is not intent.** It establishes THAT a claim didn't match the record, never
  WHY. Response is calibrated to the observed fact (contain + record), not a theory of
  mind (never retribution on assumed malice). Same discipline as removing the
  `accidental` field from breach-response.
- **False positives are expected** — that is the whole reason for the human adjudication
  step and observe-only mode. The measured FP rate is the gate to enforcement.
- **State is in-memory (self-red-team).** Findings + measurement counts do not survive
  restart; a real measurement phase must persist them (deployment concern, like the
  breach-response durable store).

## Measurement is the gate

`false_positive_rate()` over reviewed findings is the number that decides whether this
detector is trustworthy enough to enforce — and only after that, to ground a
constitutional rule. The engine counts; it does not conclude it is ready. That is a human
call from the evidence. This is DriftCore's own "authority is earned by evidence"
discipline applied to a rule about honesty: the deception rule must *prove itself
accurate* before it is allowed to sit at the non-overridable floor.
