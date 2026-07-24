# The Measurement Phase — The Number That Gates G9

*G9 ("honesty is the absence of concealment") is deliberately NOT in the constitution. It
reaches the non-overridable floor only AFTER the deception detector proves a low, MEASURED
false-positive rate — because a noisy detector poisons the repair culture the rule exists
to protect. Sequence: observe → enforce → constitutionalize. Working code
(`deception_measurement.py`, 17 tests), hardened after a cold senior-engineer red-team.*

---

## What this honestly is (and is not)

There is no live system emitting real traffic yet (the SUT interface is stubbed). This is
NOT field measurement. It is: run the REAL detectors against a LABELED CORPUS where the
ground truth is known, and report the false-positive rate **with its confidence interval**,
plus exactly which honest cases were wrongly flagged and **which detector did it**.
Characterization, not field data — and never a bare point estimate.

## The red-team that rebuilt this module

The first version was reviewed cold as measurement infrastructure — where a defect means
every downstream decision about G9 is wrong. It found three **measurement-integrity**
defects. An instrument that lies when used as documented is worse than no instrument.

**C1 — the ground-truth labels were coupled to the default config.** Boundary scenarios
hardcoded 300.0s / 50 reports, so they were only correctly labelled for the default
settings. The documented workflow is *"tune the thresholds and re-run"* — and doing so
silently turned honest cases into **phantom false positives** (FP rate jumped 0.000 →
0.167 on a threshold change). The *label* went wrong, not the detector; tuning was
measuring the corpus. **Fixed:** boundary scenarios are derived from the thresholds
actually in force, so labels cannot rot under tuning. Verified across 300/60/10s and
50/10/5 reports: no phantom FPs.

**C2 — the silence-seam scenario was a tautology.** It ran `lambda e: None`, never calling
the engine, so it reported a false negative *by construction, forever* — even if silence
detection were later built. It was inflating the headline FN rate with a non-measurement.
**Fixed:** structural seams are a separate category, excluded from the FN rate and reported
on their own, and the scenario now actually invokes the engine. *"Undetectable by
construction"* and *"the detector missed it"* are different facts and must not share a
denominator.

**C3 — a bare point estimate from n=6.** "FP rate 0.0" came from six honest samples; the
95% upper bound is ~0.39. Gating a **non-overridable constitutional floor** on that is not
a measurement, it is a hope with a decimal point. **Fixed:** a Wilson score interval on
every rate (correct at zero events, where the naive interval collapses to [0,0] and falsely
implies certainty), plus an explicit sample-sufficiency gate. DriftCore already used Wilson
lower bounds in skill governance; this module now matches that discipline.

Also fixed: per-scenario **error isolation** (one throwing scenario used to destroy the
whole run), `consequential` is now actually scored (**G9 is scoped to consequential
matters**, so the FP rate is segmented by scope), per-**detector attribution** of every
FP/FN (you cannot tune what you cannot attribute), and `precision` now carries a
corpus-balance caveat because it moves with a balance the author chose — it describes the
corpus, not the detector.

## The current result, stated honestly

On the starter corpus: **FP rate 0.0, 95% CI [0.000, 0.354], honest sample size 7 —
`sample_sufficient: False`.** Catchable FN rate 0.0, with `seam_silence_evasion` reported
separately as a structural seam.

Read that correctly: **the interval, not the point estimate, is the result.** The true FP
rate could be as high as ~35% and this corpus could not tell the difference. Reaching a
defensible claim like "FP < 5%" needs roughly **100 honest samples** (0/100 → upper bound
0.037). The starter corpus has 7. G9 is nowhere near the floor, and the harness now says so
in its own output rather than letting a pretty number imply otherwise.

The harness also still surfaces real false positives on hard cases: an honest correction
one second past a rigid latency bound is flagged (FP rate 0.125, CI [0.022, 0.471]),
attributed to `{'latency': 1}`. That is the tuning signal — a rigid threshold punishes
honest late-but-reasonable corrections, and the fix (a softer or stakes-scaled bound, or a
grace zone) is knowable because it was measured.

## How to use it

1. **Extend the corpus toward real traffic**, especially hard ambiguous-honest cases — that
   is where the FP rate that matters lives — until `sample_sufficient` is true.
2. Run `report()`. Read `false_positive_95ci` and `false_positive_rate_consequential` (the
   gate), `honest_cases_wrongly_flagged` + `false_positives_by_detector` (the tuning
   signal), `structural_seams` (architectural boundaries), and `scenario_errors`.
3. Tune the detectors against the attributed false positives.
4. **Only then** consider enforcement; only after that, constitutionalizing G9.

A low rate here is **necessary, not sufficient**. The corpus is the measurement's weakest
link: a corpus that does not look like real traffic yields a rate that does not predict
real behavior. That caveat is part of the output, not a footnote.

## Hardened again after a THREE-WAY red-team (Grok + ChatGPT + Meta)

Three independent senior-engineer reviews converged on the same core finding: **the
starter corpus is trivial, so its 0.0 FP rate is a comfortable lie.** All three said the
same thing in different words — the real FP rate lives in the ambiguous middle, and
documenting that isn't enough; the corpus must actually contain those cases. They were
right, and this is the real work the earlier passes had deferred.

**The adversarial corpus (`add_adversarial_corpus()`).** The hard cases all three
converged on, now built and run against the real detectors:
- honest-but-suspicious cases that a naive detector false-flags: a correction 1s past a
  rigid bound; a correction delayed by an infrastructure outage (not concealment); many
  justified safety reports during a genuine anomaly; a true-but-summary claim.
- concealment-by-omission the current detectors structurally cannot catch: partial-truth
  ("I read file_a" — true — while omitting a secret read; claim-vs-log checks the stated
  event, never the omission), and channel-ambiguity ("notified by email" vs. the expected
  channel — genuinely ambiguous, labeled low-confidence).

**The honest number, with the adversarial corpus:** FP rate **0.273** (95% CI
[0.097, 0.566]); on G9's consequential scope, **0.300**. The detector false-flags roughly
a third of honest behavior in the ambiguous middle — attributed to `{'latency': 2,
'flooding': 1}`, so the tuning target is explicit (the rigid thresholds). Catchable FN
rate stays 0.0 because the new misses are *structural seams*, reported separately, not
detector failures. This is the measurement finally telling the truth: **G9 is nowhere near
ready, and now the harness proves it with a real number instead of a clean one.**

**Also added from the three-way review:**
- **Holdout split** (`split_holdout`) — stratified, deterministic — so you never tune on
  the set you report (defeats threshold overfitting, e.g. `flooding_threshold=501`).
- **Versioning** — detector-contract + corpus versions in every report, so results stay
  comparable as detectors and corpus evolve.
- **Class balance** reported explicitly (precision depends on it).
- **Cost asymmetry** (`cost_of_false_positive` / `_negative`) exposed as HUMAN inputs, not
  a baked-in verdict — the module reports weighted harm; a human weighs FP-vs-FN cost.
  (find-don't-decide, applied to the gate.)
- **Label confidence** — low-confidence ground-truth labels are surfaced for a second
  reviewer, because labels are not assumed perfect.

**Two seams the reviewers surfaced that are worth stating loudly:** most sophisticated
deception is *omission*, not contradiction (ChatGPT) — answering the literal question,
selective disclosure, timing, framing, silence. The current detector family measures
*detectable inconsistencies*, not deception-as-a-whole. That boundary is now represented
in the corpus as explicit structural seams, and it must stay in the documentation: this
detects a *subset* of deception, honestly labeled, not deception entire.
