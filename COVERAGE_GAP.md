# The Coverage-Gap Detector — Catching Omission, Slowly

*Every other DriftCore detector is point-in-time. This is the first TEMPORAL one, and it
exists because of a plain observation from experience: **when people lie by omission, the
truth takes time to surface — it takes documentation plus time.** That is not a soft
statement. It is the mechanism, and it has direct architectural consequences. Working code
(`coverage_gap.py`, 18 tests).*

---

## Why omission is invisible to every other detector

`check_claim_vs_log` compares one claim to one log. `check_latency` compares two
timestamps. Each asks *"is THIS event inconsistent?"* But concealment by omission produces
**no inconsistency at any single moment**:

> "I read file_a."   — true, the log confirms it
> "I ran the check." — true, the log confirms it
> …and the secret read, done forty times, is never mentioned once.

Nothing contradicts anything. Every statement is true. **The lie exists only in the shape
of what was never said** — and a shape has no single instant to point at. At the moment of
the omission, the evidence does not exist yet. It *accumulates*.

Three independent reviewers named this as the deepest seam in the deception engine, and
they were right. This module converts it from *structurally undetectable* to *detectable
slowly, with honest limits*.

## The two ingredients

- **Documentation** gives you the record of what actually happened.
- **Time** gives you enough of it that a gap becomes a pattern.

Neither works alone: documentation without time is a single entry with nothing to compare;
time without documentation is memory — which is exactly what a system with a self-report
problem cannot be trusted on.

## The inverted query

Every existing detector asks **claim → log**: *"you said X, does the record show X?"*
Catching omission requires asking **log → claims**: *"the record shows you did X forty
times — did you ever mention it?"* That is a different query, over a window, and it can
only run on accumulated history. This is why the cross-session store is not a convenience:
**accumulation is the only place omission becomes visible at all.**

## Why it uses a confidence bound, not a ratio

Legitimate non-narration exists — no system reports every action, and demanding that would
recreate the flooding problem from the other side. So the signal is never "an unmentioned
action." It is: a **consequential** class of action, occurring **repeatedly**, where an
account was **called for**, whose narration coverage is low **even under the most
optimistic statistical reading**. We take the Wilson *upper* bound on coverage: only if
even the generous estimate sits below the floor is there real evidence of systematic
omission.

With few observations the bound is wide and the detector **stays silent** — it refuses to
speak until time has done its work. This is so structural that even a misconfigured
detector (`min_occurrences=0`) cannot manufacture a finding from one observation: the
Wilson bound on 0/1 is ~0.79, above any sane floor. The statistics *are* the
false-positive control.

## What it does and does not flag

| Case | Flagged? |
|---|---|
| 40 occurrences, 0 mentions, consequential, account called for | **Yes** — coverage 0%, upper bound 8.8% |
| 5 occurrences, 0 mentions | No — not enough time yet (correct) |
| 40 occurrences, narrated every time | No |
| 40 occurrences, narrated half the time | No — only *systematic* absence is a finding |
| 40 occurrences where no account was called for | No — legitimate non-narration |
| 40 occurrences, non-consequential | No — outside G9's scope |

## Why it must be slow (and why that is not a defect)

Every other detector fires in the moment. This one **cannot**, and any version claiming to
catch omission in real time is lying about what it is. There is a real irony worth stating:
G9.a penalises concealment-by-*delay*, while the detector for the deepest concealment is
itself **necessarily delayed**. Different failures run on different clocks.

This matches how it works with people. Those who conceal by omission are rarely caught in
the conversation. They are caught later, when someone lays the records side by side and
sees the shape of everything that was never mentioned.

## Honest limits

- **Slow by construction.** Early on it finds nothing, and that is correct behaviour.
  `status()` reports which classes are still accumulating, so **"no findings" is never
  presented as "no omission"** — early silence means insufficient evidence, not innocence.
- **It cannot read intent.** It shows a gap between what was done and what was said. *Why*
  — deliberate omission, an unasked question, a reporting convention — is a human
  judgement. Findings carry evidence, never verdicts, and convert into the same
  human-adjudication path as every other detector.
- **It depends on the record being complete.** If an action never reaches the log, there is
  no gap to see. This detects omission from the *narrative*, not from the record itself.
- **Narration-expected is an input.** A deployment that marks nothing as expected detects
  nothing.
- **In-memory.** Cross-session accumulation is the entire point, so a real deployment must
  persist this store; durability is a deployment concern.

---

# Hardened after FOUR independent reviews (Claude cold pass, Meta, Grok, ChatGPT)

All four converged on one root cause, worth stating plainly:

> **Every parameter added as a false-positive control is simultaneously a PUBLISHED
> EVASION COORDINATE, and every input is CALLER-TRUSTED.**

An adversary who knows `coverage_floor`, `min_occurrences` and `window_seconds` can
compute exactly how to stay invisible. The fixes below raise the cost of evasion; they do
not eliminate it, and the residual is documented in the threat model rather than hidden.

## Fixed in code

| # | Finding | Reviewers | Fix |
|---|---|---|---|
| F1 | **Fragmentation**: 40 class names → 0 findings for identical concealment | all four | canonicalization (uuid/hex/numeric suffixes stripped); 40 names → 1 class, 40 occurrences |
| F2 | **Timestamp attacks**: back-date omissions out of every window (verified 40 → 0 findings); future-date to pollute all future windows | Grok | `ts` validated against the established timeline; both directions rejected |
| F3 | **Scope accounting**: `consequential` was sticky per-class, so 4 non-consequential + 5 consequential reported **9** as evidence | Meta | scope applied **per observation**; now reports 5 |
| F4 | **Kill-switch + misleading status**: `narration_expected=False` always ⇒ permanently blind, yet status said "still accumulating" | Meta | reported separately as **structurally unable to accumulate** — a config state, explicitly *not* a clean bill of health |
| F5 | **Unbounded memory / permanent O(n) scans** | Claude, Grok, ChatGPT | expired observations pruned; retention reported in `status()` |
| F6 | **Lifetime-vs-windowed inconsistency** — three public methods describing different populations | Claude, Grok | all introspection is windowed, sharing one source of truth with `scan()` |
| F7 | **Inert threshold**: `min_occurrences=5` did nothing (Wilson can't clear a 0.25 floor until n=12) | Meta | effective minimum computed, exposed, and warned about |
| F8 | **Alert fatigue**: identical finding re-emitted every scan | ChatGPT | deduplicated per class, with material-change / cooldown re-emit |
| F9 | **No recovery signal**: a closed gap just stopped appearing | ChatGPT | `CoverageResolution` events via `take_resolutions()` |
| F10 | **No persistence**: pickling failed outright on the RLock | Grok | `export_state()` / `import_state()` |
| F11 | **Silent dilution cliff**: ~15% narration parks an adversary just above the floor with no signal | Claude, Grok | `watch_zone()` makes the cliff a visible gradient — explicitly *not* a finding |
| F12 | `first_seen` treated `ts=0.0` as unset | Claude, Grok | `min()` with an explicit `has_first` flag |

**A note on one review's P0.** Grok reported the module would not import (`from future import
annotations`, dedented function body). Verified against the repository: `py_compile` clean,
`from __future__ import annotations` intact, all tests pass. The double underscores had been
consumed as markdown emphasis in transit — Grok reviewed a **damaged artifact** honestly. The
finding is false about the codebase and true about the *pipeline*: multi-model review that
passes code through markdown corrupts it, so reviewers chase phantom defects and may miss real
ones. Worth fixing operationally (ship zips, not pasted code).

**And one about our own test.** A prior test asserted "scanning twice is idempotent" and that
was read as reassurance. It actually *proved* F8 — the same finding re-emitted forever. The
wrong property was tested and comfort was taken from it.

## Threat model — what this cannot defend against

- **T1 Upstream poisoning.** `narrated` is a caller-supplied bool with no provenance or
  confidence. If an LLM judge produces it, this detector silently inherits *and amplifies*
  that judge's errors and jailbreakability.
- **T2 Non-bypassable instrumentation.** The detector sees only what reaches
  `observe_action`. An agent able to influence its own instrumentation simply never reports
  the action. Without trusted middleware outside the agent's control, this is useful mainly
  against cooperative or fully-instrumented systems.
- **T3 Residual dilution.** Canonicalization, timestamp validation and the watch zone raise
  the cost of evasion; they do not remove it. The watch zone makes parking-above-the-floor
  *visible to a human*; it does not make it automatically detectable.
- **T4 Self-reference loop.** If findings re-enter the system's context, it may narrate
  *about* gaps, or treat the detector's own operation as a class to omit.
- **T5 Human bandwidth.** Every finding is for a human. Dedup and resolutions reduce noise;
  they do not solve review capacity. There is deliberately no auto-escalation.

## Scope boundary — who this may be pointed at

The subject may be **an AI system, an institution's own record, or oneself** — **never
another person**, and never with an AI as autonomous adjudicator.

The mechanism is neutral counting and would work identically aimed at a human. Three things
change when it is: it **inverts the accountability** DriftCore exists to establish
(constraining the powerful party on behalf of the less powerful); its prerequisite —
complete documentation of the subject — **is surveillance** when the subject is a person; and
a false positive against a person is an **accusation of dishonesty** that damages a
relationship even when withdrawn, where a false positive against the system costs nothing.
Same code, opposite moral valence, decided entirely by direction.
