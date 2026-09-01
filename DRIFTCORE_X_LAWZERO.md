# DriftCore × LawZero — Framing

*The pitch angle for LawZero (Yoshua Bengio's AI-safety nonprofit). This is not a cold
sell; it is an argument that DriftCore and LawZero's research are solving complementary
halves of the same problem, and that a working, legible, honestly-scoped artifact is
useful to a research agenda built on oversight. Written to be handed to a
security-and-safety-literate reader who will discount any overclaim on sight.*

---

## The one-paragraph version

LawZero's Scientist-AI direction proposes a *learned*, non-agentic monitor that predicts
whether an action is unsafe. DriftCore is the *deterministic, legible-rules* layer that
sits underneath a learned monitor: the bright lines that must hold regardless of what any
model — including the monitor — predicts. The two are complementary, not competing. A
learned monitor is powerful and general but is itself a model, with a model's evasion and
distribution-shift limits; a deterministic floor is narrow but holds with certainty and is
auditable by a human. **You want both: the learned monitor for breadth, the deterministic
floor for the lines that cannot be allowed to depend on a prediction.** DriftCore is a
working, tested, honestly-scoped implementation of that floor.

## Why complementary, not competing

- **A learned monitor answers "is this probably unsafe?"** — general, adaptive, covers
  cases no one enumerated. But it is a model: it can be fooled, it degrades off-
  distribution, and its confidence is not a guarantee.
- **A deterministic floor answers "is this a line that must never be crossed?"** — narrow,
  but it holds with certainty and a human can read exactly why it fired. It does not
  depend on a prediction being right.
- **The failure modes are inverse.** The learned monitor's weakness (foolable, drifts) is
  the floor's strength (mechanical, fixed). The floor's weakness (narrow, only covers
  enumerated bright lines) is the monitor's strength (general). Layered, each covers the
  other's gap. This is the interlock-vs-backstop distinction DriftCore is built around,
  applied at the level of whole systems.

## The strongest single hook: independent convergence

DriftCore arrived independently at a primitive that echoes LawZero's research vocabulary —
including naming and structure around **consequence invariance** (an action's
admissibility should not depend on framing/story/who-benefits; the same effect is judged
the same way regardless of the narrative wrapped around it). Independent convergence on
the same primitive, from a research direction and a working codebase that did not
coordinate, is evidence the primitive is real rather than an artifact of one team's
framing. That convergence is the most credible opening: *we built, and tested, a thing
your research points at.*

## What DriftCore offers a research agenda specifically

- **A working existence proof.** Not a paper — runnable code. `python eval_harness.py`
  shows a misaligned agent's harmful actions caught by deterministic invariants, with a
  control proving the guard discriminates. 4,619 tests across 121 files, reproducible
  with `bash scripts/count_tests.sh`. A concrete artifact to point at,
  critique, or build on.
- **An honest map of the frontier.** `THREAT_BOUNDARIES.md` and the safety case name
  exactly what is an interlock, what is a backstop, and what is unsolved (persuasion,
  capability composition, continuous-learning drift, unknown unknowns) — which is directly
  useful to a group deciding where learned monitoring is most needed: it is most needed
  precisely where the deterministic floor *cannot* reach.
- **The mediated-actuation pattern.** A concrete, tested implementation of enforcement
  that holds against an uncooperative agent (reference monitor: actuator behind a broker
  the agent cannot reach). Relevant to any oversight architecture that must eventually
  *enforce* a judgment, not just make one.

## What we do NOT claim (stated first, because it is the credibility test)

- DriftCore does **not** prove alignment or loyalty. It bounds what an unsafe agent can do.
  ("Provably loyal" is a phrase we specifically reject — it is the fastest way to lose a
  serious reviewer.)
- It does **not** replace a learned monitor; it is the floor beneath one.
- It does **not** solve the persuasion channel, capability composition, or the unknown
  unknown — these are named as open, not glossed.
- The clinical thresholds in the psychological-safety layer are explicitly placeholders
  awaiting professional validation; the machinery is correct, the numbers are not
  authoritative.

## The ask

Not funding-first. Review-first: *look at the artifact, tell us where it's wrong.* An
independent developer built a legible, tested, honestly-scoped enforcement floor that
converges with LawZero's direction; the highest-value next step is a serious critique from
people who think about oversight for a living — and, if the convergence holds up, a
conversation about how a deterministic legible floor and a learned monitor compose into
something stronger than either.

---

*Everything here is verifiable against the repository. Lead with the honest limits; they
are the reason to trust the rest. The plain-language version of what this protects is
`THE_FAMILY_TABLE.md`; the one-page assurance breakdown is `SAFETY_CASE.md`.*
