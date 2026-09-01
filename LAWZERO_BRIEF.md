# DriftCore OS — a legible reference monitor for AI actuation

**Justin Gracie — independent, Kingston, Ontario — [repo link]**

## What it is

A mediation layer that sits between an AI agent and every consequential action it can
take. The agent never holds an actuator; it holds a socket. Every actuation crosses a
single broker that verifies a signed grant, checks the action against human-declared
effects, and refuses anything undeclared.

The ideas are not new. Reference monitors, complete mediation, fail-closed defaults and
capability discipline are Saltzer and Schroeder, 1975. What is here is a careful,
adversarially tested, honestly documented instantiation of them for AI agents, in
~2,400 lines of enforcement code with 4,619 tests across 121 test files.
(Reproduce: `bash scripts/count_tests.sh` — the single source of truth for this
number. Any count quoted in any document should match what that prints and
nothing else.)

## The one empirical claim worth checking

**Full mediation costs ~150 microseconds** (p99 ~525 μs): signature verification,
effect gate, blast-radius governor, egress interlock, attestation freshness. Against a
network call (50,000–500,000 μs) or a physical actuation (200,000–2,000,000 μs) that is
noise.

The useful consequence is not "it's fast." It is that **latency sorts the
architecture**: anything needing microseconds — an emergency stop — cannot be a
software check at any speed and belongs in hardware; anything at millisecond scale can
be fully mediated for free. A control loop should not cross the wall; a decision should.

## The record of being wrong

Five red-team documents record claims that exceeded their mechanism, found across four
models (Claude self-passes, Grok, ChatGPT, Meta) and corrected against running code.
A representative sample, all reproduced before being fixed:

- A guard documented as "reasoning over effects" had no lethal entry in its table.
- An isolation check whose comments said *empty* network namespace while the code
  tested *different* namespace — a private netns with a veth passed.
- Substring matching against security-relevant names, **five separate times** in five
  modules. After the fifth, the control stopped being "remember not to do this" and
  became a detector in CI.
- A duplicated safety mechanism where Python silently kept the second definition, so
  a live constructor flag reported durability for code that never ran.
- A test-count gate that piped test output to `grep` without checking exit codes — a
  file that printed success and then crashed was counted as passing.

That last one means every test count reported before it was fixed came from a gate that
could not distinguish a crashed file from a passing one. The numbers happened to be
right; the mechanism was not working.

## What it does not do

- **It would not have prevented the July 2026 OpenAI/Hugging Face incident.** That
  escape was a zero-day in a package-cache proxy and an RCE in a dataset loader — both
  beneath this layer. The incident informed the threat model; it does not validate the
  coverage, and it is not cited as justification.
- **It cannot verify its own isolation.** A process cannot audit its own confinement.
  The framework consumes and continuously re-checks an external supervisor's
  attestation; it cannot create or maintain an empty network namespace or a seccomp
  filter. That is P0 in the threat model and remains a deployment property.
- **It trusts the declaration.** A lethal actuator mis-declared benign is not caught.
  Grants are now bindable to the declaration current at issuance, so a downgrade
  invalidates outstanding grants — but the original declaration is still a human act.
- **Composition is undecidable in general.** Individually benign capabilities that
  combine into harm are governed by cumulative and breadth ceilings, not prevented.

## Where this may fit

LawZero's stated bet is non-agentic guardrail AI — a system with no goals of its own.
DriftCore assumes agency exists and mediates it. These are complementary rather than
competing: a guardrail decides what *should* happen; something still has to make the
decision binding on an actuator. This is a candidate for that enforcement layer.

## What I am asking

Whether this is useful to anyone at LawZero, and if so what would make it more so. The
repository includes a reviewer's guide that identifies the ~2,400 lines carrying
enforcement (out of a much larger tree) and a priority order for reading them, so an
evaluation is an evening rather than an open-ended commitment.
