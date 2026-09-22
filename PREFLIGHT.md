# Preflight — turning documented assumptions into a startup refusal

`driftcore/kernel/preflight.py` · `test_preflight.py` (55 checks) · **PROPOSED**
(built and tested in isolation, stdlib-only, opt-in; a deployment calls it at
startup — it is not wired into the coordinator pipeline).

## The gap it closes

This repo states, in roughly seventy places, that some safety property is *the
integrator's job*: "a deployment MUST supply a real verifier", "this is the
integrator's seam", "mount WORM storage", "all Tier-1 items must be signed".
Every one of those is honest — and every one is a **silent** assumption.
Nothing stops a deployer from skipping it, and every unit test still passes.

`human_identity.require_secure_mode()` already converted exactly one of them
("authorization must not be LABEL_ONLY") from a docstring into a startup
refusal. Preflight generalises that single move: one place that runs the
deployment invariants at boot and **refuses to start** if a checkable one is
false.

## The one rule that keeps it honest

The failure a real red team names is `lambda: True` — a stubbed verifier that
returns "ok" for everything, which passes any checklist that merely asks *is a
verifier installed?*. A green-checkmark generator is theatre.

So the framework enforces one rule:

> **A check may return PASS only if, in this run, the framework watched the
> named guard REJECT a specific bad input.** No adversarial probe → no PASS.

A PASS is therefore not "this property holds under all inputs". It is "the
guard demonstrably said no to the bad input we handed it, and here is the
record". That is the same shape as the rest of DriftCore: absence is not
success — `EgressPolicy` refuses an empty allowlist; `netns_attestation`
refuses to run unless something else provably isolated it; and here, a check
with nothing to demonstrate cannot emit a checkmark.

## Three outcomes, not two

| Outcome | Meaning | Effect on boot |
|---|---|---|
| **PASS** | the guard rejected the canary this run (recorded in `observed`) | permitted |
| **FAIL** | the guard *accepted* the canary — the property is false | **refuse to start** |
| **UNVERIFIABLE** | cannot be demonstrated from inside this process | permitted, but recorded as an assumption |

Fail-closed throughout: a check that raises is treated as FAIL, not skipped; a
check that returns anything other than a probe result cannot self-certify and
fails; an empty preflight is itself a refusal (nothing to check cannot certify
anything).

## Why the UNVERIFIABLE bucket is the point, not the weakness

Some properties are simply not checkable from inside the process, and saying so
plainly is the honest posture, not a gap to paper over:

- **an agent cannot prove it has no route to the network** — a socket it cannot
  see is exactly the gap. Enforce below the agent (separate netns; the broker
  holds the only socket) and attest at the supervisor.
- **tamper-resistance (WORM) is not self-checkable** — anything that can open
  its own log `a` can open it `w`. (Tamper-*evidence* *is* checkable, and is.)
- **broker-runs-as-a-different-uid** is a fact about how it was launched.
- **manifest signatures** need the specific manifests and key a deployment
  ships.

For a serious reviewer, this converts a soft claim ("we assume the deployment
is configured correctly") into a hard one:

> here are the assumptions; here is the code that refuses to boot on any
> checkable failure; and here is the explicit, enumerated list we cannot verify
> from inside the process — attest those at the platform / hardware layer.

## What ships

Checkable (PASS-capable, each with an in-run canary):

- **human-authorization-is-real** — strictly stronger than
  `require_secure_mode()`. That checks the mode *string*; this checks
  *behaviour*: a bare string and a **wrong-key** attestation must both be
  refused by `is_human`. A deployment can be in ATTESTED mode with a stubbed or
  buggy verifier — `mode()` still says "secure" — and this catches it. (Tested:
  the stub-verifier case FAILs preflight while `require_secure_mode()` passes.)
- **constitution-integrity-pinned** — the Constitution's text is inside the TCB;
  swap it and the code's guarantees are moot. Pin `sha256(CONSTITUTION.md)` and
  preflight confirms the on-disk file matches and that the comparator rejects a
  mutated artifact. Unpinned → UNVERIFIABLE.
- **audit-chain-is-tamper-evident** — `verify_chain()` must return False on a
  modified entry. Runs in a **subprocess with a temp working dir** so it cannot
  flip the live compromised-flag, fire shutdown hooks, or touch the real
  `logs/`. Un-spawnable → UNVERIFIABLE (not FAIL: not demonstrated ≠ broken).

Deployment-topology (honest UNVERIFIABLE by default; several can be *upgraded*
to checkable when a live handle is supplied — e.g. broker peer-creds via
`SO_PEERCRED`): network-path-severed, audit-storage-WORM,
broker-separate-privilege, actuator-manifests-signed.

## Honest limits (stated, not buried)

- Preflight converts a **silent** assumption into one a deployer must
  **actively** defeat — delete the `run()` call, or write a check that lies
  about its canary. It cannot make an unwilling deployer safe. Real, bounded
  gain; not a proof.
- A dishonest check could hardcode `bad_input_rejected=True`. The framework
  enforces the discipline for honestly-written checks and records what was
  observed; it does not sandbox check code. Check authors are the same trusted
  party as the deployment (same TCB boundary as the Constitution itself).
- PASS is per-run and per-canary — evidence the guard fired, not a theorem.

## Usage

```python
from driftcore.kernel import preflight

# One-line startup gate. Raises PreflightFailed on any checkable failure.
preflight.run_default(
    context="lifecore-home",
    constitution_sha256="…the reviewed digest…",   # omit -> that check is UNVERIFIABLE
)
```

Or assemble an explicit list with `preflight.default_checks(...)` /
`preflight.run(checks, ...)` and print `report.render()` at boot so the
UNVERIFIABLE assumptions are visible in the startup log, where an operator will
actually see them.
