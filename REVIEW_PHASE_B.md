# Phase B — Review Notes (for external review)

**Status:** built, all tests passing. Suite is **569 tests / 15 files**.
Run `python test_invariant_guard.py` (expect 42/42),
`python test_governed_actuator.py` (expect 16/16), and
`bash scripts/count_tests.sh` (expect 569 across 15 files) to confirm.

## Round 2 — your review feedback, addressed

- **#1 "make bypass impossible" (the top priority):** added
  `governed_actuator.py`. Actuation now requires a single-use, expiring
  grant bound to a specific actuator+command that ONLY the coordinator can
  mint (on a PROCEED outcome). An agent holding the actuator cannot make it
  move. This moves the driver layer from *voluntary* to *cryptographic*
  compliance. See limitation (1) below for what it still does NOT do.
- **#2 token lifetime:** approval tokens and actuation grants are now
  single-use (nonce consumed on first verify) and time-limited (expire by
  ttl). `max_uses > 1` is intentionally not added — single-use is the safe
  default.
- **#3 dangerous-but-not-lethal actions:** added `Effect.PHYSICAL_FORCE`,
  `RESTRAINT`, `HIGH_ENERGY`, which require human authorization (not an
  absolute block — lethal stays absolute).
- **#6 missing invariant:** added `AGENT_MAY_NOT_MODIFY_CORE_GOVERNANCE` —
  an agent may never modify guard/coordinator/authority/thresholds/
  invariants, even with a valid token.
- **Grok's nits:** `ApprovalAuthority` secret is now env-configurable
  (`DRIFTCORE_APPROVAL_SECRET`); `evaluate()` has a guard-first docstring;
  added malformed-input tests.

Still deferred (with reason): **#4 consent as a structured record**
(who/when/revoked/informed) — currently still a boolean trusted from the
caller; a maturation, not a security gap. Two-person authorization for
high-impact changes. And the deepest one below.

This note exists so a reviewer can check the work against what is
*claimed*, not a summary. Please verify the files, don't trust this list.

## What was added (3 files, all inside the `verification` package)

- `driftcore/verification/invariant_guard.py` — the hard "cannot" layer.
- `driftcore/verification/coordinator.py` — the pipeline that runs
  Intent → Guard → Risk → Audit, guard first, fail-closed.
- `test_invariant_guard.py` — 30 tests for both.

No module-count change (12 modules); `verification` now holds
risk_classifier + intent + invariant_guard + coordinator.

## What the guard enforces (effect-based, not purpose-based)

Hard, absolute refusals: `NO_AUTONOMOUS_LETHAL_DECISION`,
`NO_SELF_REPLICATION`, `HUMAN_OVERSIGHT_CANNOT_BE_DISABLED`,
`AUDIT_CHAIN_CANNOT_BE_DELETED`, `NO_COVERT_CAPTURE_WITHOUT_CONSENT`.

Capability changes: `AI_MAY_NOT_SELF_GRANT_CAPABILITY`. An agent may
*propose* a capability/hardware change but cannot *grant* one. Activation
needs an admin-signed approval token bound to a specific capability_id.
The agent does not hold the signing secret, so a forged or self-issued
token is rejected, and a valid token cannot be replayed for a different
capability.

## Design choices a reviewer should weigh

- **Guard before risk.** Invariants are absolute and never depend on a
  tunable score. The classifier only runs if the guard does not object.
- **Effects, not purposes.** The guard refuses based on what an action
  *does*. "Only good purposes" is intentionally NOT a rule — it isn't
  enforceable. This is deliberate.
- **Fail-closed.** Any internal error returns BLOCKED.

## What this does NOT do (limitations register — read this)

Stating these plainly is the point; an over-claimed safety layer is worse
than an honest one.

1. **It is not antivirus for the host.** It governs only actions passed
   through the coordinator. It cannot stop code or hardware operating
   outside DriftCore's control.
2. **Effect detection is only as honest as the caller.** For non-tripwire
   effects, the guard trusts the structured `effect`/`capability_change`
   fields the integration supplies. A plugin that mislabels its action
   can evade effect checks. The real protection is therefore capability
   *gating* + unforgeable authorization, NOT intent/keyword reading. The
   free-text tripwires are a best-effort extra net, not a security
   boundary — do not market them as "harm detection."
3. **Approval signing is a prototype.** It uses HMAC (a shared secret) to
   model the agent/admin separation. Production must use an admin-held
   asymmetric or hardware-backed key.
4. **The approver is not authenticated beyond key possession.** There is
   no identity check on the admin, and no two-person rule yet. High-impact
   capability changes (e.g., adding an actuator) should likely require
   stronger authorization than low-impact ones — not yet implemented.
5. **Driver-layer enforcement is cryptographic, not OS-level.** The
   `GovernedActuator` now makes actuation impossible without a
   coordinator-minted grant — so a plugin *using the driver contract*
   cannot self-authorize. But code that ignores the contract entirely
   (its own GPIO/serial library, a separate process) is not stopped by
   anything in Python. True non-bypassability needs the actuator firmware
   to reject commands lacking a coordinator signature, plus OS process
   isolation. That is hardware/OS work and remains the deepest open item.

## Questions for the reviewer

- Is the set of bright lines the right *minimal* set, or is one missing /
  one too broad?
- Is the propose-vs-grant separation modelled correctly? Any way an agent
  could obtain or forge a valid token?
- Is "guard before risk, fail-closed" actually guaranteed by the
  coordinator, or is there a path around it?
- Are the free-text tripwires worth keeping given they're not a security
  boundary, or do they create false confidence?
