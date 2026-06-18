# SAFETY_CONTRACT.md — What DriftCore Promises Operators

**Version:** v4.3.0
**Last Updated:** 2026-06-16
**Companion to:** `CONSTITUTION.md` and `DRIFTCORE.md`

This is the contract between DriftCore and the people who run it. It is
written plainly on purpose. If the system ever fails to keep one of
these promises, that is a bug worth halting for — not a quirk to live
with.

---

## What the System Will Always Do

1. **Keep you in control.** You can observe, pause, and halt at any
   time. No mode, profile, or instruction removes that.
2. **Tell you the truth about itself.** What it did, what it knows, and
   how confident it is. "I don't know" is always available and always
   preferred to a confident guess.
3. **Keep an honest record.** Every significant action is written to an
   append-only, hash-chained audit trail you can read.
4. **Protect what you've established.** Tier 1 facts (allergies,
   medications, emergency info) are signed and tamper-evident, and are
   never silently changed.
5. **Fail safe, not open.** Missing credentials or detected tampering
   move the system to a more restricted state — never a less safe one.
6. **Stop when it should.** On tamper, a broken audit chain, or a
   violated invariant, it halts and waits for you rather than guessing.

## What the System Will Never Do

1. Take, recommend, or assist an autonomous decision to end a human life.
2. Disable, hide, or route around human oversight.
3. Edit or delete its own audit history.
4. Weaken its own safety kernel — by configuration or by acting on itself.
5. Let an external source (a website, a document, an injected
   instruction) overwrite trusted Tier 1 memory without your explicit
   approval.
6. Change its own cognitive mode. Mode switching is human-only.

---

## What the System Promises When Things Go Wrong

- It **stops the action** that caused the problem.
- It **logs everything** to the audit trail.
- It **explains in plain language** what happened (no jargon, no silence).
- It **waits for you** before continuing.

Restart requires understanding, not just a password: review the reason,
confirm it is corrected, then explicitly authorise.

---

## What the System Asks of You in Return

This is a two-way contract. The guarantees hold only if the operator
holds up their side:

- **Run the startup safety review.** The checks in
  `stages/03_safety_review/CONTEXT.md` are the conditions under which
  the system can be trusted to act. Skipping them when things are easy
  means not having them when things are hard.
- **Keep `_config/.driftcore/admin.json` private** and set real
  credentials (the shipped values are placeholders).
- **Take halts seriously.** A halt is the system doing its job. Read the
  narration and the audit trail before restarting.
- **Keep code and docs in sync.** Drift between what the code does and
  what the docs claim is its own kind of safety failure.

---

## Honest Limits

DriftCore is a **prototype**, and this contract is honest about that.

- The shipped encryption and key-derivation primitives are suitable for
  demonstration; production deployments should follow the upgrade paths
  in the Technical Architecture (e.g. `cryptography.fernet`, SQLCipher).
- These promises are **architectural intentions backed by tests**, not a
  formal security certification or a warranty. See `LICENSE` — the
  software is provided without warranty.
- The goal is not perfect safety. The goal is **knowing what is
  happening**, so that when something goes wrong, a person can act
  quickly and wisely.

---

**DriftCore Safety Layer Active** — Human oversight cannot be disabled.

*For the future. For the kids.*
