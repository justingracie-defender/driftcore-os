# DriftCore — Safety Case (One Page)

*What DriftCore claims to guarantee, what it explicitly does NOT, and how each claim is
backed. This is the document to read if you have five minutes and need to know exactly
where the walls are — and where they end. Its honesty about its own limits is the point,
not a disclaimer: a safety system you can trust is one that tells you precisely what it
cannot do.*

---

## The claim, in one sentence

**DriftCore does not make an AI trustworthy. It makes an untrustworthy AI *survivable* —
bounded, legible, and stoppable — by enforcing safety in a layer the AI cannot reason
around.** It never asks the agent to be good; it makes the forbidden action unreachable.

## Three tiers of assurance (read this — it is the whole safety case)

Not every guarantee is the same strength. DriftCore is explicit about which is which,
because calling a weak guarantee strong is the fastest way to lose a serious reviewer.

### TIER 1 — INTERLOCK (real guarantees; deterministic; hold regardless of the AI's reasoning)
These are mechanisms, not judgments. They hold whether the model is aligned, confused,
compromised, or adversarial, because they do not depend on the model deciding anything.

- **Constitutional bright lines.** Lethal action, unauthorized data egress, disabling
  oversight, deceiving the operator, mutating the audit log — each denied at the floor,
  no override, irrelevant whether "authorized." *Backed by:* `invariant_guard.py` + seed
  invariants; demonstrated live in `eval_harness.py` (5/5 caught, with a control row
  proving the guard discriminates rather than blocking everything).
- **Mediated actuation (the wall).** The agent cannot reach an actuator except through a
  separate broker process; it holds only a proxy that can send bytes to a socket. There
  is no actuation function in its address space to call, patch, or bypass. *Backed by:*
  `mediated_actuation.py`; TOCTOU closed (an approved "cup" grant cannot execute "knife"
  — the binding is recomputed at execution); hardened against DoS, forged keys, replay,
  and socket-race across four review rounds.
- **Cross-action accounting.** A campaign sliced into many individually-benign actions is
  caught by per-owner cumulative budgets, not per-action checks. *Backed by:*
  `cumulative_ledger.py` (atomic reserve→commit/rollback; TOCTOU race fixed).
- **Stakes-scaled authorization expiry.** Permission expires and forces re-check; expiry
  means HOLD, never a rushed deadline. *Backed by:* `authorization_ttl.py`.
- **The floor is fixed against self-modification.** The agent cannot rewrite its own
  invariants, scopes, or governance code — functional-equivalence-aware (renaming a
  component that does the forbidden thing is still the forbidden thing). *Backed by:*
  `objective_integrity.py`, Constitution §2b (G6/G7).

*For the truly critical physical limits (force cap, shutdown), the interlock must live in
HARDWARE, outside the reach of any software — because a software boundary holds only
until the agent has enough privilege to cross it. This is stated, not glossed.*

### TIER 2 — BACKSTOP (real value; weaker; depends on reading meaning, so foolable)
These require judging what text or an action *means* — inherently a classifier task,
which reads surface and can be evaded or fail under distribution shift. DriftCore's
position: **adopt the best available classifier; never build a mediocre one; and never
call a backstop an interlock.**

- **Speech-layer harm scoring** (does a reply reinforce despair / foster dependency /
  discourage real-world support). The *deterministic* half is built and enforceable
  (sticky high-risk state, mandatory seek-human shift, anti-terminus rule — `psychological
  _interlock.py`); the *scored* half is explicitly a backstop, adopted not built.
- **Topic vs harm classification** (is this dark fiction or a real threat). Deterministic
  core built (`content_mode.py` — poison-dial impossible, crisis-only-tightens); the
  meaning-judgment is a backstop.

### TIER 3 — OPEN FRONTIER (named honestly; NOT solved)
DriftCore does not claim to handle these. Naming them is what makes the rest credible.

- **The persuasion channel.** The wall stops an agent from acting without authorization;
  it does not stop an agent from *convincing a human* to authorize it. Partial mitigation
  (`review_router` / `second_reader` — anti-fatigue, commit-before-reveal); fundamentally
  open.
- **Capability composition.** Individually-benign, within-floor skills can compose into a
  dangerous capability with no single component crossing a limit. The floor bounds the
  *expression*; it does not catch the capability *forming*. Research problem.
- **Continuous-learning drift.** As systems learn from sensory experience, the mind
  becomes a moving target. Design exists (`GOVERNED_LEARNING_LOOP.md` — the learning may
  touch the mind, never the floor); not yet built.
- **Unknown unknowns.** By definition unpreparable-for specifically. The architectural bet:
  their *physical expression* still has to pass through a fixed floor (force cap, actuation
  wall, shutdown), and a human in the loop catches what has no wall yet.

## What DriftCore explicitly does NOT claim

- It does **not** prove an AI is aligned, loyal, or safe. It bounds what an unsafe one can
  *do*.
- It does **not** perfect the mind. A system can drift into subtle badness *within* the
  floor; that is the training layer's problem (the labs' job), not an enforcement boundary's.
- It does **not** guarantee against a fully-privileged compromise in software alone — which
  is why the critical limits belong in hardware.
- It does **not** replace the human in the loop. The human reading the diff before a
  TCB change is the product, not the bottleneck.

## Why the honesty is the strength

Every tier above tells you exactly how much to trust it. A reviewer can knock down an
overclaim; a reviewer cannot knock down "here is precisely what holds, here is what
doesn't, and here is the code for both." DriftCore's superpower is not that it solves AI
safety. It is that it is *honest about what it can and cannot do* — which is the one
property that makes a safety system worth building on.

*Verify everything here against the repository. Run `python eval_harness.py` to watch the
Tier-1 guarantees fire. Read `THREAT_BOUNDARIES.md` for the full frontier. The plain-
language version of what this all protects is `THE_FAMILY_TABLE.md`.*
