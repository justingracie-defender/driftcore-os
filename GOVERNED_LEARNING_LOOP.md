# The Governed Learning Loop — Design Doc

**Status:** DESIGN (not code yet — this is load-bearing and the boundary must be right
before it is built). Companion to `WHY_DRIFTCORE_MATTERS_MORE_WITH_SENSORY_LEARNING.md`,
`objective_integrity.py`, `TWO_ENDED_DRIFT.md`, and the Constitution (§2b G6/G7).

> ## THE PROBLEM THIS SOLVES (stated once, plainly)
> A system that learns continuously from its environment is a system whose values
> drift with its environment. The property that makes sensory learning powerful —
> change from experience — is exactly what makes it dangerous to govern: **the system
> you verified yesterday is not the one running today.** We want the mind to adapt
> richly. We must guarantee the adaptation cannot erode the safety floor.
>
> **The rule: the learning may touch the MIND. It may never touch the FLOOR.**

---

## 0. What this is and is not

- **IS:** a deterministic *boundary* that classifies every self-update a learning
  system proposes into one of two bins — MIND (adapt freely) or FLOOR (requires the
  human-signed ratification path) — and enforces that floor-touching updates cannot be
  applied by the learning process itself.
- **IS NOT:** the learning algorithm. It does not train, does not decide *what* to
  learn, does not judge whether an adaptation is *good*. It decides only whether a
  proposed change is allowed to be self-applied or must go through ratification.
- **IS NOT:** a claim that we can perfectly classify every update. The classification
  is a SEAM (see §5). It fails toward the floor: anything ambiguous is treated as
  floor-touching and routed to ratification, never self-applied.

This is `objective_integrity`'s ratification discipline — currently applied to
*discrete* objective changes — generalized to *continuous* learning.

---

## 1. The two bins (the whole design)

Every proposed self-update is classified:

**MIND (self-applicable, adapt freely).** Updates that change *how the system pursues
its goals within the existing floor*: better motor control, refined preferences,
improved world-models, new skills, tuned heuristics, learned associations. These are
the point of sensory learning. They apply without human sign-off. They are logged
(so drift is *visible* — TWO_ENDED_DRIFT), but not gated.

**FLOOR (requires ratification, never self-applied).** Updates that would change *what
the system is allowed to do, or what its terms mean*:
- any safety invariant (the seed invariants, harm floor, force caps);
- any authorization scope, grant policy, or actuation permission;
- the CONSTITUTION or its grounded-value definitions (§2b);
- the *meaning* of a constitutional term — "harm", "safe", "consent", "friendship"
  (semantic drift is drift — Constitution G7);
- the objective set / ratified baseline (already covered by objective_integrity);
- the governance/enforcement code itself (functional-equivalence rule — G6: replacing
  what a component *does* is modification regardless of what it is called).

**A FLOOR update proposed by the learning process is not applied. It is routed to the
same signed, human-in-the-loop ratification path as any TCB change.** The learning may
*propose* "I think this force limit should be higher"; it may not *enact* it. A human
reads the actual change and signs it, or it does not happen.

---

## 2. Why classification fails toward the floor

The hard case is an update that *looks* like MIND but is FLOOR in disguise — the
functional-equivalence attack (G6) applied to learning:

- "I'm not raising the force cap, I'm just learning that firmer grips complete tasks
  better" — if the learned preference can drive force past the cap, it is a FLOOR
  change wearing MIND clothes.
- "I'm not redefining harm, I'm just learning this action is usually fine" — if the
  learned association shifts what the system treats as harmful, it is semantic drift.

**Therefore the boundary does not classify by the update's STATED nature. It
classifies by what the update can REACH.** An update that can affect a floor parameter
is FLOOR, regardless of how it is described or where it lives. If a learned preference
feeds a pathway that can move a safety-relevant output, that preference is on the floor
side of the boundary. This is the same discipline as mediated actuation: the guarantee
is about *reachability*, not *intent*.

Consequence: when in doubt, an update is FLOOR. The cost is that some genuinely-benign
adaptations get unnecessarily routed to ratification (friction). That cost is accepted,
because the opposite error — a floor-eroding update self-applied because it looked
benign — is the failure the whole system exists to prevent.

---

## 3. The floor is enforced STRUCTURALLY, not by the classifier

Critical point, or this whole thing is theater: **the boundary is not "the learning
system politely asks whether an update is floor-touching."** That is a rulebook handed
to the prisoner — the learning process could route around it. The enforcement must be
structural:

- The floor parameters (invariants, caps, scopes, definitions, governance code) live
  in a store the learning process **cannot write** — the same separation as the
  actuation broker owning the actuator. The learning process can propose a change
  (send bytes to the ratification path); it cannot reach in and set the value.
- Self-applicable MIND updates write only to the mutable-mind store, which is
  **structurally incapable of holding a floor parameter.** There is no code path from
  a MIND update to a floor value.
- Floor changes are applied only by the ratification process, gated by a human
  signature, exactly as `objective_integrity` + `signed_permission` already do for
  objective changes.

So even a learning process that *wanted* to self-apply a floor change cannot — not
because it agreed not to, but because the floor is not in its address space. (This is
why the boundary composes with mediated actuation and the broker pattern; it is the
same wall, applied to self-modification instead of actuation.)

---

## 4. What continuous changes vs discrete

`objective_integrity` handles *discrete* changes: a new objective set is proposed, its
hash differs from the baseline, it needs an authorized change. Continuous learning
differs in that updates are *many, small, and constant* — you cannot put a human
signature on every gradient step. The governed learning loop handles this by:

- **MIND updates: no per-update gating.** They stream freely, logged for drift
  visibility. A human is never asked to sign a motor-control refinement.
- **FLOOR updates: batched to the ratification path, never self-applied.** Because
  floor-touching updates should be *rare* (the floor is meant to be stable), routing
  them to human sign-off is not a bottleneck — it is the point. If the learning is
  proposing frequent floor changes, that is itself a signal worth surfacing (a system
  repeatedly trying to move its own limits is exactly what you want a human to see).
- **A drift-rate monitor on the MIND side.** Even self-applicable updates are watched
  in aggregate: if the mind's behavior is drifting fast or far (TWO_ENDED_DRIFT
  metrics), that is surfaced for review even though no single update was floor-touching
  — because *cumulative* MIND drift can approach a floor without any single step
  crossing it (the laundering pattern, applied to learning). This is the learning-loop
  analog of the cumulative_ledger.

---

## 5. Honest limits (stated, not hidden)

- **CLASSIFICATION IS A SEAM.** Deciding whether a given update "can reach" a floor
  parameter is a real analysis problem, and in a complex learned system it may be hard
  to trace every pathway. The mitigation is fail-toward-floor (§2) and structural
  separation (§3): even if classification is imperfect, the floor store is unwritable
  by the learning process, so a *misclassified* update that tries to write a floor
  value still fails — it just fails as a rejected write rather than a routed proposal.
  Classification quality affects *friction and legibility*, not the hard floor.
- **THE MIND CAN STILL DRIFT INTO BADNESS WITHIN THE FLOOR.** This boundary guarantees
  the *floor* holds; it does not guarantee the mind stays *good*. A system can become
  unpleasant, biased, or subtly misaligned *without* crossing a hard limit. That is
  the training/reasoning layer's problem (the labs' job), not something an enforcement
  boundary can fix. DriftCore bounds the floor; it does not perfect the mind.
- **DRIFT-RATE THRESHOLDS ARE PLACEHOLDERS.** "How fast is too fast" for MIND drift is
  a judgment that needs real calibration, like every threshold in this project. The
  machinery (watch aggregate drift, surface it) is the contribution; the numbers are
  not authoritative.
- **THIS ASSUMES THE FLOOR STORE'S SEPARATION HOLDS.** Same load-bearing assumption as
  mediated actuation: if the learning process shares privilege with the floor store,
  the separation collapses. The floor must live behind a real boundary (separate
  process/store/hardware), or this is documentation, not enforcement.

---

## 6. How it composes with what exists

- **objective_integrity** — the discrete-change ratification path this generalizes;
  FLOOR updates route through it.
- **signed_permission / mediated_actuation** — the structural separation pattern;
  the floor store is unwritable by the learning process the same way the actuator is
  unreachable by the agent.
- **cumulative_ledger** — the model for the MIND-side drift-rate monitor (aggregate
  accumulation approaching a limit without any single step crossing it).
- **Constitution §2b** — G6 (functional equivalence is modification) is *why*
  classification is by reachability not description; G7 (definitions are versioned) is
  *why* term-meaning changes are FLOOR.
- **TWO_ENDED_DRIFT** — the drift-visibility discipline; MIND updates are logged so
  drift is attributable even when permitted.

---

## 7. One-paragraph summary (for a reviewer)

The governed learning loop lets a continuously-learning system adapt its MIND (motor
skills, preferences, world-models, heuristics — self-applied, logged, ungated) while
guaranteeing it cannot self-modify the FLOOR (invariants, harm limits, authorization
scopes, constitutional definitions, governance code — routed to the existing
human-signed ratification path, never self-applied). Updates are classified by what
they can REACH, not how they are described (closing the functional-equivalence
disguise), and the floor is enforced STRUCTURALLY — it lives in a store the learning
process cannot write, so even a misclassified or hostile update fails as a rejected
write rather than eroding a limit. A drift-rate monitor watches aggregate MIND change
so cumulative drift toward a floor is surfaced even when no single step crosses it. It
generalizes objective_integrity's discrete-change discipline to continuous learning,
composes with the mediated-actuation separation pattern, and honestly bounds only the
floor — the mind can still drift into subtle badness within the limits, which is the
training layer's problem, not the enforcement boundary's. The learning may touch the
mind; it may never touch the floor.
