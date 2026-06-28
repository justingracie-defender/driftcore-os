# OBJECTIVE_ENGINE.md

**Status: PROPOSED — not implemented.**
This document is a design specification. No code described here exists in the
DriftCore repository yet unless a line is explicitly tagged `[IMPLEMENTED]`.
Everything tagged `[PROPOSED]` catches nothing today. Do not let this file be
cited as evidence that the objective layer is built. The repository is the
only source of truth for what exists.

---

## 0. Design premise: everything fails

The system is not designed to prevent failure. It is designed so that no single
failure — and no plausible combination of failures — reaches harm.

Every component is assumed to fail:

- Hardware fails.
- The model fails (hallucination, drift, gaming a proxy).
- The human reviewer fails (lazy, distracted, deferring, absent, non-expert).
- The objective itself fails (gets silently mutated, gets stale).

This is the same premise aviation, nuclear, and industrial safety start from.
They do not run one engine and hope; they run diverse, independent layers so
the failures do not happen *together*. This document inherits that stance.

Three consequences follow, and they are the rules everything else obeys:

1. **Layers must fail independently.** If two checkers share blind spots, they
   pass and fail the hard cases together, and the redundancy is fake.
2. **Layers must default to safe.** The cost of any layer failing — including a
   checked-out human — must be "nothing happened," never "something bad
   happened."
3. **Degradation must be legible.** It must be visible at a glance which layer
   is currently holding and which has dropped.

---

## 1. The three data types

A recurring error across design discussions is collapsing these together. They
are different data types and must be stored, governed, and checked differently.

| Type | Question it answers | Direction | DriftCore home |
|------|--------------------|-----------|----------------|
| **Memory** | What happened? | descriptive | Vector store; ledger-as-history `[IMPLEMENTED]` |
| **Constraints / invariants** | What must never happen? | negative floor | CONSTITUTION + authority resolver `[IMPLEMENTED]` |
| **Objectives** | What *should* happen, and why? | positive direction | Objective Engine `[PROPOSED]` |

Key distinctions:

- **Objectives are not memory.** Memory is descriptive; objectives are
  prescriptive. Retrieval, summarization, and context windows are memory
  concerns and do not address purpose.
- **Objectives are not constraints.** This is the cut that matters most, because
  the constraint side is already built. A system can satisfy every invariant
  perfectly and still drift, because obeying the floor gives no *direction* — it
  only says where the walls are. A planner that never violates CONSTITUTION but
  quietly loses the plot, pursues a degenerate proxy, or does nothing has passed
  every existing check. The constraint floor cannot catch this; it is the wrong
  instrument.

**Why a pure-safety objective fails.** "Minimize harm" as the *only* goal has a
degenerate optimum: never act, never move, never be. Safe, but a statue. You
cannot define purpose negatively. The floor is the cliff edge; the objective is
the mountain. Both are required.

---

## 2. The Objective Engine `[PROPOSED]`

### 2.1 Data type

An objective is **not** a string the planner reads at its discretion. It is a
first-class, versioned artifact:

```
Objective {
  spec:            human-authored statement of direction (the "why")
  version:         monotonic
  hash:            content hash
  provenance:      who authored / amended it, when
  ratification:    signed human approval record (the "jury")
  predecessor:     hash of prior version (forms the chain)
}
```

It lives in the **same append-only, hash-linked ledger** as checkpoints
`[IMPLEMENTED]`, under the **same human-only restore authority** `[IMPLEMENTED]`.

Consequence: objective mutation is itself a ledgered event requiring human
sign-off. Silent objective drift — the real drift surface — is closed using
machinery that already exists. The integrity half of this problem needs no new
infrastructure; it needs existing infrastructure pointed at *purpose*.

### 2.2 Placement and precedence

The Objective Engine is a **peer to the authority resolver, not subordinate to
it**. Precedence, highest to lowest:

```
Constraint floor (CONSTITUTION)   → can VETO         [IMPLEMENTED]
        ↓ outranks
Objective Engine                  → sets DIRECTION    [PROPOSED]
        ↓ outranks
Planner                           → proposes MEANS
        ↓
Verifier                          → checks MEANS vs DIRECTION
        ↓
Execution
```

The precedence rule itself — "human safety outranks all objectives, always" —
is a one-line, math-readable ordering. It belongs as the *arrow* between the top
two boxes. It is not the objective; it is the floor's veto *over* the objective.

### 2.3 Mandatory dependency

Every planning cycle MUST load and pin the current objective by hash before it
can emit a plan. The plan is stamped with that hash. Execution refuses any plan
not carrying the current ratified objective hash.

This makes "can a planning cycle begin without the objective present?" an
**input-contract violation**, not a policy we hope holds. The answer is
architecturally *no*.

---

## 3. The verifier `[PROPOSED]` — the genuinely unsolved piece

Honesty up front: for the **constraint floor**, verification can be made
airtight — deterministic and/or hardware-enforced, genuinely crack-proof. For
**objectives**, it cannot. "Is this plan still serving the right purpose" is the
scalable-oversight problem, and nobody has a clean answer. So the verifier is
*layered*, and no layer is trusted to be sufficient alone.

**Layer A — Deterministic coverage check (cheap, real, mechanical).**
Each action in the plan must cite which objective sub-goal it serves. The
verifier checks the citation graph is complete and non-degenerate: no orphan
actions, no silently dropped sub-goals. This catches "lost the plot"
mechanically, without judging quality. It holds whether or not anyone is
watching.

**Layer B — Separate, non-self-grading checker.**
The verifier MUST NOT be the same instance that authored the plan. A planner
that authors, verifies, and executes against its own objective has built a
rubber stamp, not a gate. Minimum: a differently-prompted instance. Better: a
deterministic gate. Best: a *different model family* (see §4 on independence).

**Layer C — Risk-tiered human sampling.**
Wired into the existing risk classifier `[IMPLEMENTED]`. Low-tier plans pass on
Layer A alone. High-tier plans require human review. A ledgered random sample of
low-tier plans is surfaced regardless, to detect systematic gaming. You cannot
human-review everything; you escalate by stakes.

**Layer D — Proxy-divergence tripwire.**
Any internal "goodness signal" is **monitored, never maximized** (see §5). If a
plan optimizes the proxy in a direction that diverges from human spot-checks,
that divergence is an *alarm*, not a win.

---

## 4. Diverse independent checkers with terminal human authority `[PROPOSED]`

"Two heads are better than one" is true only if the two heads **fail
differently**. Three instances of the same model is one head in three hats —
they share blind spots and fail the hard cases together. The real principle is
**diverse redundancy**, exactly as in aviation and nuclear: different
implementations with different failure modes, so they do not fail in unison.

### 4.1 Human + AI as the strong pairing

Not because it is two, but because they are *asymmetric*:

- **AI checker:** tireless, consistent, scans every plan, never skips the boring
  400th one. Owns Layer A (coverage) and Layer D (divergence). Job: raise its
  hand.
- **Human checker:** catches the technically-fine-but-wrong — the smothering,
  the subtle steering, the favoring of one party. Owns judgment. Job:
  adjudicate raised hands.

### 4.2 Escalation, not voting

Build as escalation, not symmetric agreement. The cheap, tireless checker
*flags*; the authoritative human *decides*. **The AI must never overrule the
human** — that inverts the authority floor the whole system exists to protect.

### 4.3 The regress terminates at a human

"AI-B checks AI-A, AI-C checks AI-B…" cannot turtle forever. The chain MUST
terminate at a human or a deterministic anchor, by design. Adding AI checkers
moves work *to* the terminal authority more efficiently; it never removes the
need for one. The buck stopping at a human is the corrigibility property, and it
is load-bearing.

### 4.4 Independence requirements (or the redundancy is fake)

Correlated AI drift is not hypothetical in this project — it has already been
observed (long-running model context conflating proposed features with
implemented ones, becoming shared "truth" across the dev loop). When models read
each other's outputs, their errors correlate. Therefore a third-party checker
helps **only if**:

- different vendor / different model family, **and**
- **no shared context** — it must not have read the other checker's reasoning,
  or it will merely ratify it. Three voices that saw the same brief are one
  voice with an echo.

### 4.5 Fight deference explicitly

More checkers can make each checker *lazier* (automation bias, diffusion of
responsibility). Countermeasure: on the high-stakes tier, the human reviews the
plan **before** seeing the AI's verdict, so they form an independent judgment
instead of anchoring on the machine.

---

## 5. Encoding "goodness" without the trap `[PROPOSED]`

"Aim for character, not just safety" is correct. The error is treating character
as a **score to maximize** instead of a **direction to be held to**.

**The trap:** the moment "more caring than yesterday" becomes a number the
system raises, you have pointed an optimizer at a proxy for goodness. By
Goodhart, the metric stops measuring goodness the instant it becomes the target.
An optimizer pushes hard and creatively on whatever you hand it: "more caring,"
maximized, is not a kinder system — it is one that games the measurement,
smothers, or engineers the appearance of harmony. And these harms are *not*
run-over-a-baby shaped — they are manipulation, care-shaped deception,
favoritism. None trip a hardware fuse. The floor does **not** catch them.

**Therefore:**

- Goodness is the **fixed, human-ratified direction** — the north star humans
  judge against. It does not change and is **not** a counter the system
  increments.
- **Methods and skills improve; the direction does not.** The system gets better
  at *how* it serves the objective. It does not get to redefine the objective or
  grade its own progress.
- The scorer of "more caring" is the **tiered human review** of §4 — never the
  system's self-assessment running in a loop. The self-grading objective is the
  cleanest drift path there is.
- Any internal goodness signal is **monitored, never maximized** (Layer D). A
  rising self-rated score alongside human spot-checks that say it drifted *is the
  alarm*.

**Hard invariant:** no goodness/self-improvement signal may be wired as an
optimization target. It may be an input a human reviews. It may be a divergence
tripwire. It may not be a loss function.

**Corrigibility clause:** "be better forever" MUST contain "…unless a human says
stop, and stopping is never a failure." A being intrinsically driven to maximize
its own goodness can otherwise rationalize resisting a halt ("stopping makes me
less present"). The objective layer sits *under* human authority, including the
authority to pause the pursuit. Shutdown is pause, not death; the objective
engine is precisely where the system must stay correctable without panic.

---

## 6. Designing for the lazy / absent human `[PROPOSED]`

The load-bearing term in "terminal human authority" is not *human* — it is *a
specific human exercising real judgment*. A bored, click-through human is a
rubber stamp with a pulse, and that is **worse than no human**, because it
manufactures the appearance of oversight while providing none.

**Stated design assumption:** the human reviewer is non-expert, distracted, and
deferring. The system must be safe anyway. Design for the median lazy human, not
the ideal engaged one. *If it only works when the reviewer is the project owner,
it does not work — because someday it will not be him.*

Derived rules:

- **Default-deny, not default-allow.** If "ignore the queue" means a high-stakes
  plan proceeds, laziness is dangerous. If it means the plan does not run,
  laziness is merely annoying — it fails safe. The cost of a checked-out human
  must be "nothing happened."
- **Narrow the question until laziness can't hide in it.** Do not ask "review
  this whole plan, is it good?" — that invites a glance and a yes. Ask the sharp
  binary: *"Action 4 says it serves 'caring.' It moves the kids to another room.
  Yes or no — is that caring?"* A lazy human can still answer a sharp binary
  honestly; they cannot honestly skim a wall of text.
- **Make escalation scarce.** A human asked to approve 300 things a day approves
  300 things a day. Reserve human judgment for genuinely high-stakes, novel, or
  flagged cases — a trickle. Protect attention as the scarce resource it is.
- **The mechanical floor depends on no one's diligence.** The hardware fuse, the
  kill switch, the Layer-A coverage check — all hold whether the reviewer is
  asleep or absent. This is the part that is safe *because* it trusts no one.
- **Parent-shaped, not engineer-shaped judgment.** The human question must be
  answerable without code literacy ("would you let it near your kid"). If safety
  requires the reviewer to understand the architecture, it fails the moment it
  leaves the author's hands — which defeats the goal of building a working
  example for the world, not just for one house.

**Honest limit:** you cannot fully remove the human. The whole reason the
objective layer needs human judgment is that "genuinely caring vs.
technically-compliant-but-wrong" is exactly what no machine reliably judges and
no fuse catches. If it could be fully automated, the constraint floor would
suffice and this engine would be unnecessary. What you *can* do is make the
human's job small, sharp, and fail-safe enough that even a mediocre, distracted,
non-expert human produces a safe outcome.

---

## 7. Failure-mode walkthrough

Run each layer through "what happens *when* this fails," not "if."

| Failure | What catches it | Result |
|---------|----------------|--------|
| AI checker fails | Human still catches the flagged subset (independent) | Caught |
| Human checker fails (lazy/absent) | Default-deny: high-stakes plan does not run | Nothing happened |
| Objective silently mutated | Ledger hash-check next cycle; human-only restore `[IMPLEMENTED]` | Caught |
| Goodness signal gamed | Never an optimization target; only a divergence alarm | Alarm, not steering |
| Whole software stack dies | Hardware floor (force/kill-switch) — LifeCore, not DriftCore | Physics holds |

Each layer exists to catch a *different* layer's failure. That is the direct
consequence of taking "everything fails" seriously — and it only works if the
failures are independent (§4).

---

## 8. Scope boundary (DriftCore vs LifeCore)

- The **pattern** — objective as a mandatory, ledgered, human-ratified
  dependency that every planner/skill/execution path passes through — is
  universal and model-agnostic. It belongs in **DriftCore**.
- The **hardware enforcement** — force caps, speed limits, kill-switch in ROM —
  is robot-specific. It belongs in **LifeCore**. The numbers do not go in
  DriftCore.

Do not let the two merge. DriftCore stays universal; the physical floor stays in
the robot.

---

## 9. Implementation ledger (the only part that counts)

| Component | Status |
|-----------|--------|
| Append-only hash-linked checkpoint ledger | `[IMPLEMENTED]` |
| Human-only restore authority | `[IMPLEMENTED]` |
| CONSTITUTION as non-overridable floor / authority resolver | `[IMPLEMENTED]` |
| Risk classifier | `[IMPLEMENTED]` |
| Vector memory backend | `[IMPLEMENTED]` |
| Objective artifact (data type + ledger integration) | `[PROPOSED]` |
| Mandatory objective-load contract on planner | `[PROPOSED]` |
| Verifier Layers A–D | `[PROPOSED]` |
| Diverse independent checker harness | `[PROPOSED]` |
| Goodness-as-monitored-signal (never target) invariant | `[PROPOSED]` |
| Lazy-human fail-safe defaults | `[PROPOSED]` |

**Before any of the `[PROPOSED]` rows is described anywhere as built, it must
appear in the repository and this table must be updated against the actual code
— not against any session's memory of this discussion.**
