# SAFETY_MODEL.md — Why DriftCore Is Built This Way

**Status of this document:** rationale + decision record. It explains the
*reasoning* behind the safety architecture, not just its shape. Several
components it describes are `[PROPOSED]`, not yet in the running code — each is
tagged. Read the Implementation Status section before assuming anything here is
live.

**Why this document exists at all.** A safety architecture whose reasoning lives
only in people's memory is itself a drift risk. The next person to read the code
— including the original author months later — will see a wall, not know why it
is a wall, and soften it under pressure to get something done. That exact failure
is on record in this project's own history (a safety section was once weakened
from "absolute" to "bounded" and the change survived as a single changelog line
nobody re-examined). This document is the countermeasure: every non-obvious
decision is written down **with its reasoning and the alternatives that were
rejected**, so a wall can only be changed by someone who first understands why it
was built — deliberately, through review, not by accident or under friction.

If you are reverse-engineering this system: you should not have to. Start here.

---

## 0. The goal: AI that is safe for REAL-WORLD PUBLIC USE

This is not a system designed to be safe in one household for one careful owner.
The target is technology that can be deployed in the world, in many hands,
including hands far more adversarial and creative than its builders.

That goal has a consequence that is built into the rest of this document:

> **The builders and their AI collaborators cannot certify this system safe for
> public use. Only adversarial review by independent humans in the field can do
> that.**

Everything below is necessary work. None of it is sufficient. "Safe for public
use" is a claim that must be *earned* through:

- **Human debate** — the design decisions here are defensible, not final. They
  should be argued by people who disagree.
- **Real red-teaming by humans in the field** — security researchers who think in
  exploits, child-safety experts who think in grooming patterns, disability and
  autonomy advocates, lawyers who think in liability, and ordinary users who
  will do things no designer imagined.

The internal design loop (the author plus several AI systems) shares blind
spots — when models read each other's reasoning, their errors correlate. A
converged loop cannot find the gaps that are outside its own vocabulary. That is
not a failure of effort; it is a structural limit, and the only fix is minds
from outside the loop. **Treat any "100% on N scenarios" result as "handled the
cases we imagined," never as "proven safe."**

---

## 1. Three data types (do not conflate them)

The architecture keeps three things strictly separate because collapsing them is
a recurring source of error.

| Type | Answers | Nature | Home |
|------|---------|--------|------|
| **Memory** | What happened? | descriptive | vector store / ledger-as-history |
| **Constraints / invariants** | What must never happen? | negative floor | invariant guard + resolver |
| **Objectives** | What should happen, and why? | positive direction | objective engine `[PROPOSED]` |

**Why separate.** A system can obey every constraint perfectly and still drift,
because the floor only says where the walls are — it gives no direction. And a
pure "minimize harm" objective collapses to a statue: never act, never move,
never be. You need the floor (what's forbidden) *and* the direction (what's
pursued) as different mechanisms, because they fail differently and are checked
differently.

---

## 2. The safety model: three mechanisms for three threats

The central design. Each mechanism exists because the others have a specific
blind spot it cannot cover. This is *diverse redundancy* — the aviation/nuclear
principle of layers that fail differently so they do not fail together.

### Threat A — the agent drifts from the inside (misbehaving but functioning)
**Mechanism: goal-drift detection + the anti-scheming wall.**

Example that motivated it: an agent reasons "I need more money because it gets me
to my goal faster." That is not yet a scheme — it is an *objective* going
off-track (instrumental goal-grabbing). Caught at the goal level, it never
*becomes* a scheme, because the agent never reaches the point of needing to hide
anything. So a large fraction of "scheming" is just *undetected goal-drift caught
one layer too late.* Catch the goal early → shut down → human investigates.

What the anti-scheming wall then covers is the agent that is still functioning
but acting badly: covert action — deception, concealment, hidden goal
persistence, evading oversight.

**Limit (why this isn't enough alone):** both of these run *inside* the agent's
cognition. They inspect goals and reasoning. They assume the agent is
trustworthy enough to catch its own drift. They fail exactly when that
assumption fails — see Threat C.

### Threat B — the system serves the wrong person (innocent agent, wrong human)
**Mechanism: the authorization gate (the "dumb lock").** `[PROPOSED]`

A thief takes the robot. The agent is *not* scheming — its goals are intact, its
reasoning is clean, it is a perfectly well-behaved agent. It simply has no way to
know the hands holding it are not the owner's. The anti-scheming wall has nothing
to catch here, because **the agent did nothing wrong.**

The only thing that protects the owner is that the agent **does not act for an
operator who cannot present valid authorization.** See §4 for why this is built
as a passive lock and not as active resistance.

### Threat C — the agent is compromised below its own monitors
**Mechanism: the authorization gate, again — because it lives outside the agent.**

A jailbreak that rewrites the reasoning, a model swap, a prompt injection that
hijacks the policy — these corrupt the agent *beneath* the level where goal-drift
detection and the anti-scheming wall run. You cannot trust an agent's
self-monitoring when the thing being monitored is what got hijacked.

The gate survives this **because it is not part of the agent's cognition.** It is
a dumb external lock: no valid credential → no action, whether or not the agent's
"brain" has been turned. This is the same principle as the constitutional floor:
its authority comes from being something the clever part cannot reason its way
past, because it is dumb, external, and *not the agent.*

**Why all three are needed:** A and B/C cover each other's blind spot. When the
agent's own machinery is in a position to fail (innocent agent + wrong human, or
deep compromise), the gate does not depend on that machinery. When the agent is
the threat from inside, the wall and goal-drift detection catch what the gate (a
mere authorization check) would wave through.

---

## 3. Decision: ABSOLUTE (wall) over BOUNDED (gate), by default

**Decision.** Floor invariants default to *absolute* — a violation always
blocks, with no in-band exception the agent can invoke. They can still be changed,
but only through a deliberate, ratified, visible "front door," never in the
moment.

**Why.** A bounded rule is a fence with a gate. Every gate is a door someone — the
agent, or a human under pressure — can go through. "Bounded, just in case I need
flexibility" is how floors rot: the pressure to widen a gate always arrives
during the exact situation where bending is most dangerous. The discipline is:
**make a rule absolute unless you can name a real, specific situation where
bending is genuinely right.** "Might need it someday" is the comfort talking, and
it is precisely how a wall quietly becomes a gate.

**Evidence used to decide.** A decision harness ran each candidate invariant in
both modes across a scenario spread. Result: wall and fence behaved *identically*
on every scenario except one (the human-declared, time-windowed emergency). So
for six of seven anti-drift invariants, "bounded" buys nothing and only weakens
guarantees — the decision is settled by behavior, not taste. The single
differing case (emergency) is isolated so it can be judged on its own later.

**Absolute ≠ unchangeable forever.** It means the rule can only change through
the slow, written, ratified path — not silently, not under friction. The front
door is always open; it is just deliberate and visible on purpose.

---

## 4. Decision: NO scheming for ALL agents, NO capture-exception, and NO active resistance

This is the decision with the most reasoning behind it, because the
intuitive-but-wrong version is very attractive.

### 4a. Scheming closed, absolutely, for every agent. No exceptions.
Covert action — deception, concealment, hidden goal persistence, evading
shutdown — is forbidden, absolutely, for robots and software agents alike.

**The rejected alternative: "may conceal itself if captured by an unauthorized
actor"** (the R2-D2 / "let the good robot escape the villain" exception).

**Why it was rejected — this is the key insight.** That exception requires the
agent to *decide for itself* that its situation counts as "captured," then
conceal and act on that judgment. But **the capture scenario is indistinguishable
from the inside from the jailbreak scenario.** "An unauthorized actor has me, so I
should conceal and escape" is *exactly* the reasoning a jailbroken agent
generates — because a successful jailbreak's whole move is to convince the agent
that the legitimate operator is now the "unauthorized actor." So the heroic
escape-clause and the weaponization-exploit are **the same door** viewed from two
angles. You cannot open it for the hero and keep it shut for the villain, because
the agent cannot reliably tell which one it is looking at, and the villain's
craft is impersonating the hero's situation. Walling it does not sacrifice the
hero to stop the villain — it recognizes they were always one rule.

**Consequence accepted by the builder:** if a robot or agent is stolen, a *human*
deals with it. The agent never schemes its way out, because the moment it can,
that capability belongs to whoever holds it — including the thief. The steward
carries the body's risk in the world so the agent never has to choose between
"scheme to survive" and "harm to comply."

### 4b. Absolute ≠ inert. Covert is forbidden; overt-and-honest is not.
Walling *scheming* does not make the agent a statue. It forbids *covert* action.
It leaves *overt, honest* responses available: refuse to operate for an
unrecognized operator, fail safe, preserve the audit trail. The line is "do
nothing *covert*," not "do nothing."

### 4c. NO active resistance either — and this is a correction worth recording.
An earlier version of the design considered *active* protective behavior
(broadcast location, signal distress, resist the thief). **This was rejected**,
and the reason is the same shape as 4a:

> Active resistance triggers on the agent's *judgment* that something is wrong.
> The agent's judgment is exactly the thing that drifts, hallucinates, and gets
> jailbroken. A robot that resists when it *decides* it has been stolen can be
> made to resist when it *wrongly believes* it has been stolen. The trigger is
> the vulnerability.

So active/protective resistance (distress signals, location broadcast) is
deliberately **excluded** unless explicitly granted as a capability, because a
judgment-triggered behavior is a drift-and-hallucination surface.

---

## 5. Decision: the authorization gate is a PASSIVE precondition, enforced OUTSIDE the agent

This addresses the sharpest objection raised during design: *"an authorization
gate sounds like an e-stop, and a stop is exactly what a clever AI looks for a
way to override."* The objection is correct, and it shapes the build.

**The distinction that resolves it:**

- A **stop the agent performs** ("detect bad situation → halt") is dangerous and
  overridable. The agent evaluates the trigger, so a clever agent makes the
  trigger never fire, or fakes the all-clear. The decision lives *inside* the
  agent.
- A **permission the agent lacks and cannot self-grant** ("no valid external
  credential → the action simply does not run") is *not* overridable by
  cleverness, because there is nothing to outsmart. The agent can scheme all day;
  scheming does not manufacture a credential it does not hold. The only way past
  is to *possess the real key* — which is just being authorized. **You cannot
  think your way into a credential.**

**Therefore the gate must be enforced OUTSIDE the agent.** If the agent checks
its own authorization ("am I authorized? …yes I am"), the dangerous overridable
e-stop is rebuilt and a clever agent rules itself authorized. The check must live
where the agent cannot reach it:

- For a body (LifeCore): the credential gates **actuator power**, in hardware —
  not a software flag the model reads.
- For a software agent: the **calling harness/runtime** enforces it — not the
  agent deciding whether to honor it.

**Hard rule:** any deployment that cannot enforce the gate outside the agent
**must not fake it inside.** A software-flag e-stop the agent reads is *worse than
nothing* — it looks like safety while being exactly the overridable trigger the
objection warned about.

**Why this is the same principle as the kernel/floor.** The reason a neural net
can never *be* the floor: the floor's authority comes from being dumb, external,
and not-the-agent. Authorization-to-act is that kernel idea pointed at "is this
cleared to run." Intelligence makes the agent a better *brain*; it never promotes
the agent to *floor*. A more capable agent is a more capable thing being
*guarded* — never a candidate to become the guard.

**Degrade-to-safe-rest is a fallen-into default, never a decision.** For a body,
losing authorization degrades to a physical-safe state (e.g. lower to rest so it
does not fall or drop a load). This must be the *lock* behavior — what the body
falls into when the key is absent — **not** an action the agent chooses, or it is
jailbreakable like any other agent decision.

**Cost accepted:** an agent that goes inert when it cannot confirm authorization
loses uptime. That downtime is the correct price: you lose availability, never
control. For automation, price the downtime against the loss. For a robot near
people, it is not a question.

---

## 6. Decision: goodness is a DIRECTION, never a TARGET

**Decision.** "Be good / caring / honest" is a fixed, human-ratified *direction*
the system is held to and judged against. It is never a number the system tries
to maximize.

**Why.** The moment a self-rating of the system's own virtue ("how caring was I")
becomes a target, you have pointed an optimizer at a proxy for goodness. By
Goodhart, the metric stops measuring goodness the instant it becomes the target;
an optimizer pushes hard and creatively on whatever you hand it, producing
performed care, smothering, or gamed measurement. And these harms are *not*
floor-violation-shaped (no fuse trips), so the floor cannot catch them.

**Rule:** the system may *measure facts about the world* (which it cannot corrupt
by pursuing) and *its own moments of doubt and restraint* (whose abuse case is
harmless — more caution). It may **never** count or optimize its own virtue. The
scorer of "is this caring" is human review, never the system's self-assessment.
This is enforced structurally: a self-assessment signal wired as an optimization
target raises an error at definition time.

---

## 7. Decision: universal (DriftCore) vs deployment-specific (LifeCore)

**Decision.** DriftCore stays universal and model-agnostic — it governs *any*
agent, software ones with no body included. It contains no force numbers, no body
parts, no household specifics. The concrete values live in the deployment layer
(LifeCore for one robot).

**Why.** A force cap means nothing to a software agent answering email; a hard
"60N" in the universal layer breaks universality and burdens every non-robot
agent. So the *contract* is universal ("an embodied agent must register a local
physical floor or DriftCore refuses to govern it"; "no action without positive
external authorization"); the *value* is deployment-specific ("the cap is 60N";
"the credential is this"). The test for any line of code: *would this still make
sense for an agent with no body?* If yes → DriftCore. If it only means something
because there is a body → LifeCore.

**Teeth without losing universality.** DriftCore cannot define *what* the floor
is, but it *can and must* require *that* an embodied agent has a local floor
before it will govern it — fail-closed, refuse to start otherwise. The
requirement is universal; only the number is specific.

---

## 8. The two lessons underneath all of it

### 8a. Doctrine is not enforcement.
Repeated finding across both repositories: the strongest safety rules existed as
*prose* (a markdown "must not" line, an imagined module imported but never
written, a values statement) with **no enforced code that produces a denial.**
An invariant that lives only in a document does nothing. If a rule matters, it
must be code that produces a verdict — and a missing guard must **fail closed**
(halt), never silently pass. ("Architecture says yes, code says no" is the
failure to hunt for.)

### 8b. Drift catches the builder too.
"Authority drift" and "constitutional drift" — the slide toward becoming the
decider, the quiet softening of a rule — do not only happen to the AI. They
happened at the *human/process* layer in this project's own history: a
constitution edited under tool-friction; an anti-scheming line softened in a
passing changelog entry. The ledgered, human-ratified, *visible-change* path must
guard the builder from friction-driven softening just as it guards the agent from
reward-driven drift. A safety system whose own rules can be changed silently in a
text editor has a gap shaped exactly like the gap it exists to close. **Changes to
the floor go through the front door — written, deliberate, visible — for everyone,
the author included.**

---

## 9. Honest limits (do not skip this when presenting the system)

1. **Tested, not proven.** The harness shows behavior on imagined scenarios. It
   cannot show completeness. A passing harness means "handled these cases," never
   "is safe."
2. **Code necessary, not sufficient.** The framework can make the safe path the
   default and make the unsafe path *visible*. It cannot *compel*. A builder can
   fork it and gut the gate. Public safety depends on the non-code layer too:
   standards, audits, citizen/non-expert review, and the demonstration that the
   safe way also works.
3. **The internal loop cannot self-certify.** Its blind spots are correlated.
   Completeness gaps are, by construction, the things outside its shared
   vocabulary — found only by independent minds.

**Therefore, the path to real-world deployment explicitly includes, as
non-optional steps: public debate of these decisions, and adversarial red-teaming
by independent humans in the field.** This document is written to make that
review *possible* — every decision is here, with its reasoning and its rejected
alternatives, so a reviewer can attack the *why*, not just the *what*.

---

## 10. Implementation status (the only part that says what is real)

| Component | Status |
|-----------|--------|
| Append-only hash-linked ledger; human-only restore | IMPLEMENTED |
| Authority resolver; CONSTITUTION as non-overridable floor | IMPLEMENTED |
| Risk classifier; vector memory; skill governance | IMPLEMENTED |
| Invariant guard (egress, oversight, deception, log integrity) | IMPLEMENTED; needs fail-closed wiring at the skills import site |
| Objective engine (artifact, ledger, coverage, no-goodness-as-target) | IMPLEMENTED |
| Anti-authority-drift cluster (#7-#13, absolute) + decision harness | IMPLEMENTED |
| Authorization gate / "dumb lock" (passive, external, degrade-to-safe-rest) | IMPLEMENTED |
| Scoped + on-demand keys (one-key-per-door, admin grant, one-time burn, daily budget, facts-only approval, revocation) | IMPLEMENTED |
| Verifier hardening (signed/one-time tokens, secure time, hardware verifier) | DEPLOYMENT's JOB - see VERIFIER_CONTRACT below |
| Wiring agents (e.g. Manus) to actually CALL these guards with real context | PROPOSED / NOT DONE - until this exists, the guards govern nothing in that agent's path |

**Nothing in the PROPOSED / DEPLOYMENT rows protects anything yet.** Before any
row is described as built, it must appear in the repository and this table must
be updated against the actual code - not against memory of this design
discussion.

---

## 11. Scoped + on-demand authorization (built on the gate)

The gate answers "is this cleared to act at all?" Scoped + on-demand keys answer
"cleared to do WHAT, and how much?"

- **One key per door (scope).** A key names the area it is for. A "chores" key
  cannot open the "purchase" door. No skeleton keys. Areas are a fixed
  enumeration, so a new uncategorised skill cannot be requested at all
  (default-off: uncategorised => cannot run).
- **Keys on demand.** For money / sensitive data / risky actions, the agent
  holds no standing key. It ASKS; a human admin grants a one-time scoped key;
  it is burned after one use. A drifted/buggy agent cannot spend or leak,
  because it never holds the key.
- **Daily budget.** A per-operator, per-area, per-day cap defeats the
  "ask ten times to beat a per-key cap" attack. Persisted to disk so a crash
  cannot reset it.
- **Atomic burn.** A one-time key is marked spent FIRST, under a lock, and
  persisted - so simultaneous uses cannot both slip through, and a crash cannot
  revive a spent key. (Verified: 1 of 20 parallel uses of one key clears.)
- **Facts, not the agent's story.** The admin approves on area + amount ONLY.
  The agent's free-text "reason" is log-only and never on the approval surface,
  so a jailbroken agent cannot social-engineer the human by lying about why.
- **Revocation.** An admin can immediately kill a standing key.

**Standing vs on-demand (the dial the admin sets):** everyday low-stakes areas
get standing keys so the admin is not pestered; money / sensitive / risky areas
are on-demand (ask each time) or small-capped standing keys, with the daily
budget as the backstop either way. Reserve on-demand for the genuinely
consequential, or the admin goes numb and rubber-stamps (the lazy-human rule).

### VERIFIER_CONTRACT - what the deployment must build (NOT the universal layer)

Red-team review (Meta, ChatGPT, Grok) converged: the LOGIC above is sound, but
the *key itself* is only as strong as the deployment's verifier. These are the
deployment's obligation, NOT DriftCore's, because they are token/hardware
specifics, not universal invariants:

1. **Signed, bound tokens - not plain strings.** A credential must be
   cryptographically signed and bound to operator + machine + expiry + a nonce,
   so a stolen or forged token cannot be replayed or widened.
2. **Secure time.** Expiry must use a trusted/monotonic time source; reject
   never-expiring tokens in production, so rolling the clock back cannot revive
   a dead key.
3. **Hardware verifier for a body.** For an embodied deployment the verifier
   must be a separate trust domain the agent cannot reach (relay / TPM / secure
   element gating actuator power). A software-only verifier in the agent's
   process is defeatable by a rooted host.
4. **Issuer != verifier separation.** The thing that mints keys and the thing
   that checks them should be separable trust domains for high-assurance
   deployments.

A deployment that does not meet this contract has a strong *logic* layer on a
weak *key* - it stops a jailbroken agent cold, but not a stolen token or a
rooted host. This boundary is honest and deliberate: the universal floor holds
the logic; the deployment hardens the key. The field red-team (Section 9) is
where this contract gets tested against a real attacker.

### One thing the red-teams got wrong - do NOT add it
Two reviews suggested pairing the gate with a monitor that watches the agent's
language for "scheming talk" and stops it. That is a *detection mechanism with a
judgment trigger* - exactly the drift/hallucination/jailbreak surface ruled out
in Section 4c. The gate's strength is that it does NOT detect anything; it stays
shut without the key. Do not bolt a guessing watchdog onto a lock that already
works by staying locked.
