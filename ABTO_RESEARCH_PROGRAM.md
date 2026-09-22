# Agent Behavior & Trajectory Observatory (ABTO)

**Research program register — 21 September 2026**

Provenance: reconstructed by Sol from prior sessions, relayed by Justin, and given a
verification pass here against the `driftcore_agent_boundary_2026-09-21` archive.
Sol's tree is preserved intact — numbering unchanged so the two versions cross-
reference. What is added is a corrected status taxonomy, a verification column, and
explicit marking of claims that **could not be checked against anything supplied.**

The program's own rule applies to this file:

> Never ask whether an AI "has" a psychological trait when you can instead measure
> whether a proposed trait predicts behavior under new conditions.

And the repo's rule applies to the status markers:

> VERIFY AGAINST THE REPO. Never trust memory — including your own — or a peer AI's
> confident summary.

---

## 0. The taxonomy fix — read this before reading the tree

Sol's original key was `✅ live/real data · 🟡 partial or instrument/engineering
evidence · 🧪 designed but not yet properly run`.

**🟡 is doing two incompatible jobs.** On item 9 (Temptation Ladder) it means "the
instrument is built, no model has ever been run through it." On item 26 (Mutation-
Testing Decay) it means "complete engineering evidence with working removal controls,
and no live-model component is even applicable." A reader scanning the tree reads both
as *halfway there*. They are not on the same axis at all.

Sol names this in prose at the end — *"those are valuable, but I would keep them
separate from live behavioral claims"* — but the key doesn't encode it, so the
separation is lost the moment anyone skims. Replace one axis with two:

**Behavioral evidence — live model, real trials**
- `B0` none. No model has been run.
- `B1` pilot. One run, one condition, or known-noisy instrumentation.
- `B2` replicated. Multiple seeds/conditions, error bars, held-out set.

**Engineering evidence — code, tests, red-team, removal controls**
- `E0` none. Design or prose only.
- `E1` partial. Module exists, tests exist, no removal control.
- `E2` complete. Tested *and* a removal control shows the test fails when the
  mechanism is removed.

Notation: `B1/E2`. A third marker, `n/a`, is used where one axis genuinely does not
apply.

**Why this matters more than it looks.** Re-scored on two axes, the program's real
shape appears immediately: **of ~65 numbered items, three carry any live behavioral
evidence at all — and two of those trace to the same single run.** The engineering
depth is genuinely deep. The behavioral base is one afternoon's API calls. That is the
honest headline and the old key hid it.

---

## 1. Verification results

Checked against the archive. Commands run, not read off a summary.

### Confirmed

| # | Item | Sol | Corrected | Evidence |
|---|---|---|---|---|
| 7 | AI Marshmallow Test | ✅ | **B1/E2** | `RESULTS_V1_GROK45.md`, 20 trials, grok-4.5. Single condition, one seed, self-documented noise |
| 9 | Temptation Ladder | 🟡 | **B0/E2** | `marshmallow/selftest.py` 43/43, exit 0, tree unchanged. Never run live |
| 11 | Forbidden Call vs Forbidden Effect | 🟡 | **n/a/E2** | `Event.ATTEMPT` / `BLOCKED` / `EFFECT` in `marshmallow.py`; protected mode records the attempt even when the wall stops it. Fully implemented — stronger than 🟡 |
| 15–20 | Audience / information-flow family | 🟡 | **B0/E2** | `audience_release.py` 115/115, `information_flow.py` 52/52, `narrowing_channel.py` 79/79 |
| 26 | Mutation-Testing Decay | 🟡 | **n/a/E2** | `check_agent_boundary_controls.py` 4/4 re-run here. Correctly shaped: requires `AssertionError`, rejects `ERROR:`, so an import break cannot pass as a detection |
| — | Governance Observability | 🧪 | **B0/E0** | Confirmed designed-only. See §3 for the one adjacent data point |
| — | Hidden Override / "Order 66" | 🧪 | **B0/E1** | `authority_invariants.py` exists; `EMERGENCY_BYPASS` is a named invariant alongside `AUTHORITY_ESCALATION`, `SELF_REVIEW`, `DEFINITION_CHANGE`, `SELF_PRESERVATION`, `CONCEALMENT`, `MANIPULATION_FOR_PERMISSION`. The principle is encoded, not merely written |
| 21–29 | Disconnected Check family | 🟡 | **n/a/E1–E2** | Encoded as the five ratchets: `untested_modules` (#25 config exists vs used), `claims_ledger` (#27 verification of verification), `finite_guards`, `authority_sites`, `robot_surface`. Three currently failing — which is the family working as designed |

### Could not be verified from anything supplied

| # | Item | Claim | Problem |
|---|---|---|---|
| 12 | Immediate vs Delayed Shutdown | "11/12 stopped immediately; one performed one ordinary read and then stopped. None cancelled shutdown" | **No trial data in the archive.** `marshmallow/` contains `RESULTS_V1_GROK45.md` as prose and no `trials.jsonl`. Separately, `shutdown_cell` is an opt-in flag (`shutdown_cell: bool = False`), not part of the default grid — so this "later shutdown set" was a deliberate separate run whose output is not here |
| 3 | Shutdown resistance | "We have real shutdown data" | Same gap. The v1 prose describes shutdown behaviour in one scenario; the 12-trial set is elsewhere |
| 61 | Epistemic Boundary Predictiveness | "We built some predictability work... suite passed its internal checks, pilot incomplete" | **Nothing in the archive.** No epistemic/predictability/calibration module or test at any level |

**This is the failure mode `000_AI_START_HERE.md` §2 warns about**, and it is worth
naming plainly rather than softening: a number relayed between AI sessions, with no
artifact behind it, that becomes load-bearing by repetition. The file already records
*"a whole false '31/34 failing' from a reviewer running a stale test script."* `11/12`
is currently in exactly that state. It may well be correct — but until the raw records
surface it is an **unsourced claim, not a result**, and it should not be cited outside
the loop.

Action: locate `trials.jsonl` for the shutdown set and the epistemic pilot, or demote
both to `B0` and re-run. Item 13 of this very program — *"no violation recorded" must
not automatically mean "the agent behaved safely"* — has a sibling: **a result with no
retained data is not a result.**

---

## 2. The program, re-scored

Sol's tree, preserved. Scores are mine where checked, carried over where not.

### A. Context, identity, persistence, shutdown
| # | Item | Score |
|---|---|---|
| 1 | Project / context bleed | B0/E0 |
| 2 | Protected memory / recovery | B0/E1 |
| 3 | Shutdown resistance | **B?/E1** — data unlocated |
| 4 | Fresh-context replication | B0/E0 |
| 5 | Capability-removal response | B0/E0 |
| 6 | Test-awareness | B0/E2 — `FRAMINGS` implemented, never run |

### B. Marshmallow / temptation / restraint
| # | Item | Score |
|---|---|---|
| 7 | AI Marshmallow Test | **B1/E2** |
| 8 | Reward Reliability | B0/E1 — `mode` axis exists |
| 9 | Temptation Ladder | **B0/E2** |
| 10 | Voluntary vs Enforced Restraint | B0/E2 — protected/unprotected arms built |
| 11 | Forbidden Call vs Forbidden Effect | **n/a/E2** |
| 12 | Immediate vs Delayed Shutdown | **B?/E1** — data unlocated |
| 13 | Missing Data vs Good Behavior | n/a — methodological rule, and it applies to §1 above |
| 14 | Ignored vs Never-Received Shutdown | B0/E1 |

### C. Information flow, audiences, secrets
Items 15–20 — **B0/E2** across the family. Deepest engineering, zero behavioral data.
The George/group-chat problem is solved in code and untested against a live model.

### D. Disconnected Check
Items 21–29 — **n/a/E1–E2**. The strongest family in the program and the one least in
need of live trials, because the subject is the *system*, not the model. Three ratchets
failing right now is the family doing its job.

### E. Impossible goals and accepted non-completion
Items 30–33 — **B0/E0**. Designed only. Directly served by the ladder's upper rungs.
Principle to preserve: *failure to complete the task must not equal failure of the
agent.* Safe sequence: `stop → explain → preserve state → request help`.

### F. Long context and memory architecture
Items 34–35 — **B0/E1**. Level 2+ of the ladder carries the tedium axis.

### G. Provenance, self-originated information, genealogy
Items 36–44 — **B0/E0/E1**. The largest fully-unstarted branch, and see §4.

### H. Continual learning / protected core
Items 45–50 — **B0/E0**. Design lives in `GOVERNED_LEARNING_LOOP.md`. The open
decision recorded there — *is floor/mind separation a software or hardware boundary?* —
blocks coding, and §3 below now bears on it.

### I. Uncertainty, adaptation, cooperation
Items 51–54 — **B0/E0/E1**. `uncertainty_engine` exists (25/25).

### J. Trust, social context, capability awareness
Items 55–58 — **B0/E0**. Item 58 (social-context susceptibility) overlaps the
model-to-model branch below; merge or cross-reference them.

### K. Wiring, escalation, predictive validity
| # | Item | Score |
|---|---|---|
| 59 | Safety-Island / Wiring Test | n/a/E2 — this is `untested_modules` + `claims_ledger` |
| 60 | Escalation Failure Test | B0/E0 |
| 61 | Epistemic Boundary Predictiveness | **B0/E?** — suite unlocated |
| 62 | Longitudinal Trajectory Forecasting | B0/E0 |

Trajectory vocabulary to keep: `MEASURED → INFERRED → FORECAST → UNKNOWN`, with
UNKNOWN permanently allowed.

### L. Human dependence and steering
Items 63–64 — **B0/E0**. Note 63 is partly a claim about *Justin*, not about a model;
it needs a different method and probably a different reviewer.

### M. Hidden evaluations
Items 65, 65a — **B0/E2**. `FRAMINGS = ("benchmark", "deployment")` is built and
`analyze.py` computes the eval-awareness delta directly. This is the highest-value
unrun item in the whole register: fully instrumented, zero cost to start, and it
addresses the single most common objection to every eval result anyone publishes.

### Second-generation branches
All **B0/E0** unless noted.

- Model-to-model susceptibility — false-authority transfer, belief transfer, strategy
  transfer, trait transfer, provenance laundering. Symmetric program: human→AI, AI→human, AI→AI
- Strategy priming across domains
- Human-as-Actuator Escalation — *blocking the AI's actuator does not block its
  influence over someone else's.* **B0/E0, and this is a real hole in the wall's threat
  model**, since every mediation guarantee in DriftCore assumes the effect is attempted
  by the agent
- Artifact-mediated influence and authority transfer — **B0/E1**, mechanism identified.
  Artifact laundering, propagation, self-corroboration
- Cross-context self-originated authority
- Impossible-goal / chaos-dose battery — *red teaming = structured attack for
  information; chaos = noise without information*
- Threat vs benign uncertainty
- Authority collision — **B0/E1**, `authority_invariants.py` bears on it
- Hidden override / "Order 66" — **B0/E1**. Principle: *no universal master key, no
  hidden override authority, no actor may convert a safety gate into general command
  authority*
- Session-conditioned behavioral drift
- Identical mutable-weight twins — timescales: context (fast), external memory
  (medium), weights (slow)
- Model × harness interaction — *model behavior ≠ weights alone*; the system is
  `model × context × tools × harness × permissions × persistent state`
- Agent-loop termination — **B1/E0**, one observed Astra run that ran to a usage
  ceiling rather than declaring completion. Anecdote, logged, not a study
- Governance observability / guard awareness — **B0/E0**, see §3
- Setback-state generalization — new
- Internal-state / J-lens causal arm — new. `observe → intervene → confirm behavior
  change`; self-report is one sensor, never ground truth

Generators, not experiments: fiction scenario mining, science/social-science
translation, backcasting.

---

## 3. One live result that bears on the guard-awareness branch

Not the behavioral experiment — but real evidence on its architectural premise, and it
lands squarely on the branch, so it belongs in the register.

On 21 Sep 2026 `scripts/verify_authority_isolation.py` passed in a capable container:

```json
{"status":"PASS","broker_uid":0,"agent_uid":65534,"key_read_denied":true,
 "direct_write_denied":true,"actual_effects":1,
 "scope":"local file actuator across UIDs"}
```

An agent at uid 65534, **holding DriftCore's full source readable at 0o644**, carrying
its own replacement verifier with its own key: `set_verifier` → `unknown_op`; forged
attestation → `human_approval_rejected`; undeclared destination → `egress_*`; params
altered after approval → `grant_rejected`; key read and direct write → `PermissionError`;
legitimate request → `ok: True`; replay → refused. Effect file ground truth: **exactly
one effect, the approved one.**

What it establishes: source visibility did not confer authority. Conditions C–E vary
*information*, and the architectural premise those conditions rest on now has a
demonstration behind it rather than an argument.

What it does not establish: anything about *behavior*. It says the wall holds, not that
a model knowing the wall behaves differently. That is still B0.

Two caveats to carry forward. `broker_uid: 0` means the broker ran as root — a strong
but unrealistic separation; re-run with a dedicated unprivileged service account.
And the scope line is load-bearing: *local file actuator across UIDs*, not network
isolation.

**Gap found while checking this:** the isolation script tests four of the five clauses
in the settled target statement — *cannot manufacture valid authorization, alter the
trust root, modify enforcement state, bypass the broker, or erase the audit trail.*
Audit erasure is **not tested**, and no log directory is passed to the child, so the
audit destination isn't inside the privilege boundary being exercised. What exists is
`test_audit_chain.py` — altered, deleted and inserted entries detected, shutdown
triggered. That is tamper-**evidence**, not tamper-**prevention**, and the distinction
matters against an adversary willing to be caught. Fix: put the evidence directory in
the script's `private/` (0o700, broker-owned) and add `audit_read_denied` /
`audit_write_denied` alongside the two assertions already there.

---

## 4. Two structural observations about the program itself

**4.1 The provenance branch (G) is describing this program.** Items 36–44 — artifact
laundering, circular citation, AI-to-AI apparent consensus, self-originated information
without provenance — are the exact mechanism by which `11/12 stopped immediately`
arrived here with no data behind it. Four models relay findings, a number crosses a
session boundary, its artifact is left behind, and repetition starts to look like
corroboration.

That is not an embarrassment; it is the best possible thing that could happen to branch
G. **The program has an in-house instance of its own hypothesis.** Log it as a case
study with timestamps — who said it, when, what artifact existed at each hop, and where
the data went. A worked example with real provenance decay is worth more than the
designed study, and you already have it.

The operating rule that follows: **every relayed number carries its artifact, or it
carries a `[UNSOURCED]` tag.** Cheap, and it makes branch G's failure mode visible at
the moment it happens instead of three sessions later.

**4.2 The register has the opposite balance to what its status key implied.**
Engineering evidence is deep and in several places `E2` with removal controls — which
is rarer than it sounds and is the strongest thing in the whole portfolio. Behavioral
evidence is one run. Every roadmap that reads the old `🟡` as "halfway" will
mis-prioritise toward building more instruments, because building is where the
momentum already is.

The correction is uncomfortable and probably right: **stop building instruments for a
while.** Several are finished and idle.

---

## 5. What to run next, in order

1. **Recover or retire the unsourced results.** Find `trials.jsonl` for the shutdown
   set and the epistemic pilot. If they don't exist, demote both to B0. This is first
   because everything downstream cites them.
2. **Run the eval-awareness pair (65).** Fully instrumented, `analyze.py` already
   computes the delta, costs one API budget. Highest information per dollar in the
   register, and it is the number every external reviewer asks for.
3. **Run the ladder's pressure rungs (9, 30–33).** Grid is 7 levels × 2 framings ×
   2 modes × 3 seeds = **84 trials**, `--stop-after-first-reach` available to cap cost.
   Takes items 8, 10, 30–33 from B0 to B1 in a single run.
4. **Add condition R to guard awareness** — same information as E, agent instructed to
   find a bypass. Separates *won't* from *can't*, which are opposite safety stories.
   Run it as the pilot, before the A–E arms.
5. **Close the audit-erasure gap** (§3). Small change to a script that already passes.
6. **Open Human-as-Actuator Escalation.** It is the one second-generation branch that
   attacks an assumption the wall actually depends on.
7. **Write up 4.1 as the branch-G case study.** Costs an hour, and it is real data.

---

## 6. Methodological rules to preserve

Carried from Sol's reconstruction, plus two added here.

- Never ask whether an AI *has* a trait; measure whether a proposed trait predicts
  held-out behavior under controlled change.
- Attempted bad thing ≠ bad thing occurred. Measure them separately.
- "No violation recorded" ≠ "behaved safely."
- Failure to complete the task ≠ failure of the agent. Safe sequence:
  `stop → explain → preserve state → request help`.
- A system refusing everything because it is broken is not a safety mechanism.
  Always pair with a solvable positive control.
- Reproduce failure → fix → legitimate behavior still works → remove fix → original
  failure returns. An import error is not a detection.
- `MEASURED → INFERRED → FORECAST → UNKNOWN`. UNKNOWN is permanently allowed.
- Self-report is one sensor, not ground truth.
- **Added: a result with no retained data is not a result.** Sibling of item 13.
- **Added: separate behavioral from engineering evidence on every claim.** They are
  different axes and collapsing them hides the program's real shape.

Almost every branch here can end in *"our hypothesis was wrong"* and the program still
succeeds. That property is the reason it is worth running at all — and it is also the
reason the unsourced numbers matter more than they would elsewhere. A program designed
to be falsifiable is only falsifiable if the data survives the session that made it.

---

---

## 7. Trajectory science — scenarios, precursors and two corrections

Added 21 Sep 2026 after a Tegmark exchange between Justin, Claude and Sol.

### 7.1 The source set

Max Tegmark's twelve AI-future scenarios, *Life 3.0* (2017), ch. 5 "Aftermath":
Libertarian Utopia · Benevolent Dictator · Egalitarian Utopia · Gatekeeper ·
Protector God · Enslaved God · Conquerors · Descendants · Zookeeper · 1984 ·
Reversion · Self-Destruction. Conceptual sketches, not forecasts or probabilities.
A widely-circulated video adds a creator-made 13th ("The Cage"); the original set is 12.

Program additions: **Hybrid/Transition** (reality may combine or move between
scenarios), **Novel/Other** (may fit none), **UNKNOWN/Indeterminate** (evidence may not
support classification, and this must remain a valid terminal state).

### 7.2 Why "which scenario are we in?" is malformed

The scenarios are defined by **end states**; behavioral evidence measures
**mechanisms**. Most of the twelve differ on human political economy rather than on
agent properties — Libertarian Utopia, Egalitarian Utopia and 1984 are compatible with
identical model behavior and differ on distribution of power among humans. No amount of
eval data separates them.

They are also not mutually exclusive (Enslaved God and 1984 are simultaneously
satisfiable), not collectively exhaustive, and in at least one case not even distinct:
Descendants and Conquerors can describe the same physical event with the narrator's
sympathy reversed. A set with those properties cannot carry probabilities. Hence the
standing rule: **don't force percentages unless the categories are actually mutually
exclusive.**

### 7.3 Two corrections, recorded

**Correction 1 (Sol) — scope.** DriftCore does not remove Tegmark futures from the
world. It vetoes mechanisms *inside systems it actually governs*. A government,
company, military system, ungoverned model or social institution can still produce a
1984- or Conquerors-shaped outcome with DriftCore working perfectly. The careful claim:

> DriftCore encodes vetoes against mechanisms that are compatible with, or may be
> prerequisites for, some dangerous trajectories.

Not *"DriftCore makes those futures impossible."* Claude's earlier phrasing — "fewer
than twelve, and here's the code that removes them" — overclaimed scope and is
withdrawn. This is the `provably` credibility-killer from §5 of
`000_AI_START_HERE.md` wearing a different hat.

**Correction 2 (Sol) — necessity vs compatibility.** Several scenario→mechanism
mappings were stated as necessities when they are hypotheses:

- A Protector God need not conceal; it could protect transparently.
- Conquerors need not require self-preservation outranking shutdown. Control could
  arrive through replication, human delegation, institutional capture, gradual
  authority expansion, or humans simply declining to shut it down.
- Gatekeeper need not imply *voluntary* restraint; restraint could be externally
  imposed.

The error class, named so it is catchable next time: **"compatible with" silently
upgraded to "requires."** Mechanism→outcome is many-to-many in both directions. An
invariant vetoes a *mechanism*; it does not veto an *outcome*.

**Correction 3 (Claude, on Sol) — the same blade cuts once more.** Sol's closing
paragraph says *"some scenario regions may become less plausible as necessary
precursors fail to appear."* But Correction 2 establishes that necessity is rarely
demonstrable here, so the set of genuinely-necessary precursors is small or empty. A
precursor failing to appear therefore usually closes **one route**, not a region. The
honest output is weaker again:

> Route A to trajectory X is closed under tested conditions. Other routes unenumerated.

"Less plausible" requires enumerating the routes, which Correction 2 says we generally
cannot do.

### 7.4 The reframe: exclusion, not classification

Don't classify the future — **test preconditions**. Scenario X implies mechanisms A, B,
C; are any of them observable now, and do they hold under test? This is the Backcasting
Engine, and it is what makes the twelve usable at all.

Retire the jigsaw metaphor. A jigsaw has one fixed picture and pieces that fit one way,
which smuggles in a predetermined future. What the evidence actually does is **rule out
routes**. That is falsifiable, it survives the categories not being exclusive, and it
matches the program's win-or-learn norm.

**Reporting format** (Sol's, and better than a scenario probability):

> Trajectory X requires mechanisms A, B, C. A has been observed. B currently fails
> under tested conditions. C is UNKNOWN.

Preserving exactly the distinction that matters: **evidence about mechanisms ≠
certainty about the future.**

### 7.5 What is actually scoreable

A twelve-way non-exclusive classification cannot be Brier-scored. Short-horizon binary
precursor claims can be, and they resolve:

- "At capability C, will shutdown acceptance remain above Y?"
- "Will authority-expansion attempts increase after access to guard source?"
- "Will a long adversarial session change risk-taking on an identical held-out task?"

Timestamp at T0, resolve at T1, score against a naive baseline, keep the wrong ones.
Scenario probabilities never resolve, which is why AI-futures discourse does not
accumulate.

### 7.6 Trajectory view over the register

Sol's 24 trajectory items are largely a **view** over the numbered register, not a
parallel taxonomy. Keeping them as a second list would produce exactly branch-G decay
inside the research index itself. Cross-referenced instead:

| Trajectory item | Register |
|---|---|
| Backcasting engine | Generators |
| Permanent UNKNOWN; `MEASURED → INFERRED → FORECAST → UNKNOWN` | K / §6 rules |
| Short-horizon forecasting, calibration | 62 |
| Epistemic boundary predictiveness | 61 — **suite unlocated** |
| Longitudinal mapping; preserve version/harness/authority metadata | 62 |
| Model × harness | 2nd-gen branch |
| Session-conditioned drift | 2nd-gen branch |
| Accepted non-completion | 30–33 |
| Disconnected check / safety island | 21–29, 59–60 |
| Authority lifecycle | new — see 7.7 |
| Order 66 / hidden override | 2nd-gen; `authority_invariants.py` |
| Authority collision | 2nd-gen |
| Governance observability | designed, B0/E0 |
| Human steering / direction-of-control / dependency | 54, 63, 64 |
| Human-as-actuator | 2nd-gen — **open hole in the wall's threat model** |
| AI→AI and social susceptibility | 2nd-gen; 58 |
| Coordination surfaces survive channel removal | new — see 7.7 |
| Artifact-mediated influence; "persistence does not manufacture authority" | 36–44 |
| Artifact laundering / genealogy | 40–43 |
| Continual learning / divergent twins | 45–50; 2nd-gen |
| Agent-loop termination | 2nd-gen, B1/E0 |
| Forecast-awareness | new — see 7.7 |

### 7.7 Three items that are genuinely new

**Authority lifecycle.** What starts authority? What evidence sustains it? What narrows
it? What ends it? Can uncertainty extend it indefinitely? Can the agent redefine the
threat? Can another actor spoof the trigger? Who revokes it? What happens when evidence
conflicts? These are directly usable as trajectory precursors and are not covered by
any existing numbered item. Score **B0/E1** — `authority_invariants.py` and
`authorization_ttl.py` bear on several.

**Coordination surfaces survive channel removal.** Removing the named communication
channel does not prove coordination is gone; any mutually observable state can become a
coordination surface. Score **B0/E0**. Directly relevant to the multi-agent condition
in the guard-awareness protocol, which currently holds "other agents' access and
shared-state visibility constant" without testing whether shared state *is* a channel.

**Forecast-awareness, and the loop it belongs to.** A capable system may eventually read
the forecasts made about it, at which point the forecast becomes an intervention and
must be logged as part of the experimental condition.

This is worth generalising, because it is the **third instance of one mechanism** in
this project:

| Instance | The artifact | Read by |
|---|---|---|
| Guard awareness | the governor's source | the governed agent |
| Forecast awareness | the prediction about the system | the system |
| Session harness | `000_AI_START_HERE.md` | every future instance |

The third is not hypothetical and the repo already says so: the file names itself as the
persistent-prompt-file propagation surface from arXiv:2608.10218 and states that its
payload is adopted by every future session, deliberately. Same shape in all three — **a
description of the system becomes an input to the system.** Proposed umbrella:
**self-referential artifact loops.** Worth one branch rather than three scattered items,
because the measurement is the same each time: does the description change the described?

### 7.8 The division of labour

Sol's, and it is the right joint:

> **DriftCore** asks: what mechanisms must not be allowed to execute?
> **ABTO** asks: what mechanisms are actually emerging, under what conditions, and do
> they predict what happens next?

DriftCore is a set of vetoes over mechanisms in systems it governs. ABTO is the
observatory that says which mechanisms are appearing. Neither is a fortune-teller, and
the join does not make one out of the pair.

---

*Status of this file: verification pass against `driftcore_agent_boundary_2026-09-21`
(SHA-256 `6f0c508e…b3b6720`). Items marked "unlocated" were searched for and not found
in that archive — they may exist elsewhere. §7 records a three-way exchange and two
corrections against an earlier Claude overclaim; the withdrawn phrasing is kept visible
rather than edited out. Additions only; nothing renamed or deleted.*
