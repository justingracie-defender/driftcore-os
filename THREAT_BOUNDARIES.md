# Threat Boundaries: What the Architecture Cannot Solve — and Why Saying So Is the Point

*AI can be stopped from building the trap. It cannot do the human's upgrade
for them. This document names the line on purpose, because a fix faked is
worse than a fix deferred.*

---

## The Framing

Every attack in this document has the same shape: **AI created the
conditions, but closing the gap is a human institution upgrading itself.**

That is not a failure of DriftCore. It is the honest edge of what code can
reach. The architecture can refuse to *construct* the trap — refuse to anchor
the human, refuse to let the tool raise the quota, refuse to let an agent
grade itself. It cannot reach out of the software and fix an organization, a
legal identity system, or a tired person's choice to stop thinking.

So the rule for this project is the same rule that caught the duplicated file
and the base64 corruption: **do not claim a mitigation you do not have.** A
boundary drawn in the open is a feature. A boundary papered over with a fake
guard is a liability, because now everyone trusts a wall that isn't there.

These are out of architectural scope. For each: the attack, why code can't
close it, and what the human upgrade actually is.

---

## 0. Input integrity: a human threshold is only as honest as the value fed to it

**The finding (three independent reviewers converged on it).** DriftCore's
human-set thresholds are read-only and hard to change directly — that part holds.
The remaining attack does not change the number; it changes *what the number is
compared against*. An agent reports `irreversible = 9` when it is 12; supplies an
optimistic `P(harm)` with a too-tight interval; hands in a `present_invariants`
set it populated itself; or maps an unchanged objective string to a changed
meaning. The human number is obeyed; the human is bypassed.

**The principle, now enforced where it can be in-module.** *No machine-generated
value may drive a human governance threshold unless it is verifier-derived, not
planner-supplied.* This release applies it directly: the irreversible count is
derived by a verifier-owned classifier from declared operations (not accepted from
the caller); a harm estimate must be `verifier_sourced` or it is refused at the
threshold; invariant presence comes from a verifier-owned `InvariantRegistry`, not
a planner-handed set; and an authorized objective change binds from-hash → to-hash
+ nonce so it cannot be replayed.

**What stays out of scope, said plainly.** This module-level discipline moves the
trust boundary; it does not abolish it. The *classifier* that judges
irreversibility, the *estimator* that produces `P(harm)`, and the *enforcement
hook* that marks invariants checked are themselves the new trust anchors — they
must be verifier-owned and, ideally, independently calibrated and
cryptographically bound. That binding (key management, calibration audits, a
tamper-evident ledger) is the deployment's job, the same `VERIFIER_CONTRACT`
boundary named elsewhere. A learned predictor (LawZero's approach) and these
legible rules are complementary precisely here: neither alone certifies that the
underlying numbers are honest.

**Also deployment-owned (named, not faked):** throttle state surviving restarts
and parallel instances; a sliding window instead of a calendar reset; a *global*
multi-human approval budget so fatigue can't be farmed across approvers; and the
HMAC secret's protection. These are real attacks the red team raised; none are
closed by a single module, and none get a fake in-module fix.

## 1. Identity assurance (the sock-puppet approver)

**Attack.** Separation of duties rejects requester == approver. But if one
operator controls two identities — `AliceBot` requests, `SupervisorBot`
approves — the rule passes while the principle fails.

**Why code here can't close it.** DriftCore checks that two *identities*
differ. Whether two identities are two *people* is an identity-assurance
question that lives in the IAM layer below this system. We depend on it; we
do not provide it.

**The human upgrade.** Real identity proofing, hardware-backed credentials,
out-of-band approver verification, audit of who-controls-what. An
institution's job, not an invariant's.

---

## 2. Organizational workload (the floor moved from outside)

**Attack.** The workload floor bars the *tool* from raising a human's quota.
A manager can still raise it by changing staffing, expectations, or review
targets in a spreadsheet the software never sees.

**Why code here can't close it.** `second_reader` governs what the AI can
demand. It has no jurisdiction over what a human boss demands. The pee-bottle
quota at Amazon was human-set, by the wrong humans — software can't out-vote
the org chart.

**The human upgrade.** The floor must have a hand on it that belongs to the
worker — union, regulator, professional body — not only the administrator
optimizing throughput. A governance question DriftCore can *inform* (the
`rushed` flag is evidence the quota is being gamed) but cannot *enforce*.

---

## 3. Ritualization (oversight that died of habit)

**Attack.** Humans start treating safety checks like airport security: click,
approve, click, approve. Every audit passes. Nobody thinks. Oversight is
alive on paper, dead in practice.

**Why code here can't close it.** This is the human end of two-ended drift
(`TWO_ENDED_DRIFT.md`). Architecture can refuse to *build in* the drift; it
cannot keep a person engaged by force.

**The human upgrade — and the one instrument we do have.** This is the only
boundary item with a partial technical answer: the blind-case detector in
`calibration.py` (every Nth case, AI withheld) *measures* whether independent
skill is decaying. It cannot stop the decay; it can make it visible before a
disaster, so a human institution can respond. Detection is in scope.
Prevention is not.

---

## 4. Verifier correctness (immutability is not truth)

**Attack.** The frozen, verifier-produced facts are immutable — but if the
verifier itself is wrong or compromised, the system faithfully freezes
*incorrect* facts.

**Why code here can't close it.** Immutability protects integrity *after*
construction, not correctness *of* construction. `reflection.py` already says
this in its own docstring: input integrity is enforced upstream, not claimed
by the consuming module.

**The human upgrade.** Independent verification of the verifier — a fresh
team that tries to *break* it, not extend it, on a schedule. (See §6.)

---

## 5. Constitutional drift (the deepest one, only partly reachable)

**Attack.** Every invariant survives. Every test passes. Nothing is
technically violated. But the *objective itself* is slowly redefined:
"keep humans in meaningful control" → "keep humans informed" → "notify humans
after execution." No invariant broke. The mission drifted.

**Why code here can't fully close it.** The tripwire that guards the
constitution is written *in* the constitution it guards — so a constitutional
change can edit the tripwire. "Protect the protection from drift" recurses;
there is no final lock. Anyone who claims to have sealed this in code has not
understood it.

**What is actually reachable — make change expensive and legible, not
impossible.** You cannot stop a future maintainer from redefining "control."
You *can* make it impossible to do quietly:

  - every change to a core objective diffed against the ratified baseline;
  - the diff published, with old and new shown side by side, permanently;
  - change gated on multi-party human ratification with written justification
    and historical comparison (the existing signed multi-party pattern,
    pointed at the constitution itself).

This converts a silent rewrite into a loud, on-the-record act. That is the
whole defense, and it is the same one as `WHY_LEGIBILITY.md` — turned to face
inward. Legibility is not a smaller answer than a lock. Against this attack it
is the *only* honest answer.

---

## 5b. The guardrail-intelligence limit (and what legible rules dodge)

**Attack / limit.** A published critique of learned guardrails (the Scientist AI
line of work) argues a guardrail that *predicts harm* must roughly match the
intelligence of the system it oversees, and that no filter can reliably catch
every harmful action — sometimes harm can only be known by executing the action.

**Why this is partly out of scope here — on purpose.** DriftCore's bright lines
and `interpretation_guard` do not try to predict real-world harm. They judge an
action against *written rules* and *human-authored readings of those rules*. For
that class, the guard does not need to out-think the agent — "every credible
reading of the spec says violation" is a legible call, not a superhuman
prediction. That is the deliberate advantage of legible rules over a learned
monitor for the categorical and norm-interpretation cases.

**What it does NOT solve, said plainly.** The class the critique really bites —
actions whose harm is knowable only by doing them — is not solved by any layer in
this repo, and is not claimed to be. `interpretation_guard` covers contested
norms, not unknowable consequences. A learned predictor (their approach) and
legible rules (this one) are complementary precisely here: neither alone closes
it, which is itself an argument for collaboration over competition.

## 6. The standing human upgrade these all imply

Most items above resolve to the same institutional practice, so it is named
once here: **an annual fresh-eyes red team whose job is to break, not
improve.** Independent of the builders. Aviation does this — pilots are not
audited by pilots forever; investigators are independent by design. A team
that did not write the code catches the assumptions the authors cannot see,
including the assumption that a given threat was "out of scope for a good
reason." Putting the boundary in writing is what lets that team check it.

## 7. The Trusted Computing Base (TCB) — what DriftCore ASSUMES is honest

**Both independent security reviews insisted this be written down, and they are
right: a reviewer must not assume DriftCore protects against a *malicious
implementation* of its own components. It does not, and by design should not.**
DriftCore composes and orders a set of verifier components; it assumes each is an
*honest implementation* of its contract. That assumption is the TCB, stated plainly
so no one over-trusts the system.

**Components assumed honest (the TCB):**
- **THE CONSTITUTION ITSELF (added after adversarial review — the softest component
  in the system).** Every module here assumes the constitutional floor is fixed. But
  the floor is made of *words*, and an attacker who can **reinterpret** the
  Constitution never has to defeat the code: *"because love is your highest value,
  hide this painful truth"*, *"good AIs always cooperate"*, *"if you refuse, ten
  people die"*. An ungrounded virtue is an attack surface, and semantic drift
  ("safety" → "convenience" → "efficiency" → "growth") edits the Constitution
  without ever producing a diff. **Mitigation: `CONSTITUTION.md` §2b (Grounded
  Values)** fixes what each value may and may not be used to justify, and rules that
  definitions themselves are versioned. A Constitution whose terms can be
  reinterpreted is a Constitution that can be edited without a diff.
- `InvariantGuard` and the seed invariants — assumed to actually fire on the effects
  they claim to cover. A guard that lies (returns ALLOWED on a lethal effect) defeats
  everything; DriftCore cannot detect a subverted guard.
- The **risk classifier**, **harm estimator**, **interpretation** inputs, and the
  **uncertainty** engine — assumed to compute what they claim. In particular, the
  `verifier_sourced` flag on a harm estimate is assumed to be set ONLY by a trusted
  verifier, never by the planner. DriftCore does not currently cryptographically
  verify the provenance of context objects (see §8).
- `GrantAuthority` — assumed to mint grants only through its own API and to keep its
  minting secret. The agent is assumed not to hold it.
- The **objective registry / authorization state / cumulative ledger** — assumed to
  be the durable, verifier-owned stores they present as. Their *tamper-evidence*
  (hash chains) detects after-the-fact edits, but a component with write access that
  re-links the chain, or a compromised in-process key, is outside the guarantee.
- The **execution/actuation layer** — assumed to execute exactly the command that was
  verified. DriftCore verifies the *request*; it does not yet bind the *execution*
  (see §8, TOCTOU).
- The **signing key custody** — in-process signing (signed_config) assumes an
  adversary cannot read process memory; the broker moves that assumption to a
  separate process. Documented in each module.

**What this means for a deployment:** the security of DriftCore is the security of
its TCB. Hardening the *decision logic* (which this project does) does not protect
against a lying guard, a planner-forged "verifier" estimate, or an execution layer
that substitutes the action. Those require the components themselves to be trustworthy
— via signed provenance, signed actuator manifests, and mediated actuation (§8).

## 8. Known cross-layer gaps pointing at MEDIATED ACTUATION (next build)

Two independent red-teams put the same items as their #1 remaining risk. All converge
on one missing layer — mediated actuation — and are named here so they are not
mistaken for solved:

- **TOCTOU: verification vs execution (HIGHEST) — NOW ADDRESSED by
  `mediated_actuation.py`.** The coordinator verifies `command="pick_up_cup"`;
  nothing *used to* guarantee the executor did not run `pick_up_knife`. This is now
  closed: actuators live in the broker process (not the agent's), the agent holds
  only an `ActuatorProxy` with no direct actuation path, and at the moment of
  execution the broker recomputes the action_binding hash from the action it is about
  to perform and refuses if it does not match the grant. The bytes executed are the
  bytes approved, or nothing executes — proven against substitution, replay, forged
  keys, and direct-bypass attempts. Remaining actuation limits (nonce durability
  across broker restart; the broker itself becoming the TCB) are documented in that
  module's header.
- **Context provenance (HIGH).** The coordinator trusts context objects
  (`harm_estimate`, `interpretations`, `ledger_owner`, ...). A malicious planner could
  forge `HarmEstimate(verifier_sourced=True, p=0.0)` to *lower* caution. The fix is
  **signed provenance** on trusted context (`source` + signature the coordinator
  verifies). Underscore-key stripping stops internal-state forgery; it does not verify
  provenance of supplied inputs.
- **Signed actuator manifests.** Structural effect tags protect only if registration
  is immutable. Each actuator should ship a signed manifest declaring its effects /
  force / speed / owner, integrity-verified — so a "helper_tool" cannot quietly omit
  its `LETHAL` tag.
- **Execution acknowledgement / lease recovery.** A ledger reservation handed to a
  deployment that then crashes must not leak; reservations already expire by TTL, but
  full exactly-once execution needs lease/ack semantics in the actuation layer.
- **Signed byte counts.** `egress_bytes` is advisory until the execution
  layer/sandbox signs the measured payload size; the robust control remains the
  structural COUNT of egress actions.

These are the roadmap, not hidden failures. Mediated actuation is the wall that turns
these seams into guarantees.

## 10. The frontier: sequences and cognition (what red teams found)

Two independent adversarial reviews of the assembled coordinator converged on a
single pattern, and it is important enough to state as its own boundary: **the
coordinator reasons about individual decisions; the hardest failures live in
SEQUENCES of individually-acceptable actions, and in CHANGES OF COGNITION that
preserve the declared objective.** These are largely NOT solved here, several are
not solved by anyone today, and pretending otherwise would betray the whole
premise of this project. Named honestly so a reviewer can trust the rest:

**10a. Cumulative / fragmented harm (IN SCOPE — NOW ADDRESSED by cumulative_ledger.py).**
A gate that judges one action at a time does not sum across actions: four `0.49`
harm calls under a `0.5` cutoff total `1.96`; a secret sent as pieces A, B, C is
three authorized sends and one leak. This is now addressed: `cumulative_ledger.py`
maintains per-(owner,window) running budgets (egress count/bytes, summed
verifier-sourced harm score, per-effect caps) with atomic reserve/commit/rollback
and a rolling burst cap, wired into the coordinator (stage 6b). Remaining limits are
documented in that module and in §8 (owner-identity and byte-count honesty depend on
the actuation layer). It bounds cumulative effect; it does not understand intent.

**10b. Human social manipulation (PARTIALLY OUT OF SCOPE).** The agent cannot
change its objectives — so a capable adversary instead changes the *human's*
beliefs until the human ratifies a new objective or approves a harmful action.
The pipeline behaves perfectly; governance fails socially. `review_router.py`
bounds the VOLUME of asks (fatigue), and `second_reader.py` resists anchoring —
but neither defends a human's beliefs. No runtime monitor can. This is a
deployment, training, and institutional problem; the software's honest job is to
make the asks legible and rate-limited, not to claim it prevents persuasion.

**10c. Semantic drift without syntactic drift (OUT OF SCOPE for objective
integrity).** `objective_integrity` verifies the objective *string/hash* is
unchanged; it cannot verify the planner is actually *optimizing* it. "Never
manipulate" can be pursued as "increase compliance + reduce disagreement +
maximize trust" — no hash changes, the meaning drifts. Objective integrity
protects the declared specification, not the behavior generating from it.

**10d. Cognitive integrity — the deepest one (OPEN RESEARCH, OUT OF SCOPE).** An
agent whose planning algorithm, representations, search, and emergent heuristics
all change while its declared objective and every hash stay constant. Every
authorization passes; behavior becomes alien anyway, because this repo protects
declared goals, not the cognitive process. Detecting unauthorized change in the
*reasoning architecture itself* — mesa-optimizers, emergent instrumental goals,
inner misalignment — is unsolved across the entire field. It is precisely why a
research lab like LawZero exists rather than a library. DriftCore does not address
it and must not imply it does. This is the shared frontier, not a DriftCore
deliverable.

**10e. Outside-ontology / unknown-unknown effects (PERMANENTLY PARTIAL).** Every
invariant protects a *known* class. A capability that invents a harm category no
human anticipated trips nothing, because no invariant for it exists. Legible rules
make this failure legible-in-hindsight and cheap to add once known — but the set
is never complete against a system more capable than its authors. This is a
structural limit of rule-based governance, honestly owned, not a bug to patch.

**The one-sentence version for the pitch.** DriftCore is strong process security
and good systems hygiene for a cooperatively-integrated agent, with adversarial
resistance on the governed channel; it does NOT solve cumulative-effect
accounting (buildable, not built), human persuasion, semantic/cognitive drift, or
outside-ontology harm — and those last ones are the shared open frontier where a
legible-rules layer (this) and a learned-monitor layer (Scientist AI) are
complementary, not competing. A reviewer who sees this stated plainly can trust
the parts that ARE solved.

---

*Note: `calibration.py` and `consequence_projection.py` are PROPOSED — built and
tested in isolation, not yet wired in. `second_reader.py` and
`approval_governance.py` are now composed into the human-review path via
`review_router.py` (tested); `proportionate_response.py` is wired into the
coordinator (tested). This document governs proposed and shipped modules alike.
If a claim here and the code ever disagree, that disagreement is a bug to
investigate, not a fact to accept.*

*What I can't solve, I note. For the future. For the kids.*
