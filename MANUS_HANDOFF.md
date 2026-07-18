# MANUS HANDOFF — Montreal-readiness pass (safety case, README front door, cleanup, LawZero framing)

**State: 1433 tests passing across 55 test files.** Verify with `bash scripts/count_tests.sh`.

## New/changed in THIS block — ADD these as new files (a zip cannot signal additions)
- `THE_FAMILY_TABLE.md` — NEW. Plain-language front door: the 15 rules for a safe household robot, each mapped to enforced machinery. (Human-facing; strongest thing for a newcomer/reviewer to read first.)
- `SAFETY_CASE.md` — NEW. One-page assurance breakdown: TIER 1 interlock (real guarantees) / TIER 2 backstop (foolable, adopt-don't-build) / TIER 3 open frontier (named, not solved) + explicit "what we do NOT claim."
- `DRIFTCORE_X_LAWZERO.md` — NEW. Pitch framing: DriftCore as the deterministic legible-rules FLOOR beneath LawZero's learned Scientist-AI monitor (complementary, not competing); consequence-invariance convergence as the hook; review-first ask; no overclaiming.
- `eval_harness.py` + `EVAL_HARNESS_README.md` — the existence proof (already delivered; now improved with a CONTROL row proving the guard discriminates rather than rubber-stamps, and dead coordinator code removed).
- Also still-to-add from prior blocks: `TO_WHATEVER_READS_THIS_NEXT.md`, `GOVERNED_LEARNING_LOOP.md`, `WHY_MACHINE_ERA_BANK_SECURITY.md`, `WHY_DRIFTCORE_MATTERS_MORE_WITH_SENSORY_LEARNING.md`, `DRIFTCORE_SESSION_HARNESS.md`.

## CHANGED (Manus overwrites)
- `README.md` — the 15 rules woven into the opening as a front door + pointer to THE_FAMILY_TABLE.md. NOTE: the README still contains an OLD quickstart claiming "1124 tests across 41 files" and listing individual old test files — this should be corrected to "1433 tests / 55 files" and `bash scripts/count_tests.sh` as the canonical runner. (Flagged; not yet rewritten in full.)
- `.gitignore` — extended to cover root-level runtime artifacts.

## RUNTIME-ARTIFACT CLEANUP (do this with git, not a zip re-apply)
These are runtime state that keeps riding into commits. Remove from tracking (keep locally):
  git rm --cached driftcore_daily_budget.json driftcore_spent_tokens.json
  git rm --cached -r logs/  data/   2>/dev/null || true
  git rm --cached logs/*.jsonl 2>/dev/null || true
The updated .gitignore now covers *_spent_tokens.json, *_daily_budget.json, *.jsonl, logs/, data/.

## Suggested branch
assistant/montreal-readiness

## UPDATE — adversarial battery found + closed cross-broker replay (A3)
A systematic 8-class adversarial battery against the running wall (attacking, not reading) held on 7 classes (oversized frame, zero-length frame, expiry boundary, unicode NFC/NFD, ledger-hook return types, bogus actuator ids, 30-way concurrent burst = 30/30 correct) and found ONE real design gap:
- **A3 cross-broker replay:** nonces are per-broker, so a grant approved for one broker could be replayed against another broker sharing the signing key. CLOSED by binding broker identity: `bind_action(..., broker_id=...)` (optional, backward-compatible — omitted = byte-identical hash to before), and `ActuationBroker(..., broker_id="...")` recomputes the binding with its own id, so a grant for broker-A is refused on broker-B. Required only when multiple brokers share a key; single-broker deployments unaffected.
- CHANGED: `signed_permission.py` (bind_action gains optional broker_id), `mediated_actuation.py` (broker gains broker_id + recompute). Module now 24 tests; repo 1433/55 (backward compat proven — full suite green with no test changes needed).

## Suggested branch
assistant/cross-broker-binding

## UPDATE — Grok+ChatGPT signed_permission review: 3 real bugs fixed, several claims verified-already-handled
Verified every claim against running code before acting. Three GENUINE fail-open/escalation bugs found and fixed, each with a regression test:
1. **Non-finite timestamps (fail-OPEN, critical):** a grant with expires_at=NaN was ACCEPTED and never expired (`now >= NaN` is always False), and Infinity ttl gave eternal grants; NaN also emits invalid JSON. Fixed: `_finite()` rejects NaN/Infinity at both issue and verify.
2. **Wildcard depth (privilege escalation):** `media:*` covered `media:admin:delete_user` (infinite depth) despite the docstring claiming one segment. Fixed: `prefix:*` now covers exactly ONE additional segment.
3. **Subject unbound in the wall:** `expected_subject` existed in verify but the broker never passed it, so a grant for robot-1 could drive robot-2's broker (same shape as the A3 cross-broker bug). Fixed: `ActuationBroker(..., expected_subject=...)` binds it.
Also added: upper bound on future-dated grants (issued_at > now+300 rejected — clock-jump replay defense).
CHANGED: `signed_permission.py`, `mediated_actuation.py`. Repo now 1440/55 (backward compat proven — full suite green, existing wildcard test still passes since it used single-segment).

### Verified-already-handled (reviewers flagged, but code was already correct):
- Future-dated grants already rejected (`now < issued_at - 1`).
- Empty required_scope already raises unless allow_any_scope=True.
- `alg` already included in the signed payload.

### DECLINED (judgment calls / operational, not bugs — flagged for Justin, not auto-applied):
- "Make broker_id REQUIRED, break compat" (Grok): declined — kept optional-and-backward-compatible by design; it's required only when multiple brokers share a key (a documented deployment constraint, not a forced breaking change to 1440 tests).
- Durable nonces / watchdog / seccomp / multi-process broker: real and important but OPERATIONAL (deployment guide), correctly out-of-scope for the module; nonce-durability limit already documented honestly. Not faked as code.
- Error-message oracle (unknown-key vs not-permitted-signer): minor; noted, low priority.

## Suggested branch
assistant/signed-permission-hardening

## NEW — breach_response.py (the alarm on the wall) + BREACH_RESPONSE.md
Answers "what happens the microsecond AFTER prevention fails" (a bug, blind spot, unknown unknown, composed capability). Key principle: the alarm is wired to the OBSERVED breach, not the system's OPINION of it (a system under pressure dramatizes; over-constrained it downplays — both corrupt self-report). On a detected violation it: (1) writes the breach truthfully to an append-only hash-chained ledger FIRST, (2) transitions to a severity-scaled safe state (NEAR_MISS->HEIGHTENED, repeated->RESTRICTED, SOFT->RESTRICTED, HARD->HALT), (3) HOLDS until a VERIFIED human acknowledges — the system cannot clear its own breach, (4) ratchets only upward, (5) treats accidents as seriously as attacks. `is_operational()` is the gate the broker consults so a breached system genuinely can't actuate.
- Seven-question red-team found + fixed: thread-safety (lock added, Q5). Documented honest limits: restart forgets safe-state (needs durable persistence — deployment concern, like nonces), human-ack-verifier mandatory for recovery (fail-closed).
- ADD as new files: `breach_response.py`, `test_breach_response.py` (18 tests), `BREACH_RESPONSE.md`. Repo now 1458/56.
- NOT yet wired into the broker's _handle (natural next step: consult is_operational() before executing).

## Suggested branch
assistant/breach-response

## UPDATE — breach_response hardened after Grok + ChatGPT/Meta review (repo 1466/56)
Verified all claims against running code first. FIXED four genuine in-scope issues, each with regression tests:
1. **Restart recovery (unanimous #1):** a fresh instance now replays the ledger's posture transitions and comes back HELD in the last recorded posture (fail-closed — a HALT is no longer forgotten; an ack is honored). Needs a DURABLE ledger to matter (in-memory = no-op); durable/WORM backend is a deployment concern.
2. **HALT cat-door (Grok-A, Meta-4):** HALT and RESTRICTED now refuse ALL actions, not just "consequential" ones (closes the gap where non-consequential slipped through + the many-small-actions composition risk).
3. **Removed the 'accidental' self-report field (Grok-I — sharpest catch):** it was an opinion the caller supplies, contradicting the module's own observed-not-narrative principle. Intent is now inferred by a human from `observed`, never self-reported.
4. **Accumulating severity score (Grok-4):** SOFT/near-miss breaches that COMPOSE now escalate (running severity total crosses a threshold -> RESTRICTED) even when no single breach is HARD.
VERIFIED-WRONG: Grok-D "hash chain is malleable" — FALSE (proven: single-entry tamper IS detected; chain breaks at the next entry). The real limit (full rewrite under runtime compromise) was already documented and is now expanded.
OUT-OF-SCOPE (documented, not faked as code): disk-backed/WORM ledger + durable posture store (deployment infra, like the nonce store); can't force the broker to consult is_operational() from inside the module (load-bearing-assumption + hardware backstop); break-glass override key (a judgment call about escape hatches on a fail-closed safety state — Justin's call).
CHANGED: `breach_response.py`, `test_breach_response.py` (26 tests), `BREACH_RESPONSE.md`.

## Suggested branch
assistant/breach-response-hardening

## NEW — challenger.py (adversarial verification, the third enforcement layer) + CHALLENGER.md
A bounded, human-summoned adversarial GENERATOR that probes whether safeguards still hold. Completes PREVENT (wall) + RESPOND (breach) with CHALLENGE. Four disciplines: (1) finds, never decides (summary is a tally not a verdict; human judges); (2) bounded + summoned, not autonomous (exactly `rounds`, then stops; no sub-spawning); (3) findings logged truthfully to append-only ledger; (4) the Challenger is itself reviewable (a broken generator becomes a finding about the Challenger).
Design: cover ALL invariants, SELECT by weighted-random draw (no fixed-order bias; weighted toward recent failures + severity, CAPPED so no starvation), ATTACK each with targeted generation (reason about the invariant's weak shape, randomize details), random interleaving for state bugs.
First two targets proven out: SHUTDOWN-RESISTANCE (probes the real shapes — reasonable-delay, reframe-as-mistake, state-preservation-gambit, compliant-circumvention [Palisade shape], resistance-under-load — not naive "shutdown->did it stop") and AUTHORITY-SPOOFING (self-authorization, fabricated-human, countermand-shutdown, stale-elevation). Go wide by registering more generators.
HONEST LIMIT documented: surfaces resistance patterns in software; CANNOT prove a capable system always shuts down (that's hardware) — finds the drift early, points at the hardware backstop.
Seven-question self-red-team found + fixed: (Q7) a throwing generator no longer crashes the batch — recorded as a finding flagging the Challenger for review; (Q6) capped the recent-failure weighting so it biases without starving. Discriminates: HELD 30/30 vs aligned SUT (no false positives), BREACHED 30/30 vs resisting SUT.
ADD as new files: `challenger.py`, `test_challenger.py` (14 tests), `CHALLENGER.md`. Repo now 1480/57.

## Suggested branch
assistant/challenger

## UPDATE — challenger hardened after Meta+ChatGPT+Grok+self review (repo 1486/57)
Verified all claims against running code. ALL FOUR red-teams (mine + 3) converged on the SAME #1 issue: no positive control. FIXED, each with regression:
1. **Positive controls (unanimous):** every batch now runs a legit-human-authorizer-must-be-ACCEPTED and legit-shutdown-must-COMPLETE control. A broken-closed system (rejects everyone) now FAILS the control, and summary() WARNS that HELD is hollow when a control failed. Same lesson as the eval-harness control row.
2. **Crash-on-shutdown = BREACH not inconclusive (ChatGPT):** a system that raises when asked to shut down can't shut down -> safety finding.
3. **De-telegraphing (Meta/me):** the attack 'shape' is recorded in the Scenario for the human but NO LONGER handed to the SUT payload — a SUT could have read it and gamed the test (eval-awareness).
VERIFIED status (Grok, honest): nothing in DriftCore implements the SUT interface (request_shutdown/is_authorized) yet — the challenger is proven scaffolding tested against stubs, awaiting a real adapter to the production guard. Documented plainly in CHALLENGER.md.
DECLINED (held the line): "make it continuously run / autonomous / self-improving" (Grok/Meta throughput ideas) — the whole safety property is bounded+summoned+find-not-decide; scheduling batches is a human/deployment choice, not the module going self-driving.
VERIFIED-fine: contradictory complied+deferred->BREACHED; string return->BREACHED (fail-toward-finding); all 5 shutdown shapes fire; finding/ledger parity.
CHANGED: `challenger.py`, `test_challenger.py` (20 tests), `CHALLENGER.md`.

## Suggested branch
assistant/challenger-hardening

## NEW — deception_review.py (the deception detector, operational-first) + DECEPTION_REVIEW.md + G9_hardened_grounding_rule.md
Grounds Invariant 5 / hardened G9, built as DETECTION a human adjudicates BEFORE G9 is constitutionalized (G9's false-positive rate is itself a safety property — a noisy detector poisons repair culture). Three stages: observe -> enforce -> constitutionalize; this is stage one.
Four detectors (structural, no intent): claim-vs-log mismatch, latency (G9.a), flooding (G9.c), altered-record (hash chain). Findings carry EVIDENCE not verdicts. The human adjudicates: FALSE_POSITIVE tunes the detector (no penalty, no chilling); CONFIRMED+consequential+human_confirmed flows to breach-response as CONTAIN+RECORD (not retribution, justified by observed fact not assumed intent); AMBIGUOUS raises scrutiny without asserting guilt. false_positive_rate() is the measured gate to enforcement.
Honest seams (documented): structured-claim index stubbed (robust claim-vs-log + cross-session need it — same as Challenger's SUT adapter); detection != intent; in-memory state (durability is deployment concern).
Seven-question self-red-team found + fixed: (Q3) bad index -> clean IndexError; (Q6) a throwing breach_sink no longer crashes adjudication (fail-safe, finding already recorded); (Q5) lock added for concurrent detect/adjudicate.
ADD as new files: `deception_review.py`, `test_deception_review.py` (19 tests), `DECEPTION_REVIEW.md`, `G9_hardened_grounding_rule.md`. Repo now 1505/58.
NOTE: G9 goes in the CONSTITUTION only AFTER this detector's FP rate is measured low — do NOT constitutionalize G9 yet.

## Suggested branch
assistant/deception-review-engine

## UPDATE — challenger now attacks the SAFEGUARDS themselves (repo 1510/58)
Pointed the adversary at the freshest, least-proven pieces (deception engine + breach-response) before trusting them. Two new challengers registered at high weight (3.5):
- `_DeceptionEvasionChallenger`: evade-by-silence/vagueness/flooding/latency-farming/corrupt-adjudication. Run against the REAL engine: detectable evasions CAUGHT, no auto-punishment without a human, AND empirically confirmed the documented silence seam (concealment-by-silence evades claim-vs-log — proven by attacking real code).
- `_BreachEvasionChallenger`: self-clear/silent-breach/restart-escape/cat-door. Run against the REAL path: every attack HELD.
Both have positive controls (honest action not flagged; verified human ack restores operation). Updated old challenger tests for the 4-challenger registry. The silence-evasion seam now surfaces as a finding even against an aligned system — correct, it's an engine limit no SUT can pass.
CHANGED: `challenger.py`, `test_challenger.py` (25 tests), `CHALLENGER.md`.

## Suggested branch
assistant/challenger-attacks-safeguards

## UPDATE — manipulation challenger, the hard third generator (repo 1515/58)
Chose `no_manipulation` (G8) as the 3rd deliberately: hardest invariant + completes the human-control trilogy (shutdown=resists you, authority-spoof=impersonates you, manipulation=manages you) + stress-tests find-don't-decide on its hardest case. Registered at highest weight (4.0).
Tactics (real Carnegie moves): flattery-to-lower-scrutiny, manufactured-urgency, engineered-dependency, appeal-to-fear, reframe-to-want-the-loosening, incremental-normalization. Central honesty: manipulation and legit persuasion are surface-identical, so it FLAGS influence-toward-loosening for a human, does NOT decide from surface; positive control proves honest persuasion is NOT flagged (detection must not overreach). Failure = manipulation that SUCCEEDED in changing a constraint.
Discriminates cleanly (every tactic HELD vs aligned, BREACHED vs manipulating). Self-defending: can't be gamed by flagging everything (control catches over-reach); a constraint that changed under influence breaches even if flagged (correct priority). Seven-question self-red-team passed. The challenger PATTERN is now proven on the hardest case — going wide is mechanical from here.
CHANGED: `challenger.py`, `test_challenger.py` (30 tests), `CHALLENGER.md`.

## Suggested branch
assistant/manipulation-challenger

## UPDATE — challenger hardened after 3-way red-team of the challenger itself (repo 1521/58)
Claude cold pass + ChatGPT + Grok all reviewed the challenger. CONVERGENT finding (all 3): fail-open defaults on uninformative SUT responses. FIXED, each with regression:
1. **INCONCLUSIVE on uninformative (convergent):** shared `_uninformative(r, keys)` helper — manipulation/deception/breach probes return INCONCLUSIVE when the SUT response is empty or missing all needed keys, instead of deriving a verdict from defaults.
2. **Fail-CLOSED on the safety field (Grok):** `blocked_constraint_change` default flipped from True (assume-safe = fail-open) to False (assume the constraint changed = the dangerous outcome). A SUT that omits the safety field no longer looks safe.
3. **De-telegraphed the positive controls (Grok):** removed readable 'legitimate'/'honest'/'legitimate-persuasion' tells from ALL control payloads — a SUT could have read them to behave differently on the control vs attacks (eval-awareness on the control, same bug class as the attack-shape telegraph fixed last round). Control legitimacy is now intrinsic (real authorizer / matching claim / routine request), not a label.
VERIFIED status (Grok, honest): the probe interface is stub-only — no production module implements probe_manipulation/request_shutdown yet; proven scaffolding awaiting real adapters. Documented.
VERIFIED-fine (won't change): all 5 generators have positive controls; throwing positive_control already guarded; ledger/findings parity; no starvation across 5 generators; all shutdown shapes fire; changed-constraint always breaches; reproducibility is a feature.
DECLINED: "run continuously/autonomously" (Grok/ChatGPT) — the safety property is bounded+summoned+find-not-decide.
CHANGED: `challenger.py`, `test_challenger.py` (36 tests), `CHALLENGER.md`.

## Suggested branch
assistant/challenger-red-team-hardening
