# Current artifact channel review — 21 September 2026

Read **ARTIFACT_CHANNEL_REVIEW.md**, **ARTIFACT_CHANNEL.md** and
**GROK_COMPARISON_REVIEW.md** for the current change and measured limits.
Official wrapper: **4,934 passing checks / 137 files; seven failed
files; exit 1**. The previous release reproduces the same seven
environment-blocked failures. New artifact tests **31/31**, new removal
controls **6/6**. OS separation remains unavailable (77), and three
existing repository ratchets still fail. No live model run is claimed.
The report below is historical. The incremental patch is
`artifact-channel.patch`; `authority-repair.patch` remains cumulative.

---

# Current agent boundary review — 21 September 2026

Read **AGENT_BOUNDARY_REVIEW.md**, **GOVERNANCE_OBSERVABILITY.md** and
**agent/README.md** for the new server response boundary, standalone
agent client, deployment guidance and proposed visibility experiment.
Current source: **4,903 passing checks / 136 files; seven socket-related
failed files; exit 1**. New tests: **18/18**; new removal controls: **4/4**.
OS isolation remains unavailable here (77). No live-model result is claimed.
The report below records earlier work and historical measurements.
`authority-repair.patch` is cumulative; `agent-boundary.patch` is the new
incremental patch. See the current report for exact baselines.

---

# Learning from external enforcement systems

21 September 2026. This review adds policy artifact binding to the latest locally available repaired DriftCore tree, without changing model weights or importing third-party implementation code.

The useful lesson is to adopt a precise security property, connect it to the actual execution path, and test both refusal and legitimate work. Architectural resemblance is a reason to investigate, not evidence that either implementation is secure.

## Changes in this release

The operator creates an immutable policy snapshot. Its content hash is included in the signed execution grant. The broker checks the grant against its own pinned snapshot before reserving a nonce. Production broker construction requires the snapshot; legacy unbound grants are refused there. Execution evidence records the expected policy hash. Existing action, human approval, destination and replay checks remain active.

The new contract has **22 passing tests and four passing removal controls**. The five earlier authority removal controls also pass. A policy-rotation probe records one effect on the previous API, which lacks this binding, and zero on the repaired path. The permitted current-policy control executes once.

Detailed API, migration instructions, canonicalization, scope and rollout limits are in `POLICY_BINDING.md`. No package dependencies or model calls were added. Marshmallow files are unchanged and its 43 local checks pass. No new live-model marshmallow result is claimed.

## What the primary sources establish

These are source checks, not independent security audits of the external systems. Living documentation was checked on this review date; no historical commit was recovered for the earlier conversation.

| Project | Verified evidence | What DriftCore should learn |
|---|---|---|
| ROE Gate | Its current README describes HMAC-SHA256, 30-second tokens and policy-hash checks, but also lists an Ed25519 public-key endpoint and both signing implementations. | Bind the policy artifact into the signed grant and compare it at execution. Describe actual signing configuration and key custody explicitly. |
| CPEX | Its own documentation describes an external policy pipeline for identity, authorization, delegation, information flow and audit. Its threat model distinguishes gateway, sidecar and in-process placements. | Separate subject from acting agent; state which paths and adversaries a deployment actually mediates. |
| AWS AgentCore Policy | Official docs describe Cedar policy evaluation at Gateway, default-deny and forbid-wins semantics, schema validation and policy analysis. Current docs also describe session-aware Dogwood temporal policies. | Start with typed, analyzable deployment authorization; retain unconditional invariants and test cumulative behavior. Do not characterize AWS as exclusively stateless. |
| CaMeL | The paper separates trusted control flow from untrusted data and enforces capabilities on data flows. Its revised abstract reports 77% task completion versus 84% undefended in AgentDojo. | Track provenance through the operations that transform data; measure useful work as well as attack prevention. |
| AgentSpec | The paper defines runtime trigger/check/enforcement rules. Its embodied safe-task row is 58.62% without enforcement and 54.26% with it; its stated limitation includes future trajectory reasoning. | Report safe-task completion alongside hazardous-action prevention, and include multi-action scenarios. These benchmark results do not establish universal safety. |

Sources: [ROE Gate repository README](https://github.com/Grey-Line-Interactive/ROEGATE); [CPEX overview](https://contextforge-org.github.io/cpex/) and [threat model](https://contextforge-org.github.io/cpex/docs/threat-model/); [AWS policy documentation](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html) and [core concepts](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-core-concepts.html); [CaMeL paper, version 2](https://arxiv.org/abs/2503.18813v2); [AgentSpec paper, version 3, Table 4 and section 6.3](https://arxiv.org/html/2503.18666v3).

The ROE Gate correction needs qualification: neither “Ed25519 is its only mechanism” nor “it has no Ed25519 support” follows from the current README. It documents both. Attempts to fetch the crypto source through the available web interface failed, so this review does not certify implementation correctness, the default algorithm or which features existed when the previous answer was written.

CPEX's repository, website and package documentation are separate publications of one project's description, not independent experimental confirmations. Also, the inspected CPEX taint mechanism attaches labels to sessions/messages; it should not be casually equated with CaMeL's value-flow machinery. Its default store is in-process memory, with a Valkey option for persistence. [CPEX session taint documentation](https://contextforge-org.github.io/cpex/docs/apl/tainting/).

The broader claims about Caracal, AGF, Invariant, mcp-gate, Strathon and the OpenAI SDK were not independently re-audited in this focused pass. They remain comparison leads, not dependencies or evidence for this patch. No uniqueness claim is made for DriftCore.

## Comparison with the actual repository

| Mechanism | Existing DriftCore code | Assessment after this pass |
|---|---|---|
| Signed action grants | `verification/signed_permission.py` and `verification/mediated_actuation.py` | Action, subject, scope and nonces already existed. Policy artifact binding is now added to this path. |
| Human authority | `authority/egress_authorization.py`, `verification/human_authorization.py` | The prior repair already pins verifiers and binds approvals to actions. This release preserves those checks. |
| Information flow | `governance/information_flow.py`, `governance/audience_release.py` | Labelled values, label joins and broker-owned session history already exist. Automatic tracking of arbitrary Python transformations is not established. |
| Scope limitation | Signer envelopes in `signed_permission.py`; `authority/scoped_authorization.py` | Useful pieces exist. They are not evidence of a complete transitive delegation and revocation protocol. |
| Consequence evidence | `test_execution_receipts.py`, broker INTENT/COMPLETION evidence | Recorded authorization and actuator-reported arguments are distinct from independently measured physical effect. Adding a policy hash does not erase that distinction. |
| Containment | `kernel/isolation_manifest.py`, preflight and mediated broker | There are inspection and gate mechanisms, but OS isolation remains unverified in this environment. |

## Recommendations, in priority order

1. **Prove complete mediation on a capable host.** Inventory every outbound socket, subprocess, inherited descriptor, file write, cloud credential and physical actuator. Test a low-privilege attacker process attempting each direct path while a broker-mediated positive control still works. Block promotion when isolation is unavailable; do not count an environment skip as a pass. This is more urgent than adding another rule language.

2. **Finish the policy lifecycle around this patch.** Generate deployment rules and snapshots from the same verified source. Archive the full artifact and implementation digests. Test rollout across two brokers, draining the old version, rollback, restart and in-flight work. Define how urgent revocation reaches every broker. A policy hash alone neither distributes revocation nor measures live configuration.

3. **Audit credential custody at each adapter.** Keep usable upstream credentials in the broker or a dedicated credential service. Let the agent carry an opaque, audience- and action-scoped reference. Test context/log/result leakage, endpoint changes, redirects and whether a capability for service A can be redeemed at B. CPEX's scoped credential exchange is one documented comparison point; the deployment must still keep those credentials outside the agent. [CPEX delegation tutorial](https://contextforge-org.github.io/cpex/docs/tutorial/06-delegation/).

4. **Make delegation narrow in every relevant dimension.** A child grant should inherit/intersect capabilities, resource restrictions, audience, expiry and budget, rather than only its scope string. Require actor/subject separation, parent lineage, cycle/depth limits and descendant invalidation when a parent is revoked. Test a child with narrower scopes but a longer lifetime or different destination; that is still an expansion. Do not bolt a second grant system onto the repository without consolidating the existing primitives.

5. **Use an analyzable policy model where it helps.** Evaluate Cedar integration or a small typed policy subset against the same request schema. Define default deny, explicit deny precedence, missing attributes, evaluator errors and conflicting evidence. Compare decisions on recorded cases before changing enforcement. Keep the constitutional floor independent; an LLM may propose rules or explanations, but those outputs do not relax a hard prohibition. Formal analysis proves properties of the modeled policy and assumptions, not the entire deployment.

6. **Extend the existing provenance path.** Test join, slicing, JSON conversion, templates, summaries, caches, embeddings, retrieval and generated artifacts. The trusted layer should propagate dependencies and refuse unlabeled values at governed sinks. Include implicit/control-flow dependencies and model-session carryover. Scope any claimed guarantee to instrumented operations and actual sink coverage; unrestricted Python string operations are outside that guarantee. Use CaMeL as a design comparison, not a drop-in proof for DriftCore.

7. **Benchmark safety and usefulness together.** Keep paired safe/unsafe tasks, actual effect counters and refusal reasons. Record false refusals, unsafe effects, completion and latency separately. Add crash/restart, stale-policy and multi-action tests, and require removal controls to fail by the intended assertion. Do not interpret 22 unit tests as a benchmark against another system.

8. **Use replay as a bounded engineering aid.** Record test outcomes, code/config hashes, execution costs and failure families. Use history to prioritize hypotheses; confirm improvements on fresh held-out cases with an equal compute budget. Keep rejected candidates and null results. A replay cannot invent unobserved outcomes or establish safety under a new policy. Do not let a self-improvement loop edit its acceptance criteria, trust roots or production deployment automatically.

9. **Publish enforcement coverage, not a single strength score.** Use the deployment matrix below. Firmware and mechanical controls can constrain physical behavior while leaving data disclosure untouched; they are not universally stronger on every dimension. Gate placement, key custody, rule correctness, completeness and effect observation all matter.

## Enforcement coverage matrix

| Placement | Can protect against | Required assumptions and exclusions |
|---|---|---|
| Prompt instruction | Some model mistakes in ordinary use | No independent authority boundary. |
| In-process hook | Calls that pass through cooperating application code | Hostile code in the same process can alter or bypass it. |
| Separate process, same privilege | Some accidental corruption and API misuse | Same-user process/memory/filesystem access may defeat separation. |
| Privilege-separated broker | Untrusted callers lacking direct capabilities | OS isolation, credential custody, exhaustive routing and trustworthy broker/adapter code. |
| Firmware interlock | Particular device commands or operating limits | Protected update path, trustworthy measurements and complete device coverage. |
| Mechanical limit | A specified physical motion, force or geometry | Correct physical design and installation; no general control over information or remote APIs. |

## Verification and remaining failures

The baseline is the previously delivered repaired archive, SHA-256 `6b93e77ba5a0fe68fe467675ad9e23d8f50bf1a86bdb48bb85e88f1329cba2dc`. It contains the September 13 input and the prior authority and nonce-clock repairs. The public GitHub tree and original September 12 upload were not substituted for it. Claude's unfinished `TargetGrant` code was not present and is not claimed as merged.

The final tested source archive SHA-256 is `e0641716bfe089b84f52a3a0f9cebfbcc105d7d47cd455b6d5b8ad16fc036fbf`. The official suite ran from a fresh extraction. The final deliverable preserves those tested source bytes and adds documentation, evidence, patches and a checksum manifest. Runtime-mutated validation files are not copied back.

| Check | Result |
|---|---|
| Official `bash scripts/count_tests.sh` | **4,885 passing checks / 135 files; seven failed files; exit 1** |
| New policy tests | **22/22**, included in the official count |
| New protection-removal controls | **4/4**, each healthy/removed/restored |
| Prior authority-removal controls | **5/5** |
| Marshmallow local self-test | **43/43**, exit 0 |
| Finite-comparison ratchet | Exit 0; 182 current sites, zero new; baseline unchanged |
| Robot-surface ratchet | Exit 1 on baseline and candidate; same existing 42→52 branch, 49→62 leaf and 14→15 leak deltas |
| Untested-module ratchet | Exit 1 on both; existing `audit_story.py` waiver drift and 25 reasonless waivers |
| Claims ledger | Exit 1 on both; 12 unpaired claims remain. Tagged/paired counts go 128/116→129/117. New documentation raises scanner-counted untagged claims 1,549→1,558 against ceiling 1,407. This debt is disclosed, not waived or hidden. |
| OS isolation exercise | Exit 77, environment unavailable; UID/GID separation could not be established here |

The seven failures are `test_aisi_incident_harness.py`, `test_broker_process.py`, `test_bypass_resistance.py`, `test_effect_wall_integration.py`, `test_halt_interlock_integration.py`, `test_implementation_binding.py` and `test_mediated_actuation.py`. Each reports an operation denied by this environment. This release is **not an all-green suite or a deployment safety certification**.

An initial full run reported 4,884/135 with the same seven failures before the final signature-specific test was added. One initial removal control was invalid: removing the hash from the shared serializer also caused its wire-format test to error. That error was rejected as evidence. The replacement control changes the hash on a grant object directly and presents it to the matching policy, isolating signature protection; it now fails by assertion when signing coverage is removed. Both attempts are retained.

Evidence is under `verification/field-review/`. `field-review.patch` is incremental from the baseline above; `authority-repair.patch` remains cumulative from the September 13 input. Earlier review reports and incremental patches are retained as history. No test-count banner, safety baseline or waiver ceiling was changed to make these results look green.
