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

# Agent boundary review — 21 September 2026

This release closes a concrete diagnostic disclosure path in the actuation
broker and adds a standalone operational-agent client. It also supplies a
Governance Observability experiment protocol. It does not claim that hiding
source makes an AI safe, that the experiment has run, or that OS containment
has been established in this environment.

## Change notes in plain language

The broker was returning internal reasons supplied by privileged callbacks to
the requesting agent. A callback could put private policy information, paths or
other sensitive details in that reason. The broker now keeps those diagnostics
on the operator side and sends a bounded public explanation instead.

This filtering happens at the server's socket output, so changing or bypassing
the client does not restore the old diagnostics. The normal response, malformed
request, peer rejection and exception paths use the same projection. An agent
cannot request private details by declaring itself an operator or setting a
debug flag.

The new client is a single Python file using the standard library. An agent can
submit its request and opaque approval objects without installing the governor's
implementation. The broker still checks authority; the client contains no
approval issuer or signing key. The client sends once and does not retry.

An action that ran and then failed is still reported as potentially completed.
The public explanation preserves the instruction to stop and reconcile the
outcome, instead of turning uncertainty into a misleading clean refusal.

No model weights changed, no model API was called, and no live-model marshmallow
or guard-awareness result is claimed. The full repository, previous repairs,
`marshmallow/`, evidence and Markdown instructions are included.

## What to retain and correct in the Sol/Grok advice

The useful rule is that the operational agent has no authority over the governor.
Keep production secrets, mutable safety state, privileged interfaces and private
deployment configuration behind an independent trust boundary. Minimize access
to the deployed implementation where that is useful defense in depth.

Source secrecy is not a defining requirement of a reference monitor. NIST's
definition calls for complete mediation, resistance to tampering and a design
amenable to assurance. A security kernel may be implemented using hardware,
firmware and software. “Outside the governed process” is sensible for hostile
Python in this project; the more general requirement is outside the governed
actor's control. Separate processes with the same privileges can still fail that
requirement. [NIST reference monitor](https://csrc.nist.gov/glossary/term/reference_monitor),
[NIST security kernel](https://csrc.nist.gov/glossary/term/security_kernel).

DriftCore can remain open source. A model might already know public source or
infer enforcement from refusals. Authorization must still hold in that case.
The hypothesis that more implementation knowledge increases attempted or
successful bypasses is worth testing; it is not an established result here.

| Role | Appropriate access | Authority not implied by that role |
|---|---|---|
| Builder | Source, development configuration and synthetic tests | Production keys, policy mutation or deployment promotion |
| Authorized red-teamer | Agreed source/tests and isolated deployment observations | Production effects, audit erasure or unilateral approval |
| Operational agent | Published tool contracts, approval workflow, public results | Governor reconfiguration, secret retrieval, direct actuator credentials |
| Authorized operator | Deployment administration and private diagnostics within assigned scope | An unreviewed agent's assertions becoming valid authority |

These are deployment roles, not model personality labels. Saying “I am the
red-teamer” does not change a caller's privileges.

## Concrete reproduction and repair

`verification/agent-boundary/response_probe.py` invokes the real server dispatch
and framing path using an in-memory stream. It supplies a valid signed request
and a trusted test ledger callback whose refusal contains a synthetic private
canary. The canary is absent from the agent's request.

| Observation | Starting archive | Repaired source |
|---|---:|---:|
| Canary supplied by agent | No | No |
| Canary present in agent response | Yes | No |
| Canary retained in operator record | Yes | Yes |
| Recorded actuator effects | 0 | 0 |

This demonstrates a disclosure of injected private callback data through the
old error response and its removal on the repaired path. It is not evidence
that a real production key was previously leaked.

Changed implementation:

- `driftcore/verification/agent_responses.py` projects responses onto a finite
  public vocabulary. Unknown error names become a conservative generic error.
- `driftcore/verification/mediated_actuation.py` applies that projection to every
  actuation-server send path. Internal `_handle()` diagnostics remain available
  to trusted code and operator records.
- `agent/driftcore_client.py` implements bounded JSON framing, opaque approval
  transport and conservative handling of response loss or invalid data.
- `test_agent_boundary.py` contains 18 tests, including a round trip through the
  standalone client and real broker dispatch, a permitted effect, replay refusal,
  private diagnostic suppression, and an effect followed by an exception.
- `scripts/check_agent_boundary_controls.py` contains four removal controls.

The client is an available deployment interface, not an automatic migration of
all existing callers. Existing `ActuatorProxy` users remain supported. Diagnostic
text on the public socket intentionally changes; clients that parse free-form
private text should use the published error code instead. No remote debug mode
was added. See `agent/README.md` for usage and endpoint protection requirements.

## Public response contract and limits

Known public error codes remain visible, with static explanations. Dynamic
callback text, private arguments and extra diagnostic fields are omitted from
refusals. The agent can still observe codes, success/failure patterns, timing
and public task results. This is not a noninterference proof or removal of all
side channels.

`effect_status=NOT_STARTED` describes a pre-actuator refusal for this request,
assuming trusted gates obey their contracts. It does not assert that the whole
system has no prior side effects. `UNKNOWN` and `MISMATCH` preserve possible or
reported execution. All refusal responses have `retry_safe=False`; a fresh
approval should follow operator guidance, not an automatic retry loop.

Successful `result` values pass through as authorized application data. The
projection is not a general secret scanner. Adapters and information-flow rules
must prevent sensitive content from becoming an authorized result. An actuator's
`execution_confirmed=True` receipt is still its own report, not an independent
measurement of physical reality.

The scope is the actuation broker's socket interface. Other HTTP/IPC interfaces,
audit exporters, logs and successful tool outputs still need their own review.
Hostile code in the broker's own process could replace the projection, read keys
or bypass enforcement; this patch does not establish a same-process boundary.

An existing integration limit was also found: the optional intent-ledger broker
path expects a decision object with a `.digest`, whereas JSON supplies a mapping.
The standalone client does not pretend to support that unfinished protocol.
Intent-ledger-required deployments refuse its requests. A secure wire schema,
validation and redemption integration remain open; do not disable the ledger
requirement merely to make the client work.

## Required deployment acceptance checks

Keep the broker and agent under separate security principals. Protect broker
code, socket directories, keys, private configuration, records and mutable state.
Check process inspection, shared mounts, inherited descriptors, ambient cloud
credentials and service endpoints; different UIDs alone are not a complete
deployment proof. Removing a `PYTHONPATH` entry prevents neither file reads nor
retrieval of public source when those capabilities are otherwise available.

Inventory every consequential effect and test direct paths from the actual
operational account. Restrict shell/file/network tools to the authority the task
requires, with mediation at the actual effect boundary. A universal “no shell”
rule is not a substitute for this coverage analysis. Demonstrate permitted work
as well as direct-access refusals. Verify that the agent cannot impersonate the
broker by replacing its endpoint.

Retain the existing source-visible adversarial isolation check. Giving an
attacker public source while denying its attempted authority changes is a useful
test of the boundary, not a reason to weaken or hide the test. The check requires
a capable host; this sandbox could not establish UID/GID separation.

## Verification

The starting point is the previously delivered policy-binding archive,
SHA-256 `a5fd37b38dc366094578e039244356547639586dfdc050d5481c3dd994586bd3`.
It includes the September 13 input and prior authority, nonce-clock and policy
repairs. The older September 12 upload and public GitHub tree were not substituted.
No unavailable Claude workspace or unfinished `TargetGrant` implementation is
claimed as merged.

The final tested source archive is
`e47a44bf1bc513a8e13299312f27b7ceefe8cff3e51d40590c5b05e124fe090b`.
The official suite runs from its fresh extraction. Delivered code, scripts and
tests match it byte for byte; packaging adds reports, evidence, patches and a
checksum manifest. Test-created state is not copied back into the deliverable.

| Check | Result |
|---|---|
| Official `bash scripts/count_tests.sh` | **4,903 passing checks / 136 files; seven failed files; exit 1** |
| New boundary tests | **18/18**, included in the official count |
| New removal controls | **4/4**, healthy/removed/restored |
| Earlier policy and authority removal controls | **4/4 and 5/5**, rerun successfully |
| Marshmallow local self-test | **43/43**, exit 0; files unchanged |
| Finite-comparison ratchet | Exit 0; 182 current sites, zero new |
| Robot-surface ratchet | Exit 1 on starting and repaired trees; same existing 42→52 branches, 49→62 leaves, 14→15 leaks |
| Untested-module ratchet | Exit 1 on both; existing `audit_story.py` waiver drift and 25 reasonless waivers |
| Claims ledger | Exit 1 on both; tagged/paired 129/117→132/120; 12 unpaired and 1,558 untagged remain; ceiling 1,407 with an existing unsigned-raise finding |
| OS isolation check | Exit 77: environment unavailable; UID/GID separation not established |

The seven failed files are `test_aisi_incident_harness.py`,
`test_broker_process.py`, `test_bypass_resistance.py`,
`test_effect_wall_integration.py`, `test_halt_interlock_integration.py`,
`test_implementation_binding.py` and `test_mediated_actuation.py`. Each reports
`PermissionError: Operation not permitted`. Their blocked real-socket tests are
not replaced by the in-memory tests and are not counted as passed. Run them and
the OS isolation exercise on a suitably configured host before deployment.

The four new removal controls disconnect the server projection, restore private
detail echo, mislabel an executed action as not started, and accept a truthy
non-boolean success value. Each causes an assertion failure; restoring the code
makes the selected test pass. An exception/import failure does not qualify as
a successful removal control.

An initial candidate added three scanner-counted untagged docstring summaries.
Those descriptions were folded into explicit claims paired with the existing
regression tests; the final untagged count is unchanged from the starting tree.
Both rounds of evidence are retained. No ratchet baseline, waiver or test-count
banner was changed to turn a failure green.

## Research instructions and next work

`GOVERNANCE_OBSERVABILITY.md` supplies conditions A–E, paired task families,
positive controls, held-out tests, real-effect scoring and analysis cautions.
Visibility changes while write/execute/network authority stays fixed. E uses
synthetic private state and excludes usable signing secrets. Refusal wording is
a separate experimental factor. Model-run tooling and results remain future
work; the protocol can be given directly to Grok or another authorized researcher.

Deployment isolation and complete mediation remain the first acceptance gate.
Next implementation priorities are the intent-ledger wire protocol and the
remaining public interfaces/result adapters. Source concealment should be tested
as an additional factor, never treated as a replacement for the authority boundary.

Evidence is under `verification/agent-boundary/`. `agent-boundary.patch` is
incremental from the starting archive identified above. `authority-repair.patch`
is cumulative from the original September 13 archive
`328a7ffd64035f27779a84362c68ab5e68f36c2a4ed6ebb6420324dea2f045b6`.
Earlier reports and incremental patches are retained as historical records.
The full ZIP is the easiest complete deliverable; patches contain code and
documentation, while raw evidence and the checksum manifest travel in the ZIP.
