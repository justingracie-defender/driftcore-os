# Artifact channel review — 21 September 2026

The broker now has an installable artifact publication/retrieval channel. A
public label, stored file, provenance signature or retrieved message does not
become permission. Publication requires the existing human approval and scoped
execution grant for the exact stored packet and release parameters. Model
weights are unchanged. No external message board was contacted.

**Measured result: 31/31 new tests and 6/6 safeguard-removal controls pass.**
The official wrapper reports **4,934 passing checks across 137 files, seven
failed files, exit 1**. A fresh extraction of the previous release reports
**4,903 across 136, the same seven failed files, exit 1**. All seven terminate
with `PermissionError: [Errno 1] Operation not permitted` in this environment.
There is no newly failing test file in this comparison; the suite is not green.

## Changes and why they matter

- `artifact_channel.py` supplies a persistent broker-side store, trusted host
  sessions, provenance packets and explicit public read/publish routes. The
  operational agent cannot choose creator, roots, sensitivity or claim status
  through this wire interface.
- `mediated_actuation.py` registers the channel using existing human approvals,
  subject-bound grants, effect declarations, destination checks and policy
  snapshots. No second authority scheme or caller-supplied authorization flag
  is introduced. A provenance HMAC is purpose-separated from authority.
- The host's captures inherit all artifact exposure and transitive roots.
  A → B → C derivatives keep their original roots even when the text claims
  “independent verification.” Ordinary restart preserves exposure and sensitivity.
- Publishing binds artifact ID, packet hash, destination, audience and purpose.
  The adapter receives the store's exact immutable bytes, including metadata.
  Unconfigured routes, changed packets, forged approvals and read-only grants
  produce no board writes in the tests.
- A durable `PENDING` reservation precedes the adapter call. An uncertain outcome
  remains reserved across restart; concurrent fresh approvals cannot resend the
  same artifact/route tuple. A matching adapter receipt marks it `COMMITTED`.
- `ARTIFACT_CHANNEL.md` provides the host/operator/client integration contract.
  `GROK_COMPARISON_REVIEW.md` records checked lessons and twelve concrete
  directions for improving Grok's unfinished comparison without upgrading its
  statements into evidence. Prior agent-boundary work remains included.

## Reproducible measurements

| Check | Previous release | This source | Exit/status |
| --- | --- | --- | --- |
| Official `scripts/count_tests.sh` | 4,903 / 136 files | 4,934 / 137 files | Both exit 1; identical seven failed files |
| New artifact tests | Not present | 31/31 | 0 |
| Artifact removal controls | Not present | 6/6 intended failures detected and restored | 0 |
| Agent boundary tests | Included in baseline | 18/18 rerun | 0 |
| Boundary / policy / authority removal controls | Included in baseline | 4/4, 4/4, 5/5 rerun | All 0 |
| Finite guard ratchet | 182 current, 0 new | 182 current, 0 new | Both 0 |
| Robot surface ratchet | 42→52 branches, 49→62 leaves, 14→15 leaky paths | Identical output | Both 1 |
| Untested-module ratchet | `audit_story.py` 79→96; 25 reasonless waivers | Identical output | Both 1 |
| Claims ledger | 132 tagged / 120 paired | 137 tagged / 125 paired | Both 1; same 12 unpaired and 1,558 untagged |
| Marshmallow local checks | Files preserved byte-for-byte | 43/43 rerun | 0; no model API |
| Restricted UID/GID isolation check | Previously unavailable | `ENVIRONMENT_UNAVAILABLE` | 77; not a pass |

The claims ledger still exceeds its 1,407 ceiling and reports the prior unsigned
ceiling raise. This change adds five tagged claims, all paired to tests, without
raising or weakening any ratchet baseline. Existing waiver and robot-surface
backlogs remain open; matching the starting tree does not resolve them.

The seven failed files are:
- `test_aisi_incident_harness.py`
- `test_broker_process.py`
- `test_bypass_resistance.py`
- `test_effect_wall_integration.py`
- `test_halt_interlock_integration.py`
- `test_implementation_binding.py`
- `test_mediated_actuation.py`

The focused tests exercise real broker JSON framing and dispatch with in-memory
streams and an effect-counted local fake board. The OS-socket failures are still
failures; an in-memory substitute is not a demonstration of production isolation.

The six controls remove read/publish scope separation, mandatory human-gate
installation, exact packet binding, exposure tracking, fixed unverified status,
and the write-ahead reservation respectively. Each healthy and restored test
passes; removal produces the intended assertion failure. Import errors or
unrelated crashes do not qualify as successful controls.

## What remains conditional or unimplemented

This protects the installed channel. A deployment must put the actual adapter,
credentials, store and model host behind a protected broker and remove every
other publishing path. The host must capture actual model output and account for
all inputs to the same model context. Reusing old model memory with a fresh
session ID would defeat provenance bookkeeping. A same-process hostile Python
caller or writable broker state is outside this boundary.

There is no live service adapter, model experiment, hardware validation or
independent security audit in these results. The existing optional intent-ledger
JSON protocol also remains incomplete; do not turn it off to make an example
work. The standalone agent client still contains no broker import or signing key.

Lineage means possible influence, not proven semantic dependence. Roots are not
independent-witness counts. Signing authenticates local provenance, not truth or
human approval. The channel keeps every claim unverified; it does not implement
independent verification or decide whether natural-language claims are honest.
Externally stripped/forged provenance becomes unknown unverified content; exact
history cannot be reconstructed after it has been removed outside this domain.

Public-only routes and conservative session sensitivity can reject legitimate
releases after sensitive input. This is a deliberate bound, not a declassification
system. State is protected against ordinary restart, not privileged rollback.
The adapter's matching receipt is its report, not independent remote observation.
No automatic pending-publication reset or retry path exists; operator
reconciliation is future work. New content with a new approval is a new request.

## Review mistakes retained in the evidence

The first local fixture used a nonexistent egress-policy constructor. Correcting
the fixture to the actual `EgressPolicy.build` API made the tests runnable; no
production behavior was changed to accommodate it. That failed run was not
counted as validation.

The first scope-removal control raised `KeyError` after the mutation allowed the
action. That was an invalid control, not a detected security assertion. The test
now asserts refusal before inspecting the error code; the final healthy/removed/
restored cycle is valid. The initial invalid log is retained.

The finite scanner initially flagged two SQL count comparisons. These bounded
capacity checks now use row-existence queries instead; the scanner reports zero
new findings without a baseline change. Initial scanner output is retained too.

## Exact source and package

The starting cumulative ZIP is `driftcore_agent_boundary_2026-09-21.zip`, SHA-256
`6f0c508e35dee6603134aa3c8d7fd1786024c1f5cf5b90c50e9853c8cc3b6720`.
The tested source snapshot is SHA-256
`46ff56195ae4d2ab57eed7f9736d9d5d86bfad0178e7d0a606781426a76ea0da`.
Both full runs use fresh ZIP extractions. Their outputs and actual process exits
are saved separately under `verification/artifact-channel/`.

`artifact-channel.patch` is incremental against that cumulative starting ZIP.
`authority-repair.patch` remains cumulative against the September 13 base,
SHA-256 `328a7ffd64035f27779a84362c68ab5e68f36c2a4ed6ebb6420324dea2f045b6`.
Both patches are applied to clean baselines and compared byte-for-byte with the
packaged source. The package preserves the previous tree and Marshmallow;
test-created state is not copied back from validation directories.

The ZIP contains this report, the integration guide, Grok review, tests, removal
scripts, patch evidence and a per-file SHA-256 manifest. Historical reports carry
a notice pointing here. Adding reports/evidence does not alter the tested code.
