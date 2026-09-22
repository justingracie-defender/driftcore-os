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

# Current policy review — 21 September 2026

Read **FIELD_REVIEW.md** and **POLICY_BINDING.md** for the new signed policy
artifact binding, migration instructions, external-source comparison and limits.
The current source run reports **4,885 passing checks / 135 files, seven
restricted-socket failures, exit 1**. New policy tests: 22/22; removal
controls: 4/4. The report below records an earlier review and its historical
measurements. `authority-repair.patch` now includes this review as well.

---

# DriftCore: bounded replay review — 20 September 2026

I used earlier failures to look for related defects, compared two repairs in
separate copies, and kept the one that passed the fixed checks and fresh tests.
The result is a concrete improvement to spent-approval storage and test isolation.
No model weights changed, no external model API was called, and no autonomous
background worker or deployment was installed.

The current full suite reports **4,863 passing checks across 134 test files,
seven failed files, exit 1**. This is not an all-green release. The seven files
encounter the same socket restrictions recorded in the preceding review.

## What the video contributed

The [Dream-RSI paper](https://arxiv.org/html/2609.14858v1) describes replaying
recorded experiments to improve exploration policy while keeping the underlying
models and evaluator fixed. Replay reveals recorded outcomes; it cannot supply
results for experiments that never ran.

For this repository, I adapted that into a bounded review: historical failures
suggested hypotheses, fixed regressions compared candidates, and fresh executions
checked the selected repair. This is not a reproduction of the paper's complete
recursive policy-development system or evidence of unlimited improvement.

## What was found and changed

**Routine status checks could reopen a spent approval.** Both nonce backends
discarded expired entries through `len(store)` and `store.stats()` without updating
the clock rollback barrier. In the reproduced sequence, an approval was spent at
time 5,000, housekeeping discarded it at 5,200, and the clock returned to 5,000.
The same signed grant could then be reserved again. Explicit `prune()` tests had
missed these indirect paths.

Cleanup now uses a checked clock sample. The append-log backend records the
high-water value before deletion and carries that sample through loading and
rewriting. Its high-water rename also uses the existing directory-sync helper.
SQLite records the high-water value and deletes expired entries in one transaction.
SQLite membership checks also serialize their clock update with other writers.

**Checking one timestamp and using another was unsafe.** Membership and several
cleanup paths sampled the clock again after checking it. A changing clock could
therefore authorize expiry using a value that had never passed the check. The
repair carries the checked value through each decision. Automatic cleanup that
starts a new transaction checks its own sample.

**Invalid numeric inputs could defeat the intended comparisons.** Both backends
now share validation for retention, maximum grant lifetime and clock skew. These
must be finite built-in integers or floats; booleans and strings are refused.
Retention and maximum lifetime must be positive, skew non-negative, and retention
must cover a finite lifetime-plus-skew sum. Invalid clock readings raise a
nonce-store error before they can authorize cleanup or a spent-state write.
These stricter input requirements are an intentional compatibility change.

**A self-test could leave its deliberately unsafe fixture in the real package.**
The first full run encountered a leftover `_audit_selftest_tmp.py`, causing
`test_one_door_client.py` to fail. An interrupted-test control reproduced this
contamination mechanism in the old fixture. `test_no_egress_bypass.py` now plants
its example in a disposable fixture tree. Its checks of the actual source tree
remain in place; a real planted source bypass still fails.

The exact event that left the probe in the first full run was not established:
that run reported the earlier fixture test passing, and a later sequential replay
did not reproduce the leftover. The evidence distinguishes this uncertainty from
the interruption mechanism that was directly reproduced.

## The improvement cycle

The same 26-test contract, with SHA-256
`def2b2b631f5c41da88c378ec657058da756233577b35190dbf0c54c65869f0e`,
was used throughout candidate selection. Existing release gates and their
baselines were not relaxed.

| Candidate | Fixed contract | Decision |
|---|---:|---|
| Starting repaired repository | 2/26 | Reproduced missing protections |
| A: check the clock at cleanup entry | 16/26 | Rejected as incomplete |
| B: checked samples, atomic cleanup and numeric validation | 26/26 | Accepted after fresh checks |

These are results of the **new targeted contract**, not the old repository's
overall test totals. Ten additional tests cover seeded operation sequences,
boundary values and real child-process termination during SQLite cleanup. All ten
pass. The interruption controls for the audit fixture are separate experiments.

Five protection-removal controls each pass when healthy, fail by assertion when
one protection is removed, and pass after restoration. They cover append-log
housekeeping, SQLite housekeeping, finite clock values, finite retention, and the
checked membership timestamp. Import errors do not count as successful detection.

## What replay did not improve

`verification/dream-review/replay_review.py` compares three diagnostic test orders
using only saved outcomes. Orders use earlier rounds' results, then reveal the
next round's outcomes one at a time. It executes no tests or edits.

| Retrospective diagnostic order | Checks through first failure or exhaustion |
|---|---:|
| Alphabetical | 29 |
| Previous failures first | 29 |
| Housekeeping tests first | 37 |

There was **no observed gain** from changing the order. The existing order was
retained. This small analysis was retrospective; every candidate actually ran the
entire fixed contract. It establishes no measured runtime saving or generalization
to other projects. The null result is retained in `replay-policy-results.json`.

## Measured verification

| Check | Result |
|---|---|
| New fixed nonce contract | 26/26, exit 0 |
| Fresh sequence and process-death checks | 10/10, exit 0 |
| New nonce removal controls | 5/5, exit 0 |
| Previous authority removal controls | 5/5, exit 0 |
| Previous SQLite startup removal control | 1/1, exit 0 |
| Authority boundary tests | 22/22 in final suite |
| SQLite startup tests | 9/9 in final suite |
| Existing nonce tests / conformance | 37/37 and 59/59, exit 0 |
| Marshmallow self-test | 43/43, exit 0 |
| Final official suite | 4,863 across 134 files; seven failures; exit 1 |
| Finite-value ratchet | Exit 0: 182 current findings, no new findings; baseline unchanged |
| Robot-surface ratchet | Exit 1: prior broker baseline drift remains |
| Untested-modules ratchet | Exit 1: prior `audit_story.py` waiver drift remains |
| Claims ledger | Exit 1: 128 tagged, 116 paired, 12 unpaired; 1,549 untagged versus ceiling 1,407 |
| OS isolation acceptance | Exit 77, `ENVIRONMENT_UNAVAILABLE`; not a pass |

The first full run was **4,787/134, eight failures, exit 1** before fixture
isolation. Its log is retained as `release-full-suite.log`; the final result is
`final-full-suite.log`. The wrapper excludes counts from files that exit nonzero.
The 76-check difference is the recovered `test_one_door_client.py` file, not 76
new tests.

The remaining seven failures are `test_aisi_incident_harness.py`,
`test_broker_process.py`, `test_bypass_resistance.py`,
`test_effect_wall_integration.py`, `test_halt_interlock_integration.py`,
`test_implementation_binding.py`, and `test_mediated_actuation.py`.

The final executable snapshot was extracted fresh before its full-suite run.
SHA-256: `33a39b1fc19899b826909371eabfd15f452b384a71f09a4e077c6c4df74cf5fa`.
The deliverable adds reports and evidence; packaging verifies that the tested
source bytes match. Counts describe this snapshot and environment, not all future
versions or machines. Python used here: 3.12.14.

## Use and review instructions

The full ZIP contains the combined September 13 tree and both rounds of repair.
`dream-review.patch` is the incremental source/report diff against the previous
repaired ZIP, SHA-256
`f342417816c99deca78d157a3302974f00af36c617b5f0f6dfcdc8d043f22138`.
`authority-repair.patch` is regenerated cumulatively against the original
September 13 upload, SHA-256
`328a7ffd64035f27779a84362c68ab5e68f36c2a4ed6ebb6420324dea2f045b6`.
Use the matching patch from its project root with `patch -p1`; do not apply both
patches to the same tree. Evidence and manifests are supplied in the full ZIP.

From the project root, run each command separately and preserve its exit code:

```sh
python3 test_nonce_clock_paths.py
python3 test_nonce_clock_sequences.py
python3 scripts/check_nonce_clock_controls.py /tmp/new-nonce-clock-controls
python3 scripts/check_authority_controls.py /tmp/new-authority-controls
python3 scripts/check_nonce_startup_control.py /tmp/new-startup-control
python3 marshmallow/selftest.py
bash scripts/count_tests.sh
python3 verification/dream-review/replay_review.py
```

Control output directories must not already exist. The replay command only
analyzes recorded data and does not substitute for running tests. Raw command
statuses, rejected candidates, source hashes and probe scripts are retained in
`verification/dream-review/`.

For the next bounded cycle, select one concrete question from a failed test or
execution trace; define the expected behavior before editing; keep candidate
copies separate; retain unsuccessful outcomes; and validate any selected change
with fresh cases and a removal control. An improvement search must not grant
itself wider execution authority or rewrite the criteria that judge it.

## Remaining limits

This repairs the demonstrated paths, not every replay or clock problem. Existing
recovery heuristics for corrupted time metadata were not redesigned. Review the
distinction between genuine clock movement and corrupted high-water values before
claiming protection against arbitrary clock control. A trusted time source and
protected storage remain deployment requirements.

SQLite now serializes additional clock-dependent decisions; contention may rise
under heavy concurrent use. No throughput improvement is claimed. The two process
crash tests do not certify every power-loss or filesystem failure mode. The
append-log backend retains its existing single-owner and filesystem limitations.

The earlier R2/R3 deployment limits still apply: protect the broker, signer keys,
configuration and direct actuator paths with a real OS boundary. This work does
not establish universal model honesty, OS isolation in this sandbox, or safety of
every action a legitimate authority might approve.
