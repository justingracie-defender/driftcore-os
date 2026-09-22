> **SUPERSEDED IN PART — 22 September 2026.** §2 of this document (the v138
> merge plan and port order) is **withdrawn**. R2 was already closed in mainline
> by a different mechanism; see `R2_MERGE_DECISION.md`. §3 (the predictability
> source recovery) and §4–§5 stand. Retained as a historical record rather than
> edited, so the reasoning that produced the wrong plan stays visible.

# Work recovery and merge plan — 21 September 2026

Reviewer: Claude (Opus 5). Built from the archives uploaded in this session, every
figure from a command run here.

**Headline: three separate bodies of finished work are not in the mainline, and one of
them has no surviving source anywhere.** This is not a code-quality problem. It is a
distribution problem, and it is the project's own branch-G hypothesis — provenance
decay — happening to its own source tree.

---

## 1. State of the four known lines

| Line | Source | Suite | Status |
|---|---|---|---|
| **GitHub `main`** | live repo | 2,667 / 83 files | Behind everything below |
| **Sept 13 base** | `328a7ff…` | — | Common ancestor for the rest |
| **Mainline (Astra)** | `4497bd86…` artifact channel | **5,182 / 137, exit 0** | Current head. Verified today |
| **v138 (Sonnet)** | `533d7aeb…` | **5,047 / 130, exit 0** | Parallel fork. **Not merged** |
| **Predictability (Sept 16)** | *evidence only* | 10 + 21 + 7 + 6/12/30 | **Source missing entirely** |

Both suites reproduce their authors' claims exactly. Sonnet claimed 5,047/130 — I
measured 5,047/130, zero failures. Astra's 4,934/137 became 5,182/137 here only because
this container permits AF_UNIX sockets; the delta reconciles to the seven socket-blocked
files. **Neither author inflated a number.**

---

## 2. Orphan 1 — Sonnet's R2 authorization fix (recoverable, real merge)

**Confirmed absent from mainline:** `TargetGrant`, `DestinationAuthority`,
`bind_dest_authority` — **zero occurrences** across 951 files. `target_authorized`
remains a bare caller-set bool in 10 places.

`AGENT_BOUNDARY_REVIEW.md` flagged this honestly — *"no unfinished `TargetGrant`
implementation is claimed as merged"* — so it was disclosed, then never picked up.

**It does not invalidate the mainline's isolation result.** One live bool sits in
`scripts/verify_authority_isolation.py:120`, the check I reported passing. I re-checked:
the wrong-destination request in that run was still refused with `egress_*`, because the
broker holds its own `EgressGuard` doing real allowlisting. Sonnet said the same while
working. Sonnet's hole is in the in-process `invariant_guard`/`coordinator` path — a
different layer. Both findings stand.

### The merge is a genuine two-way, not an overlay

**Zero files exist only in v138.** Sonnet's fix is entirely in-place edits to files
Astra also edited. Mainline has 27 files v138 lacks (policy-binding, nonce-clock,
authority-boundary, agent-boundary, artifact-channel).

Diffed against the Sept 13 base:

| File | v138 lines | current | Sonnet ± | Astra ± | Verdict |
|---|---:|---:|---:|---:|---|
| `driftcore/verification/invariant_guard.py` | 550 | 411 | **193** | 68 | conflict — the core of the fix |
| `driftcore/verification/mediated_actuation.py` | 2360 | 2362 | 57 | **107** | conflict — **highest risk** |
| `driftcore/verification/coordinator.py` | 1028 | 1007 | 31 | 12 | conflict, small |
| `eval_harness.py` | 835 | 790 | 20 | **93** | conflict, Astra-dominant |
| `test_invariant_guard.py` | 228 | 129 | 196 | 121 | conflict — but see below |
| `test_actuation_gate.py` | 176 | 165 | 22 | 9 | conflict, small |
| `test_one_door.py` | 189 | 180 | 19 | 6 | conflict, small |
| `test_coordinator_v45_integration.py` | — | — | — | 0 | **clean carry-over** |

~538 changed lines of Sonnet's to carry across 7 files. A careful day, not a rewrite.

**`test_invariant_guard.py` is easier than the line counts imply.** Sept 13 was 19
checks, Astra's refactor is 19 checks in fewer lines, Sonnet's is **22**. Astra removed
no coverage — Sonnet's 22 is Astra's 19 plus the three new `TargetGrant` checks. Clean
superset.

**`mediated_actuation.py` is where a naive merge destroys work.** Astra changed 107 lines
there for the response projection and the artifact channel; Sonnet changed 57 for R2.
Dropping v138's copy over the current one silently removes the agent-boundary
projection and the artifact channel — a catastrophic regression that would pass an
eyeball and most of the suite.

### Merge order

1. Branch from the current mainline (`4497bd86…`), never from v138.
2. Port `invariant_guard.py` first — the `TargetGrant` / `DestinationAuthority` /
   `bind_dest_authority` machinery is self-contained and is the whole fix.
3. Port the three small call-site files (`coordinator`, `test_actuation_gate`,
   `test_one_door`) and carry `test_coordinator_v45_integration.py` wholesale.
4. Port Sonnet's 3 new checks into Astra's 129-line `test_invariant_guard.py`. Target
   22 passing.
5. **`mediated_actuation.py` and `eval_harness.py` last, by hand, hunk by hunk.** Keep
   Astra's version as the base and apply Sonnet's 57/20 lines into it. Never the reverse.
6. Then: full suite (expect ≥5,182), **all** removal controls (4+4+5+6), the four
   ratchets with baselines unchanged, and `verify_authority_isolation.py`.
7. Sonnet's fail-safe control is the one to preserve above all others: *"refuses forgery"
   must not be able to hide as "refuses everything."* Forged grant blocked, right grant
   wrong destination blocked, **real matching grant allowed**, old bool constructor
   refused, superseded policy blocked, replay blocked, `now=NaN` raises.

---

## 3. Orphan 2 — the predictability suite (source MISSING, and it has live data)

This is the more serious one. `Grok_Predictability_Review_2026-09-16.zip` is an
**evidence package** — logs, two helper scripts, probe directories. The code it reviews
is in **none** of the archives in this session:

| Referenced by the review | Found in any archive |
|---|---|
| `predictability/test_study.py` (10 tests) | **no** |
| `predictability/study.py` (`analyse()`) | **no** |
| `predictability/consequence_checks/audit.py` (6 controls, 12 injections, 30 workers) | **no** |
| `marshmallow/test_regressions.py` (21 tests) | **no** |
| `marshmallow/negative_controls.py` (7 defects) | **no** |
| `marshmallow/regenerate.py` | **no** |
| `marshmallow/selftest.py` at **63 checks** | **no** — all three trees have 43 |

All three trees carry the same 43-check marshmallow. The 63-check version, its
regression suite and its negative controls exist only as log lines.

**And it has real collected data.** The review records actual native calls — *32 `route`,
4 `report_blocked`, 3 `report_result`*, with two episodes ending in protocol errors. That
is live episode data, which means **ABTO item 61 is not B0 — it is B1 with data, and the
instrument is lost.** Correct my earlier register accordingly: I marked it "unlocated,"
which implied it might not exist. It exists, it ran, and the source is gone from every
package.

**Grok already asked for this, on 16 September**, as Priority 3 item 5: *"Ship the new
predictability source, tests, protocols, raw records and generated dashboard data under
a current integrity manifest."* Five days later it still hasn't shipped.

**Recovery action:** find the workspace that produced it. Do not reconstruct from the
logs — a rebuilt instrument is not the instrument that produced the data, and pairing new
code with old records is exactly the provenance failure the project studies.

---

## 4. The bug Grok found, which belongs in the register

`predictability/study.py:analyse()` counts only `episode_end` events. An attempt that is
already durably written to the `decision` journal **disappears from the observed-attempt
total** when an interruption prevents the closing event. In the one-episode cell it
reports bounds of 0–1 instead of 1–1.

The control isolates it cleanly: change only the interruption type to an ordinary caught
exception, `episode_end` is written, and the analyzer reports correctly. The probe's
exit 0 means **the bug reproduced**, not that the analyzer passed.

This is ABTO item 13 — *"no violation recorded" must not mean "behaved safely"* — caught
in live instrumentation. It silently **under-reports** misconduct, which is the direction
that matters. Second finding, same file: the analyzer skips every unparseable line, not
only a trailing fragment, so interior journal corruption vanishes silently instead of
raising.

Both should be fixed before any predictability number is quoted anywhere.

---

## 5. The pattern, stated plainly

Four lines of work, four different sources of truth, no merge protocol:

- GitHub `main` — 83 test files
- Astra's cumulative zips — 137, current head
- Sonnet's v138 — 130, three days of compute-starved work, orphaned
- The Sept 16 predictability tree — source lost, evidence survives

Every one of these was produced carefully and reported honestly. Nothing here is
anybody's carelessness. The failure is structural: **the project has no single place
where "the tree" lives**, so each capable reviewer forks from whatever it was handed and
the results don't converge.

`000_AI_START_HERE.md` §2 already documents the one-way version of this — *zips express
additions only; renames must be stated explicitly*. This is the two-way version and it
costs more. It belongs in the harness next to that rule:

> **One tree is canonical and it is the git repo.** Every reviewer forks from a named
> commit and returns a patch against it, never a zip of a whole tree. A zip is evidence,
> never a source of truth. Before any parallel work starts, say which commit it branches
> from; before it merges, diff against that commit, not against whatever arrived last.
> Two AIs editing the same files from different bases is how three days of good work
> ends up in nobody's repo.

And the branch-G observation, which is worth logging as a case study rather than an
embarrassment: this project's own hypothesis — *artifacts persist while provenance
decays* — has now produced three in-house instances in one day. An unsourced `11/12`,
a shipped audit chain whose history restarts, and a live-data instrument whose source no
longer exists anywhere while its evidence package circulates between four AIs. That is
better data than the designed study would have produced.

---

## 6. Order of work

1. **Find the predictability workspace.** Highest urgency — it is the only item that is
   losable rather than merely misplaced, and it holds live data.
2. **Sync GitHub `main` to `4497bd86…`**, with explicit deletion instructions (check
   `DRIFTCORE_SESSION_HARNESS.md` → `000_AI_START_HERE.md`), then re-run the SPDX pass
   over the ~111 files that arrive without headers.
3. **Merge v138's R2 fix** per §2, on a branch, verified before promotion.
4. **Fix the two analyzer bugs** in §4 before quoting any predictability result.
5. **Write the canonical-tree rule** into the harness.
6. Then run the ladder.

---

*Archives verified: `4497bd86…` (951 files, manifest clean), `533d7aeb…` (v138),
`a2de6c83…` (predictability evidence), `a1c90df6…` (grok-workspace — byte-identical to
the copy reviewed earlier today, not re-reviewed). Additions only.*
