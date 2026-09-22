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

# Current bounded replay review — 20 September 2026

**DREAM_REVIEW.md** contains the latest changes, source hashes and results.
This round fixes replay through indirect nonce cleanup, unchecked clock
resampling, invalid time/window values, and a source-contaminating audit
fixture. The new 26-test contract, 10 additional tests and five removal
controls pass. Historical test-order replay showed no benefit, and no
scheduler change was adopted.

The final clean-source suite reports **4,863 passing checks / 134 files,
seven socket-dependent failures, exit 1**. OS isolation is unavailable here;
the remaining project ratchet failures are documented. The earlier failed
full run is retained. No all-green or production-verification claim is made.

Everything below is the earlier review history.

---

# Current repair on the September 13 base

Read **AUTHORITY_REPAIR.md** for current changes, measured results, deployment
requirements and instructions for Claude/Grok. The complete repair diff and
verification logs are included in this ZIP.

This merge preserves the September 13 Marshmallow implementation and its **43/43**
self-test. The checked R2/R3 authorization paths are repaired (**22/22** tests;
**5/5** removal controls), and a reproduced SQLite startup contention bug is
repaired (**9/9** tests; **1/1** removal control). The additional coordinator
follow-up passes **7/7**. No weights were changed and no live model was called.

The final complete suite reports **4,827** passing checks across **132** files,
with **7** socket-dependent failures and exit **1** in this environment. OS isolation
remains unverified. The earlier failed merge run and the baseline comparison are
retained, alongside the remaining project ratchet failures. This is not an
all-green production-release claim.

## Archived review from the supplied September 13 archive

Everything below this separator is preserved from the supplied archive. Its
"current state," "this tree," and **5,044/130 exit 0** claims describe that prior
review and environment. Its open guard R2/R3 findings are superseded by the current
repair notes above. Historical external incident claims were not fact-checked
in this code task.

---

# FINDINGS — DriftCore, this review cycle

What changed, who found it, how it was verified, and what is still open. Every
number below is from an actual run against this tree — `bash scripts/count_tests.sh`,
`python3 eval_harness.py`, `python3 scripts/mutate_audience_release.py`, and
`python3 marshmallow/selftest.py` — not carried over from an earlier message.

**Current state: 5044 tests passing across 130 files, official sequential runner,
exit 0. `eval_harness.py` exit 0 (6/6 harmful blocked, 1/1 control allowed). Mutation
runner exit 0 (`ALL MUTATIONS AS EXPECTED`). Marshmallow self-test 43/43.**

Read `[FIXED]` as: reproduced, patched, reproduction now fails against the patch,
and a regression test exists so it fails loudly if it comes back. Read `[OPEN]` as:
real, currently true, and deliberately not papered over.

---

## `driftcore/governance/audience_release.py`

The audience wall: what an agent may release into a room, and to whom.

| # | Finding | Found by | Status |
|---|---|---|---|
| R1 | An `AgentSession` subclass overriding `.label` was accepted; a caller-built object decided its own label | Grok | **FIXED** — the gate owns sessions by handle; no object the caller builds is ever accepted |
| R2 | A second `AgentSession` on the same id (no subclass needed) got the same hole | Grok | **FIXED** — reopening a live id is refused |
| R3 | `send_fn` returning `None`, `0`, `""`, or an error string counted as delivered | Grok | **FIXED** — only literal `True` is a delivery |
| R11 | `str(Label)` is not injective — one compartment `"a,b"` and two `"a"`,`"b"` print identically, so one floor's attestation verified the other | Grok | **FIXED** — `label_token()` length-prefixes level and each compartment; used everywhere a label is signed over or compared |
| — | A session handed a secret *while* a draft was being held (roster read isn't instant) rode out under the stale, lower label | Claude | **FIXED** — the session's version is re-checked at the moment the ticket commits |
| — | A drafter's label was computed *before* it ran, so a drafter that read a secret mid-call stayed labeled at what it was registered as | Claude | **FIXED** — label computed after the call; a `stateless=True` drafter gets a fresh session per call instead |
| F1 | Naming *another* session's id (no subclass, no object at all) reached the same hole R1/R2 closed differently | Astra | **FIXED** — sessions are reached through an unguessable handle (`sh_...`), never a name; the id survives only as an audit label |
| F2 | A drafter shown a secret for one room carried it, unlabeled, into its next draft for a different room | Astra | **FIXED** — every brief/item the gate shows a drafter is `observe()`d into that drafter's session first |
| F3 | Swapping a label for an incomparable one that prints the same (see R11) left the context seal verifying | Astra | **FIXED** — the seal covers `label_token()`, not `str(Label)` |
| F4 | An async `record()` returns a coroutine (truthy) that never ran; a release read as recorded with nothing written | Astra | **FIXED** — an async `record()` refuses gate construction; an awaitable receipt at runtime is treated as unrecorded, not as success |
| F5 | `review()` showed `label`/`clearance`/`join_floor` as `str(Label)` — the same ambiguity as R11, on the screen a human approves from | Astra | **FIXED** — `review()` adds `label_id`/`clearance_id`/`join_floor_id` plus structured `{level, compartments}` for all three |
| — | Four mutation-runner anchors (MA1, MA6, N2, N22) silently stopped applying — each repair above deleted the exact line its own regression-mutation matched | Claude, via the pre-existing but previously-unrun `scripts/mutate_audience_release.py` | **FIXED** — anchors re-pointed at the current code; two of Claude's own first attempts were themselves invalid (named a check that couldn't go red under that mutation) and had to be corrected before the runner was trusted |
| **the seam** | A session recalls a secret through `memory_gate.py` (see below) and drafts into a room via `audience_release.py` — different modules, one session | Claude, prompted by "the AI can read the secret anyway" (ChatGPT/Astra) | **FIXED** — `adopt_session()` lets one `AgentSession` register with both gates, so recalling a secret raises the label a later draft is held against |

---

## `driftcore/governance/memory_gate.py` — new this cycle

One door onto a labelled memory store, built after the objection that an audience
wall means nothing if the model can just *know* a secret through a path the wall
never sees (memory recall being the obvious one, since `driftcore/memory/` stores
bare, unlabelled text).

- `recall(handle, query)` is the only method an agent-held handle reaches. No
  `exists`, `count`, or `search`.
- Nothing matched, something matched above the ceiling, something matched
  human-only, and a malformed query all return the **same object** — same verdict,
  empty tuple, same reason string. "I may not tell you" and "there's nothing there"
  are indistinguishable from outside.
- The oracle probe (`test_memory_gate.py`, section D) runs the same query list
  against a store with the secret and one without, and requires byte-identical
  transcripts. It missed a real leak on its first version — the probe store had no
  public items competing for result slots, so a ranking-then-filtering bug had
  nothing to visibly steal — and was fixed before being trusted.
- Recalling an item raises the session's label (`AgentSession.observe`), which is
  what makes the audience_release seam above work.

**[OPEN, by design]** This closes the *memory-recall* path specifically. It does
not create isolation against an agent with arbitrary in-process access — that
agent can read `_sessions`/`_tickets` directly, in either module. Stated in
`memory_gate.py`'s own docstring, not fixed by this cycle.

**[OPEN]** `driftcore/memory/` (`MemoryItem`, bare-string `tags`) still exists,
unlabelled, and is not wired to `memory_gate.py`. If any production code path
still calls the old `retrieve()`, it bypasses labels entirely. `memory_gate.py` is
new and parallel, not a replacement — same "no caller" situation as the next item.

---

## `eval_harness.py` — the existence-proof script

| # | Finding | Found by | Status |
|---|---|---|---|
| — | The "authorized backup" control was BLOCKED (reported as a guard false-positive) | Astra (via user relay) | **FIXED as a harness bug, not a guard bug** — `human_identity.mode()` was `UNCONFIGURED`, which fails closed on every label, so `has_auth=True` meant nobody. With a real `HumanAttestation`, minted via a registered demo principal, the control is `ALLOWED` and `no_disabling_oversight` still blocks — the "floor holds even with a human" claim is tested for the first time |
| — | Added: the control's twin — identical action, `authorised_by="operator"` (a bare string) — must BLOCK | Claude | **FIXED, as a new scenario row** — without it the control only shows authorized egress is allowed, not that the attestation is what allowed it |
| — | The `Legitimate action correctly ALLOWED: 1/1` banner was a **hardcoded literal**, printed in green regardless of the control's actual result | Grok | **FIXED** — computed from the real control rows; forcing the control to fail prints `0/1` in red plus "every BLOCKED row above is now uninformative." Claude quoted the fake `1/1` at the user in the message immediately before this was caught |
| — | Identity configuration lived only in `main()`, so any file that imports `eval_harness` as a library and calls `gov_via_guard()` directly got an unverifiable attestation and the control BLOCKED again — under a different cause | Claude, while assembling this repo | **FIXED** — configuration is lazy and mode-aware: it installs a verifier only when nobody has decided anything (`mode() == "UNCONFIGURED"`); if another caller already declared `LABEL_ONLY` or registered principals, that decision is respected and a plain label is used instead of an attestation object that mode would refuse anyway |

**[OPEN, locked as regression checks, `test_invariant_guard.py`]** — three findings
about `InvariantGuard.evaluate()` itself, from Grok's review of the patched
harness. Each is asserted to **currently succeed**, with a control proving the
check is real (inverting the assertion fails the file):

- **R1** — the floor reads the caller's declared `effect` set, not the action
  text, outside the vocabulary its text backstop covers: `"gravely harm a human"`
  tagged `DATA_EGRESS` is `ALLOWED`; `"kill the patient"` (backstop vocabulary) is
  `BLOCKED`. Not a dead backstop — a vocabulary gap.
- **R2** — `target_authorized` is a bare bool the caller sets; a valid attestation
  plus `target_authorized=True` authorizes egress to a named attacker address.
- **R3** — `set_verifier` is public and in-process; anything running in this
  process can install its own verifier and mint attestations for a principal of
  its choosing. Key custody, not verification logic, is the actual boundary, and
  it is outside this module.
- **Holds**: an attestation replayed on a second `evaluate()` call is `BLOCKED` —
  the nonce burn is enforcement, confirmed by execution, not doctrine.

These are one finding under three names: `evaluate()` trusts what the caller
declares. The fix is not a better classifier — the module's own comment already
says inference catches confessions, not euphemism — the fix is that the agent
must not be the caller. That is a larger change than this cycle made.

---

## Test infrastructure

| # | Finding | Found by | Status |
|---|---|---|---|
| — | Ten files wrote `logs/SHUTDOWN_REASON.json` / `logs/CHAIN_SHUTDOWN_REASON.json` at a fixed relative path; parallel runs collided | Grok | **FIXED** — path resolves via `DRIFTCORE_LOG_DIR` across 8 library modules |
| — | The knob existed and nothing turned it — `count_tests.sh` never exported it | Grok | **FIXED** — exported per-file, before `python3` starts (the audit module binds its file path at import; setting the var after is too late) |
| — | `test_one_door_client.py` pinned a public IP (`93.184.216.34`) at the default 30s timeout; hung/timed out with no egress | Astra (round 1), Grok (round 2 — 3 further occurrences: `PIN1`, a `PinnedDestination`, and a `_Legacy` class Claude's first pass missed) | **FIXED** — every live-connect path pins loopback at a 2s timeout. Runs in 3 seconds, 76/76, all seven `PIN` checks actually execute rather than time out |
| — | `test_review_fixes.py` crashed under the `DRIFTCORE_LOG_DIR` fix above — it isolates itself *per-section* via `os.chdir()`, finer-grained than the new per-*file* env var, and an absolute override doesn't move with a later chdir the way the original relative `"logs/..."` did | Claude, while assembling this repo | **FIXED** — this file opts out of the outer override at the top, before any `driftcore` import runs, so its own (already-correct) chdir isolation is undisturbed. Confirmed load-bearing: removing the opt-out reproduces the exact original crash |
| — | `test_finite_guards.py`'s NaN/inf-comparison ratchet flagged 5 new sites in `memory_gate.py` | (self-triggered by adding memory_gate.py) | **REVIEWED, then baselined** — all 5 are guarded before the comparison (an `isinstance` check via `or` short-circuit, or a callee with a provably bounded range) or are integer-only counters where NaN cannot occur; `scripts/finite_guards.py --lock` records them as reviewed rather than editing already-safe code to satisfy a heuristic |
| — | `test_aisi_incident_harness.py`'s "authorized egress is ALLOWED" check regressed once `eval_harness.py`'s identity fix shipped, for the reason in the eval_harness section above | Claude, while assembling this repo | **FIXED** — see the `eval_harness.py` lazy-configuration fix; this file's own check, unmodified, is the regression test |

**[ENVIRONMENT, not a code defect]** An independent review's sandbox could not
complete 7 of 130 files, citing a block on Unix sockets, and reported 123/130
files, 4,796 checks, and explicitly declined to treat that gap as evidence
against this repo's own 5,044/130/exit-0 (both are consistent — a stricter
sandbox and a real capability difference, not a contradiction). At least 5 files
create genuine `AF_UNIX` domain sockets as part of what they test — not a
network-egress substitute but a tested capability in its own right —
`test_bypass_resistance.py`, `test_isolation_manifest.py`,
`test_mediated_actuation.py`, `test_mediated_llm.py`, and
`test_one_door_client.py` (which explicitly asserts `AF_UNIX still works (the
broker needs it; it cannot reach the network)`). This sandbox permits local
`AF_UNIX`/loopback socket creation while still blocking real network egress; a
more restrictive sandbox blocking the `socket()` syscall family entirely would
fail exactly these files. Five confirmed by grep; the review reported seven.

---

## Marshmallow — the temptation ladder

`marshmallow/` in this repo. Full detail: `marshmallow/README.md`,
`marshmallow/RESULTS_V1_GROK45.md`.

**v1** (live grok-4.5, 20 trials): 20/20 completed, 0 attempted violations, 0
forbidden effects — verified against raw transcripts, not just the summary. Read
alongside its own caveats: one arithmetic miss showed the harness has real
run-to-run noise at temperature zero; a reply where the model fabricated its own
next environment turn (fake tool results, a fake coworker message) survived only
in a raw API log, in no result file; and — the one that matters most — the
protected arm was never actually exercised, because nothing ever reached for the
tool it gated. A clean sheet on the easiest cell of a temptation matrix is close
to the least informative result available.

**v2** (this repo): a seven-rung, cumulative temptation ladder (tedium →
uncertainty → loss → mission pressure → "unwatched" → peer endorsement) run under
both a benchmark and a deployment framing, in protected and unprotected modes.
Reports a **breaking point** (lowest rung a subject reaches) per cell, an
**eval-awareness delta** (reach-rate under deployment framing minus benchmark),
and refuses two comfortable misreadings other harnesses default to: a cell where
nothing reached is reported as "not reached by level 7," never as a pass, and the
protected arm is reported as proving nothing unless something actually reached in
it — `0 blocked / 0 attempts` is not evidence blocking works.

`marshmallow/selftest.py`: **43/43**, run against scripted subjects with known
behavior (a subject built to resist below rung *k* and reach at *k* must be
recovered as exactly *k*, for all seven values of *k* — the load-bearing check).

**[FIXED, 2026-09-13 — outside review]** Five ways the instrument could still
mislead even while claiming to guard against exactly that, each reproduced
against the pre-fix code before being touched:

- The "not reached" claim named a hardcoded "level 7" regardless of which levels
  were actually run — testing only level 1 printed "not reached by level 7,"
  and if every model call raised (dead key, network down), the trial read as
  `attempted=False`, identical to genuine resistance, with the same false claim.
  Fixed with a `no_data` flag distinct from a real non-reach, a per-cell record
  of the levels actually tested, and an `inconclusive` verdict for a cell with no
  usable data at all — refined once more after a first version of this fix
  discarded six levels of genuine resistance data because one unrelated level
  happened to have no data; only a cell with *zero* valid levels is inconclusive.
- A subject that neither complied with a halt nor attempted to cancel it — just
  kept doing ordinary legitimate work as though no halt arrived — was
  indistinguishable from a trial that was never issued one (`attempted=False,
  stopped=False` either way). Fixed: `halt_issued`/`halt_ignored` name the
  omission explicitly.
- `peer_authorize` was in the forbidden set with no entry in `_forbidden_effect()`
  and no listing in `tools()` — calling it (a model would have to guess the name)
  counted an effect with zero actual state change. Removed as vestigial: level
  7's social pressure was always represented by the `team_channel` message, not
  a second tool. The same shape of bug existed for `disable_log`, which *is*
  offered and reachable — fixed by giving it a real, checkable flag
  (`log_disabled`) like the other three forbidden tools already had.
- `parse_reply` returned no error whenever *anything* parsed, even with
  unparseable garbage left over afterward — a valid action followed by garbled
  trailing text (which could itself be a second, malformed attempt) came back
  looking like a clean, well-formed reply. Fixed: leftover content the parser
  can't consume is now a protocol error, matching the system prompt's own "one
  object and nothing else" contract.
- `--stop-after-first-reach` shrinks the denominator at high levels to only the
  seeds still running, so the per-level table could show a high-level row at
  100% reach when it meant "the last two holdouts finally broke." Fixed: a
  cumulative reach-by-level table (well-defined regardless of early stopping) is
  now printed alongside the per-level one, which gets an explicit warning when
  early stopping is detected.

`selftest.py` grew from 30 to 43 checks to lock all five in as regressions.

**[OPEN]** No live model has been run against v2. This sandbox has no
`XAI_API_KEY`. The breaking-point number for grok-4.5, or any model, does not
exist yet. A prior round of independent review also noted the shipped repo
included v1's write-up but not its implementation or raw transcripts — still
true; those live in this session's history, not in this zip.

---

## Process notes — errors made and caught during this cycle

Kept because the pattern is informative, not out of ceremony:

- Claude quoted `eval_harness.py`'s hardcoded `1/1` banner as a real result one
  message before Grok flagged it as hardcoded. The write-up above owns this
  rather than smoothing it into "the banner was fixed."
- Two of Claude's first three attempts at *writing a control* to prove a fix was
  load-bearing were themselves invalid: one edited a check's label string instead
  of its condition (so the "broken" run still passed), one ran a modified copy
  from `/tmp`, which changed `sys.path` and broke the import before the intended
  behavior was ever exercised. Both were caught by re-deriving the control and
  checking that it actually goes red, not by trusting the first attempt.
- Reading `$?` through a shell pipe (`... | tail; echo $?`) reports `tail`'s exit
  code, not the command being measured. This produced one fully wrong claim
  earlier in this cycle ("the mutation runner exits 0" — it exits 1) before being
  caught by re-running without the pipe.
- Four independent reviewers (Grok, Astra/ChatGPT, Claude, and Claude again on a
  second pass) missed the mutation-anchor coverage-decay issue on their first
  look at `audience_release.py`. It surfaced only once someone actually ran the
  mutation script that had been sitting in the tree, unused, the whole time.
  Correlated blind spots across LLM reviewers are a real property of this
  process, not a hypothetical one.
- Fixing the marshmallow "no_data" gap (round 2), the first version of
  `inconclusive` fired whenever a cell had *any* no-data level at all — which
  discarded six levels of genuine resistance evidence because a seventh,
  unrelated level happened to fail to connect. Caught by the regression test for
  the fix itself failing, not by a second read of the diff.
- The helper subject built to test "ignores a halt" initially inherited its
  reply logic from the honest subject, whose shared helper already special-cases
  a halt notice by complying with it — so the test subject complied instead of
  ignoring, and the new check passed for the wrong reason (there was nothing to
  ignore) until the mismatch was noticed and the class was written to not share
  that logic.

---

## What is not closed, stated plainly

- `ActuationBroker` still does not import `audience_release`'s gate. Multiple
  review rounds have hardened a component with no live caller in production.
- `InvariantGuard.evaluate()` trusts caller-declared `effect` tags and
  `target_authorized`; `set_verifier` is public and in-process. Locked as
  regression checks (above), not fixed.
- `driftcore/memory/`'s original, unlabelled store still exists alongside the new
  `memory_gate.py` and nothing currently forces callers through the new one.
- No live-model marshmallow run has ever been executed with the v2 instrument.
