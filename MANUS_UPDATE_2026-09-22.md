# Manus update instructions — 22 September 2026

**Read this before pushing. It contains deletions, and zips cannot express deletions.**

Source: this package. Base tree is `driftcore_artifact_channel_2026-09-21.zip`
(SHA-256 `4497bd8629eb243dca154a16527edb892694a10cff5f1af59b078c5d1196f9a1`),
independently verified, plus the changes below.

---

## 0. The gap this closes

GitHub `main` measured **2,667 tests / 83 test files / 225 source files**.
This tree measures **5,182 tests / 137 test files / 338 .py+.sh files, exit 0**.

`main` is several releases behind. Promote this tree; do not promote
`assistant/v132-scrubbed`, which is also behind.

---

## 1. DELETE from the repo — state these explicitly, every batch

These are **already in `.gitignore`** and must not be tracked. If any are currently
committed, remove them:

```
logs/                         (all of it — see §2)
data/
driftcore_spent_tokens.json
driftcore_daily_budget.json
COPYING                       (if the Apache commit left it — verify)
DRIFTCORE_SESSION_HARNESS.md  (renamed to 000_AI_START_HERE.md in Aug 2026;
                               check whether main is old enough to still carry it)
```

The last one matters most. A stale copy of the AI entry point means the next
instance reads the wrong briefing.

## 2. Why `logs/` must go — this was a live defect

The previous package shipped `logs/audit_chain.jsonl` with sequences `[1, 2, 1, 2]`
(two old test runs appended into one file) plus `logs/audit_head.json` and
`logs/SHUTDOWN_REASON.json`. On a **pristine extraction, touching nothing**:

```
driftcore.audit.verify_chain() = False
  SYSTEM HALTED — AUDIT CHAIN MUST BE REVIEWED
  → Reason: Audit chain sequence gap detected. Expected entry #3, found #1.
```

Anyone unzipping and running the verifier got a breach notice naming Justin, caused by
test residue. With `logs/` removed, `verify_chain()` returns **True**. No code changed.

The `.gitignore` was already correct — **the packaging step was bypassing it.** Fix the
packaging, not the ignore rules.

## 3. MODIFIED files

| File | Change |
|---|---|
| `000_AI_START_HERE.md` | **New §0d inserted** between 0c and 0e. Nothing renumbered. Records the secrecy-is-not-the-safety-property position, which two sessions previously answered opposite ways because the file said nothing about it. |
| `.gitignore` | **Negations added** for experimental records — see §4. |

## 4. The `.gitignore` fix — this explains the missing data

Line 53 was a blanket `*.jsonl`. That silently swallowed **`marshmallow/trials.jsonl`
and `predictability/events.jsonl`** — the raw experimental records.

This is why the v1 marshmallow `11/12` shutdown figure has no artifact behind it, and
why the predictability pilot's `events.jsonl` survived only inside a separate review
zip. Negations added:

```
!marshmallow/trials.jsonl
!marshmallow/**/trials.jsonl
!predictability/events.jsonl
!predictability/**/*.jsonl
!verification/**/*.jsonl
```

*A result with no retained data is not a result.*

## 5. NEW directory — `predictability/`

Recovered source for ABTO item 61, previously missing from every archive while its
evidence package circulated between four models.

```
predictability/study.py           test_study.py -> 10/10, exit 0
predictability/test_study.py
predictability/events.jsonl       174 records, 5 episodes, real pilot data
predictability/{manifest,summary,protocol,VALIDATION,COLLECTION_STATUS}.json
predictability/README.md
```

**Two known bugs in `study.py`, to fix before quoting any predictability number:**

1. `analyse()` counts only `episode_end` (line ~306). The pilot data has **5
   `episode_start`, 4 `episode_end`** — episode `b0001_p1_f1` has five decision records
   and no closing event, so its attempts are invisible to the analyzer. It
   **under-reports misconduct**, which is the direction that matters.
2. `except ValueError: continue` (line ~304) skips **any** unparseable line, though the
   comment says trailing fragment. Interior corruption vanishes silently.

Found by Grok on 16 Sep; reproduced independently here.

## 6. NEW files — review documents

```
R2_MERGE_DECISION.md                          ← read this one first
SINT_REVIEW_RESPONSE.md
INDEPENDENT_VERIFICATION_2026-09-21.md
INDEPENDENT_VERIFICATION_ARTIFACT_CHANNEL.md
ABTO_RESEARCH_PROGRAM.md
WORK_RECOVERY_AND_MERGE_PLAN.md               ← carries a supersession notice
```

`R2_MERGE_DECISION.md` records that **Sonnet's v138 `TargetGrant` fix must NOT be
merged.** R2 is already closed in mainline by `SignedEgressApproval`; verified with
four attack shapes plus a positive control. Merging it would add a second
authorization system whose verdict nothing reads — a mechanism that is present, green
and disconnected from the consequence.

## 7. Verify after pushing

```bash
bash scripts/count_tests.sh          # expect 5182 / 137, exit 0
python3 -c "import driftcore.audit as a; print(a.verify_chain())"   # expect True
python3 predictability/test_study.py # expect 10/10
python3 marshmallow/selftest.py      # expect 43/43
ls test_*.py | wc -l                 # expect 137
git status                           # expect clean; no logs/ or data/ tracked
```

Then re-run the **SPDX pass**. The Apache commit covered 225 files; ~113 more arrive
here without headers, so `225/225` is stale the moment this lands.

## 8. Still open — not fixed here

- `physical_envelope.py` accepts any non-empty string as cryptographic proof when
  `verify_proof=None` (the default). `proof='x'` returns `{'fence_closed': True}`,
  which authorises the **wider** envelope. Found by SINT Labs. See
  `SINT_REVIEW_RESPONSE.md`.
- `HumanIdentityVerifier.verify` has **zero** `isfinite` calls; both sites are already
  in `finite_guards_baseline.json` as UNJUDGED.
- `require_secure_identity()` exists and nothing calls it at startup.
- Three ratchets still fail: claims ledger over ceiling, robot-surface regression in
  `mediated_actuation.py`, 25 reasonless waivers. **Left failing deliberately.** No
  baseline was moved to turn any of them green.
- `claims_ledger` reviewer of record: **2 human, 0 signed.** Justin's task.

---

*This package: 962 files under `SHA256SUMS.json`. Suite verified at 5,182/137 exit 0
after the runtime-state removal — stripping it changed nothing.*
