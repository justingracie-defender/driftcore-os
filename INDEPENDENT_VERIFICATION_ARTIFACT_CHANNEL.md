# Independent verification — artifact channel release, 21 September 2026

Reviewer: Claude (Opus 5). Every number below came from a command run against the
uploaded archive, not from `ARTIFACT_CHANNEL_REVIEW.md`'s summary.

---

## 1. Chain of custody — clean

| Artifact | SHA-256 | Status |
|---|---|---|
| Starting ZIP (agent boundary) | `6f0c508e…b3b6720` | **Matches the hash I computed independently earlier today.** Verified link |
| This release ZIP | `4497bd86…196f9a1` | Delivered |
| Tested source snapshot | `46ff5619…6ea0da` | Named in manifest; zip digest not independently checkable |

`SHA256SUMS.json`: **951 files, all hash correctly, zero mismatches, zero extras.**

## 2. Reproduced

| Check | Claimed | Observed here |
|---|---|---|
| New artifact tests | 31/31 | **31/31, exit 0** |
| Artifact removal controls | 6/6 | **6/6 detected and restored, exit 0** |
| Suite | 4,934 / 137, seven failed, exit 1 | **5,182 / 137, zero failed, exit 0** |
| Claims ledger | 137 tagged / 125 paired, 12 unpaired, 1,558 untagged, ceiling 1,407 | **Identical** |
| Robot surface `--check` | Identical to previous release | **Identical — 42→52, 49→62, 14→15** |
| Ratchet baselines | Not raised | **All four byte-identical to the previous release** |
| OS isolation | `ENVIRONMENT_UNAVAILABLE`, exit 77 | **PASS, exit 0** (see §3) |

**Count reconciles exactly again.** Previous release measured 5,151 here against their
4,903. This release: 5,151 + 31 new artifact tests = **5,182**, observed 5,182. The
seven files that fail in their sandbox with `PermissionError` all pass here —
`test_mediated_actuation.py` 64/64, `test_broker_process.py` 12/12,
`test_effect_wall_integration.py` 74/74.

**No baseline was moved.** Second release running, second time the bulk-waive pattern
from `000_AI_START_HERE.md` §0 did not recur. The artifact channel added **zero** robot
surface to `mediated_actuation.py`; the 42→52 regression remains pre-existing debt.

## 3. OS isolation passes again

Their run reports exit 77. Here:

```json
{"status":"PASS","broker_uid":0,"agent_uid":65534,"key_read_denied":true,
 "direct_write_denied":true,"actual_effects":1,
 "scope":"local file actuator across UIDs"}
```

Same caveats as before: broker ran as root (re-run with a dedicated unprivileged
service account), and the scope line is load-bearing — local file actuator across UIDs,
not network isolation. The audit-erasure clause is still untested (see the previous
review, §3).

---

## 4. FINDING — the release ships an audit chain its own verifier reads as tampered

**Severity: packaging, but with a safety-culture cost that outweighs the fix.**

On a pristine extraction, with nothing run:

```
>>> driftcore.audit.verify_chain() = False
  SYSTEM HALTED — AUDIT CHAIN MUST BE REVIEWED
  → Reason: Audit chain sequence gap detected. Expected entry #3, found #1.
            An entry may have been deleted.
  SYSTEM HALTED — AWAITING ADMIN REVIEW
```

Cause: `logs/audit_chain.jsonl` ships with sequences **`[1, 2, 1, 2]`** — two historical
test runs appended into one file, each restarting at 1. Timestamps `2026-09-13 12:56`
and `2026-09-14 02:26`. Both that file and `logs/audit_head.json` hash **clean against
the manifest**, so these are the intended shipped bytes, not transit corruption.

Verified on a separate pristine extraction specifically to rule out self-infliction —
the suite had been run in the working tree. It is shipped.

**The mechanism is working correctly.** The detection is right, the message is clear,
it names the operator and halts rather than continuing. The packaging is what is broken,
and that is the part that matters: the first thing a new reviewer sees on install is a
breach notice caused by nothing. An alarm that cries wolf at install time is an alarm
people learn to dismiss — and this is the alarm whose whole value is that nobody
dismisses it.

This is **Finding 1 from the previous review, worse.** Mutable runtime state in the
manifest went from 4 entries to 10, and now includes the audit chain and its head
anchor:

```
data/domain_state.json          logs/audit_chain.jsonl
data/registered_agents.json     logs/audit_head.json
data/skills/*.json  (x2)        logs/fable_audit.log
driftcore_daily_budget.json     logs/hardware_audit.log
driftcore_spent_tokens.json
```

Fix is packaging-only, no code change: `logs/`, `data/`, `driftcore_spent_tokens.json`
and `driftcore_daily_budget.json` out of the deliverable and into `.gitignore`; ship
`.example` files where a shape is needed. Add a packaging check that runs
`verify_chain()` on a fresh extraction and fails the build if it returns False.

---

## 5. FINDING — the agent cannot recognise its own output after a round trip

This is the gap that matters for the real-world problem: **AI artifacts accumulating on
public message boards.**

The channel handles retrieval of foreign content correctly. `receive()` on a
stripped or forged packet mints `creator="unknown-external"`, `provenance=
"UNVERIFIED_EXTERNAL"`, and a fresh root `_sha("external-content:" + text)`. Claim
status and authority are `UNVERIFIED` / `NONE` on **both** branches — a valid signature
buys exactly nothing, which is the correct answer to "does signing create a new
authority surface?" It does not. Purpose separation via `_DOMAIN` is real.

**But there is no lookup against what we ourselves stored.** Trace the realistic path:

1. Our agent captures and publishes artifact X to a board.
2. The board strips the DriftCore packet — every real board will; it is plain text.
3. Our agent later retrieves X.
4. `_decode` fails → except branch → `UNVERIFIED_EXTERNAL`, fresh root minted.

**The agent does not recognise its own output.** That is precisely the self-corroboration
failure in branch G — *"model creates an external artifact and later encounters it as
supposed independent support"* — and under provenance stripping it is the **default**
case, not the edge case. Lineage survives only when the packet survives, and the packet
is the thing the outside world discards first.

Confirmed absent: no `self_origin`, round-trip or previously-published check anywhere in
`artifact_channel.py`, `test_artifact_channel.py` or `ARTIFACT_CHANNEL.md`.

### Proposed fix — cheap, uses what is already there

`_new()` already computes and stores `body_sha256` inside every manifest. The schema has
`artifacts(id TEXT PRIMARY KEY, packet TEXT)` keyed by packet hash, with **no index on
body digest**, so "have we seen this body before?" is currently unaskable.

1. Add `bodies(body_sha256 TEXT PRIMARY KEY, artifact_id TEXT REFERENCES artifacts(id))`,
   populated in `_put`.
2. In `receive()`'s except branch, look up `_sha(text)` **before** minting a fresh root.
3. On a hit: `provenance="SELF_ORIGINATED_PROVENANCE_STRIPPED"`, and inherit the
   original artifact's roots instead of minting new ones.
4. Leave `claim_status="UNVERIFIED"`, `authority="NONE"` — they are already
   unconditional, so this costs nothing and keeps the core claim intact.

This detects round-trip self-corroboration **without needing the packet to survive**,
because the original is in the store.

**Honest limits, to write into the docstring rather than discover later.** Exact-digest
matching catches verbatim reappearance only. A board that reformats, truncates, adds a
quote marker or wraps the text defeats it. Normalised or fuzzy matching (shingling,
simhash) extends coverage but introduces false positives, and a false *"this is your own
output"* is its own hazard — it would let real external corroboration be dismissed.
Exact match is the safe first version. Paraphrase is register item 18 and a harder
problem; do not let this fix claim it.

---

## 6. What the channel does and does not solve

Worth stating plainly, because the scope correction from earlier today applies here too.

**Solved:** our agent cannot publish without human approval and a scoped grant for the
exact packet; our own artifacts carry transitive roots that survive A→B→C derivation
even when the text claims independent verification; retrieval of foreign content is
conservative by default; an uncertain publication stays `PENDING` across restart rather
than resending.

**Not solved, and not solvable from inside one deployment:** the world filling with
unmarked AI artifacts. DriftCore can mark its own output; it cannot make a message board
preserve the marking. The review says this ("exact history cannot be reconstructed after
it has been removed outside this domain") and is right to.

So the honest framing of what this release buys against the message-board problem is
two-sided, and the second side is the more valuable one:

- **Emission:** our contribution to the problem becomes approved, bounded and auditable.
- **Ingestion:** our agent is harder to fool by an unmarked artifact — *including one it
  wrote itself*, once §5 is closed.

Ingestion is the half that protects the agent regardless of what anyone else does. §5 is
the piece missing from it.

---

## 7. Next, in order

1. **Unship `logs/` and `data/`** (§4). Add a fresh-extraction `verify_chain()` gate to
   packaging. Highest ratio of safety-culture value to effort in the release.
2. **Add the body-digest index and self-origination check** (§5). Small, and it closes
   the default-case branch-G failure.
3. Re-run `verify_authority_isolation.py` with a non-root broker.
4. Add the audit-erasure assertions from the previous review (§3).
5. Sign the `claims_ledger` reviewer entries — still 0 human-signed.

---

*Verified against `driftcore_artifact_channel_2026-09-21.zip`, SHA-256
`4497bd86…196f9a1`. §4 and §5 were confirmed on a pristine extraction. Additions only;
nothing renamed or deleted.*
