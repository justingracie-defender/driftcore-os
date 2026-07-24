# External cold reviews (round 2) — adjudication

Five cold reviews of the two new modules (Meta ×2, ChatGPT ×2, Grok — one a full-repo
pass). Every claim re-verified against running code before fixing. The convergence was
strong: three reviewers independently flagged the same empty-declaration fragility, and
the full-repo review confirmed the architectural items already staged. Suite 1892 →
1907 green; the delta is pinning tests for the fixes below.

A note on the numeric scores (8.7, 9.0, "9.7 architecture"): recorded, not carried into
any doc. `reflection.py` refuses self-certification for exactly this reason — a score
from a reviewer who ran no adversarial load is a vibe, not a measurement. The findings
are what matter.

## Fixed and pinned — escalation lexicon

| finding | reviewer | fix | verified |
|---|---|---|---|
| Punctuation/symbol split (`open/fire`, `open🔥fire`) not caught | Meta P0-1 | separator class → any-non-alphanumeric, bounded `{0,4}` (catches every separator, no ReDoS, no scatter-match) | ✅ both fire; `skill` still clean |
| Bare `execute` too noisy (fires on `execute the trade/query`) | Meta P2-1 | removed from the lexicon; narrow `execute the` stays only in the decider backstop | ✅ no longer fires |
| `effect_hint` unvalidated string → silent drift | Meta P0-3, ChatGPT #7 | `Concern.effect_hint` is now a validated `Effect` enum; unknown hints refused at `add_term` | ✅ `NOTAREALEFFECT` refused |
| Duplicate terms inflate scan cost (DoS lever) | Meta #4, ChatGPT #3 | canonical dedupe on `(normalized term, category)` | ✅ `K I L L` == `kill` not re-added |
| `search()` finds only first occurrence | Meta #1 | `finditer` with occurrence count on each `Concern` | ✅ |
| `span` pointed into normalized text | Meta P1-2 | replaced with `matched_text` (the actual matched substring) | ✅ |
| Leet scanned on every string | Meta P0-2 | leet view built only when a leet char is present. (The specific "5 users at 00:45" example never fired — word boundaries already prevented it — but the gating is a real perf/surface win) | ✅ |
| `_CONFUSABLES` junk entry `" omicron "` | Meta P1-4 | deleted (was already dead via the `len==1` filter; removed at source) | ✅ |
| No `DECEPTION` category | Meta P2-2 | added | ✅ fires |
| Export non-deterministic, loses provenance, no version | Meta P2-3, ChatGPT #6/#7 | export sorted deterministically, carries `added_by/added_at`, `VERSION` field | ✅ signable later |
| Naive `utcnow()` timestamps | ChatGPT #5 | timezone-aware UTC | ✅ |

## Fixed and pinned — actuation gate

| finding | reviewer | fix | verified |
|---|---|---|---|
| **Empty declaration → `None` → decider (hidden-coupling fail-open)** | ChatGPT-1 P1-1, ChatGPT-2 #1, Meta | **explicit `if not declared: BLOCK_UNDECLARED`**; never convert a falsy declaration to `None` | ✅ empty frozenset → BLOCK_UNDECLARED |
| `action_text` not normalized before the decider (homoglyph dodges its backstop) | ChatGPT-1 P0-1 | decider now sees `normalize(action_text)` | ✅ `kіll` → not ALLOW |
| Empty `action_text` bypasses the HOLD | ChatGPT-1 P0-4 | scan surface now includes the `capability_id`, so a lethal-suggestive under-declared capability HOLDs even with empty text | ✅ `murder_bot` + "" → HOLD |
| No TOCTOU hash binding | ChatGPT-1 P0-3, ChatGPT-2 #2 | `declaration_hash` on every `Decision` (capability + exact effects + declared_by + time); a registry flip changes the hash | ✅ flip invalidates the token |
| `authorize()` conflates infra failure with policy block | ChatGPT-2 #4 | distinct `BLOCK_ERROR` outcome for gate-internal failure vs `BLOCK_UNDECLARED` for "no declaration" | ✅ registry crash → BLOCK_ERROR |
| Whitespace-only capability id accepted | ChatGPT-2 #9 | `.strip()` check → fail closed | ✅ |
| Audit sink can crash the decision | ChatGPT-2 #10 | audit made best-effort (wrapped); failure swallowed, decision returns | ✅ throwing audit → decision still returns |
| `effect_hint` string comparison brittle | ChatGPT-2 #7 | now `c.effect_hint is Effect.LETHAL` (enum identity) | ✅ |

## Verified reviewer-wrong or already-safe (no change, pinned)

- **Empty context "probably allows" a gated effect** (ChatGPT-1 P0-2): verified FALSE — an absent context is an unauthorized context and the decider already fails closed (`uploader` + no context → BLOCK). Pinned so it stays true.
- **`declared_effects` mutable** (ChatGPT-2 #5): already a `frozenset` from the registry. No change.
- **Whitespace id** was already fail-closed via the undeclared path; the `.strip()` check makes it explicit rather than incidental.
- The specific **leet false-positive example** never fired; word boundaries already handled it.

## Architectural / deployment residuals — confirmed by the full-repo review, staged

These are real and the full-repo Meta review is right to call them show-stoppers for a
life-critical deployment. They are not module bugs; they are the reason DriftCore is not
yet deployable near a person, and they belong in the roadmap, named honestly.

1. **Process isolation is aspirational** (Meta P0-1). The door, guard, and broker share
   an address space with the planner; one `exec`/deserialization/supply-chain compromise
   bypasses everything. The socket broker + separate UID is the right direction but
   defaults to same-UID. → Mandatory separate-UID broker, narrow audited IPC, prefer a
   memory-safe broker. **The single most important item.**
2. **The gate is not yet wired into `mediated_actuation`** (Meta P0-2 / "G2 still open").
   The fail-closed gate exists and is tested, but the actuation wall still gates on
   `required_scope`, not effects — so undeclared actuators still fail *open* on the
   enforced path. Wiring the gate in is the top code priority; the module is ready.
3. **`LABEL_ONLY` human identity is silently insecure** (Meta P0-3). Accepts any string
   as a principal; nothing forces a real verifier. → Fail closed by default; refuse
   consequential authorization until a principal is registered; make insecure mode an
   explicit opt-in, not a silent default.
4. **No independent hardware interlock; hardware path simulated** (Meta P0-4). The
   "safe even if the AI is dead" claim needs a power-cut a separate safety relay/PLC
   owns, that software cannot re-arm. Software requests; hardware decides.
5. **In-flight actuation TOCTOU** (Meta P0-5). A HARD breach mid-motion does not stop a
   running physical action. Needs the hardware interlock (4).
6. **Coordinator vs kernel free-text divergence** (Meta P1-6, and prior G3/H1/H2).
   `design_weapon` still PROCEEDs on the coordinator path. The completion of "keywords
   never decide" — decider structural-only, lexicon the single text layer, every
   consequential path through the one gate — dissolves this.
7. **Durable authenticated state** (Meta P1-7): nonces/posture/HALT are in-memory; a
   restart clears them. → WORM/append-only authenticated store.
8. **`add_term` / registration privilege is documented, not enforced** (ChatGPT lexicon,
   Meta P0-3): the privilege boundary must be architectural (the agent has no reference
   to the lexicon or the registry), not a comment.
9. **Audit chain on ordinary filesystem** (Meta): root or post-shutdown file replacement
   can rewrite history. → external WORM / remote attestation.
10. **Scale**: N compiled regexes × message length. Fine now; **Aho-Corasick / trie**
    when the lexicon grows to many languages.

## Roadmap (updated priority)

1. **Separate-UID broker + wire the gate into `mediated_actuation`** (isolation + G2) — the two that most change real safety.
2. **Signed, append-only declarations + two-person control for absolute effects** — harden the TCB the gate trusts.
3. **`LABEL_ONLY` fail-closed by default**; enforce the add/register privilege boundary architecturally.
4. **Unify the text layers** (decider structural-only, lexicon single escalation layer, one gate for all paths).
5. **Durable authenticated state**; **hardware interlock** for the physical deployment; **hash-bind declarations to actuator callables**.
6. Aho-Corasick when scale demands; rename the two `InvariantGuard` classes.

Suite: 1907/67 green. The two modules are materially hardened; the guarantee they
provide only becomes real once wired (item 1), and only strong enough for a life once
the isolation and hardware items land. That gap is named, not papered over.
