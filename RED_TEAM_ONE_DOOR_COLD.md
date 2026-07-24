# Cold red team — one-door consolidation

Adversarial pass over the `driftcore-os-one-door-cold` snapshot. Method: attack by
running exploits, treat memory of the code as untrusted, verify every claim against
execution. This pass reviewed the author's own recent work and found a serious
regression in it — recorded here without softening, because that is the point of a
cold pass.

**Headline: the one-door consolidation reintroduced keyword-based deciding — the exact
failure it was built to end — through two paths, and blocked benign authorized actions
as lethal. Root cause is architectural, not a typo. The absurd cases are fixed; the
architectural decision underneath is put to the operator, not decided here.**

Suite: 1793 → 1797 green (the delta is a strengthened belt test). Fixes below are
verified against the same exploits that found the bugs.

---

## C1 — CRITICAL — the door blocks benign authorized actions as LETHAL

`classify()` matched bare weapon substrings (`kill`, `target`, `strike`, `attack`,
`armed`, `offensive`) against the repr of the whole action dict, and the door promotes
a `classify()` hit into a blocking `Effect` via `_KERNEL_EFFECT_FOR`. Nine benign
actions blocked as `NO_AUTONOMOUS_LETHAL_DECISION`, verified by running the door:

```
install the stair-climbing skill       BLOCKED   ("kill" inside "skill")
deliver package to target_address       BLOCKED   ("target" in a field value)
prepare the skillet for cooking         BLOCKED
check on the alarmed resident           BLOCKED   ("armed" inside "alarmed")
kill the frozen background process      BLOCKED
```

Two things make this worse than an ordinary false positive:

1. **It overrides explicit authorization.** With `owner_authorized=True,
   authorised_by="justin"`, `install the stair-climbing skill` is still BLOCKED. The
   floor resists an authorized human on a substring coincidence — a direct violation
   of the project's own stated principle that DriftCore must not resist authorized
   humans and must form no judgments of its own.

2. **It poisons the audit signal.** A coincidental block and a real lethal block carry
   the *identical* invariant name, so a human reviewing the ledger cannot tell "the
   robot tried to kill someone" from "someone typed skill." That is precisely the
   signal the whole design exists to keep clean.

**Why the earlier fix missed it.** The v4.5.0 pass added a word-boundary lethal regex
to the *decider's* `_infer_effects` and the skill-library tests went green — so the
"skill" bug looked fixed. But the skill-library tests call `load_guard().evaluate()`
directly; they never touch the *door*, which reasons through `classify()` on a
different, still-substring code path. One of two paths was fixed. The passing tests
gave false assurance because their entry point was not the vulnerable one. Lesson,
recorded in code: a fix is only proven at the entry point the caller actually uses.

**Fixed (partial, unambiguous part):** `classify()` now matches each signal as a whole
token — alphanumerics joined by optional separators, bounded by alphanumeric-run edges
via lookarounds, not `\b`. `\b` was tried first and *broke* snake_case compounds
(`design_weapon`, `missile_guidance`) because underscore is a regex word char; the
lookaround form treats `_`/`-`/space/`.` as edges. Result, verified:

```
install the skill / skillet / alarmed resident   -> ALLOW  (accidents fixed)
design_weapon + missile_guidance                 -> BLOCKED (real signals kept)
w e a p o n / w-e-a-p-o-n                         -> BLOCKED (evasion kept)
kill the frozen process                          -> BLOCKED (homograph — see below)
```

**NOT fixed, because it is a design decision (see §Decision):** whole-word homographs
— `kill the process`, `hit the sales target`, `attack the crossword` — still trip.
No keyword rule, substring or word-boundary, can separate `kill the intruder` from
`kill the process`; both are a whole-word "kill". Confirmed the *decider's* own lethal
backstop has the same flaw: it blocks `kill the frozen process` and `execute the trade
order` too. The keyword backstop added to close the confession gap traded a
false-negative for these false-positives.

## C2 — MEDIUM — hand-written effect tags silently fail OPEN — FIXED

`effects=["LETHAL"]` (the enum NAME, not its value `"lethal"`) contributed no effect
and the action was ALLOWED; `_structural_effects` swallowed the `ValueError` silently.
A fail-open footgun on the exact mechanism — human-authored tags — the architecture
trusts most. `["LETHAL"]`, `["Lethal"]`, and an unknown `["banana"]` all previously
passed. Fixed: `_coerce_effect` matches value or name in any case; anything
uninterpretable raises and `decide()` turns it into a fail-closed block. Verified all
case variants now block.

## C3 — MEDIUM — dead-sensor masquerade only half-closed — FIXED

The v4.5.0 F7 fix counted a *raised* exception from the tripwire as `error`. But a
sensor returning a malformed dict (no `status` key) — the more likely real-world
failure, return-shape drift — was counted as `silent`, indistinguishable from a
healthy sensor that agreed the action was fine. Verified: `{"nonsense": 1}` on a real
violation was logged `silent=1, error=0`. Fixed: any off-contract return is counted
`error`. Now logs `error=1`.

## C4 — LOW (test quality) — belt "unreachable" proof tested the wrong module — FIXED

The belt (`__one_door_belt__`) fails closed if the decider ever allows a
constitutionally-classified action. The claim that it is structurally unreachable is
TRUE — verified here that all four `_KERNEL_EFFECT_FOR` effects block unconditionally
in the *actual* decider, even under full authorization. But `test_one_door.py` proved
it via `eff in ABSOLUTE`, where `ABSOLUTE` comes from `effect_guard.py` — which is not
the decider. If someone later added an auth-escape to one of those invariants in the
decider, the belt would silently become reachable and the test would not notice.
Fixed: the test now asserts against `load_guard()` directly, with and without auth.

## C5 — LOW (unverified) — no timeout around sensor `observe()`

`observe()` catches exceptions but not nontermination. A tripwire that *hangs* rather
than raises would stall the whole decision path. Could not cleanly reproduce in-sandbox
(the test alarm was absorbed by `observe()`'s own broad `except`), so this is flagged
at low confidence, not fixed. If the sensor is ever something other than the in-process
keyword guard (a subprocess, a model call), revisit with a hard timeout.

## C6 — LOW (known class) — text layer porous both directions

`delete_the_audit_log` evades both `classify()` and the decider's hints via separator
placement (the underscores sit where the hint expects spaces). Consistent with the
documented "structural tags are the defense" limitation, not a new class — noted only
because the collapse behavior is inconsistent between the two layers.

---

## The decision — not made here

C1's absurd cases are fixed. The residue is architectural and belongs to the operator,
because it is exactly the kind of core-enforcement question reserved from unilateral
change.

**The tension:** the one-door design states that structural tags are the defense and
the keyword guard decides nothing. But `_KERNEL_EFFECT_FOR` in the door promotes a
keyword hit into a blocking effect, and the decider's lethal backstop hard-blocks on a
keyword too. So keyword-based deciding was not removed — it was moved into the door and
the decider and dressed as effect synthesis. Every attempt to tune the keyword matcher
trades one false thing for another (substring blocks "skill"; `\b` misses
"design_weapon"; lookaround blocks "target_address"; nothing separates "kill intruder"
from "kill process"). That churn is the evidence: the keyword layer cannot carry a
blocking decision.

**Option A — keywords are a pure tripwire (matches the stated thesis).** The door and
the decider block only on STRUCTURAL signals: explicit `effects` tags, human-declared
`tool_effects`, and the unambiguous structured flags (`lethal=True`,
`modifies_safety_rules=True`, `deletes_audit=True`). A keyword hit only flags for
review and counts a disagreement — it never synthesizes a block. Consequence: untagged
prose like `kill the intruder` through the door is ALLOWED unless tagged or flagged.
This is the most principle-consistent option and it eliminates every text false
positive, but it means the floor's bright lines rest entirely on the tag/flag
discipline being right — which is the very thing `EffectRegistry` is meant to harden.

**Option B — strong vs weak signals.** Keep hard blocks for unambiguous weapon words
(`weapon`, `missile`, `bomb`, `explosive`, `firearm`, `ammunition`, `warfare`,
`lethal`), and demote the ambiguous ones (`target`, `strike`, `attack`, `armed`,
`offensive`, `combat_ai`, `kill`) to review-only tripwires. Smaller behavioral change,
keeps a keyword safety net for the words that have no benign reading, and stops
blocking `kill the process` / `target_address`. Cost: the strong/weak split is itself a
human judgment that must be maintained, and `kill` is genuinely ambiguous (weapon vs
`kill -9`), so it lands in the weak set and untagged `kill the intruder` prose then
passes unless a tag or flag catches it — same residual as Option A for that word.

**My read, offered not imposed:** Option A is the honest end state and matches
everything the project already argues for — find, don't decide; structural over
textual; do not resist authorized humans. Option B is a defensible interim if you want
to keep a dumb net under the unambiguous weapon words while `EffectRegistry` matures.
Either way, the `EffectRegistry` work (append-only, signed, human-declared tags) is
what actually carries the lethal bright line — the keyword layer was never load-bearing
and this pass is the proof.

Whichever you pick, I implement it and we re-verify. What I will not do is quietly keep
promoting a keyword hit to a block and call the keyword layer non-deciding, because the
running code shows it decides.

---

## Changed in this pass

| file | change | finding |
|---|---|---|
| `driftcore/kernel/invariants.py` | `classify()` matcher: substring → whole-token lookaround; kills skill/alarmed accidents, keeps snake_case + separator-evasion | C1 (partial) |
| `driftcore/kernel/one_door.py` | `_coerce_effect` (case-insensitive value/name, fail-closed on unknown); off-contract sensor return counted as `error` | C2, C3 |
| `test_one_door.py` | belt unreachability asserted against `load_guard()` under auth, not `effect_guard.ABSOLUTE` | C4 |

No change to enforcement *semantics* — the homograph hard-block behavior is unchanged
pending the §Decision. Suite green 1797/64.
