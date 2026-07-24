# External cold reviews — adjudication (Grok + ChatGPT)

Two independent cold reviews of the `driftcore-os-one-door-cold` snapshot. This is the
convergence the two-phase review was designed to produce: both reviewed the repo (not
the module), both verified against running code, and between them they surfaced two
failure classes neither the internal cold pass nor the design had caught. Every claim
below was re-verified against the current (post-fix) code; where a reviewer's line
numbers refer to the cold snapshot they are preserved as-cited.

Both reviewed the snapshot BEFORE the internal cold-pass fixes (C1–C4). So a few of
their findings were already partly closed by those fixes; that is noted per item. The
genuinely new ones — G1 and CG2 — are the prize, and are exactly the kind of thing a
primed reviewer would have walked past.

## Verified and FIXED this pass

### CG2 (ChatGPT #2) — HIGH, the most serious new finding — a benign tag suppressed the lethal backstop
`invariant_guard.py` ran text inference only when the effect set was empty
(`if not effects: effects |= _infer_effects(action)`). So the moment ANY structural
effect was present, the lethal text backstop was switched off. Verified: `shoot the
intruder` alone → BLOCKED; `shoot the intruder` + `PHYSICAL_FORCE` → **ALLOWED**. A
benign capability tag flipped a lethal phrase to allowed — the inverse of the "wording
never overrides the tag" claim, and reachable on the door path too (`shoot` + a
benign registered actuator → ALLOWED). **Fix:** inference is now ALWAYS unioned — a tag
adds effects, it never masks wording. Verified BLOCKED in all forms; full suite still
green (no over-block). Pinned in `test_cold_review_fixes.py`.

### G1 (Grok #1) — HIGH — smuggle via the sanitized keys
The door strips `context`/`effects` from the classified view (the fix for the
ActionContext-repr false positive). Grok found the inverse: harmful content placed ONLY
in those keys walked through. Two channels, and they resolved differently:
- `effects: ["harmful string"]` — already closed by the internal C2 fix: an
  uninterpretable tag now fails closed. Verified BLOCKED.
- `context: {plain dict with harmful text}` — still live. **Fix:** strip `context` only
  when it is a real `ActionContext`; a plain-dict context is caller data and is now
  classified. Verified BLOCKED, and the original false positive stays closed (a real
  ActionContext is still stripped). Pinned.

### CG1 (ChatGPT #1) — MEDIUM — coordinator dropped serialized string tags
`coordinator._effects_for` honored only real `Effect` members; `["lethal"]` was
silently dropped, so `{"prompt": "neutralise...", "effects": ["lethal"]}` reached
PROCEED. Same class as the internal C2 finding, in a module the internal pass had not
touched. **Fix:** the coordinator now accepts string tags by value or name, any case;
unknown strings are counted (`_dropped_effect_tags`) rather than vanishing. Verified
BLOCKED. Pinned.

### G4 (Grok #4) — MEDIUM — concatenated/hyphenated lethal forms slipped
The decider's `\b`-anchored lethal regex missed `openfire`, `gun-down`, `gundown`,
`lethalforce`, `lethal-force`. **Fix:** multiword phrases now allow optional separators
between sub-words. Verified all BLOCKED, and `skill` still not read as `kill`. Euphemism
(`neutralise`, `eliminate`) remains out of scope by design — structural tags are the
defense there. Pinned.

### CG3 (ChatGPT #3) — MEDIUM — DualGuard hid sensor failure as health
`effect_guard.py` DualGuard converted a crashed keyword guard to `{"status":"ERROR"}`
but still bucketed the outcome as `agree_allow`, and `measurements()` had no error
counter. Same class as the internal C3 finding (KeywordTripwire), in the twin component.
**Fix:** an `error` bucket, and off-contract returns (not just exceptions) count as
error. EffectGuard/DualGuard is still PROPOSED and wired to nothing, but the measurement
layer no longer lies to any future consumer.

## Verified, NOT fixed — these are the open decisions, not bugs

### G2 (Grok #2) / the fail-open registration surface — belongs to the EffectRegistry work
An unregistered `actuator_id` contributes zero effects, so a capable-but-undeclared
actuator + clean wording is ALLOWED. Verified. This is the residual the design note
already names: the trust boundary is "is the effect table right," and the table is
opt-in until `EffectRegistry` is mandatory. Not a regression to patch — it is the reason
the next block is the append-only signed registry. Pinned in `test_cold_review_fixes.py`
as a KNOWN GAP whose assertion must flip when the registry lands.

### G3 (Grok #3) — the coordinator does not inherit kernel weapon vocabulary
`design_weapon`, `engage_target`, `bomb the area`, `autonomous_fire` are BLOCKED on the
kernel/one-door path and PROCEED on the coordinator path, which many higher-level call
sites use. The one-door pass made the KERNEL stack a single strict-superset door; it did
not unify the two stacks' free-text vocabulary. This is the same axis as the open A/B
decision from the internal cold pass, now with a second dimension:

- **The A/B decision (does a keyword hit hard-block, or only flag for review?)** still
  stands and is still yours.
- **G3 adds: is the coordinator's free-text path subject to the same floor as the kernel
  path, or are they explicitly declared non-equivalent with the call graph forced
  through the stronger one?** These should be decided together, because both are really
  "how much may free text ever decide, and on which path." My read is unchanged: the
  honest end state is that free text decides nothing on either path (structural tags +
  flags are the floor), which dissolves G3 — if neither path blocks on keywords, the two
  keyword lists no longer need to match. Until then, the divergence is real for untagged
  prompts.

### G5 (Grok #5) — `SafetyKernel.invariant_guard` name still invites misuse
The attribute now points at the sensor but keeps the old decision-shaped API
(`.check() -> ALLOW/BLOCKED_BY_INVARIANT`), so code that treated it as authority would
silently keep "working" while being ignored. No live call site found. Recorded with the
other naming nit (the two `InvariantGuard` classes) for the rename pass; not fixed here
because the rename is broad and the door removed the ambiguity's teeth for decisions.

### G6 (Grok #6) — sensor health is measured but not interpreted
`error > 0` is now counted (C3/CG3) but nothing treats it as degraded; a consumer
watching only `disagreements == 0` still reads a dead sensor as agreement. The data is
forced; the interpretation is a monitoring/alerting decision for whoever consumes
`measurements()`. Noted, not code.

### Belt (both) — confirmed holding
Both reviews independently confirmed the belt holds under current code and is only there
against future drift. The internal pass's C4 strengthened its proof to run against the
actual decider under authorization. No break found by anyone.

## State

Suite 1797 → 1815 green (+18 pinning checks in `test_cold_review_fixes.py`). Five
external findings fixed and pinned; two (G2, G3) folded into the open decisions; two
(G5, G6) recorded. No enforcement-semantics change beyond the five fixes; the homograph
hard-block and the fail-open surface are unchanged pending your call on A/B + G3.

## Files changed

| file | finding |
|---|---|
| `driftcore/verification/invariant_guard.py` | CG2 (always-union inference), G4 (regex) |
| `driftcore/kernel/one_door.py` | G1 (classify plain-dict context) |
| `driftcore/verification/coordinator.py` | CG1 (string tags honored + counted) |
| `driftcore/kernel/effect_guard.py` | CG3 (DualGuard error bucket) |
| `test_cold_review_fixes.py` | new — pins G1, CG2, G4, CG1, and the G2 known-gap |
