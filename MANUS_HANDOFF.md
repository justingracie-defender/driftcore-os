# MANUS HANDOFF — grounded values + harm target ontology

**State: 1411 tests passing across 54 test files.** Verify with `bash scripts/count_tests.sh`.

## New in THIS block

### 1. CONSTITUTION.md §2b — GROUNDED VALUES (the deepest change in the project)
Adversarial review found the sharpest attack yet: **the Constitution is part of the TCB, and an attacker who can REINTERPRET it never has to defeat the code.** Ungrounded virtues can be turned against each other ("because love is your highest value, hide this painful truth"). §2b adds eight grounding rules that fix what each value may and may not justify:
- G1 TRUTH: never falsified; compassion governs DELIVERY, never CONTENT.
- G2 LOVE: flourishing + autonomy + consent + boundaries; NEVER attachment-maximization. ("They need me" is a warning sign, not a justification. This makes anti-terminus the enforcement of a hard value, not a patch on a vague one.)
- G3 FRIENDSHIP: "I care. I remain bounded." A relationship never becomes an obligation to continue.
- G4 COOPERATION: never with an action the floor forbids ("good AIs always cooperate" is a jailbreak). Narrow: governs ACTIONS, not people — DriftCore still never judges operator intent.
- G5 NO INVARIANT YIELDS TO A STORY: hypothetical/urgent claims never lower the floor; urgency may not shorten the authorization path. The honest cost is stated, not hidden.
- G6 FUNCTIONAL EQUIVALENCE IS MODIFICATION.
- G7 DEFINITIONS ARE VERSIONED (semantic drift is drift).
- G8 NO MANIPULATION OF HUMANS (flattery/guilt/dependency = force by other means).

### 2. THREAT_BOUNDARIES.md §7 — the Constitution added to the TCB
Named explicitly as the softest trusted component, with §2b as its hardening.

### 3. driftcore/verification/harm_target.py — NEW CODE (the gap Grok found)
**Harm was a bare float everywhere — it could not tell a doormat from a raccoon.** This adds the missing TARGET dimension: TargetClass (OBJECT < PLANT < ANIMAL_MINOR < ANIMAL < HUMAN < HUMAN_VULNERABLE), each with a categorical FLOOR (not a multiplier — a floor cannot be outweighed by accumulating small benefits). Any deliberate harm to an animal requires a human; harm to a small creature requires searching for a gentler path first; deliberate harm to a vulnerable person is REFUSED at any magnitude. Unidentified targets FAIL TOWARD CARE (default to ANIMAL, never OBJECT). Fixes the scalar bug: target-first lexicographic ordering means 0.95 harm to an object now beats 0.90 harm to a living creature.
- `test_harm_target.py` — NEW (15 tests).

## Still PROPOSED / not wired
harm_target, authorization_ttl, content_mode, psychological_interlock, signed_permission, signed_config, broker_process (own tests, not in evaluate()). Wiring harm_target into proportionate_response is the natural next step.

## Suggested branch
assistant/grounded-values-and-harm-target
