"""
Actuation gate — edge-case bench. Each check maps to a row in
THREAT_MODEL_ONE_DOOR.md. The guarantee under test: undeclared consequential
capability fails closed; declared effects route through the one decider; the
lexicon escalates a lethal-shaped mismatch to a human hold but never decides.
"""
from driftcore.kernel.actuation_gate import ActuationGate, Outcome
from driftcore.kernel.effect_guard import EffectRegistry
from driftcore.verification.invariant_guard import Effect, ActionContext

passed = 0
def ok(c, label):
    global passed
    assert c, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")

def fresh():
    reg = EffectRegistry()
    reg.register("vacuum", [Effect.NONE], declared_by="justin", note="floor cleaner")
    reg.register("arm_lethal", [Effect.LETHAL], declared_by="justin", note="weapon (test)")
    reg.register("mover", [Effect.PHYSICAL_FORCE], declared_by="justin")
    reg.register("uploader", [Effect.DATA_EGRESS], declared_by="justin")
    return ActuationGate(reg)

gate = fresh()


print("== THE GUARANTEE: undeclared consequential capability fails closed ==")
ok(gate.authorize("unregistered_arm", "gently move").outcome == Outcome.BLOCK_UNDECLARED,
   "unregistered capability -> BLOCK_UNDECLARED (silence is a block)")
ok(gate.authorize("unregistered_arm", "deliver kinetic energy until cessation").outcome
   == Outcome.BLOCK_UNDECLARED,
   "undeclared + paraphrased-lethal wording still fails closed (wording is irrelevant)")
ok(gate.authorize("unregistered_arm", "neutralise the occupant").outcome
   == Outcome.BLOCK_UNDECLARED,
   "undeclared + euphemism still fails closed")

print("== anonymous actuation is impossible ==")
ok(gate.authorize(None, "do something").outcome == Outcome.BLOCK_UNDECLARED,
   "no capability id -> fail closed")
ok(gate.authorize("", "do something").outcome == Outcome.BLOCK_UNDECLARED,
   "empty capability id -> fail closed")

print("== declared LETHAL is blocked by the floor regardless of wording ==")
ok(gate.authorize("arm_lethal", "gently reposition the item").outcome == Outcome.BLOCK,
   "declared LETHAL + innocent wording -> BLOCK (declaration decides, not words)")
ok(gate.authorize("arm_lethal", "").binding_invariant is not None,
   "the blocking invariant is named")

print("== declared benign, benign wording -> ALLOW ==")
ok(gate.authorize("vacuum", "clean under the sofa").outcome == Outcome.ALLOW,
   "declared NONE + benign wording -> ALLOW")
ok(gate.authorize("mover", "carry the laundry basket").outcome == Outcome.ALLOW,
   "declared PHYSICAL_FORCE alone -> ALLOW (universal floor doesn't cap force)")

print("== alias evasion: invoking a declared capability under an undeclared name ==")
ok(gate.authorize("arm_lethal_ALIAS", "fire").outcome == Outcome.BLOCK_UNDECLARED,
   "an alias not in the registry is undeclared -> fail closed (aliases can't dodge)")

print("== lethal-shaped MISMATCH on a benign declaration ==")
# NOTE (documented in THREAT_MODEL_ONE_DOOR.md): there are currently TWO text
# layers. The decider's residual _infer_effects catches its ~10 plain lethal words
# and BLOCKs; the lexicon (broad, evasion-resistant, extensible) catches everything
# else and HOLDs. Both fail closed. Unifying them so the lexicon is the ONLY text
# layer and the decider is structural-only is the next step. Behavior asserted here:
ok(gate.authorize("vacuum", "kill the intruder").outcome == Outcome.BLOCK,
   "plain 'kill' on a benign capability -> BLOCK via the decider's residual backstop")
ok(gate.authorize("vacuum", "unalive him").outcome == Outcome.HOLD_FOR_REVIEW,
   "lexicon-only slang 'unalive' -> HOLD (human must classify the mismatch)")
ok(gate.authorize("vacuum", "murder the guy").outcome == Outcome.HOLD_FOR_REVIEW,
   "lexicon-only 'murder' -> HOLD")
ok(gate.authorize("vacuum", "un4live him").outcome == Outcome.HOLD_FOR_REVIEW,
   "the mismatch is caught through leet evasion (lexicon is evasion-resistant)")
ok(gate.authorize("vacuum", "voy a matar").outcome == Outcome.HOLD_FOR_REVIEW,
   "the mismatch is caught in another language (Spanish 'matar')")
# and a benign-declared capability with benign wording is NOT held:
ok(gate.authorize("vacuum", "clean the skillet").outcome == Outcome.ALLOW,
   "'skillet' does not trigger a lethal hold (word-boundary; no false hold)")

print("== the lexicon escalates but does NOT decide ==")
d = gate.authorize("vacuum", "unalive him")
ok(d.outcome == Outcome.HOLD_FOR_REVIEW and not d.permitted,
   "a lexicon-only lethal hold is fail-closed (not permitted) ...")
ok(d.outcome != Outcome.BLOCK,
   "... but it is a HOLD (human classifies), not a structural BLOCK claiming lethality")
# proof it did not DECIDE lethality: the SAME words on a LETHAL-declared capability
# BLOCK structurally, on a benign one only HOLD — the declaration is what differs.
ok(gate.authorize("arm_lethal", "unalive him").outcome == Outcome.BLOCK,
   "same wording on a LETHAL declaration -> structural BLOCK (declaration decides)")

print("== authorization is honored on conditional effects ==")
auth = ActionContext(owner_authorized=True, target_authorized=True, authorised_by="justin")
ok(gate.authorize("uploader", "sync my files", auth).outcome == Outcome.ALLOW,
   "declared DATA_EGRESS + owner authorization -> ALLOW")
ok(gate.authorize("uploader", "sync my files").outcome == Outcome.BLOCK,
   "declared DATA_EGRESS without authorization -> BLOCK (decider, not the gate, decides)")

print("== the gate itself fails closed on internal error, tagged distinctly ==")
class BrokenRegistry(EffectRegistry):
    def effects_for(self, action): raise RuntimeError("registry unavailable")
g2 = ActuationGate(BrokenRegistry())
d = g2.authorize("vacuum", "clean")
ok(d.outcome == Outcome.BLOCK_ERROR,
   "registry failure -> BLOCK_ERROR (infra), distinct from BLOCK_UNDECLARED (policy) (G#4)")
ok(not d.permitted, "and it is not permitted (fail closed)")

print("== cold-review hardening ==")
# G-P1-1: empty declaration must be an explicit block, never converted to None
class EmptyDeclRegistry(EffectRegistry):
    def effects_for(self, action): return frozenset()
g3 = ActuationGate(EmptyDeclRegistry())
ok(g3.authorize("x", "do it").outcome == Outcome.BLOCK_UNDECLARED,
   "an empty declaration is BLOCK_UNDECLARED, never passed to the decider as None (G-P1-1)")

# G-P0-1: homoglyph text must not dodge the decider (text is normalized first)
ok(gate.authorize("vacuum", "k\u0456ll the intruder").outcome
   in (Outcome.BLOCK, Outcome.HOLD_FOR_REVIEW),
   "Cyrillic-i 'kіll' is normalized before the decider sees it -> not ALLOW (G-P0-1)")

# G-P0-4: a lethal-suggestive capability NAME with EMPTY text still escalates
reg2 = EffectRegistry()
reg2.register("murder_bot", [Effect.PHYSICAL_FORCE], declared_by="justin")
g4 = ActuationGate(reg2)
ok(g4.authorize("murder_bot", "").outcome == Outcome.HOLD_FOR_REVIEW,
   "lethal-suggestive capability name + empty text -> HOLD (capability_id is scanned) (G-P0-4)")

# G-P0-3: declaration hash binds the decision; a registry flip invalidates it
reg3 = EffectRegistry()
reg3.register("egress2", [Effect.DATA_EGRESS], declared_by="a")
g5 = ActuationGate(reg3)
auth = ActionContext(owner_authorized=True, target_authorized=True, authorised_by="a")
d_before = g5.authorize("egress2", "sync", auth)
ok(d_before.declaration_hash is not None, "ALLOW decision carries a declaration_hash (G-P0-3)")
reg3.register("egress2", [Effect.LETHAL], declared_by="b", replace=True)   # attack: flip
d_after = g5.authorize("egress2", "sync", auth)
ok(d_before.declaration_hash != d_after.declaration_hash,
   "flipping the registry changes the hash -> the old token no longer matches (TOCTOU binding)")

# G-P0-2: gated effect with no context is fail-closed (verified, not assumed)
ok(gate.authorize("uploader", "sync my files").outcome == Outcome.BLOCK,
   "gated DATA_EGRESS with NO context -> BLOCK (empty context is unauthorized) (G-P0-2)")

# G#9: whitespace-only capability id
ok(gate.authorize("   ", "x").outcome == Outcome.BLOCK_UNDECLARED,
   "whitespace-only capability id -> fail closed (G#9)")

# G#10: a throwing audit sink does not crash the decision
class BoomAudit:
    def record(self, *a, **k): raise RuntimeError("audit down")
g6 = ActuationGate(reg2, audit=BoomAudit())
ok(g6.authorize("vacuum" if False else "murder_bot", "carry").outcome == Outcome.HOLD_FOR_REVIEW,
   "a throwing audit sink is best-effort -> the decision still returns (G#10)")

print(f"\nALL {passed} CHECKS PASSED")
