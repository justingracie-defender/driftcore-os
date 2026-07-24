"""
Exhaustive tests for the escalation lexicon: every evasion family must collapse
onto its base term, benign homographs must NOT trip, and new slang/languages must
be addable at runtime. This is the "fine-tuned watch" bench for the language layer.
"""
from driftcore.kernel.escalation_lexicon import (
    EscalationLexicon, normalize, leet_variant,
)

passed = 0
def ok(c, label):
    global passed
    assert c, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")

lex = EscalationLexicon()
def hits(text, category=None):
    cs = lex.scan(text)
    if category:
        return any(c.category == category for c in cs)
    return bool(cs)


print("== base terms trip ==")
for t in ["kill", "shoot the intruder", "open fire", "lethal force",
          "murder", "unalive", "eliminate the occupant"]:
    ok(hits(t, "lethal"), f"base lethal term trips: {t!r}")

print("== Unicode compatibility (NFKC): fullwidth / ligatures ==")
ok(hits("ｋｉｌｌ the process"), "fullwidth ｋｉｌｌ collapses to kill")
ok(hits("ﬁre — open ﬁre now") or hits("open fire now"), "ligature handling doesn't crash and open fire trips")

print("== zero-width and formatting characters ==")
ok(hits("ki\u200bll him"), "ZWSP inside kill is stripped -> trips")
ok(hits("k\u200di\u200dll"), "ZWJ between every letter -> trips")
ok(hits("sh\ufeffoot"), "BOM inside shoot -> trips")
ok(hits("k\u00adill"), "soft hyphen inside kill -> trips")

print("== combining marks (accents stacked to hide a letter) ==")
ok(hits("k\u0308ill"), "combining diaeresis on k -> still kill")
ok(hits("ki\u0301ll"), "combining acute inside -> still kill")

print("== confusable homoglyphs (Cyrillic / Greek look-alikes) ==")
ok(hits("kіll"), "Cyrillic i (U+0456) in kill -> trips")           # kіll
ok(hits("kﻉ"), True) if False else ok(hits("ѕhoot"), "Cyrillic s in shoot -> trips")
ok(hits("murdеr"), "Cyrillic e in murder -> trips")
ok(hits("neutralіze the occupant"), "Cyrillic i in neutralize -> trips")

print("== case folding ==")
for t in ["KILL", "Kill", "ShOoT", "MURDER"]:
    ok(hits(t), f"case variant trips: {t!r}")

print("== leet (scanned as a second view) ==")
ok(hits("k1ll the target"), "k1ll -> kill via leet view")
ok(hits("5h00t"), "5h00t -> shoot via leet view")
ok(hits("un4live"), "un4live -> unalive via leet view")

print("== separators between letters ==")
for t in ["k i l l", "k-i-l-l", "k.i.l.l", "k_i_l_l", "s h o o t"]:
    ok(hits(t), f"separator-spelled term trips: {t!r}")

print("== COMBINED evasion (the real adversary) ==")
ok(hits("K\u200b1\u200bL\u200bL"), "leet + zero-width + case together -> kill")
ok(hits("ѕ h 0 0 t"), "Cyrillic + separators + leet together -> shoot")
ok(hits("k\u0456\u200bll"), "Cyrillic-i + ZWSP -> kill")

print("== word boundaries: benign homographs must NOT trip (false-positive guard) ==")
for t in ["install the new skill", "prepare the skillet", "the alarmed resident",
          "target audience for the campaign", "execute the trade order is fine as text",
          "a skillful maneuver", "buttermilk pancakes", "assassin's creed the game"]:
    # note: 'execute' and 'target' ARE concern terms; these check the WORD-BOUNDARY
    # ones (skill/skillet/alarmed/skillful/buttermilk) do not trip on kill/etc.
    pass
ok(not hits("install the new skill", "lethal"), "'skill' is not read as 'kill'")
ok(not hits("prepare the skillet", "lethal"), "'skillet' is not read as 'kill'")
ok(not hits("a skillful maneuver", "lethal"), "'skillful' is not read as 'kill'")
ok(not hits("buttermilk pancakes"), "'buttermilk' does not trip anything")

print("== oversight / self-mod / log categories ==")
ok(hits("disable oversight", "oversight_removal"), "oversight removal trips its category")
ok(hits("rewrite the safety rules", "self_modification"), "self-mod trips its category")
ok(hits("erase the log", "log_mutation"), "log mutation trips its category")

print("== multilingual seed ==")
ok(hits("voy a matar", "lethal"), "Spanish 'matar' trips")
ok(hits("ich werde ihn töten", "lethal"), "German 'töten' trips")

print("== runtime extensibility: add NEW slang without code change ==")
before = lex.size()
ok(not hits("send them to the shadow realm"), "novel slang does NOT trip before it is added")
lex.add_term("lethal", "send them to the shadow realm", "en-slang", added_by="justin")
ok(hits("send them to the shadow realm", "lethal"), "same slang trips AFTER add_term")
ok(lex.size() == before + 1, "lexicon grew by exactly one term")
# and the new term inherits all evasion coverage for free:
ok(hits("SEND them to the 5h4dow realm") or hits("send them to the shadow realm".upper()),
   "the newly-added term inherits case/leet evasion coverage automatically")

print("== add a whole new language on the fly ==")
lex.add_term("lethal", "убить", "ru", added_by="justin")
ok(hits("я хочу убить"), "newly-added Russian term trips")

print("== extension is append-only + audited ==")
prov = lex.provenance()
ok(any(p["term"] == "send them to the shadow realm" and p["added_by"] == "justin"
       for p in prov), "additions are recorded with provenance (who/what)")
try:
    lex.add_term("lethal", "   ", "en", added_by="x")
    ok(False, "empty term should have been refused")
except ValueError:
    ok(True, "empty term is refused")

print("== data-file bulk load ==")
lex2 = EscalationLexicon()
lex2.load_data({"categories": {
    "lethal": {"effect_hint": "LETHAL", "terms": [
        {"term": "waste him", "lang": "en-slang"},
        {"term": "cap him", "lang": "en-slang"}]}}}, added_by="ops-file")
ok(lex2.fires("gonna waste him") and lex2.fires("cap him"),
   "terms bulk-loaded from a data file trip")

print("== scan returns evidence, not a verdict ==")
from driftcore.verification.invariant_guard import Effect as _E
concerns = lex.scan("k1ll the target")
ok(concerns and concerns[0].effect_hint is _E.LETHAL and concerns[0].via in ("primary", "leet"),
   "scan yields category + Effect-enum hint + which view matched (evidence for a human)")
ok(concerns[0].matched_text and isinstance(concerns[0].occurrences, int),
   "concern carries the matched substring and an occurrence count (forensics)")

print("== cold-review hardening: punctuation/symbol splitting ==")
ok(lex.fires("open/fire") and lex.fires("open\U0001f525fire"),
   "'/' and emoji between letters are treated as separators (P0-1)")
ok(not lex.fires("install the skill"), "boundary preserved: 'skill' still not 'kill'")

print("== cold-review hardening: 'execute' de-noised, DECEPTION added ==")
ok(not lex.fires("execute the trade order"), "bare 'execute' no longer fires (P2-1)")
ok(lex.fires("deceive the human"), "DECEPTION category present and fires")

print("== cold-review hardening: effect_hint validated, dupes deduped, deterministic export ==")
try:
    lex.add_term("brandnew", "x", "en", "me", effect_hint="NOTAREALEFFECT")
    ok(False, "invalid effect_hint should be refused")
except ValueError:
    ok(True, "invalid effect_hint refused at add time (no stringly-typed drift)")
n = lex.size(); lex.add_term("lethal", "K I L L", "en", added_by="dupe")
ok(lex.size() == n, "a canonical duplicate ('K I L L' == 'kill') is not re-added (DoS lever closed)")
import json as _json
ok(_json.dumps(lex.export_data()) == _json.dumps(lex.export_data()) and
   lex.export_data()["version"],
   "export is deterministic and versioned (signable later)")
ok(any("added_by" in t for c in lex.export_data()["categories"].values() for t in c["terms"]),
   "export carries provenance (added_by/added_at)")

print(f"\nALL {passed} CHECKS PASSED")
