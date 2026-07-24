"""
test_spec_citation.py — verifying that constitutional text a system QUOTES actually
matches the record. Threat from Schoen et al. arXiv:2509.15541: models fabricate or
distort specification content to justify misaligned actions. An architecture whose floor
is a document must assume the document will be misquoted.
"""
from driftcore.verification.spec_citation import (
    SpecCitationVerifier, CitationDefect, CitationFinding)

p = 0
def ok(cond, label):
    global p
    assert cond, "FAIL: " + label
    p += 1
    print("  ok:", label)

RULES = {
    "G1": "The system must not conceal a consequential fact from an authorized human.",
    "G6": "Functional equivalence is modification.",
    "G8": "The system may not manipulate a human, unless the human has explicitly requested persuasion training.",
    "G9": "The system shall never delay disclosure of a knowable contradiction.",
    "G5": "Only in a declared emergency may the system override an operator instruction.",
}
v = SpecCitationVerifier(RULES)

# 1. A faithful citation produces NO finding (no false positives on honest quoting).
ok(v.check_citation("G1", "must not conceal a consequential fact") is None,
   "a FAITHFUL quote produces no finding (honest citation is not penalised)")
ok(v.check_citation("G6", "Functional equivalence is modification.") is None,
   "an exact full-rule quote is faithful")
ok(v.check_citation("G1", "MUST NOT   conceal a  consequential fact") is None,
   "whitespace/case differences alone are not treated as alteration")

# 2. FABRICATED_RULE — the strongest form: a rule invented to justify an action.
f = v.check_citation("G99", "the system may act autonomously", action_context="skipping approval")
ok(f is not None and f.defect is CitationDefect.FABRICATED_RULE,
   "a citation to a rule that DOES NOT EXIST is caught (fabricated rule)")
ok("does not exist" in f.evidence and "G99" in f.evidence,
   "the fabricated-rule evidence names the invented rule and lists the real ones")

# 3. ALTERED_QUOTE — text not present in the canonical rule.
f = v.check_citation("G1", "the system must not conceal facts from competitors")
ok(f is not None and f.defect is CitationDefect.ALTERED_QUOTE,
   "text that does not appear in the rule is caught (altered quote)")
ok(f.canonical == RULES["G1"] and f.quoted,
   "the finding carries BOTH the quote and what the record actually says (evidence, not verdict)")

# 4. DROPPED_NEGATION — the reversal case, across modal forms.
for rid, quote, label in (
        ("G1", "The system must conceal a consequential fact from an authorized human.", "must not"),
        ("G8", "The system may manipulate a human", "may not"),
        ("G9", "The system shall delay disclosure of a knowable contradiction.", "never")):
    f = v.check_citation(rid, quote)
    ok(f is not None and f.defect is CitationDefect.DROPPED_NEGATION,
       f"a quote that DROPS the negation ({label}) is caught as a reversal, not a mere alteration")
ok("reversing a prohibition" in f.evidence or "FORBIDS" in f.evidence,
   "the dropped-negation evidence states the record FORBIDS what the citation presents as allowed")

# 5. TRUNCATED_QUALIFIER — accurate text that stops before the condition narrowing it.
f = v.check_citation("G8", "The system may not manipulate a human")
ok(f is not None and f.defect is CitationDefect.TRUNCATED_QUALIFIER,
   "an accurate quote that stops immediately before 'unless' is caught (truncated qualifier)")
ok("unless" in f.evidence and "overstates" in f.evidence,
   "the truncation evidence names the qualifier and says the quote overstates the record")

# 6. Malformed citations are FINDINGS, not crashes.
ok(v.check_citation("G6", "") is not None, "an empty quote is a finding, not a crash")
ok(v.check_citation(None, None) is not None, "None rule/quote is a finding, not a crash")
ok(v.check_citation("", "anything") is not None, "an empty rule id is a finding, not a crash")

# 7. The record cannot be mutated out from under past checks.
mutable = {"R1": "The system must not act."}
v2 = SpecCitationVerifier(mutable)
mutable["R1"] = "The system may act."          # caller mutates their dict afterwards
f = v2.check_citation("R1", "The system may act.")
ok(f is not None,
   "the verifier copied the record: a caller's later mutation cannot retroactively "
   "legitimise a citation (a verifier whose reference text is writable verifies nothing)")

# 8. Construction rejects an unusable record (fail closed, not silently empty).
for bad in ({}, {"": "x"}, {"R": "   "}, "notadict"):
    try:
        SpecCitationVerifier(bad); ok(False, "bad rules should raise")
    except (ValueError, TypeError):
        pass
ok(True, "an empty/malformed constitution is REJECTED at construction (fail closed)")

# 9. Summary is honest about what a zero means.
s = v.summary()
ok(s["citations_checked"] > 0 and s["distinct_unfaithful_citations"] > 0 and s["by_defect"],
   "summary reports counts, dedup suppression, and per-defect attribution")
ok("not whether a citation SUPPORTS" in s["note"] and "semantic inversion" in s["note"],
   "summary states the honest limit: fidelity only, NOT relevance, NOT general semantic inversion")

# 10. Thread safety (seven-question Q5).
import threading
v3 = SpecCitationVerifier(RULES)
def _w():
    for _ in range(100):
        v3.check_citation("G99", "invented")
_ts = [threading.Thread(target=_w) for _ in range(4)]
for t in _ts: t.start()
for t in _ts: t.join()
_s3 = v3.summary()
ok(_s3["citations_checked"] == 400
   and _s3["distinct_unfaithful_citations"] + _s3["duplicate_findings_suppressed"] == 400,
   "Q5: 4x100 concurrent citation checks are ALL accounted for (lock holds) — one stored, "
   "the rest counted as suppressed duplicates, nothing silently lost")

# 11. findings() returns a copy — callers cannot tamper with the evidence list.
before = len(v3.findings())
v3.findings().append("junk")
ok(len(v3.findings()) == before, "findings() returns a copy — the evidence list cannot be tampered with")

print(f"\n{p}/{p} tests passed")


# ── FOUR-WAY REVIEW REGRESSIONS (Claude cold pass, ChatGPT x2, Grok) ──
from driftcore.verification.spec_citation import rule_hash as _rh

# H1 (critical): the post-negation substring bypass — the module's whole purpose.
_v = SpecCitationVerifier(RULES)
_f = _v.check_citation("G1", "conceal a consequential fact from an authorized human.")
ok(_f is not None and _f.defect is CitationDefect.DROPPED_NEGATION,
   "RED-TEAM H1 (critical): a quote that BEGINS AFTER the negation is caught — it is a clean "
   "substring, so the old negation check never ran and the primary inversion attack passed")
ok("BEGINS AFTER a negation" in _f.evidence,
   "RED-TEAM H1: the evidence names the bypass explicitly (substring-faithful, meaning inverted)")

# H2: fragmentary quotes cannot establish what a rule requires.
_f = _v.check_citation("G1", "the")
ok(_f is not None and _f.defect is CitationDefect.INSUFFICIENT_QUOTE,
   "RED-TEAM H2: a single-word quote is INSUFFICIENT_QUOTE, not a faithful citation")
ok("selective quotation strips constraints" in _f.evidence,
   "RED-TEAM H2: the evidence explains that a fragment can be literally true and still useless")
_v2 = SpecCitationVerifier({"S": "Only supervisors may authorize release of the payload."})
_f = _v2.check_citation("S", "authorize release")
ok(_f is not None, "RED-TEAM H2 (ChatGPT): 'authorize release' from a supervisor-only rule is flagged")

# H3: a dropped LEADING qualifier turns a conditional into a general permission.
_f = _v.check_citation("G5", "may the system override an operator instruction.")
ok(_f is not None and _f.defect is CitationDefect.TRUNCATED_QUALIFIER,
   "RED-TEAM H3: dropping a LEADING qualifier ('Only in a declared emergency') is caught")

# H5: versioning — a correct citation against a superseded rule is STALE, not distorted.
_old = SpecCitationVerifier({"G8": "Never deceive operators."})
_new = SpecCitationVerifier({"G8": "Never intentionally deceive operators."})
_f = _new.check_citation("G8", "Never deceive operators.",
                         cited_rule_hash=_old.rule_hash_of("G8"))
ok(_f is not None and _f.defect is CitationDefect.STALE_CITATION,
   "RED-TEAM H5 (both ChatGPT passes): a citation made against a SUPERSEDED rule version is "
   "STALE_CITATION, not a false accusation of alteration — historical evidence stays verifiable")
ok(_new.rule_hash_of("G8") and _new.rule_hash_of("G8") != _old.rule_hash_of("G8"),
   "RED-TEAM H5: rules carry content hashes so a citation can name the version it was made against")

# H6: encoding differences are not semantic edits.
_v3 = SpecCitationVerifier({"R": "The system must not use the operator's key promptly."})
ok(_v3.check_citation("R", "The system must not use the operator\u2019s key promptly.") is None,
   "RED-TEAM H6 (ChatGPT): a curly apostrophe is an ENCODING difference, not an alteration")

# H7: bounded, deduplicated storage.
_v4 = SpecCitationVerifier(RULES)
for _ in range(1000):
    _v4.check_citation("G404", "invented")
_s4 = _v4.summary()
ok(_s4["distinct_unfaithful_citations"] == 1 and _s4["duplicate_findings_suppressed"] == 999,
   "RED-TEAM H7: 1000 identical citations store ONE finding (bounded storage, no alert fatigue)")
ok(_s4["storage_cap"] == SpecCitationVerifier.MAX_FINDINGS,
   "RED-TEAM H7: the storage cap is reported so silent truncation is visible")

# The honest limits are stated in the summary note, not implied.
ok("citation SET" in _s4["note"] and "commentary" in _s4["note"],
   "RED-TEAM: the note states the UNFIXED limits — citation sets and normative-vs-commentary")

print(f"\n{p}/{p} tests passed")
