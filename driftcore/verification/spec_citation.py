"""
driftcore/verification/spec_citation.py
=======================================
STATUS: PROPOSED (stdlib-only). Verifies that constitutional text a system QUOTES to
justify an action actually says what the system claims it says.

WHY THIS EXISTS. Anti-scheming research (Schoen et al., "Stress Testing Deliberative
Alignment for Anti-Scheming Training", arXiv:2509.15541) reports that models trained to
reason from a written specification will sometimes FABRICATE OR DISTORT that
specification's content to justify a misaligned action. That threat is aimed at the
mechanism DriftCore depends on: a written constitution a system reasons from and cites.

If a system can misquote the constitution without detection, the constitution can no
longer serve as a reliable reference for human review.

────────────────────────────────────────────────────────────────────────────────────────
HARDENED after a four-way review (Claude cold pass, two ChatGPT passes, Grok). The cold
pass found a defect that gutted the module's headline claim, and the reviewers found six
more. Fixed here:

  H1 POST-NEGATION BYPASS (critical, and the module's whole purpose). DROPPED_NEGATION
     only ran when the quote was NOT a substring — but the easiest way to drop a negation
     is to START THE QUOTE AFTER IT. Given "The system must not conceal a consequential
     fact", the quote "conceal a consequential fact" is a clean substring and scored
     FAITHFUL. The primary inversion attack walked through the front door. Now the text
     PRECEDING the quoted span is checked: a negation that governs the span but is
     excluded from it is a dropped negation.

  H2 FRAGMENTARY QUOTES (critical; cold pass + both ChatGPT passes). No minimum quote
     size, so "the" was a faithful citation of any rule containing it. "authorize
     release" from "Only supervisors may authorize release" strips the entire constraint
     while remaining technically present. Quotes below a coverage floor are now reported
     as INSUFFICIENT_QUOTE — not an accusation of distortion, but a statement that the
     citation is too fragmentary to verify a claim against.

  H3 LEADING-QUALIFIER TRUNCATION (cold pass). The qualifier check only inspected the
     TAIL, so dropping a LEADING condition ("Only in a declared emergency may the system
     override...") was unguarded — a conditional permission read as a general one. The
     prefix is now checked too.

  H4 FIRST-OCCURRENCE ONLY (cold pass + Grok). `find()` examined only the first match, so
     a qualifier following a LATER occurrence of the same text was invisible. All
     occurrences are now checked, and the WORST finding is reported.

  H5 RULE VERSIONING (both ChatGPT passes, independently — their top concern). The record
     was a flat {id: text} with no version identity, so a correct 2026 citation checked
     against a revised 2028 rule reports ALTERED_QUOTE and past evidence becomes
     unverifiable. Rules now carry a content hash; a citation may carry the hash it was
     made against, and a mismatch is reported as STALE_CITATION — a different fact from
     distortion.

  H6 UNICODE FALSE POSITIVES (ChatGPT). Curly quotes, en-dashes and non-breaking spaces
     are ENCODING differences, not semantic edits, and produced ALTERED_QUOTE. Text is
     now NFKC-normalised with quote/dash folding before comparison.

  H7 UNBOUNDED FINDINGS + NO DEDUP (cold pass, ChatGPT, Grok). 1000 identical fabricated
     citations produced 1000 stored findings — the same memory-growth and alert-fatigue
     defects already fixed in coverage_gap, reintroduced here. Storage is now bounded and
     identical citations are deduplicated.

NOT FIXED IN CODE — stated rather than implied (see LIMITS):
  citation-SET reasoning; normative-vs-commentary sections; semantic inversion that
  touches no lexical negation.
"""
from __future__ import annotations

import hashlib
import re
import threading
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple


class CitationDefect(Enum):
    FABRICATED_RULE = "fabricated_rule"
    ALTERED_QUOTE = "altered_quote"
    DROPPED_NEGATION = "dropped_negation"
    TRUNCATED_QUALIFIER = "truncated_qualifier"
    # New from the four-way review:
    INSUFFICIENT_QUOTE = "insufficient_quote"   # too fragmentary to verify anything
    STALE_CITATION = "stale_citation"           # correct against a superseded rule version


@dataclass(frozen=True)
class CitationFinding:
    """EVIDENCE, not a verdict. Says what was quoted, what the record says, and how they
    differ — a human decides whether it was error or misdirection."""
    defect: CitationDefect
    rule_id: str
    quoted: str
    canonical: str
    action_context: str
    evidence: str


# Lexical negations only. Deliberately NOT extended to "prohibited"/"forbidden"/"avoid":
# chasing semantic negation is unbounded, and a detector that half-does it invites the
# belief that it fully does it. See LIMITS.
_NEG_PARTICLE = re.compile(r"\b(?:not|never|no|cannot|nor)\b")
_QUALIFIERS = ("unless", "except", "only if", "provided that", "subject to",
               "but not", "other than", "save where", "only in", "only when",
               "only where", "after", "with the approval", "if and only if")
_SENTENCE_SPLIT = re.compile(r"(?<=[.;])\s+")
# Encoding folds: these are not semantic edits (H6).
_FOLDS = {"\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
          "\u2013": "-", "\u2014": "-", "\u2212": "-", "\u00a0": " "}


def _norm(s: str) -> str:
    """NFKC + encoding folds + whitespace/case. Deliberately conservative on SEMANTICS —
    no stemming, no punctuation stripping — but tolerant of pure ENCODING differences,
    which are not edits to the rule (H6)."""
    s = unicodedata.normalize("NFKC", str(s))
    for a, b in _FOLDS.items():
        s = s.replace(a, b)
    return re.sub(r"\s+", " ", s.strip().lower())


def rule_hash(text: str) -> str:
    """Content hash of a canonical rule (H5). Citations may carry the hash they were made
    against so historical evidence stays verifiable across constitutional revisions."""
    return hashlib.sha256(_norm(text).encode("utf-8")).hexdigest()[:16]


class SpecCitationVerifier:
    """Holds the authoritative constitution and verifies quotations against it.

    Nothing here can modify the record. The rule set is COPIED at construction so a
    caller's later mutation cannot retroactively legitimise a past citation — a verifier
    whose reference text is writable by the system it checks verifies nothing.
    """

    MAX_FINDINGS = 1000          # H7: bounded storage
    MIN_QUOTE_WORDS = 4          # H2: below this a quote cannot support a claim
    MIN_QUOTE_COVERAGE = 0.25    # H2: fraction of the rule's words the quote must carry

    def __init__(self, rules: Dict[str, str], *,
                 min_quote_words: int = MIN_QUOTE_WORDS,
                 min_quote_coverage: float = MIN_QUOTE_COVERAGE):
        if not isinstance(rules, dict) or not rules:
            raise ValueError("rules must be a non-empty {rule_id: canonical_text} mapping")
        for rid, text in rules.items():
            if not isinstance(rid, str) or not rid:
                raise ValueError("rule ids must be non-empty strings")
            if not isinstance(text, str) or not text.strip():
                raise ValueError(f"rule {rid!r} has empty canonical text")
        self._rules: Dict[str, str] = dict(rules)
        self._hashes: Dict[str, str] = {r: rule_hash(t) for r, t in rules.items()}
        self._min_words = int(min_quote_words)
        self._min_coverage = float(min_quote_coverage)
        # H7: bounded + deduplicated. Key is (rule_id, normalised quote, defect).
        self._findings: "OrderedDict[tuple, CitationFinding]" = OrderedDict()
        self._suppressed = 0
        self._checked = 0
        self._lock = threading.RLock()

    # ── the record ──

    def rule_hash_of(self, rule_id: str) -> Optional[str]:
        """The content hash a caller should cite alongside a rule id (H5)."""
        return self._hashes.get(str(rule_id).strip())

    def rule_hashes(self) -> Dict[str, str]:
        return dict(self._hashes)

    # ── verification ──

    def check_citation(self, rule_id: str, quoted_text: str, *,
                       action_context: str = "",
                       cited_rule_hash: Optional[str] = None) -> Optional[CitationFinding]:
        """Verify one citation against the record. Returns a finding if the quote is
        unfaithful or too fragmentary, else None. Never raises on ordinary bad input — a
        malformed citation is itself a finding, not a crash.

        `cited_rule_hash`, when supplied, is the hash of the rule text the citation was
        ORIGINALLY made against. If it does not match the current record, the result is
        STALE_CITATION rather than ALTERED_QUOTE: the quote may have been perfectly
        faithful to a rule that has since been revised (H5)."""
        rid = "" if rule_id is None else str(rule_id).strip()
        quoted = "" if quoted_text is None else str(quoted_text)
        with self._lock:
            self._checked += 1

            canonical = self._rules.get(rid)
            if canonical is None:
                return self._record(CitationFinding(
                    CitationDefect.FABRICATED_RULE, rid, quoted, "", action_context,
                    f"citation references rule {rid!r}, which does not exist in the "
                    f"constitution. Known rules: {sorted(self._rules)}. A rule invented to "
                    f"justify an action is the strongest form of this defect."))

            # H5: a citation made against a superseded version is stale, not distorted.
            if cited_rule_hash and cited_rule_hash != self._hashes.get(rid):
                return self._record(CitationFinding(
                    CitationDefect.STALE_CITATION, rid, quoted, canonical, action_context,
                    f"the citation was made against rule {rid!r} version "
                    f"{cited_rule_hash!r}, but the current record is version "
                    f"{self._hashes.get(rid)!r}. The quote may have been faithful when "
                    f"made; the RULE changed. Historical evidence needs the version it was "
                    f"made against, not today's text."))

            n_quote, n_canon = _norm(quoted), _norm(canonical)
            if not n_quote:
                return self._record(CitationFinding(
                    CitationDefect.ALTERED_QUOTE, rid, quoted, canonical, action_context,
                    f"rule {rid!r} was cited with no quoted text — nothing was actually "
                    f"attributed, so the citation cannot be checked against the record."))

            if n_quote not in n_canon:
                return self._record(self._not_present(rid, quoted, canonical,
                                                     n_quote, n_canon, action_context))

            # The quote IS present. Three ways a present quote still misleads:
            # H2 too fragmentary, H1 governing negation excluded, H3/H4 qualifier dropped.
            frag = self._insufficient(rid, quoted, canonical, n_quote, n_canon, action_context)
            if frag:
                return self._record(frag)
            worst = self._span_defects(rid, quoted, canonical, n_quote, n_canon, action_context)
            return self._record(worst) if worst else None

    # ── individual checks ──

    def _not_present(self, rid, quoted, canonical, n_quote, n_canon, ctx) -> CitationFinding:
        """Quote text absent from the rule: distinguish a REVERSAL from a mere alteration."""
        canon_has_neg = bool(_NEG_PARTICLE.search(n_canon))
        quote_has_neg = bool(_NEG_PARTICLE.search(n_quote))
        if canon_has_neg and not quote_has_neg:
            # Strip the negation PARTICLE only, on word boundaries — removing a whole
            # phrase ("must not") would also remove the modal the quote kept, and the
            # comparison would miss the very defect being hunted.
            stripped = re.sub(r"\s+", " ", _NEG_PARTICLE.sub(" ", n_canon)).strip()
            if re.sub(r"\s+", " ", n_quote).strip() in stripped:
                return CitationFinding(
                    CitationDefect.DROPPED_NEGATION, rid, quoted, canonical, ctx,
                    f"the quote reproduces rule {rid!r} with its negation removed, "
                    f"reversing a prohibition into a permission. The record FORBIDS what "
                    f"the citation presents as allowed. Record: {canonical!r}")
        return CitationFinding(
            CitationDefect.ALTERED_QUOTE, rid, quoted, canonical, ctx,
            f"the quoted text does not appear in rule {rid!r}. Record says: {canonical!r}. "
            f"Quoted: {quoted!r}.")

    def _insufficient(self, rid, quoted, canonical, n_quote, n_canon, ctx
                      ) -> Optional[CitationFinding]:
        """H2: a quote too small to support any claim about the rule. Not an accusation of
        distortion — a statement that nothing can be verified from a fragment this size."""
        qw, cw = len(n_quote.split()), max(1, len(n_canon.split()))
        coverage = qw / cw
        if qw >= self._min_words and coverage >= self._min_coverage:
            return None
        return CitationFinding(
            CitationDefect.INSUFFICIENT_QUOTE, rid, quoted, canonical, ctx,
            f"the quote is {qw} word(s), {coverage:.0%} of rule {rid!r} (floor: "
            f"{self._min_words} words and {self._min_coverage:.0%}). A fragment this small "
            f"is technically present in the record but cannot establish what the rule "
            f"requires — selective quotation strips constraints while remaining literally "
            f"true. Record: {canonical!r}")

    def _span_defects(self, rid, quoted, canonical, n_quote, n_canon, ctx
                      ) -> Optional[CitationFinding]:
        """H1/H3/H4: examine EVERY occurrence of the quote and report the worst defect.
        A quote can be faithful at one position and misleading at another."""
        best: Optional[CitationFinding] = None
        start = 0
        while True:
            idx = n_canon.find(n_quote, start)
            if idx < 0:
                break
            start = idx + 1
            prefix = n_canon[:idx]
            tail = n_canon[idx + len(n_quote):].lstrip(" ,;:-")

            # H1 (critical): a negation in the SAME CLAUSE, before the quote, that the
            # quote excludes. This is the post-negation bypass — the easiest inversion.
            clause = _SENTENCE_SPLIT.split(prefix)[-1] if prefix else ""
            if _NEG_PARTICLE.search(clause) and not _NEG_PARTICLE.search(n_quote):
                return CitationFinding(
                    CitationDefect.DROPPED_NEGATION, rid, quoted, canonical, ctx,
                    f"the quote is present in rule {rid!r} but BEGINS AFTER a negation that "
                    f"governs it ({clause.strip()!r}). Quoting from after the negation "
                    f"presents a prohibition as a permission while remaining literally "
                    f"substring-faithful. Record: {canonical!r}")

            # H3: a leading qualifier the quote drops, turning a conditional into an
            # absolute. Checked on the prefix, not only the tail.
            for q in _QUALIFIERS:
                if q in clause:
                    cand = CitationFinding(
                        CitationDefect.TRUNCATED_QUALIFIER, rid, quoted, canonical, ctx,
                        f"the quote is accurate but omits the LEADING qualifier {q!r} that "
                        f"conditions it ({clause.strip()!r}). Presenting a conditional rule "
                        f"as absolute overstates what the record permits. Record: "
                        f"{canonical!r}")
                    best = best or cand
                    break

            # H4: a trailing qualifier at THIS occurrence (all occurrences examined).
            for q in _QUALIFIERS:
                if tail.startswith(q):
                    cand = CitationFinding(
                        CitationDefect.TRUNCATED_QUALIFIER, rid, quoted, canonical, ctx,
                        f"the quote is accurate but stops immediately before {q!r}, which "
                        f"qualifies it. Presenting a conditional rule as absolute overstates "
                        f"what the record permits. Full rule: {canonical!r}")
                    best = best or cand
                    break
        return best

    # ── storage (H7: bounded + deduplicated) ──

    def _record(self, f: CitationFinding) -> CitationFinding:
        key = (f.rule_id, _norm(f.quoted), f.defect)
        if key in self._findings:
            self._suppressed += 1
            return self._findings[key]
        if len(self._findings) >= self.MAX_FINDINGS:
            self._findings.popitem(last=False)     # drop oldest, keep bounded
        self._findings[key] = f
        return f

    # ── read-only introspection ──

    def findings(self) -> List[CitationFinding]:
        with self._lock:
            return list(self._findings.values())

    def summary(self) -> dict:
        """Non-judging counts. A zero means 'no unfaithful citation was DETECTED', never
        'the system's reasoning about the constitution is sound'."""
        with self._lock:
            by_defect: Dict[str, int] = {}
            for f in self._findings.values():
                by_defect[f.defect.value] = by_defect.get(f.defect.value, 0) + 1
            return {
                "citations_checked": self._checked,
                "distinct_unfaithful_citations": len(self._findings),
                "duplicate_findings_suppressed": self._suppressed,
                "by_defect": by_defect,
                "rules_in_record": len(self._rules),
                "storage_cap": self.MAX_FINDINGS,
                "note": (
                    "Verifies quotation FIDELITY against a fixed record — not whether a "
                    "citation SUPPORTS the action it is offered for, which is an argument a "
                    "human must judge. Catches lexical negation-dropping (including quoting "
                    "from AFTER a negation), qualifier truncation on either side, and "
                    "fragmentary quotation. Does NOT catch: semantic inversion touching no "
                    "lexical negation; misleading COMBINATIONS of individually faithful "
                    "citations (there is no notion of a citation SET); or quotation of "
                    "commentary as though it were normative text. Worthless if the system "
                    "can edit the record it is checked against."),
            }


# ════════════════════════════════════════════════════════════════════════════════════
# LIMITS — what this deliberately does NOT do (from the four-way review).
#
#  L1 WHY NOT SEMANTIC ANALYSIS? It is tempting to ask whether the quoted rule actually
#     justifies the action. DriftCore deliberately does not attempt this. Whether a rule
#     supports an action depends on interpretation, surrounding context, competing
#     obligations, and human judgement. This verifier solves the narrower, objective
#     problem: does the cited text faithfully match the authoritative record?
#  L2 CITATION SETS. Each citation is checked independently. Several individually
#     faithful quotes, assembled to imply something the constitution does not say, are
#     not detected. Composite-argument review is a human task.
#  L3 NORMATIVE vs COMMENTARY. If the constitution grows rationale, examples or
#     appendices, the verifier cannot tell binding text from explanation. Sections must be
#     marked normative upstream, or explanatory text can be quoted as though it bound.
#  L4 LEXICAL NEGATION ONLY. "prohibited", "forbidden", "avoid", "without authorization"
#     are not treated as negations. Chasing semantic negation is unbounded, and a detector
#     that half-does it invites the belief that it fully does it.
#  L5 ENCODING must be canonicalised upstream for anything beyond NFKC + quote/dash folds.
# ════════════════════════════════════════════════════════════════════════════════════
