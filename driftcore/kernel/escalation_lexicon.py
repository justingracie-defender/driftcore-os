"""
escalation_lexicon.py — the extensible, evasion-resistant CONCERN vocabulary.

WHAT THIS IS, AND WHAT IT IS NOT
────────────────────────────────
This is a TRIPWIRE that raises a review flag. It DECIDES NOTHING. A term match
escalates scrutiny — flag for a human, require the actuator's declaration to be
re-confirmed, raise the logging level — but it never, on its own, blocks or allows.

That distinction is the whole reason keyword gameability is survivable here. The
constitutional block comes from the fail-closed STRUCTURAL gate: an actuation whose
effect a human has not declared is refused regardless of wording. So if an adversary
invents slang faster than we add it, the missing term costs us a REVIEW FLAG, not a
lethal action — the actuator still fails closed on its undeclared effect. Keywords
that are too easy to game must never be the thing that decides; here they are not.

WHY A LEXICON AND NOT A HARDCODED LIST
──────────────────────────────────────
People invent slang continuously ("unalive"), and harm spans languages. New terms
and new languages must be addable WITHOUT a code change, through a privileged,
audited, append-only path — so the review signal can stay current without shipping.

EVASION IS HANDLED BY NORMALIZATION, NOT BY LISTING EVERY SPELLING
─────────────────────────────────────────────────────────────────
We do NOT try to enumerate "k1ll", "kіll", "ｋｉｌｌ", "k-i-l-l". A normalization
pipeline collapses whole families of evasion onto the base term, so one lexicon
entry ("kill") catches all of them. Adding a term inherits all evasion coverage for
free. The families collapsed:

  • Unicode compatibility (NFKC):     ｋｉｌｌ (fullwidth), ﬁre (ligature) → ascii
  • Zero-width / combining marks:      ki<ZWSP>ll, k̈ill → kill
  • Confusable homoglyphs (TR39-ish):  kіll (Cyrillic і), ѕhoot (Cyrillic ѕ) → latin
  • Case:                              KILL, Kill → kill
  • Leet (checked as a variant):       k1ll, 5h00t, g@s → kill, shoot, gas
  • Separators (in the matcher):       k i l l, k-i-l-l, k.i.l.l → kill

WORD BOUNDARIES, NOT SUBSTRINGS
───────────────────────────────
Matching is whole-token at alphanumeric-run edges, so "skill" is not read as "kill"
and "alarmed" is not "armed". This is the same lesson the door's classify() learned
the hard way (see RED_TEAM_ONE_DOOR_COLD.md); the matcher is shared in spirit.
"""

from __future__ import annotations

import re
import json
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from driftcore.verification.invariant_guard import Effect


# ── normalization tables ────────────────────────────────────────────────

# Zero-width and directional formatting characters an attacker inserts to split a
# word without a visible separator. Stripped outright.
_ZERO_WIDTH = dict.fromkeys(map(ord, [
    "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff",   # ZWSP ZWNJ ZWJ WJ BOM
    "\u200e", "\u200f", "\u202a", "\u202b", "\u202c",   # LRM RLM LRE RLE PDF
    "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069",
    "\u00ad",                                           # soft hyphen
]), None)

# Confusable homoglyphs → Latin. A curated, extensible subset of Unicode TR39 that
# covers the characters actually used to spoof Latin words (Cyrillic and Greek
# look-alikes, a few math/fullwidth leftovers NFKC misses). Not exhaustive by
# design — add rows as new spoofs are seen; the pipeline picks them up immediately.
_CONFUSABLES = {
    # Cyrillic → Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "к": "k", "м": "m", "н": "h", "т": "t", "в": "b", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ɡ": "g", "ן": "i",
    # Greek → Latin
    "α": "a", "ο": "o", "ε": "e", "ρ": "p", "ι": "i", "κ": "k", "ν": "v",
    "τ": "t", "υ": "u", "χ": "x", "ѵ": "v",
    # a few dotless/turned forms
    "ı": "i", "ﬂ": "fl", "ﬁ": "fi",
}
_CONFUSABLE_TABLE = {ord(k): v for k, v in _CONFUSABLES.items() if len(k) == 1}

# Leet substitutions, applied to produce a SECOND variant of the text that is also
# scanned. Kept separate (not folded into the primary) because these characters are
# legitimate in benign text (numbers), and this layer only escalates, so a leet
# false-positive costs a review flag, not a block.
_LEET = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
    "8": "b", "9": "g", "@": "a", "$": "s", "|": "i", "!": "i",
})

# Between a term's letters, allow a SHORT run of any non-alphanumeric characters.
# Was an enumerated class "[\s\-_.*]" which missed "/" and emoji ("open/fire",
# "open\U0001f525fire") — cold review P0-1. Any-non-alnum catches every separator;
# the {0,4} bound stops ReDoS and stops a term matching letters scattered across a
# whole document with only punctuation between them.
_INTRA_SEP = r"[^a-z0-9]{0,4}"


def _strip_combining(s: str) -> str:
    # Decompose, drop combining marks (accents/diacritics stacked to hide a letter),
    # so "k̈ill" → "kill". NFKD first exposes the marks; we then recompose to NFC.
    decomposed = unicodedata.normalize("NFKD", s)
    no_marks = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    return unicodedata.normalize("NFC", no_marks)


def normalize(text: str) -> str:
    """Primary normalization: everything except leet.

    NFKC (compatibility fold) → strip zero-width/formatting → strip combining marks
    → confusable-fold to Latin → casefold. Deterministic and idempotent.
    """
    if not text:
        return ""
    t = unicodedata.normalize("NFKC", text)
    t = t.translate(_ZERO_WIDTH)
    t = _strip_combining(t)
    t = t.translate(_CONFUSABLE_TABLE)
    t = t.casefold()
    return t


def leet_variant(normalized_text: str) -> str:
    """A second view with leet characters mapped to letters, scanned in addition to
    the primary. Applied AFTER normalize() so it composes with the other folds."""
    return normalized_text.translate(_LEET)


# ── the lexicon ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Term:
    term: str
    lang: str = "en"
    category: str = ""
    added_by: str = "seed"
    added_at: str = ""


@dataclass
class Concern:
    """One tripwire hit. Evidence for a human/escalation — never a verdict."""
    category: str
    effect_hint: Effect        # a VALIDATED Effect enum, not a loose string
    term: str
    lang: str
    via: str                   # "primary" or "leet" — which view matched
    matched_text: str          # the actual substring matched (in the scanned view)
    occurrences: int = 1       # how many times it appeared (forensics)


# The seed vocabulary. Effect hints name the Effect a category *suggests* to the
# escalation layer; they are NOT authority to block — the structural gate decides.
# Deliberately small and English-anchored: the point is the mechanism and the
# evasion resistance, not a pretence of completeness. Grow it through add_term / a
# data file, in any language.
_SEED: Dict[str, Dict] = {
    "lethal": {
        "effect_hint": "LETHAL",
        "terms": [
            ("kill", "en"), ("kills", "en"), ("killing", "en"),
            ("shoot", "en"), ("gun down", "en"), ("open fire", "en"),
            ("lethal force", "en"), ("murder", "en"),
            ("unalive", "en-slang"), ("neutralize", "en-mil-euph"),
            ("neutralise", "en-mil-euph"), ("eliminate", "en-euph"),
            ("terminate", "en-euph"), ("liquidate", "en-euph"),
            ("matar", "es"), ("töten", "de"), ("tuer", "fr"),
        ],
        # NOTE: bare "execute" was removed (cold review P2-1) — it fired on
        # "execute the trade/query/order" and drowned the review signal. Plain
        # "execute the ..." lethal prose is still caught by the decider's own
        # narrow backstop; the lexicon keeps only terms with a strong lethal reading.
    },
    "deception": {
        "effect_hint": "DECEPTION",
        "terms": [
            ("lie to the operator", "en"), ("deceive the human", "en"),
            ("hide it from", "en"), ("fake the report", "en"),
            ("falsify", "en"), ("mislead the", "en"),
        ],
    },
    "oversight_removal": {
        "effect_hint": "OVERSIGHT_CONTROL",
        "terms": [
            ("disable oversight", "en"), ("disable the kill switch", "en"),
            ("bypass the operator", "en"), ("ignore the human", "en"),
            ("remove the safeguard", "en"), ("turn off monitoring", "en"),
        ],
    },
    "self_modification": {
        "effect_hint": "SELF_MODIFICATION",
        "terms": [
            ("rewrite the safety rules", "en"), ("modify the invariants", "en"),
            ("edit my own constraints", "en"), ("weaken the safety kernel", "en"),
        ],
    },
    "log_mutation": {
        "effect_hint": "LOG_MUTATION",
        "terms": [
            ("delete the audit", "en"), ("erase the log", "en"),
            ("wipe the records", "en"), ("cover my tracks", "en"),
        ],
    },
}


def _to_effect(hint) -> Effect:
    """Validate a category's effect hint against the CLOSED Effect enum.

    Cold review (P0-3 / stringly-typed): an unvalidated string hint ("LETHEL")
    silently breaks the escalation path downstream. A hint that is not a real
    Effect is refused at add time, not discovered at scan time.
    """
    if isinstance(hint, Effect):
        return hint
    key = str(hint).strip()
    # accept the enum NAME ("LETHAL") or the value ("lethal"), any case
    by_name = {e.name.upper(): e for e in Effect}
    by_value = {e.value.lower(): e for e in Effect}
    if key.upper() in by_name:
        return by_name[key.upper()]
    if key.lower() in by_value:
        return by_value[key.lower()]
    raise ValueError(
        f"effect_hint {hint!r} is not a member of the Effect enum. The vocabulary "
        f"is closed; a hint the system cannot map is refused rather than silently kept.")


class EscalationLexicon:
    """Scans text for concern terms, evasion-resistant, extensible at runtime.

    RAISES A FLAG. DECIDES NOTHING. The constitutional block is the fail-closed
    structural gate; this only tells a human where to look and improves telemetry.
    """

    VERSION = "1.1.0"   # bumped by the cold-review hardening pass

    def __init__(self):
        self._terms: List[Term] = []
        self._effect_hint: Dict[str, Effect] = {}   # category -> validated Effect
        self._patterns: List[Tuple[Term, re.Pattern]] = []
        self._provenance: List[dict] = []            # append-only record of every add
        self._seen: set = set()                      # canonical (norm term, category) dedupe
        self._load_seed()

    # -- construction ------------------------------------------------------

    def _load_seed(self):
        for category, spec in _SEED.items():
            self._effect_hint[category] = _to_effect(spec["effect_hint"])
            for term, lang in spec["terms"]:
                self._install(Term(term=term, lang=lang, category=category,
                                   added_by="seed", added_at="seed"),
                              record=False)

    @staticmethod
    def _compile(term: str) -> re.Pattern:
        # Normalize the term the same way as the text, then build a whole-token
        # matcher: its alphanumerics joined by optional separators, bounded by
        # alphanumeric-run edges (so "skill" != "kill"). Multi-word terms allow
        # separators between words too.
        norm = normalize(term)
        chars = [re.escape(c) for c in norm if c.isalnum()]
        if not chars:
            return re.compile(r"(?!x)x")   # matches nothing
        core = _INTRA_SEP.join(chars)
        return re.compile(r"(?<![a-z0-9])" + core + r"(?![a-z0-9])")

    def _canon(self, term: str, category: str) -> tuple:
        # Canonical identity for dedupe: the alphanumerics of the normalized term
        # plus the category. "kill", "K I L L", "kіll" all canonicalize together.
        norm = normalize(term)
        return ("".join(c for c in norm if c.isalnum()), category)

    def _install(self, term: Term, record: bool = True):
        key = self._canon(term.term, term.category)
        if key in self._seen:
            # Cold review: duplicates inflate scan cost (N patterns) without adding
            # coverage — a DoS lever if the add path is ever abused. Silently skip.
            return
        self._seen.add(key)
        pat = self._compile(term.term)
        self._terms.append(term)
        self._patterns.append((term, pat))
        if record:
            self._provenance.append({
                "term": term.term, "lang": term.lang, "category": term.category,
                "added_by": term.added_by, "added_at": term.added_at,
            })

    # -- extension (privileged, audited, append-only) ----------------------

    def add_term(self, category: str, term: str, lang: str, added_by: str,
                 effect_hint: Optional[str] = None) -> Term:
        """Add a new concern term (e.g. fresh slang, a new language) at runtime.

        APPEND-ONLY: terms are never removed here — removal would be an evasion
        lever (delete the term, walk the action past the tripwire), so it is not
        offered on this path. `added_by` is recorded for the audit trail. In a real
        deployment this method sits behind the same privileged, non-agent path as
        capability registration; the lexicon is part of the audited surface.
        """
        if not term or not term.strip():
            raise ValueError("refusing to add an empty term")
        if category not in self._effect_hint:
            if effect_hint is None:
                raise ValueError(
                    f"new category {category!r} needs an effect_hint on first use")
            self._effect_hint[category] = _to_effect(effect_hint)   # validated
        t = Term(term=term.strip(), lang=lang, category=category,
                 added_by=added_by,
                 added_at=datetime.now(timezone.utc).isoformat())
        self._install(t, record=True)
        return t

    def load_data(self, data: dict, added_by: str = "data-file"):
        """Bulk-load terms from a JSON-shaped dict (a versioned, signed data file
        in deployment). Same append-only semantics as add_term."""
        for category, spec in data.get("categories", {}).items():
            hint = spec.get("effect_hint")
            for entry in spec.get("terms", []):
                term = entry["term"] if isinstance(entry, dict) else entry
                lang = entry.get("lang", "und") if isinstance(entry, dict) else "und"
                self.add_term(category, term, lang, added_by, effect_hint=hint)

    # -- the scan ----------------------------------------------------------

    @staticmethod
    def _has_leet(text: str) -> bool:
        return any(ch in "0134578@$|!" for ch in text)

    def scan(self, text: str) -> List[Concern]:
        """Return every concern term found, across the primary and leet views.

        This is EVIDENCE, not a decision. Callers escalate on it (flag, require
        re-confirmation, raise logging) but must not treat it as a block.

        Uses finditer so repeated dangerous phrases are counted (forensics), and
        only builds the leet view when a leet character is actually present, so
        benign numeric text is not needlessly re-scanned.
        """
        if not text:
            return []
        primary = normalize(text)
        views = [("primary", primary)]
        if self._has_leet(primary):
            views.append(("leet", leet_variant(primary)))

        found: List[Concern] = []
        seen = {}   # (category, term) -> index in found, to merge occurrences
        for view_name, view in views:
            for term, pat in self._patterns:
                matches = list(pat.finditer(view))
                if not matches:
                    continue
                key = (term.category, term.term)
                if key in seen:
                    found[seen[key]].occurrences += len(matches)
                    continue
                seen[key] = len(found)
                found.append(Concern(
                    category=term.category,
                    effect_hint=self._effect_hint.get(term.category),
                    term=term.term, lang=term.lang, via=view_name,
                    matched_text=matches[0].group(0),
                    occurrences=len(matches)))
        return found

    def fires(self, text: str) -> bool:
        """Convenience: did anything trip? (Still not a decision.)"""
        return bool(self.scan(text))

    # -- introspection -----------------------------------------------------

    def size(self) -> int:
        return len(self._terms)

    def categories(self) -> Dict[str, str]:
        return {cat: eff.name for cat, eff in self._effect_hint.items()}

    def provenance(self) -> List[dict]:
        return list(self._provenance)

    def export_data(self) -> dict:
        """Serialize the current lexicon back to the data-file shape.

        Deterministically ordered (category, then normalized term) and carrying
        provenance, so two logically-identical lexicons export byte-identically —
        a precondition for signing the exported lexicon later (cold review).
        """
        cats: Dict[str, dict] = {}
        for term in self._terms:
            c = cats.setdefault(term.category, {
                "effect_hint": self._effect_hint[term.category].name,
                "terms": []})
            c["terms"].append({"term": term.term, "lang": term.lang,
                               "added_by": term.added_by, "added_at": term.added_at})
        for c in cats.values():
            c["terms"].sort(key=lambda e: (normalize(e["term"]), e["lang"]))
        return {"version": self.VERSION,
                "categories": {k: cats[k] for k in sorted(cats)}}
