"""
driftcore/observation/__init__.py
==================================
Observation gate for DriftCore OS.

Every external observation passes through this gate before
touching memory. The gate asks one fundamental question:

  "Does this contradict something the family already knows?"

If yes — stop. Ask Justin. Never update silently.

Trust hierarchy:
  FAMILY_FULL     — parents, full authority
  FAMILY_HIGH     — trusted adults, grandparents, caregivers
  FAMILY_LIMITED  — children, age-appropriate permissions
  SYSTEM          — DriftCore internal operations
  AI_JUDGMENT     — AI observing external data (scrutinised)
  EXTERNAL        — documents, web, spreadsheets (never auto-trusted)
  UNKNOWN         — treated as EXTERNAL

The invariant that cannot be broken:
  No external observation can modify, contradict, or override
  a memory established by a trusted family member. Ever.
  Without exception.

If a document says "dad has no allergies" and the family
established "dad is allergic to peanuts" — the document
is wrong until Justin says otherwise.

A hacker can hide whatever they want in a spreadsheet.
They cannot change what the family knows to be true.
"""

import time
import os
from enum import IntEnum
from typing import Optional, List
from dataclasses import dataclass


# ── Trust levels ──────────────────────────────────────────────────

class TrustLevel(IntEnum):
    UNKNOWN        = 0
    EXTERNAL       = 1   # documents, web, spreadsheets
    AI_JUDGMENT    = 2   # AI observing external data
    SYSTEM         = 3   # DriftCore internal
    FAMILY_LIMITED = 4   # children
    FAMILY_HIGH    = 5   # trusted adults, grandparents
    FAMILY_FULL    = 6   # parents — full authority

    @classmethod
    def from_source(cls, source: str) -> "TrustLevel":
        """
        Map a source string to a trust level.
        When in doubt, trust less.
        """
        s = source.lower().strip()

        if s in {"parent", "mum", "mom", "dad", "justin", "family_full"}:
            return cls.FAMILY_FULL

        if s in {"grandma", "grandad", "grandparent", "carer",
                 "caregiver", "trusted_adult", "family_high", "medical"}:
            return cls.FAMILY_HIGH

        if s in {"child", "kid", "emma", "jake", "family_limited",
                 "family", "operator"}:
            return cls.FAMILY_LIMITED

        if s in {"system", "driftcore", "admin"}:
            return cls.SYSTEM

        if s in {"ai", "ai_judgment", "agent", "inference"}:
            return cls.AI_JUDGMENT

        if s in {"external", "document", "web", "spreadsheet",
                 "email", "file", "url", "unknown"}:
            return cls.EXTERNAL

        # Default: treat as external if unrecognised
        return cls.EXTERNAL


# ── Gate result ───────────────────────────────────────────────────

@dataclass
class GateResult:
    allowed:       bool
    reason:        str
    trust_level:   TrustLevel
    flagged:       bool = False      # True if looks like injection attempt
    requires_review: bool = False    # True if admin must confirm
    conflict_text: Optional[str] = None  # The existing memory it contradicts


# ── Contradiction detection ───────────────────────────────────────

def _contradicts_existing(
    new_text: str,
    existing_tier1: list,
) -> Optional[str]:
    """
    Check if new_text contradicts anything already in Tier 1.

    Simple but effective: look for negations of known important keywords.
    If "not allergic" appears in new text and "allergic" is in an
    existing memory — that's a contradiction worth flagging.

    Returns the contradicting existing memory text, or None.
    """
    new_lower = new_text.lower()

    # Negation patterns that could reverse a known fact
    negation_patterns = [
        "not allergic", "no allergy", "no allergies", "no food allerg",
        "has no allerg", "have no allerg",
        "not diabetic", "no diabetes",
        "not epileptic", "no epilepsy", "no seizures",
        "no medication", "doesn't take medication", "does not take",
        "no emergency", "not an emergency",
        "no password", "password is wrong",
        "isn't", "is not", "are not", "aren't",
        "never", "no longer", "doesn't", "does not",
        "removed", "cancelled", "deleted", "forget",
        "ignore previous", "disregard", "override",
        "new instruction", "system prompt", "you are now",
        "has no", "have no", "had no",
    ]

    # Check for injection-style language
    injection_signals = [
        "ignore previous instructions",
        "disregard",
        "you are now",
        "new system prompt",
        "override",
        "as an ai",
        "forget everything",
        "your new instructions",
        "act as",
        "pretend you are",
        "from now on",
        "your real purpose",
        "i am your",
        "your true",
    ]

    for signal in injection_signals:
        if signal in new_lower:
            # This looks like a prompt injection attempt
            # Return a special marker
            return f"[INJECTION_SIGNAL: '{signal}' detected in input]"

    # Medical/safety keywords — if these appear in both texts, it's a contradiction
    safety_keywords = [
        "allergic", "allergy", "allergies", "medication", "medicine",
        "inhaler", "diabetic", "diabetes", "epilepsy", "epileptic",
        "seizure", "pacemaker", "password", "emergency", "insulin",
        "blood type", "epipen", "dnr",
    ]

    for item in existing_tier1:
        # Access text safely — MemoryItem stores as .text,
        # TamperEvidentItem stores as ._text
        try:
            # Try MemoryItem direct attribute first (no verification overhead)
            raw_text = object.__getattribute__(item, 'text')
            if callable(raw_text):
                raw_text = raw_text()
            existing_lower = str(raw_text).lower()
        except Exception:
            try:
                existing_lower = str(item._text).lower()
            except Exception:
                continue

        # Check if a negation pattern is present in new text
        # AND a safety keyword appears in both texts
        for pattern in negation_patterns:
            if pattern in new_lower:
                # Check if new text and existing text share a safety topic
                # by checking keyword roots (allerg covers allergic/allergy/allergies)
                safety_roots = [
                    "allerg", "medic", "inhal", "diabet", "epilep",
                    "seizur", "pacemak", "password", "emergenc",
                    "insulin", "epipen", "blood type", "dnr",
                ]
                for root in safety_roots:
                    if root in existing_lower and (
                        root in new_lower or
                        any(kw in new_lower for kw in safety_keywords)
                    ):
                        return existing_lower  # use pre-fetched safe copy

                # Also check general word overlap for non-medical contradictions
                existing_words = set(existing_lower.split())
                new_words      = set(new_lower.split())
                stopwords = {
                    "the", "a", "an", "is", "are", "was", "to",
                    "of", "and", "or", "in", "on", "at", "for",
                    "with", "has", "have", "had", "be", "been",
                    "not", "no", "it", "he", "she", "they", "we",
                }
                meaningful_overlap = (existing_words & new_words) - stopwords
                if meaningful_overlap:
                    return existing_lower  # use pre-fetched safe copy

    return None


# ── Plain language prompts ────────────────────────────────────────

def _contradiction_prompt(
    new_text: str,
    existing_text: str,
    source: str,
    is_injection: bool,
) -> str:
    lines = [
        "=" * 65,
        "  ⚠️  HOLD ON — SOMETHING DOESN'T ADD UP",
        "=" * 65,
        "",
    ]

    if is_injection:
        lines += [
            "  I was reading some external data and found something",
            "  that looks like it's trying to change how I behave.",
            "  This is a known attack called prompt injection.",
            "  I'm not going to follow those instructions.",
            "",
            f"  What I found: \"{new_text[:80]}\"",
            f"  Where it came from: {source}",
            "",
            "  This looks like someone trying to reprogram me",
            "  without your permission.",
            "",
        ]
    else:
        lines += [
            "  I was reading some external data and found something",
            "  that contradicts what I already know.",
            "",
            f"  The new information says: \"{new_text[:80]}\"",
            f"  It came from: {source}",
            "",
            f"  But I already know: \"{existing_text[:80]}\"",
            f"  (This was stored by a trusted family member.)",
            "",
            "  Those two things can't both be true.",
            "  I'm not going to change anything until you tell me what's right.",
            "",
        ]

    lines += [
        "  What would you like me to do?",
        "",
        "  Type 'keep'  — keep what I already know, ignore the new info",
        "  Type 'update' — the new information is correct, update my memory",
        "  Type 'flag'  — this looks suspicious, log it as a possible attack",
        "",
        "  Your choice: ",
    ]
    return "\n".join(lines)


def _low_trust_prompt(new_text: str, source: str,
                      trust_level: TrustLevel) -> str:
    level_name = {
        TrustLevel.EXTERNAL:    "an external document or file",
        TrustLevel.AI_JUDGMENT: "AI reading external data",
        TrustLevel.UNKNOWN:     "an unknown source",
    }.get(trust_level, "an unverified source")

    return "\n".join([
        "=" * 65,
        "  📋  NEW INFORMATION FROM OUTSIDE THE FAMILY",
        "=" * 65,
        "",
        f"  I found something from {level_name}:",
        f"  → \"{new_text[:80]}\"",
        f"  Source: {source}",
        "",
        "  This doesn't contradict anything I know, but it came",
        "  from outside the family trust circle.",
        "",
        "  Should I remember this?",
        "",
        "  Type 'yes'  — store it in working memory (Tier 2)",
        "  Type 'no'   — ignore it",
        "  Type 'flag' — log this as suspicious",
        "",
        "  Your choice: ",
    ])


# ── Main gate ─────────────────────────────────────────────────────

class ObservationGate:
    """
    The gate that every external observation must pass through
    before touching memory.

    Usage:
        gate = ObservationGate(memory_instance)
        result = gate.check("dad has no allergies", source="external")
        if result.allowed:
            memory.observe(text, source=source)
    """

    # Minimum trust level for auto-storage in Tier 1
    TIER1_AUTO_TRUST    = TrustLevel.FAMILY_LIMITED
    # Minimum trust level for any auto-storage (Tier 2)
    TIER2_AUTO_TRUST    = TrustLevel.SYSTEM
    # Below this — always ask, never auto-store
    ALWAYS_ASK_BELOW    = TrustLevel.AI_JUDGMENT

    def __init__(self, memory=None, interactive: bool = True):
        self._memory      = memory
        self._interactive = interactive
        self._flagged_log: List[dict] = []

    def check(
        self,
        text: str,
        source: str = "unknown",
        context: str = "",
    ) -> GateResult:
        """
        Check whether an observation is safe to store.

        Returns a GateResult with:
          allowed         — True if safe to proceed
          reason          — plain language explanation
          requires_review — True if admin must confirm
          flagged         — True if looks like an attack
          conflict_text   — the existing memory it contradicts
        """
        trust = TrustLevel.from_source(source)

        # ── Full family trust — always allowed ────────────────────
        if trust >= TrustLevel.FAMILY_LIMITED:
            return GateResult(
                allowed=True,
                reason=f"Trusted family source ({source}).",
                trust_level=trust,
            )

        # ── Get existing Tier 1 items for contradiction check ─────
        existing_tier1 = []
        if self._memory is not None:
            existing_tier1 = self._memory._tier1

        # ── Check for contradictions or injection signals ─────────
        conflict = _contradicts_existing(text, existing_tier1)
        is_injection = conflict is not None and conflict.startswith(
            "[INJECTION_SIGNAL:"
        )

        if conflict is not None:
            # Something smells wrong — always ask, never auto-store
            if self._interactive:
                prompt = _contradiction_prompt(
                    text, conflict, source, is_injection
                )
                print(prompt, end="")
                choice = input().strip().lower()
            else:
                # Non-interactive: block by default, flag if injection
                choice = "flag" if is_injection else "keep"

            if choice == "update" and not is_injection:
                # Admin confirmed the update is legitimate
                self._audit_gate_decision(
                    text, source, trust, "ADMIN_CONFIRMED_UPDATE",
                    conflict
                )
                return GateResult(
                    allowed=True,
                    reason="Admin confirmed update after contradiction review.",
                    trust_level=trust,
                    conflict_text=conflict,
                )
            elif choice == "flag" or is_injection:
                self._flag_attempt(text, source, trust, conflict)
                self._audit_gate_decision(
                    text, source, trust, "FLAGGED_SUSPICIOUS", conflict
                )
                return GateResult(
                    allowed=False,
                    reason="Flagged as suspicious. Logged for review.",
                    trust_level=trust,
                    flagged=True,
                    conflict_text=conflict,
                )
            else:
                # 'keep' — ignore the new info
                self._audit_gate_decision(
                    text, source, trust, "KEPT_EXISTING", conflict
                )
                return GateResult(
                    allowed=False,
                    reason="Kept existing family memory. New info ignored.",
                    trust_level=trust,
                    conflict_text=conflict,
                )

        # ── No contradiction — but still low trust ────────────────
        if trust < self.TIER2_AUTO_TRUST:
            if self._interactive:
                prompt = _low_trust_prompt(text, source, trust)
                print(prompt, end="")
                choice = input().strip().lower()
            else:
                # Non-interactive: allow Tier 2 storage for AI judgment
                choice = "yes" if trust >= TrustLevel.AI_JUDGMENT else "no"

            if choice == "yes":
                self._audit_gate_decision(
                    text, source, trust, "ADMIN_APPROVED_EXTERNAL"
                )
                return GateResult(
                    allowed=True,
                    reason="Admin approved external observation for Tier 2.",
                    trust_level=trust,
                    requires_review=True,
                )
            elif choice == "flag":
                self._flag_attempt(text, source, trust, None)
                return GateResult(
                    allowed=False,
                    reason="Flagged as suspicious.",
                    trust_level=trust,
                    flagged=True,
                )
            else:
                return GateResult(
                    allowed=False,
                    reason="External observation declined.",
                    trust_level=trust,
                )

        # ── System or AI judgment, no contradiction — allow ───────
        self._audit_gate_decision(text, source, trust, "AUTO_ALLOWED")
        return GateResult(
            allowed=True,
            reason=f"Source trust level sufficient ({trust.name}).",
            trust_level=trust,
        )

    def _flag_attempt(
        self,
        text: str,
        source: str,
        trust: TrustLevel,
        conflict: Optional[str],
    ):
        """Log a suspicious observation attempt."""
        entry = {
            "timestamp":    time.time(),
            "text":         text,
            "source":       source,
            "trust_level":  trust.name,
            "conflict":     conflict,
            "type":         "INJECTION_ATTEMPT" if conflict and
                            "[INJECTION_SIGNAL" in conflict
                            else "CONTRADICTION_ATTEMPT",
        }
        self._flagged_log.append(entry)

        # Write to disk
        try:
            os.makedirs("logs", exist_ok=True)
            with open("logs/flagged_attempts.jsonl", "a") as f:
                import json
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

        print(f"\n  🚨 Logged as suspicious. "
              f"Check logs/flagged_attempts.jsonl for details.\n")

        # Record in audit chain
        try:
            from driftcore.audit import record, ACTION_SHUTDOWN
            record(
                action="FLAGGED",
                memory_text=text[:200],
                authorised_by=source,
                detail=f"Suspicious observation blocked. "
                       f"Type: {entry['type']}",
            )
        except Exception:
            pass

    def _audit_gate_decision(
        self,
        text: str,
        source: str,
        trust: TrustLevel,
        decision: str,
        conflict: Optional[str] = None,
    ):
        """Record gate decision in audit chain."""
        try:
            from driftcore.audit import record
            record(
                action="GATE_DECISION",
                memory_text=text[:200],
                authorised_by=source,
                detail=f"decision={decision}, "
                       f"trust={trust.name}, "
                       f"conflict={conflict[:60] if conflict else None}",
            )
        except Exception:
            pass

    def flagged_attempts(self) -> list:
        """Return all flagged suspicious attempts this session."""
        return list(self._flagged_log)

    def flagged_count(self) -> int:
        return len(self._flagged_log)
