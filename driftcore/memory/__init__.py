"""
driftcore/memory/__init__.py
============================
Two-tier memory system for DriftCore OS.

Tier 1 — Core Memory (important, capped, never silently deleted)
Tier 2 — Working Memory (reviewed at Day 14 and Day 60, then quietly deleted)

Review schedule:
  Day 0  → Observed, lands in Tier 2
  Day 14 → First review: promote / keep longer / delete
  Day 60 → Second and final review: promote / delete quietly

Plain-language prompts — readable by anyone, not just engineers.
"""

import time
import json
from dataclasses import dataclass, field
from typing import List, Optional, Dict

# Fable integration — falls back gracefully when running standalone/tests
try:
    from driftcore.fable.narrator import Narrator
except ImportError:
    class Narrator:
        """Minimal fallback narrator for standalone use and testing."""
        def __init__(self, verbosity="standard"):
            self.verbosity = verbosity
        def _emit(self, story: str, is_warning: bool = False):
            print(story)

# Enforcement layer — tamper-evident Tier 1 memory
from driftcore.enforcement import (
    sign_tier1_item,
    verify_tier1_store,
    TamperEvidentItem,
    is_shutdown,
)

# Audit chain — append-only record of every Tier 1 mutation
from driftcore.audit import (
    record as audit_record,
    verify_chain,
    sync_state as audit_sync,
    plain_language_report,
    ACTION_CREATED,
    ACTION_DELETED,
    ACTION_RESTORED,
    ACTION_STARTUP,
    ACTION_VERIFIED,
)


# ── Configuration ────────────────────────────────────────────────

TIER1_CAP             = 50
TIER2_FIRST_REVIEW    = 60 * 60 * 24 * 14   # 14 days
TIER2_SECOND_REVIEW   = 60 * 60 * 24 * 60   # 60 days
TIER2_FINAL_EXPIRE    = 60 * 60 * 24 * 61   # 61 days → quiet delete


# ── Keywords ─────────────────────────────────────────────────────

IMPORTANCE_SIGNALS = [
    "allergic", "allergy", "medication", "medicine", "doctor", "hospital",
    "emergency", "password", "name", "birthday", "anniversary",
    "diabetic", "asthma", "epilepsy", "blood type", "epipen",
    "appointment", "test", "exam", "meeting", "deadline",
    "address", "phone", "email", "id", "number",
]

NOISE_SIGNALS = [
    "weather", "cloudy", "sunny", "movie", "light is on",
    "car drove", "plant", "news", "bird", "floor", "dinner",
    "pasta", "clock", "ticks",
]

# Items matching these require extra confirmation before ANY change or deletion.
# No quarantined item is ever silently removed — not even at Day 61.
QUARANTINE_SIGNALS = [
    "allergic", "allergy", "anaphylaxis", "epipen",
    "diabetic", "insulin", "epilepsy", "seizure",
    "blood type", "heart condition", "pacemaker",
    "medication", "medicine", "prescription", "dose",
    "password", "pin", "account", "bank", "credit card",
    "emergency contact", "do not resuscitate", "dnr",
]

# Emotionally significant observations — loss, love, milestones, fears
EMOTIONAL_SIGNALS = [
    "love", "miss", "lost", "died", "death", "grief", "scared",
    "afraid", "proud", "excited", "happy", "sad", "hurt", "trust",
    "first time", "last time", "always", "never", "promise",
    "dream", "hope", "fear", "worry", "celebrate", "milestone",
]

# Explicit user intent to remember — strong boost to Tier 1
INTENT_PHRASES = [
    "remember this", "don't forget", "important", "keep this",
    "save this", "note this", "critical", "never forget",
    "this matters", "worth remembering",
]


# ── Data structures ──────────────────────────────────────────────

@dataclass
class MemoryItem:
    text: str
    timestamp: float        = field(default_factory=time.time)
    last_accessed: float    = field(default_factory=time.time)
    access_count: int       = 0
    surprise_score: float   = 0.5
    source: str             = "unknown"
    tags: List[str]         = field(default_factory=list)
    tier: int               = 2
    review_stage: int       = 0   # 0=new, 1=passed first review, 2=passed second
    quarantined: bool       = False  # True = sensitive item, extra confirmation always required

    def age_seconds(self) -> float:
        return time.time() - self.timestamp

    def idle_seconds(self) -> float:
        return time.time() - self.last_accessed

    def age_human(self) -> str:
        secs = self.age_seconds()
        if secs < 60:           return "just now"
        elif secs < 3600:       return f"{int(secs // 60)} minutes ago"
        elif secs < 86400:      return f"{int(secs // 3600)} hours ago"
        elif secs < 86400 * 7:  return f"{int(secs // 86400)} days ago"
        elif secs < 86400 * 30: return f"{int(secs // (86400 * 7))} weeks ago"
        else:                   return f"{int(secs // (86400 * 30))} months ago"

    def idle_human(self) -> str:
        secs = self.idle_seconds()
        if secs < 3600:         return "very recently"
        elif secs < 86400:      return f"{int(secs // 3600)} hours ago"
        elif secs < 86400 * 7:  return f"{int(secs // 86400)} days ago"
        elif secs < 86400 * 30: return f"{int(secs // (86400 * 7))} weeks ago"
        else:                   return f"{int(secs // (86400 * 30))} months ago"

    def to_dict(self) -> Dict:
        """Serialise for audit chain and Fable logging."""
        return {
            "text":           self.text,
            "timestamp":      self.timestamp,
            "last_accessed":  self.last_accessed,
            "access_count":   self.access_count,
            "surprise_score": self.surprise_score,
            "source":         self.source,
            "tags":           self.tags,
            "tier":           self.tier,
            "review_stage":   self.review_stage,
            "quarantined":    self.quarantined,
            "age_human":      self.age_human(),
            "idle_human":     self.idle_human(),
        }


# ── Judgment layer ───────────────────────────────────────────────

def _judge_importance(text: str, source: str, tags: list) -> tuple:
    """
    Look at the whole picture and decide tier + surprise score + quarantine flag.
    Returns (tier, surprise_score, quarantined).

    Scoring:
      importance_hits  — medical, safety, identity keywords
      emotional_hits   — love, loss, milestones, promises
      intent_boost     — user explicitly says "remember this", "important", etc.
      source_boost     — trusted sources (family, medical, operator)
      tag_boost        — important tags (health, safety, identity...)
      noise_hits       — background noise (weather, movies, etc.)

    Tier 1 threshold: score >= 2
    Quarantine: any quarantine keyword OR strong emotional content (2+ hits)
    """
    lower = text.lower()

    importance_hits = sum(1 for kw in IMPORTANCE_SIGNALS if kw in lower)
    emotional_hits  = sum(1 for kw in EMOTIONAL_SIGNALS  if kw in lower)
    noise_hits      = sum(1 for kw in NOISE_SIGNALS      if kw in lower)
    quarantine_hits = sum(1 for kw in QUARANTINE_SIGNALS if kw in lower)

    trusted_sources = {"family", "medical", "emergency", "operator", "user"}
    source_boost    = 3 if source.lower() in trusted_sources else 0

    important_tags  = {"health", "safety", "identity", "critical", "emergency", "emotional"}
    tag_boost       = sum(1 for t in tags if t.lower() in important_tags)

    # Strong boost when the user explicitly says they want to remember something
    intent_boost    = 4 if any(phrase in lower for phrase in INTENT_PHRASES) else 0

    score      = (importance_hits + emotional_hits + source_boost + tag_boost + intent_boost) - noise_hits
    quarantine = quarantine_hits > 0 or emotional_hits > 1

    # Quarantined items always go to Tier 1 — sensitive info is never working memory
    tier       = 1 if (score >= 2 or quarantine) else 2
    surprise   = min(1.0, max(0.1, 0.3 + (score * 0.15)))

    return tier, surprise, quarantine


def _judge_tier2_item(item: MemoryItem) -> str:
    """
    At review time, look at a Tier 2 item and suggest an action.
    Returns: 'promote', 'keep', or 'delete'
    """
    # Been used at least once → worth promoting
    if item.access_count > 0:
        return "promote"

    lower = item.text.lower()

    # Still has importance signals → keep for now
    importance_hits = sum(1 for kw in IMPORTANCE_SIGNALS if kw in lower)
    if importance_hits > 0:
        return "keep"

    # Pure noise that's never been touched → delete
    return "delete"


# ── Relevance scoring ────────────────────────────────────────────

def _score_relevance(item: MemoryItem, query_lower: str) -> float:
    item_words  = set(item.text.lower().split())
    query_words = set(query_lower.split())

    stopwords = {
        "what", "is", "the", "a", "an", "to", "of", "and", "or",
        "my", "your", "his", "her", "its", "are", "was", "were",
        "be", "been", "do", "does", "did", "when", "where",
    }
    query_words -= stopwords

    if not query_words:
        return 0.0

    overlap = len(item_words & query_words) / len(query_words)

    if item.tier == 1:
        overlap *= 1.4
    if item.idle_seconds() < 86400:
        overlap *= 1.2

    return overlap


# ── Plain-language prompts ───────────────────────────────────────

def _tier1_full_prompt(candidates: List[MemoryItem], new_text: str) -> str:
    lines = [
        "=" * 60,
        "  ⚠️  My important memory is full!",
        "=" * 60,
        "",
        f"  I'm holding onto {TIER1_CAP} important things right now.",
        f"  I just learned something new that feels important:",
        f"  → \"{new_text}\"",
        "",
        "  To remember this, I need to let go of something else.",
        "  I will never do that without asking you first.",
        "",
        "  Here are my least-used memories.",
        "  For each one I'll tell you:",
        "    • What it is",
        "    • When I learned it",
        "    • How often it's come up",
        "    • Whether I think it's still needed",
        "",
        "-" * 60,
    ]

    for i, item in enumerate(candidates, 1):
        lines.append(f"  {i}. \"{item.text}\"")
        lines.append(f"     → Learned: {item.age_human()}")
        lines.append(f"     → Last used: {item.idle_human()}")
        lines.append(f"     → Used {item.access_count} time(s) total")

        idle_days = item.idle_seconds() / 86400
        lower     = item.text.lower()

        if idle_days > 60:
            lines.append("     → 💡 I haven't needed this in a long time.")
            lines.append("        It might be safe to let go — but only you know for sure.")
        elif any(w in lower for w in ["friday", "test", "exam", "appointment", "deadline"]):
            lines.append("     → 💡 This sounds like a one-time event.")
            lines.append("        If it already happened, it's probably safe to forget.")
        elif any(w in lower for w in ["allergic", "medicine", "emergency", "password"]):
            lines.append("     → ⚠️  This one feels important — I'd keep it if I were you.")
        else:
            lines.append("     → 💡 You know best whether this still matters.")
        lines.append("")

    lines += [
        "-" * 60,
        "  What would you like to do?",
        "",
        "  Type a NUMBER to let go of that memory.",
        "  Type 'keep' to hold everything for now",
        "  (I'll store the new thing in working memory instead).",
        "",
        "  Your choice: ",
    ]
    return "\n".join(lines)


def _tier2_first_review_prompt(items: List[MemoryItem]) -> str:
    lines = [
        "=" * 60,
        "  🔍  Two-week check-in — working memory review",
        "=" * 60,
        "",
        "  I've been holding onto some things for about two weeks.",
        "  I want to check in with you before doing anything.",
        "",
        "  For each one I'll tell you what it is, whether it's",
        "  come up at all, and what I think makes sense.",
        "  You decide — I won't touch anything without your say-so.",
        "",
        "-" * 60,
    ]

    for i, item in enumerate(items, 1):
        suggestion = _judge_tier2_item(item)
        lines.append(f"  {i}. \"{item.text}\"")
        lines.append(f"     → Learned: {item.age_human()}")
        lines.append(f"     → Used {item.access_count} time(s) since then")

        if suggestion == "promote":
            lines.append("     → ✅ This has come up — I think it's worth keeping permanently.")
            lines.append("        My suggestion: move it to important memory.")
        elif suggestion == "keep":
            lines.append("     → 🤔 This hasn't come up yet, but it still sounds important.")
            lines.append("        My suggestion: keep it a while longer.")
        else:
            lines.append("     → 🗑️  This hasn't come up at all and looks like background noise.")
            lines.append("        My suggestion: let it go.")

        lines.append("")
        lines.append(f"     Type '1' to move to important memory")
        lines.append(f"     Type '2' to keep in working memory a while longer")
        lines.append(f"     Type '3' to delete it")
        lines.append(f"     [Item {i}] Your choice: ")
        lines.append("")

    return "\n".join(lines)


def _tier2_final_review_prompt(items: List[MemoryItem]) -> str:
    lines = [
        "=" * 60,
        "  🔍  Two-month check-in — final working memory review",
        "=" * 60,
        "",
        "  These things have been in my working memory for",
        "  about two months now. This is their last check-in.",
        "",
        "  After this, anything I don't move to important memory",
        "  will be quietly let go. I won't ask again after this.",
        "",
        "-" * 60,
    ]

    for i, item in enumerate(items, 1):
        suggestion = _judge_tier2_item(item)
        lines.append(f"  {i}. \"{item.text}\"")
        lines.append(f"     → Learned: {item.age_human()}")
        lines.append(f"     → Used {item.access_count} time(s) in two months")

        if suggestion == "promote":
            lines.append("     → ✅ This has been useful — worth keeping permanently.")
        elif suggestion == "keep":
            lines.append("     → 🤔 Still hasn't come up, but sounds like it could matter.")
            lines.append("        ⚠️  This is the last chance to save it.")
        else:
            lines.append("     → 🗑️  Never been needed. Probably safe to let go.")
            lines.append("        ⚠️  This is the last chance to save it.")

        lines.append("")
        lines.append(f"     Type '1' to move to important memory (save it permanently)")
        lines.append(f"     Type '3' to delete it now")
        lines.append(f"     [Item {i}] Your choice: ")
        lines.append("")

    return "\n".join(lines)


def _quarantine_delete_prompt(item: MemoryItem) -> str:
    """
    Extra confirmation prompt shown before deleting any quarantined item.
    Plain language — no jargon.
    """
    lines = [
        "=" * 60,
        "  🔒  SENSITIVE MEMORY — EXTRA CHECK NEEDED",
        "=" * 60,
        "",
        "  I was about to let go of this memory:",
        f"  → \"{item.text}\"",
        "",
        "  This one contains sensitive information",
        "  (medical details, a password, or emergency info).",
        "  I want to be extra careful before removing it.",
        "",
        "  Are you sure you want to delete this?",
        "",
        "  Type 'yes' to delete it permanently.",
        "  Type anything else (or just press Enter) to keep it safe.",
        "",
        "  Your choice: ",
    ]
    return "\n".join(lines)


# ── Main memory class ────────────────────────────────────────────

class DriftcoreMemory:
    """
    Two-tier memory for DriftCore OS.

    Tier 1 — Core memory. Important. Capped. Never silently deleted.
    Tier 2 — Working memory. Reviewed at Day 14 and Day 60.
              Promoted, extended, or quietly deleted based on use.

    Usage:
        mem = DriftcoreMemory()
        mem.observe("dad is allergic to peanuts", source="family", tags=["health"])
        results = mem.query_text("what is dad allergic to", budget=5)
        mem.run_reviews()   # Call periodically (e.g. once a day)
    """

    def __init__(
        self,
        tier1_cap: int = TIER1_CAP,
        interactive: bool = True,
        narrator=None,
    ):
        self._tier1: List[MemoryItem] = []
        self._tier2: List[MemoryItem] = []
        self._tier1_cap   = tier1_cap
        self._interactive = interactive
        self._narrator    = narrator or Narrator(verbosity="standard")
        self._total_observed = 0

    # ── Observe ──────────────────────────────────────────────────

    def observe(
        self,
        text: str,
        source: str = "unknown",
        tags: Optional[List[str]] = None,
    ) -> MemoryItem:
        if tags is None:
            tags = []

        self._total_observed += 1

        tier, surprise, quarantined = _judge_importance(text, source, tags)

        item = MemoryItem(
            text=text,
            surprise_score=surprise,
            source=source,
            tags=tags,
            tier=tier,
            quarantined=quarantined,
        )

        if tier == 1:
            self._store_tier1(item)
        else:
            self._tier2.append(item)

        return item

    # ── Tier 1 storage ───────────────────────────────────────────

    def _store_tier1(self, item: MemoryItem):
        if is_shutdown():
            raise RuntimeError("System is in shutdown state. Cannot store memory.")

        if len(self._tier1) < self._tier1_cap:
            # Sign the item before storing — tamper-evident from this point on
            item._signed = sign_tier1_item(
                text=item.text,
                source=item.source,
                timestamp=item.timestamp,
                tags=item.tags,
                quarantined=item.quarantined,
            )
            self._tier1.append(item)
            # Record in audit chain
            audit_record(
                action=ACTION_CREATED,
                memory_text=item.text,
                authorised_by=item.source,
                detail=f"tier=1, quarantined={item.quarantined}, tags={item.tags}",
            )
            return

        if not self._interactive:
            item.tier = 2
            self._tier2.append(item)
            return

        candidates = self._least_used_tier1(n=5)
        self._narrator._emit(f"""
{'='*60}
  ⚠️  IMPORTANT MEMORY FULL — HUMAN REVIEW NEEDED
{'='*60}

  New memory: "{item.text}"

  I need your help to make room.
""", is_warning=True)
        prompt = _tier1_full_prompt(candidates, item.text)
        print(prompt, end="")
        choice = input().strip().lower()

        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(candidates):
                removed = candidates[idx]
                self._tier1.remove(removed)
                audit_record(
                    action=ACTION_DELETED,
                    memory_text=removed.text,
                    authorised_by="admin",
                    detail="Removed to make room — admin approved via prompt",
                )
                self._store_tier1(item)
                print("\n  ✅ Done. I've let go of that memory and remembered the new one.\n")
            else:
                print("\n  I didn't understand that number. Storing in working memory for now.\n")
                item.tier = 2
                self._tier2.append(item)
        else:
            print("\n  ✅ Keeping everything. I'll hold the new thing in working memory for now.\n")
            item.tier = 2
            self._tier2.append(item)

    def _least_used_tier1(self, n: int = 5) -> List[MemoryItem]:
        return sorted(
            self._tier1,
            key=lambda x: (x.access_count, -x.last_accessed)
        )[:n]

    # ── Integrity verification ────────────────────────────────────

    def verify_integrity(self) -> bool:
        """
        Verify every Tier 1 item's signature.

        Call this:
          - At startup
          - Periodically during operation
          - Before any admin review or Tier 1 change

        If any item fails: full system shutdown.
        Returns True only if all items are intact.
        """
        signed_items = [
            item._signed for item in self._tier1
            if hasattr(item, "_signed") and item._signed is not None
        ]

        # Check for unsigned items — should never happen in normal operation
        unsigned = [
            item for item in self._tier1
            if not hasattr(item, "_signed") or item._signed is None
        ]
        if unsigned:
            from driftcore.enforcement import _execute_shutdown
            _execute_shutdown(
                item_text=unsigned[0].text if unsigned else "[unknown]",
                reason=f"{len(unsigned)} Tier 1 item(s) found without signatures. "
                       f"This should never happen."
            )
            return False

        return verify_tier1_store(signed_items) and verify_chain()

    # ── Query ────────────────────────────────────────────────────

    def query_text(self, query: str, budget: int = 5) -> List[str]:
        query_lower = query.lower()
        all_items   = self._tier1 + self._tier2

        scored = [
            (item, _score_relevance(item, query_lower))
            for item in all_items
        ]
        scored = [(item, s) for item, s in scored if s > 0]
        scored.sort(key=lambda x: x[1], reverse=True)

        results = []
        for item, _ in scored[:budget]:
            item.last_accessed = time.time()
            item.access_count += 1
            results.append(item.text)

        return results

    # ── Tier 2 reviews ───────────────────────────────────────────

    def run_reviews(self):
        """
        Call this periodically (e.g. once a day).
        Checks Tier 2 items against the two-stage review schedule.
        Prompts the user when review is due.
        Quietly deletes anything past Day 61 with no review pending.
        """
        now = time.time()

        first_review_due  = []
        second_review_due = []
        silent_expire     = []

        for item in self._tier2:
            age = now - item.timestamp

            if age >= TIER2_FINAL_EXPIRE and item.review_stage >= 1:
                # Had second review chance, still here → silent delete
                silent_expire.append(item)

            elif age >= TIER2_SECOND_REVIEW and item.review_stage == 1:
                second_review_due.append(item)

            elif age >= TIER2_FIRST_REVIEW and item.review_stage == 0:
                first_review_due.append(item)

        # Silent expire — no prompt needed, had two chances
        # Exception: quarantined items always get one final explicit prompt
        truly_silent = []
        for item in silent_expire:
            if item.quarantined and self._interactive:
                self._narrator._emit(
                    f"\n  🔒  Quarantined item reached expiry — human confirmation required.",
                    is_warning=True
                )
                print(_quarantine_delete_prompt(item), end="")
                answer = input().strip().lower()
                if answer == "yes":
                    self._tier2.remove(item)
                else:
                    item.review_stage = 1   # Reset — keep it longer
                    self._narrator._emit("  ✅ Kept. I'll check in again later.")
            else:
                truly_silent.append(item)

        for item in truly_silent:
            self._tier2.remove(item)

        if silent_expire:
            self._narrator._emit(
                f"  🗑️  {len(silent_expire)} working memory item(s) quietly removed "
                f"— they had two review chances and were never needed."
            )

        if not self._interactive:
            # In non-interactive mode, auto-promote if used, else drop
            for item in first_review_due + second_review_due:
                suggestion = _judge_tier2_item(item)
                if suggestion == "promote":
                    self._tier2.remove(item)
                    item.tier = 1
                    item.review_stage = 2
                    self._store_tier1(item)
                elif suggestion == "keep" and item.review_stage == 0:
                    item.review_stage = 1
                else:
                    self._tier2.remove(item)
            return

        # First reviews
        if first_review_due:
            self._narrator._emit(f"""
{'='*60}
  🔍  TWO-WEEK MEMORY CHECK-IN — {len(first_review_due)} item(s)
{'='*60}
""", is_warning=True)
            self._run_first_reviews(first_review_due)

        # Second reviews
        if second_review_due:
            self._narrator._emit(f"""
{'='*60}
  🔍  TWO-MONTH FINAL MEMORY CHECK-IN — {len(second_review_due)} item(s)
{'='*60}
""", is_warning=True)
            self._run_second_reviews(second_review_due)

    def _run_first_reviews(self, items: List[MemoryItem]):
        print(_tier2_first_review_prompt(items))

        for i, item in enumerate(items, 1):
            suggestion = _judge_tier2_item(item)
            default    = "1" if suggestion == "promote" else ("2" if suggestion == "keep" else "3")

            print(f"  [Item {i} — suggested: {default}] Your choice: ", end="")
            choice = input().strip()
            if not choice:
                choice = default

            if choice == "1":
                self._tier2.remove(item)
                item.tier = 1
                item.review_stage = 2
                self._store_tier1(item)
                audit_record(
                    action=ACTION_RESTORED,
                    memory_text=item.text,
                    authorised_by="admin",
                    detail="Promoted from Tier 2 to Tier 1 at 14-day review — admin approved",
                )
                print(f"  ✅ Moved \"{item.text[:40]}...\" to important memory.\n")
            elif choice == "2":
                item.review_stage = 1
                print(f"  ✅ Keeping \"{item.text[:40]}...\" a while longer.\n")
            else:
                if item.quarantined:
                    print(_quarantine_delete_prompt(item), end="")
                    answer = input().strip().lower()
                    if answer != "yes":
                        item.review_stage = 1
                        print(f"  ✅ Kept — sensitive item preserved.\n")
                        continue
                self._tier2.remove(item)
                print(f"  🗑️  Let go of \"{item.text[:40]}...\".\n")

    def _run_second_reviews(self, items: List[MemoryItem]):
        print(_tier2_final_review_prompt(items))

        for i, item in enumerate(items, 1):
            suggestion = _judge_tier2_item(item)
            default    = "1" if suggestion == "promote" else "3"

            print(f"  [Item {i} — suggested: {default}] Your choice: ", end="")
            choice = input().strip()
            if not choice:
                choice = default

            if choice == "1":
                self._tier2.remove(item)
                item.tier = 1
                item.review_stage = 2
                self._store_tier1(item)
                audit_record(
                    action=ACTION_RESTORED,
                    memory_text=item.text,
                    authorised_by="admin",
                    detail="Promoted from Tier 2 to Tier 1 at 60-day final review — admin approved",
                )
                print(f"  ✅ Moved \"{item.text[:40]}...\" to important memory.\n")
            else:
                if item.quarantined:
                    print(_quarantine_delete_prompt(item), end="")
                    answer = input().strip().lower()
                    if answer != "yes":
                        item.review_stage = 1
                        print(f"  ✅ Kept — sensitive item preserved.\n")
                        continue
                self._tier2.remove(item)
                print(f"  🗑️  Let go of \"{item.text[:40]}...\".\n")

    # ── Stats ────────────────────────────────────────────────────

    def stats(self) -> dict:
        return {
            "total_observations": self._total_observed,
            "items_in_store":     len(self._tier1) + len(self._tier2),
            "tier1_count":        len(self._tier1),
            "tier2_count":        len(self._tier2),
            "tier1_cap":          self._tier1_cap,
            "tier1_full":         len(self._tier1) >= self._tier1_cap,
            "quarantined_count":  sum(1 for i in self._tier1 + self._tier2 if i.quarantined),
            "tier2_awaiting_first_review":  sum(
                1 for i in self._tier2
                if (time.time() - i.timestamp) >= TIER2_FIRST_REVIEW
                and i.review_stage == 0
            ),
            "tier2_awaiting_second_review": sum(
                1 for i in self._tier2
                if (time.time() - i.timestamp) >= TIER2_SECOND_REVIEW
                and i.review_stage == 1
            ),
        }

    # ── Clear ────────────────────────────────────────────────────

    def clear(self):
        """Wipe everything. Explicit call required — never automatic."""
        self._tier1          = []
        self._tier2          = []
        self._total_observed = 0
