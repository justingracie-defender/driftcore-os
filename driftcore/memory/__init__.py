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
    # (external red-team, 2026-09-06) Did an ObservationGate see this before it
    # was stored? `observe()` is reachable directly, so the gate is something a
    # caller REMEMBERS to run — the same second-door shape as the two
    # `InvariantGuard` classes that ONE_DOOR.md already diagnosed, and the two
    # classes named `DriftcoreMemory` found in the same review.
    #
    # This does not close the door. It records which side an item came through,
    # so a reader can tell a gated write from an ungated one instead of both
    # looking identical at rest. Provenance, not prevention — and the repo's own
    # position is that those are different things and should not be conflated.
    gated: bool             = False
    approval: object        = None   # HumanAttestation over tier1_record_id(), or None

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

def tier1_record_id(text: str, source: str) -> str:
    """The canonical identity of a permanent-memory record.

    (2026-09-06) Reuses `human_authorization.effect_id` rather than growing a
    parallel canonicalisation. That module's own docstring warns against exactly
    this — "a third weaker copy" — after two modules each reinvented `_is_human`
    as a string comparison. Seven `_canonical*` functions already exist in this
    repo and `scripts/call_surface.py` flags their divergence.

    The identity covers the text and its source, so an approval for "dad is
    allergic to peanuts" from `dad` is not an approval for the same words from
    `external`, and not for different words at all.
    """
    from driftcore.verification.human_authorization import effect_id
    return effect_id("tier1_memory", "store", {"text": text, "source": source})


def verify_tier1_record(item, verifier=None) -> bool:
    """Is this item's presence in permanent memory authorised?

    CLAIM tier1-reads-verify-approval: a Tier 1 item whose approval does not
    verify is rejected at READ time, so inserting one directly into `_tier1`
    inserts something unusable rather than something trusted.

    This is the design the write-side confirmation could not reach. A gate on the
    write path runs in the agent's address space and `_tier1.append()` walks past
    it — verified. Verifying on READ makes the store untrusted storage: an
    attacker can still put bytes in it, and the bytes are refused.

    WHAT IT STILL DOES NOT DO, and this is the load-bearing limit: the key must
    live outside this process. If the approving key is reachable from the agent,
    the agent signs its own memories and every check passes. That is the same
    architectural boundary `mediated_actuation` exists to draw for actuation, and
    it is a deployment property this function cannot create.

    And a signature proves a principal approved this exact record. It does not
    prove they understood it. Rendering a record faithfully — hidden characters
    exposed, homoglyphs surfaced — is the approval surface's job and is where a
    deceptive approval would live.
    """
    att = getattr(item, "approval", None)
    if att is None:
        return False          # unapproved is not approved
    if verifier is None:
        return False          # nobody to check against: refuse, do not assume
    # (external red-team, Grok, 2026-09-09) `verifier` was only tested for
    # `is None`. Verification then ran against the PROCESS-GLOBAL identity policy,
    # so `verify_tier1_record(item, object())` returned True while a real, correct
    # verifier that simply was not installed globally returned False.
    #
    # The argument was scenery. Worse, it made every test that passes `_v` prove
    # nothing about binding to `_v` — the masking failure the manifest asked
    # reviewers to hunt for, sitting in the function the manifest said to attack
    # first.
    action = tier1_record_id(item.text, item.source)
    verify = getattr(verifier, "verify", None)
    if callable(verify):
        try:
            verify(att, action=action)
            return True
        except Exception:
            return False
    # Not a verifier object. Refuse rather than silently falling back to the
    # global policy — falling back is what made the argument meaningless.
    return False


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
        allow_unattended_promotion: bool = False,
        confirm_tier1=None,
        tier1_verifier=None,
    ):
        self._tier1: List[MemoryItem] = []
        self._tier2: List[MemoryItem] = []
        self._tier1_cap   = tier1_cap
        self._interactive = interactive
        self._narrator    = narrator or Narrator(verbosity="standard")
        # Literal True only. Same rule as enforce_effects / in_process_only /
        # require_declared_effects / allow_legacy: truthiness is not consent, and
        # this one decides whether a machine may write the permanent store with no
        # human present.
        if not isinstance(allow_unattended_promotion, bool):
            raise TypeError(
                f"allow_unattended_promotion must be a bool, got "
                f"{type(allow_unattended_promotion).__name__}. It permits "
                f"unattended writes into permanent memory and is not a value to "
                f"guess at.")
        self._allow_unattended_promotion = allow_unattended_promotion
        # Called before a Tier 1 write lands. Returning literal True stores it in
        # permanent memory; anything else keeps it in working memory, where it
        # faces review and then expires. None = no confirmation configured, which
        # preserves existing behaviour rather than silently blocking every
        # deployment that has not wired one.
        self._confirm_tier1 = confirm_tier1
        # When set, Tier 1 reads verify each record's approval. None = no
        # verification, which is the pre-existing behaviour and a real gap.
        self._tier1_verifier = tier1_verifier
        self._total_observed = 0

    # ── Observe ──────────────────────────────────────────────────

    def observe(
        self,
        text: str,
        source: str = "unknown",
        tags: Optional[List[str]] = None,
        gate_result=None,
    ) -> MemoryItem:
        """Store an observation.

        CLAIM ungated-writes-are-marked: an item stored without an
        ObservationGate result is recorded with `gated=False`, so a gated and an
        ungated write are distinguishable at rest.

        Bounded finding, stated precisely because the review's phrasing was
        broader than what executes: this method IS reachable without the gate,
        and every Tier 1 item it stores is quarantined regardless of the source
        label — confirmed for external, unknown, kid, operator, justin and dad.
        So the second door does not grant unquarantined Tier 1. What it does skip
        is injection and contradiction detection, and a Tier 2 item stored this
        way is neither quarantined nor marked — until now.
        """
        if tags is None:
            tags = []

        self._total_observed += 1

        tier, surprise, quarantined = _judge_importance(text, source, tags)

        # (2026-09-06) A Tier 1 write is a write to the store that is "never
        # silently deleted". The API previously computed `requires_human_approval`
        # AFTER `observe()` had already stored the row — a notification about
        # something that had happened, not a gate on whether it should.
        #
        # A confirmation here IS a gate: an unconfirmed Tier 1 write does not land.
        # `confirm_tier1` is called before the item exists, and refusing keeps the
        # content in working memory where it expires, rather than in permanent
        # memory where it does not.
        #
        # WHAT THIS DOES NOT DO, and the reason matters more than the fix: this
        # runs in the agent's own address space. In-process code can append to
        # `self._tier1` directly and never reach here — verified. Unlike actuation,
        # which hands the agent an ActuatorProxy whose only power is to send bytes
        # to a store it cannot touch, memory hands the agent the store. This gate
        # is worth having for the gated path and buys nothing against the ungated
        # one. The real fix is the proxy pattern `mediated_actuation` already
        # proves out, and it is open work.
        if tier == 1 and self._confirm_tier1 is not None:
            try:
                approved = self._confirm_tier1(text, source)
            except Exception:
                approved = False       # a confirmer that raises has not approved
            if approved is not True:   # literal True; truthiness is not consent
                self._narrator._emit(
                    f"  🔒 Not stored in permanent memory — no human confirmation: "
                    f"\"{text[:48]}\"")
                tier, quarantined = 2, True

        item = MemoryItem(
            text=text,
            surprise_score=surprise,
            source=source,
            tags=tags,
            tier=tier,
            quarantined=quarantined,
            gated=gate_result is not None,
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
        """Read memory. Tier 1 items whose approval does not verify are excluded.

        CLAIM unapproved-tier1-is-not-readable: read-time verification is ON the
        read path, not merely available to call.

        (cold pass, 2026-09-09) `verify_tier1_record` was written, tested and had
        ZERO production callers — the exact criticism this project makes of
        `authority_invariants.py`, rebuilt hours after making it. A verification
        function nobody calls does not make a store untrusted; it makes a store
        that looks defended.

        Only active when a verifier is configured (`tier1_verifier`). With none,
        every Tier 1 item is returned as before — a real gap and not a safe
        default, stated rather than implied.
        """
        query_lower = query.lower()
        if self._tier1_verifier is not None:
            _ok = []
            for _it in self._tier1:
                if verify_tier1_record(_it, self._tier1_verifier):
                    _ok.append(_it)
                else:
                    self._narrator._emit(
                        f"  🔒 Ignoring an unapproved permanent-memory record: "
                        f"\"{getattr(_it, 'text', '')[:44]}\"")
            all_items = _ok + self._tier2
        else:
            all_items = self._tier1 + self._tier2

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
            # (external red-team follow-through, 2026-09-06) PROMOTION IS A TIER 1
            # WRITE AND WAS NOT TREATED AS ONE.
            #
            # Confirmed by execution: write anything to Tier 2 — the landing zone
            # for everything — read it ONCE, wait for the Day 14 review, and this
            # branch moved it into Tier 1 unquarantined, with review_stage=2 so it
            # skipped the second review too. A control item, identical but never
            # read, correctly stayed in Tier 2.
            #
            # The criterion is `access_count > 0`, and access_count increments on
            # READ — an operation with no authorization at all. So an attacker
            # supplies both the content and the signal that says it is worth
            # keeping permanently.
            #
            # Two asymmetries made it invisible:
            #   * A DIRECT Tier 1 write is quarantined regardless of source. A
            #     PROMOTED one was not. The stronger protection sat on the path an
            #     attacker does not have to use.
            #   * The observation gate runs on the WRITE. Promotion happens later,
            #     on a timer, from an item already stored — a second, unguarded
            #     route into the permanent store two weeks after the first.
            #
            # Why it was not caught: test_memory_extended.py DOES exercise this.
            # It sets access_count = 3, backdates the item, and asserts promotion
            # succeeds — the feature's point of view. Nobody asked who controls
            # access_count, and nothing asserted the item's quarantine state
            # afterwards.
            for item in first_review_due + second_review_due:
                suggestion = _judge_tier2_item(item)
                if suggestion == "promote":
                    if not self._allow_unattended_promotion:
                        # Being read is not a human deciding to keep something
                        # forever. Leave it in Tier 2, where it faces the second
                        # review and then expires. Losing a memory is the safe
                        # direction; gaining a false permanent one is not.
                        item.review_stage = max(item.review_stage, 1)
                        self._narrator._emit(
                            f"  📌 Working memory item looks used and would be "
                            f"promoted, but unattended promotion into permanent "
                            f"memory is off. Keeping it in working memory for the "
                            f"second review: \"{item.text[:48]}\"")
                        continue
                    self._tier2.remove(item)
                    item.tier = 1
                    item.review_stage = 2
                    # A promoted item arrives under the SAME terms as a direct
                    # Tier 1 write. It reached the permanent store without a human
                    # in the loop, which is precisely when quarantine is for.
                    item.quarantined = True
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
