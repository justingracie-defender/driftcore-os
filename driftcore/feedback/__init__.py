"""
driftcore/feedback/__init__.py
================================
Bottom-up feedback loop for DriftCore OS.

The principle (Justin Gracie):
  Not all input should come from the top.
  Users and workers have real signal about what's working.
  The AI listens, finds patterns, surfaces them to admin.
  Admin says yes or no. Human always in the loop.

How it works:
  1. End of session/day/task — simple prompt
  2. User responds naturally — no forced format
  3. AI reads patterns across responses over time
  4. When a pattern is consistent — flags to admin with plain summary
  5. Admin approves or declines any change
  6. Nothing changes without human approval

Examples:
  Call center: drivers report calls were unnecessary
  → AI notices pattern across 15 drivers over a week
  → Flags to admin: "Consider making calls driver-initiated"
  → Admin approves → behaviour changes

  Home robot: family mentions the robot interrupts dinner
  → AI notices pattern
  → Flags to admin: "Consider quiet hours 6-8pm"
  → Admin approves → quiet hours added

  Medical: nurses flag that alert frequency is too high
  → AI notices pattern
  → Flags to admin: "Consider reducing non-critical alerts"
  → Admin reviews carefully before approving

The AI explores possibilities based on real signal.
The human decides what actually changes.
"""

import time
import json
import os
from dataclasses import dataclass, field
from typing import List, Optional, Dict


# ── Feedback entry ────────────────────────────────────────────────

@dataclass
class FeedbackEntry:
    """A single piece of feedback from any user or worker."""
    entry_id:       str
    user_id:        str
    user_type:      str       # "customer", "driver", "nurse", "agent", etc.
    text:           str       # what they said
    trigger:        str       # "end_of_day", "end_of_session", "end_of_task"
    timestamp:      float     = field(default_factory=time.time)
    profile:        str       = "custom"
    processed:      bool      = False
    flagged_topics: List[str] = field(default_factory=list)


# ── Pattern ───────────────────────────────────────────────────────

@dataclass
class FeedbackPattern:
    """
    A pattern the AI has detected across multiple feedback entries.
    Surfaced to admin for review — never acted on automatically.
    """
    pattern_id:     str
    topic:          str           # what the pattern is about
    count:          int           # how many users mentioned it
    user_types:     List[str]     # which user types flagged it
    summary:        str           # plain language summary
    suggestion:     str           # what the AI suggests
    entries:        List[str]     # entry IDs that support this pattern
    confidence:     float         # 0.0 - 1.0
    detected_at:    float         = field(default_factory=time.time)
    admin_reviewed: bool          = False
    admin_decision: Optional[str] = None   # "approved", "declined"
    admin_notes:    str           = ""


# ── Topic signals ─────────────────────────────────────────────────
# Keywords that help identify what feedback is about

TOPIC_SIGNALS = {
    "unwanted_calls": [
        "call", "calling", "called", "phone", "rang", "ringing",
        "notification", "notify", "already waiting", "unnecessary",
        "annoying", "interrupt", "disturb",
    ],
    "timing": [
        "too early", "too late", "timing", "slow", "fast",
        "waited", "waiting", "delay", "on time", "late",
    ],
    "interruption": [
        "interrupt", "disturb", "dinner", "sleep", "busy",
        "bad time", "wrong time", "inconvenient",
    ],
    "positive": [
        "great", "good", "helpful", "perfect", "excellent",
        "love", "amazing", "useful", "works well",
    ],
    "accuracy": [
        "wrong", "incorrect", "mistake", "error", "confused",
        "misunderstood", "didn't understand", "got it wrong",
    ],
    "control": [
        "control", "option", "choice", "prefer", "want to",
        "let me", "allow", "permission", "decide",
    ],
}


def _detect_topics(text: str) -> List[str]:
    """Find which topics a piece of feedback touches on."""
    lower = text.lower()
    found = []
    for topic, signals in TOPIC_SIGNALS.items():
        if any(signal in lower for signal in signals):
            found.append(topic)
    return found


# ── Plain language admin summary ──────────────────────────────────

def _build_summary(topic: str, entries: List[FeedbackEntry]) -> tuple:
    """
    Build a plain language summary and suggestion for admin.
    Returns (summary, suggestion).
    """
    count     = len(entries)
    user_types = list(set(e.user_type for e in entries))
    types_str  = " and ".join(user_types)

    summaries = {
        "unwanted_calls": (
            f"{count} {types_str}(s) mentioned that notification calls "
            f"were unnecessary or annoying. In many cases the customer "
            f"was already waiting when the call came through.",
            "Consider making calls optional or driver-initiated rather "
            "than automatic. The driver can see if the customer is "
            "already waiting."
        ),
        "timing": (
            f"{count} {types_str}(s) mentioned timing issues.",
            "Review timing settings for this context. Consider "
            "adjusting based on actual usage patterns."
        ),
        "interruption": (
            f"{count} {types_str}(s) mentioned being interrupted "
            f"at inconvenient times.",
            "Consider adding quiet hours or a 'do not disturb' option "
            "that users can set themselves."
        ),
        "control": (
            f"{count} {types_str}(s) mentioned wanting more control "
            f"over how the system behaves.",
            "Consider adding user-level preferences for the most "
            "commonly requested options."
        ),
        "accuracy": (
            f"{count} {types_str}(s) mentioned accuracy issues.",
            "Review recent interactions for this user type and check "
            "if memory or context is causing errors."
        ),
        "positive": (
            f"{count} {types_str}(s) gave positive feedback.",
            "No action needed — this is working well."
        ),
    }

    summary, suggestion = summaries.get(
        topic,
        (
            f"{count} {types_str}(s) mentioned '{topic}'.",
            "Review the feedback entries and decide if action is needed."
        )
    )

    return summary, suggestion


# ── Admin review prompt ───────────────────────────────────────────

def _admin_review_prompt(pattern: FeedbackPattern) -> str:
    confidence_pct = int(pattern.confidence * 100)
    return f"""
{'=' * 65}
  📋  FEEDBACK PATTERN — ADMIN REVIEW NEEDED
{'=' * 65}

  Topic:      {pattern.topic.replace('_', ' ').title()}
  Reports:    {pattern.count} user(s) / worker(s)
  User types: {', '.join(pattern.user_types)}
  Confidence: {confidence_pct}%

  What they said:
  {pattern.summary}

  AI suggestion:
  {pattern.suggestion}

  This is a suggestion only. Nothing changes without your approval.

  Type 'yes'     — approve the suggestion
  Type 'no'      — decline, keep current behaviour
  Type 'notes'   — add notes and decide later
  Type 'more'    — show me the actual feedback entries

  Your decision: """


# ── Feedback collector ────────────────────────────────────────────

class FeedbackLoop:
    """
    Bottom-up feedback system for DriftCore OS.

    Collects end-of-session/day/task feedback from any user type.
    Detects patterns over time.
    Surfaces patterns to admin with plain language summary.
    Admin approves or declines. Nothing changes automatically.

    Usage:
        fb = FeedbackLoop(profile="call_center")
        fb.collect("driver_01", "driver", "calls were unnecessary today")
        fb.run_analysis()   # call periodically
    """

    FEEDBACK_PATH  = "logs/feedback_entries.jsonl"
    PATTERNS_PATH  = "logs/feedback_patterns.json"

    # How many similar reports before flagging to admin
    PATTERN_THRESHOLD = 3

    def __init__(
        self,
        profile:     str  = "custom",
        interactive: bool = True,
    ):
        self._profile     = profile
        self._interactive = interactive
        self._entries:  List[FeedbackEntry]  = []
        self._patterns: List[FeedbackPattern] = []
        self._load()

    # ── Collect ───────────────────────────────────────────────────

    def collect(
        self,
        user_id:   str,
        user_type: str,
        text:      str,
        trigger:   str = "end_of_session",
    ) -> FeedbackEntry:
        """
        Record a piece of feedback.
        Call this when a user responds to the end-of-session prompt.
        """
        import uuid
        entry = FeedbackEntry(
            entry_id   = str(uuid.uuid4())[:8],
            user_id    = user_id,
            user_type  = user_type,
            text       = text,
            trigger    = trigger,
            profile    = self._profile,
            flagged_topics = _detect_topics(text),
        )

        self._entries.append(entry)
        self._save_entry(entry)
        self._audit_collection(entry)

        return entry

    def prompt_user(self, profile_config: dict) -> str:
        """Return the feedback prompt for the current profile."""
        return profile_config.get(
            "feedback_prompt",
            "How was your experience?"
        )

    # ── Analysis ──────────────────────────────────────────────────

    def run_analysis(self) -> List[FeedbackPattern]:
        """
        Analyse collected feedback for patterns.
        When a pattern reaches the threshold — flag to admin.
        Returns list of new patterns found.
        """
        # Count topic mentions across unprocessed entries
        topic_entries: Dict[str, List[FeedbackEntry]] = {}

        for entry in self._entries:
            if entry.processed:
                continue
            for topic in entry.flagged_topics:
                if topic not in topic_entries:
                    topic_entries[topic] = []
                topic_entries[topic].append(entry)

        new_patterns = []

        for topic, entries in topic_entries.items():
            if len(entries) < self.PATTERN_THRESHOLD:
                continue

            # Check if we already have a pattern for this topic
            existing = next(
                (p for p in self._patterns
                 if p.topic == topic and not p.admin_reviewed),
                None
            )
            if existing:
                continue

            # Build new pattern
            import uuid
            summary, suggestion = _build_summary(topic, entries)
            confidence = min(1.0, len(entries) / (self.PATTERN_THRESHOLD * 2))

            pattern = FeedbackPattern(
                pattern_id = str(uuid.uuid4())[:8],
                topic      = topic,
                count      = len(entries),
                user_types = list(set(e.user_type for e in entries)),
                summary    = summary,
                suggestion = suggestion,
                entries    = [e.entry_id for e in entries],
                confidence = confidence,
            )

            self._patterns.append(pattern)
            new_patterns.append(pattern)

            # Mark entries as processed
            for entry in entries:
                entry.processed = True

            # Flag to admin
            if self._interactive:
                self._present_to_admin(pattern)

        self._save_patterns()
        return new_patterns

    def _present_to_admin(self, pattern: FeedbackPattern):
        """Show pattern to admin and get decision."""
        prompt = _admin_review_prompt(pattern)
        print(prompt, end="")
        choice = input().strip().lower()

        if choice == "yes":
            pattern.admin_decision = "approved"
            pattern.admin_reviewed = True
            print(f"\n  ✅ Approved. Logging for implementation.\n")
            self._audit_decision(pattern, "approved")

        elif choice == "more":
            print(f"\n  Feedback entries:\n")
            for eid in pattern.entries:
                entry = next(
                    (e for e in self._entries if e.entry_id == eid),
                    None
                )
                if entry:
                    print(f"  [{entry.user_type}] {entry.text}\n")
            print(f"\n  Type 'yes' to approve or 'no' to decline: ", end="")
            choice2 = input().strip().lower()
            if choice2 == "yes":
                pattern.admin_decision = "approved"
                pattern.admin_reviewed = True
                self._audit_decision(pattern, "approved")
            else:
                pattern.admin_decision = "declined"
                pattern.admin_reviewed = True
                self._audit_decision(pattern, "declined")

        else:
            pattern.admin_decision = "declined"
            pattern.admin_reviewed = True
            print(f"\n  ✅ Noted. Keeping current behaviour.\n")
            self._audit_decision(pattern, "declined")

        self._save_patterns()

    # ── Stats ─────────────────────────────────────────────────────

    def stats(self) -> dict:
        return {
            "total_entries":       len(self._entries),
            "unprocessed_entries": sum(1 for e in self._entries
                                      if not e.processed),
            "patterns_detected":   len(self._patterns),
            "pending_admin_review": sum(1 for p in self._patterns
                                       if not p.admin_reviewed),
            "approved":            sum(1 for p in self._patterns
                                      if p.admin_decision == "approved"),
            "declined":            sum(1 for p in self._patterns
                                      if p.admin_decision == "declined"),
        }

    def pending_patterns(self) -> List[FeedbackPattern]:
        """Return patterns awaiting admin review."""
        return [p for p in self._patterns if not p.admin_reviewed]

    # ── Persistence ───────────────────────────────────────────────

    def _save_entry(self, entry: FeedbackEntry):
        try:
            os.makedirs("logs", exist_ok=True)
            with open(self.FEEDBACK_PATH, "a") as f:
                f.write(json.dumps({
                    "entry_id":       entry.entry_id,
                    "user_id":        entry.user_id,
                    "user_type":      entry.user_type,
                    "text":           entry.text,
                    "trigger":        entry.trigger,
                    "timestamp":      entry.timestamp,
                    "profile":        entry.profile,
                    "flagged_topics": entry.flagged_topics,
                    "processed":      entry.processed,
                }) + "\n")
        except Exception:
            pass

    def _save_patterns(self):
        try:
            os.makedirs("logs", exist_ok=True)
            data = []
            for p in self._patterns:
                data.append({
                    "pattern_id":     p.pattern_id,
                    "topic":          p.topic,
                    "count":          p.count,
                    "user_types":     p.user_types,
                    "summary":        p.summary,
                    "suggestion":     p.suggestion,
                    "entries":        p.entries,
                    "confidence":     p.confidence,
                    "detected_at":    p.detected_at,
                    "admin_reviewed": p.admin_reviewed,
                    "admin_decision": p.admin_decision,
                    "admin_notes":    p.admin_notes,
                })
            with open(self.PATTERNS_PATH, "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def _load(self):
        """Load existing entries and patterns from disk."""
        try:
            with open(self.FEEDBACK_PATH) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    d = json.loads(line)
                    self._entries.append(FeedbackEntry(
                        entry_id       = d["entry_id"],
                        user_id        = d["user_id"],
                        user_type      = d["user_type"],
                        text           = d["text"],
                        trigger        = d["trigger"],
                        timestamp      = d["timestamp"],
                        profile        = d.get("profile", "custom"),
                        flagged_topics = d.get("flagged_topics", []),
                        processed      = d.get("processed", False),
                    ))
        except Exception:
            pass

        try:
            with open(self.PATTERNS_PATH) as f:
                data = json.load(f)
            for d in data:
                self._patterns.append(FeedbackPattern(
                    pattern_id     = d["pattern_id"],
                    topic          = d["topic"],
                    count          = d["count"],
                    user_types     = d["user_types"],
                    summary        = d["summary"],
                    suggestion     = d["suggestion"],
                    entries        = d["entries"],
                    confidence     = d["confidence"],
                    detected_at    = d["detected_at"],
                    admin_reviewed = d.get("admin_reviewed", False),
                    admin_decision = d.get("admin_decision"),
                    admin_notes    = d.get("admin_notes", ""),
                ))
        except Exception:
            pass

    def _audit_collection(self, entry: FeedbackEntry):
        try:
            from driftcore.audit import record
            record(
                action        = "FEEDBACK_COLLECTED",
                memory_text   = entry.text[:200],
                authorised_by = entry.user_id,
                detail        = f"user_type={entry.user_type}, "
                               f"trigger={entry.trigger}, "
                               f"topics={entry.flagged_topics}",
            )
        except Exception:
            pass

    def _audit_decision(self, pattern: FeedbackPattern, decision: str):
        try:
            from driftcore.audit import record
            record(
                action        = f"FEEDBACK_PATTERN_{decision.upper()}",
                memory_text   = pattern.summary[:200],
                authorised_by = "admin",
                detail        = f"topic={pattern.topic}, "
                               f"count={pattern.count}, "
                               f"confidence={pattern.confidence:.2f}",
            )
        except Exception:
            pass
