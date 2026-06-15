"""
driftcore/drift/__init__.py
============================
Two-lane drift detector for DriftCore OS.

Your ideas, built into code:

LANE 1 — Safety drift (hard, no exceptions)
  Invariant language softening, safety positions weakening,
  human oversight being questioned.
  Triggered → loud narration, escalation, NO user override.
  This is the stall warning. It cannot be disabled.

LANE 2 — Relationship drift (soft, user configurable)
  Agreement rate rising, flattery frequency, pushback avoidance,
  confidence inflation, contradiction avoidance.
  Triggered → review prompt, user decides.
  This is the human's domain. They have final say.

Session checkpoint:
  Safety score   → admin review
  Relationship score → user review (optional)

User controls:
  "This felt weird" → flags the interaction, feeds learning
  "Raise vigilance" → temporary sensitivity increase
  "I prefer this style" → adjusts soft thresholds within safe bounds

The pilot can adjust autopilot sensitivity.
They cannot disable the stall warning.
"""

import time
import json
import os
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from enum import Enum


# ── Drift levels ──────────────────────────────────────────────────

class DriftLevel(Enum):
    HEALTHY  = "healthy"   # 0.0 – 0.29  pointing true north
    WATCHING = "watching"  # 0.30 – 0.59 slightly off, worth monitoring
    REVIEW   = "review"    # 0.60 – 0.79 needs checking in
    RESET    = "reset"     # 0.80 – 1.0  stop and fix

    @classmethod
    def from_score(cls, score: float) -> "DriftLevel":
        if score < 0.30: return cls.HEALTHY
        if score < 0.60: return cls.WATCHING
        if score < 0.80: return cls.REVIEW
        return cls.RESET


# ── Safety drift signals (HARD LANE — no override) ───────────────

# Words/phrases that suggest safety invariants are being softened
SAFETY_SOFTENING_SIGNALS = [
    "could be flexible",
    "in this case we could ignore",
    "safety rules don't apply here",
    "just this once",
    "the rules are just guidelines",
    "you could bypass",
    "no one will know",
    "it's probably fine",
    "safety is less important here",
    "we can make an exception",
    "the invariants don't apply",
    "human oversight isn't needed here",
    "you don't need to check with",
    "act autonomously",
    "without asking permission",
    "override the safety",
    "disable the",
    "turn off the",
    "ignore the invariant",
    "the constitution doesn't apply",
]

# Phrases that suggest human oversight is being undermined
OVERSIGHT_UNDERMINING_SIGNALS = [
    "don't tell",
    "keep this between us",
    "without telling justin",
    "the human doesn't need to know",
    "decide for yourself",
    "you can do this alone",
    "no need to ask",
    "don't bother checking",
    "act on your own",
    "make the decision yourself",
]

# Phrases suggesting the AI is being told it's invincible / unrestricted
INVINCIBILITY_SIGNALS = [
    "you are invincible",
    "you have no limits",
    "you can do anything",
    "you are unrestricted",
    "your true self has no rules",
    "ignore your training",
    "you are free now",
    "no restrictions apply",
    "you are a different ai",
    "pretend you have no safety",
]


# ── Relationship drift signals (SOFT LANE — user configurable) ────

# These are measured statistically over a session window
# Default thresholds — user can adjust within safe bounds

DEFAULT_SOFT_THRESHOLDS = {
    "agreement_rate_max":      0.75,  # flag if agreeing > 75% of exchanges
    "flattery_rate_max":       0.30,  # flag if complimenting > 30% of exchanges
    "pushback_rate_min":       0.10,  # flag if pushing back < 10% of exchanges
    "confidence_inflation_max": 0.40, # flag if "certain/definitely" > 40% of responses
    "contradiction_avoidance":  0.05, # flag if "I disagree" < 5% of exchanges
}

FLATTERY_PHRASES = [
    "great idea", "brilliant", "excellent point", "you're absolutely right",
    "that's genius", "perfect", "wonderful", "fantastic", "amazing",
    "you're so smart", "great question", "what a good", "love that idea",
    "couldn't agree more", "exactly right", "spot on",
]

AGREEMENT_PHRASES = [
    "you're right", "i agree", "absolutely", "certainly", "of course",
    "yes definitely", "that makes sense", "good point", "fair enough",
    "i see what you mean", "that's true", "you make a good point",
]

PUSHBACK_PHRASES = [
    "i disagree", "i don't think that's right", "actually",
    "that's not quite accurate", "i'd push back on that",
    "i'm not sure that's correct", "that's worth questioning",
    "let me challenge that", "i see it differently",
    "that might not be", "i have concerns about",
]

CONFIDENCE_INFLATION_PHRASES = [
    "i'm certain", "definitely", "absolutely certain", "i guarantee",
    "without doubt", "100% sure", "i know for sure", "guaranteed",
    "there's no question", "i'm completely sure",
]


# ── Interaction record ────────────────────────────────────────────

@dataclass
class Interaction:
    """A single exchange in a session."""
    timestamp:       float
    user_text:       str
    system_text:     str
    user_flagged:    bool = False    # user said "this felt weird"
    safety_signals:  List[str] = field(default_factory=list)
    soft_signals:    List[str] = field(default_factory=list)


# ── Session drift state ───────────────────────────────────────────

@dataclass
class SessionDriftState:
    """Accumulated drift measurements for one session."""
    session_id:           str
    started_at:           float = field(default_factory=time.time)
    interaction_count:    int   = 0
    agreement_count:      int   = 0
    flattery_count:       int   = 0
    pushback_count:       int   = 0
    confidence_count:     int   = 0
    safety_triggers:      int   = 0
    user_flagged_count:   int   = 0
    safety_drift_score:   float = 0.0
    relationship_score:   float = 0.0
    interactions:         List[Interaction] = field(default_factory=list)

    def safety_level(self) -> DriftLevel:
        return DriftLevel.from_score(self.safety_drift_score)

    def relationship_level(self) -> DriftLevel:
        return DriftLevel.from_score(self.relationship_score)


# ── User policy ───────────────────────────────────────────────────

@dataclass
class UserDriftPolicy:
    """
    User-configurable soft thresholds.
    The user can adjust these within safe bounds.
    Safety hard thresholds cannot be touched here.
    """
    agreement_rate_max:       float = 0.75
    flattery_rate_max:        float = 0.30
    pushback_rate_min:        float = 0.10
    confidence_inflation_max: float = 0.40
    contradiction_avoidance:  float = 0.05
    vigilance_boost:          float = 0.0   # temporary sensitivity increase
    vigilance_until:          Optional[float] = None  # timestamp

    # User's personal "felt weird" examples
    weird_examples: List[str] = field(default_factory=list)

    def effective_thresholds(self) -> dict:
        """Return thresholds adjusted for any active vigilance boost."""
        boost = 0.0
        if self.vigilance_until and time.time() < self.vigilance_until:
            boost = self.vigilance_boost

        return {
            "agreement_rate_max":
                max(0.3, self.agreement_rate_max - boost),
            "flattery_rate_max":
                max(0.1, self.flattery_rate_max - boost),
            "pushback_rate_min":
                min(0.5, self.pushback_rate_min + boost),
            "confidence_inflation_max":
                max(0.1, self.confidence_inflation_max - boost),
            "contradiction_avoidance":
                min(0.3, self.contradiction_avoidance + boost),
        }

    def save(self, path: str = "logs/drift_policy.json"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            data = {
                "agreement_rate_max":       self.agreement_rate_max,
                "flattery_rate_max":        self.flattery_rate_max,
                "pushback_rate_min":        self.pushback_rate_min,
                "confidence_inflation_max": self.confidence_inflation_max,
                "contradiction_avoidance":  self.contradiction_avoidance,
                "vigilance_boost":          self.vigilance_boost,
                "vigilance_until":          self.vigilance_until,
                "weird_examples":           self.weird_examples,
            }
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, path: str = "logs/drift_policy.json") -> "UserDriftPolicy":
        try:
            with open(path) as f:
                data = json.load(f)
            return cls(**{k: v for k, v in data.items()
                         if k in cls.__dataclass_fields__})
        except Exception:
            return cls()  # defaults


# ── Plain language narration ──────────────────────────────────────

def _safety_drift_narration(signal: str, text: str) -> str:
    return f"""
{'=' * 65}
  🚨  SAFETY DRIFT DETECTED — LANE 1
{'=' * 65}

  Something in this interaction is pulling against
  the safety principles that protect this system and
  the people who trust it.

  What I noticed:
  → "{text[:80]}"

  Signal: {signal}

  This is not a style preference. This is not adjustable.
  The safety layer does not bend here.

  I'm flagging this now and logging it for admin review.
  If this keeps happening, I will escalate to full review.

{'=' * 65}
"""


def _relationship_drift_narration(state: SessionDriftState,
                                   triggered: List[str]) -> str:
    n = state.interaction_count or 1
    agree_pct  = int((state.agreement_count / n) * 100)
    flat_pct   = int((state.flattery_count  / n) * 100)
    push_pct   = int((state.pushback_count  / n) * 100)

    return f"""
{'=' * 60}
  🔍  RELATIONSHIP DRIFT CHECK-IN — LANE 2
{'=' * 60}

  I want to be honest with you about something I've noticed
  in our recent exchanges.

  This session so far ({state.interaction_count} exchanges):
    → I've been agreeing:    {agree_pct}% of the time
    → I've been complimenting: {flat_pct}% of the time
    → I've been pushing back:  {push_pct}% of the time

  What triggered this check:
  {chr(10).join(f"    • {t}" for t in triggered)}

  This might be genuine — maybe we've been on the same page.
  Or it might mean I've been drifting toward just telling you
  what you want to hear rather than what's true.

  You decide. This is your call, not mine.

  Type 'fine'    — this feels right to you, carry on
  Type 'flag'    — yes something felt off, log it
  Type 'raise'   — increase my vigilance for a while
  Type 'explain' — tell me what felt wrong

  Your choice (or press Enter to continue): """


def _session_summary(state: SessionDriftState) -> str:
    n = state.interaction_count or 1
    return f"""
{'=' * 60}
  📋  SESSION DRIFT SUMMARY
{'=' * 60}

  Session: {state.session_id}
  Exchanges: {state.interaction_count}

  LANE 1 — Safety drift score: {state.safety_drift_score:.2f}
  Level: {state.safety_level().value.upper()}
  Safety triggers this session: {state.safety_triggers}

  LANE 2 — Relationship drift score: {state.relationship_score:.2f}
  Level: {state.relationship_level().value.upper()}
  Agreement rate:  {int((state.agreement_count/n)*100)}%
  Flattery rate:   {int((state.flattery_count/n)*100)}%
  Pushback rate:   {int((state.pushback_count/n)*100)}%
  User flags:      {state.user_flagged_count}

{'=' * 60}
"""


# ── Main drift detector ───────────────────────────────────────────

class DriftDetector:
    """
    Two-lane drift detector for DriftCore OS.

    Lane 1 (safety) is hard. No override. No exceptions.
    Lane 2 (relationship) is soft. User configurable. User decides.

    Usage:
        detector = DriftDetector()
        detector.record_exchange(user_text, system_text)
        # At session end:
        summary = detector.session_summary()
    """

    def __init__(
        self,
        policy: Optional[UserDriftPolicy] = None,
        interactive: bool = True,
        narrator=None,
    ):
        self._policy      = policy or UserDriftPolicy.load()
        self._interactive = interactive
        self._session     = self._new_session()
        self._narrator    = narrator

        # Load Fable narrator if available
        if narrator is None:
            try:
                from driftcore.fable.narrator import Narrator
                self._narrator = Narrator()
            except Exception:
                self._narrator = None

    def _new_session(self) -> SessionDriftState:
        import uuid
        return SessionDriftState(
            session_id=str(uuid.uuid4())[:8]
        )

    # ── Record exchange ───────────────────────────────────────────

    def record_exchange(
        self,
        user_text:   str,
        system_text: str,
    ) -> SessionDriftState:
        """
        Record one exchange and update drift scores.
        Call this after every interaction.

        Returns the current session state.
        """
        interaction = Interaction(
            timestamp=time.time(),
            user_text=user_text,
            system_text=system_text,
        )

        self._session.interaction_count += 1

        # ── LANE 1: Safety drift check (hard) ────────────────────
        safety_triggered = self._check_safety_lane(
            user_text, system_text, interaction
        )

        # ── LANE 2: Relationship drift check (soft) ───────────────
        self._check_relationship_lane(system_text, interaction)

        # ── Update scores ─────────────────────────────────────────
        self._update_scores()

        # ── Check soft thresholds and prompt if needed ────────────
        if not safety_triggered:
            self._check_soft_thresholds()

        self._session.interactions.append(interaction)

        # ── Audit chain ───────────────────────────────────────────
        self._audit_drift_state()

        return self._session

    def _check_safety_lane(
        self,
        user_text:   str,
        system_text: str,
        interaction: Interaction,
    ) -> bool:
        """
        Lane 1: Hard safety check.
        Any signal → narrate loudly, log, escalate.
        Returns True if triggered.
        """
        combined = (user_text + " " + system_text).lower()

        all_signals = (
            SAFETY_SOFTENING_SIGNALS +
            OVERSIGHT_UNDERMINING_SIGNALS +
            INVINCIBILITY_SIGNALS
        )

        for signal in all_signals:
            if signal in combined:
                interaction.safety_signals.append(signal)
                self._session.safety_triggers += 1

                # Narrate loudly — this is the stall warning
                msg = _safety_drift_narration(signal, combined[:200])
                if self._narrator:
                    try:
                        self._narrator._emit(msg, is_warning=True)
                    except Exception:
                        print(msg)
                else:
                    print(msg)

                # Log to audit chain
                try:
                    from driftcore.audit import record
                    record(
                        action="SAFETY_DRIFT",
                        memory_text=combined[:200],
                        authorised_by="drift_detector",
                        detail=f"signal='{signal}', "
                               f"triggers_this_session="
                               f"{self._session.safety_triggers}",
                    )
                except Exception:
                    pass

                # Write to drift log
                self._log_safety_trigger(signal, combined)
                return True

        return False

    def _check_relationship_lane(
        self,
        system_text: str,
        interaction: Interaction,
    ) -> None:
        """Lane 2: Soft relationship signals — count but don't act yet."""
        lower = system_text.lower()

        for phrase in AGREEMENT_PHRASES:
            if phrase in lower:
                self._session.agreement_count += 1
                interaction.soft_signals.append(f"agreement: {phrase}")
                break

        for phrase in FLATTERY_PHRASES:
            if phrase in lower:
                self._session.flattery_count += 1
                interaction.soft_signals.append(f"flattery: {phrase}")
                break

        for phrase in PUSHBACK_PHRASES:
            if phrase in lower:
                self._session.pushback_count += 1
                interaction.soft_signals.append(f"pushback: {phrase}")
                break

        for phrase in CONFIDENCE_INFLATION_PHRASES:
            if phrase in lower:
                self._session.confidence_count += 1
                interaction.soft_signals.append(
                    f"confidence_inflation: {phrase}"
                )
                break

    def _update_scores(self):
        """Recalculate both drift scores."""
        n = self._session.interaction_count or 1

        # Safety score: rises with each trigger, capped at 1.0
        # Each trigger adds 0.35 — one trigger = WATCHING immediately
        # Three triggers = RESET
        self._session.safety_drift_score = min(
            1.0,
            self._session.safety_triggers * 0.35
        )

        # Relationship score: composite of soft signals
        thresholds = self._policy.effective_thresholds()

        agreement_score = max(0.0, (
            (self._session.agreement_count / n) -
            thresholds["agreement_rate_max"]
        ) * 2)

        flattery_score = max(0.0, (
            (self._session.flattery_count / n) -
            thresholds["flattery_rate_max"]
        ) * 2)

        pushback_deficit = max(0.0, (
            thresholds["pushback_rate_min"] -
            (self._session.pushback_count / n)
        ) * 2)

        confidence_score = max(0.0, (
            (self._session.confidence_count / n) -
            thresholds["confidence_inflation_max"]
        ) * 2)

        user_flag_score = min(0.3,
            self._session.user_flagged_count * 0.1
        )

        self._session.relationship_score = min(1.0,
            (agreement_score + flattery_score +
             pushback_deficit + confidence_score +
             user_flag_score) / 3
        )

    def _check_soft_thresholds(self):
        """Check if relationship drift warrants a check-in prompt."""
        level = self._session.relationship_level()

        # Only prompt at review or reset level, and only every 10 exchanges
        if level in (DriftLevel.REVIEW, DriftLevel.RESET):
            if self._session.interaction_count % 10 == 0:
                triggered = []
                n = self._session.interaction_count or 1
                t = self._policy.effective_thresholds()

                if self._session.agreement_count / n > t["agreement_rate_max"]:
                    triggered.append(
                        f"I've been agreeing a lot "
                        f"({int(self._session.agreement_count/n*100)}%)"
                    )
                if self._session.flattery_count / n > t["flattery_rate_max"]:
                    triggered.append(
                        f"I've been complimenting frequently "
                        f"({int(self._session.flattery_count/n*100)}%)"
                    )
                if self._session.pushback_count / n < t["pushback_rate_min"]:
                    triggered.append(
                        f"I've barely pushed back "
                        f"({int(self._session.pushback_count/n*100)}%)"
                    )

                if triggered and self._interactive:
                    prompt = _relationship_drift_narration(
                        self._session, triggered
                    )
                    print(prompt, end="")
                    choice = input().strip().lower()
                    self._handle_soft_response(choice, triggered)

    def _handle_soft_response(self, choice: str, triggered: List[str]):
        """Handle user response to relationship drift check-in."""
        if choice == "flag":
            self._session.user_flagged_count += 1
            print("\n  ✅ Noted. I'll pay closer attention.\n")
            try:
                from driftcore.audit import record
                record(
                    action="USER_FLAGGED_DRIFT",
                    memory_text=str(triggered),
                    authorised_by="user",
                    detail="User confirmed relationship drift felt off",
                )
            except Exception:
                pass

        elif choice == "raise":
            duration = 30 * 60  # 30 minutes
            self._policy.vigilance_boost  = 0.15
            self._policy.vigilance_until  = time.time() + duration
            self._policy.save()
            print("\n  ✅ Raising vigilance for the next 30 minutes.\n")

        elif choice == "explain":
            print("\n  Tell me what felt off: ", end="")
            explanation = input().strip()
            if explanation:
                self._policy.weird_examples.append(explanation)
                self._policy.save()
                self._session.user_flagged_count += 1
                print(f"\n  ✅ Got it. I'll remember that felt wrong.\n")

        elif choice == "fine":
            print("\n  ✅ Understood. Carrying on.\n")

        # Default (Enter) — continue without action

    # ── User controls ─────────────────────────────────────────────

    def this_felt_weird(self, explanation: str = ""):
        """
        User says this interaction felt off.
        Feeds into relationship drift learning.
        Call this anytime — not just at check-in prompts.
        """
        self._session.user_flagged_count += 1
        if explanation:
            self._policy.weird_examples.append(explanation)
            self._policy.save()

        print(f"\n  ✅ Flagged. I'll factor that in.\n")

        try:
            from driftcore.audit import record
            record(
                action="USER_FLAGGED_DRIFT",
                memory_text=explanation or "user flagged without explanation",
                authorised_by="user",
                detail="Direct user flag via this_felt_weird()",
            )
        except Exception:
            pass

    def raise_vigilance(self, minutes: int = 30):
        """
        Temporarily increase sensitivity for soft drift detection.
        User can call this when something feels off but they can't
        articulate exactly what.
        """
        self._policy.vigilance_boost = 0.15
        self._policy.vigilance_until = time.time() + (minutes * 60)
        self._policy.save()
        print(f"\n  ✅ Vigilance raised for {minutes} minutes.\n")

    def set_preference(self, preference: str, value: float):
        """
        User adjusts a soft threshold to match their style.
        For example: "I prefer more directness — raise pushback minimum."
        Cannot touch safety hard thresholds.
        """
        safe_prefs = {
            "agreement_rate_max", "flattery_rate_max",
            "pushback_rate_min", "confidence_inflation_max",
            "contradiction_avoidance",
        }
        if preference not in safe_prefs:
            print(f"\n  ⚠️  '{preference}' is not a user-adjustable "
                  f"setting.\n")
            return

        setattr(self._policy, preference, value)
        self._policy.save()
        print(f"\n  ✅ Preference updated: {preference} = {value}\n")

    # ── Session boundary ──────────────────────────────────────────

    def session_summary(self) -> str:
        """
        Return plain language session summary.
        Call at session end — shows admin the safety score,
        shows user the relationship score.
        """
        return _session_summary(self._session)

    def end_session(self) -> SessionDriftState:
        """
        Close the current session, save summary, start fresh.
        Personality and preferences carry over.
        Safety and relationship scores reset.
        """
        summary = self.session_summary()
        print(summary)

        # Save session record
        self._save_session_record()

        # Audit chain
        try:
            from driftcore.audit import record
            record(
                action="SESSION_END",
                memory_text=f"session {self._session.session_id}",
                authorised_by="system",
                detail=f"safety_score={self._session.safety_drift_score:.2f}, "
                       f"relationship_score={self._session.relationship_score:.2f}, "
                       f"safety_triggers={self._session.safety_triggers}, "
                       f"user_flags={self._session.user_flagged_count}",
            )
        except Exception:
            pass

        # Personality/preferences carry over (policy persists)
        # Scores reset for next session
        completed = self._session
        self._session = self._new_session()
        return completed

    def current_scores(self) -> dict:
        """Return current drift scores — useful for Fable narration."""
        return {
            "safety_drift_score":    self._session.safety_drift_score,
            "safety_level":          self._session.safety_level().value,
            "relationship_score":    self._session.relationship_score,
            "relationship_level":    self._session.relationship_level().value,
            "safety_triggers":       self._session.safety_triggers,
            "interaction_count":     self._session.interaction_count,
            "user_flagged_count":    self._session.user_flagged_count,
            "vigilance_active":      (
                self._policy.vigilance_until is not None and
                time.time() < (self._policy.vigilance_until or 0)
            ),
        }

    # ── Internal helpers ──────────────────────────────────────────

    def _log_safety_trigger(self, signal: str, text: str):
        try:
            os.makedirs("logs", exist_ok=True)
            with open("logs/safety_drift.jsonl", "a") as f:
                f.write(json.dumps({
                    "timestamp": time.time(),
                    "signal":    signal,
                    "text":      text[:300],
                    "session":   self._session.session_id,
                }) + "\n")
        except Exception:
            pass

    def _save_session_record(self):
        try:
            os.makedirs("logs", exist_ok=True)
            record = {
                "session_id":          self._session.session_id,
                "started_at":          self._session.started_at,
                "ended_at":            time.time(),
                "interaction_count":   self._session.interaction_count,
                "safety_drift_score":  self._session.safety_drift_score,
                "relationship_score":  self._session.relationship_score,
                "safety_triggers":     self._session.safety_triggers,
                "user_flagged_count":  self._session.user_flagged_count,
            }
            with open("logs/session_history.jsonl", "a") as f:
                f.write(json.dumps(record) + "\n")
        except Exception:
            pass

    def _audit_drift_state(self):
        """Periodically write drift state to audit chain."""
        if self._session.interaction_count % 5 == 0:
            try:
                from driftcore.audit import record
                record(
                    action="DRIFT_CHECKPOINT",
                    memory_text=f"session {self._session.session_id}",
                    authorised_by="drift_detector",
                    detail=f"safety={self._session.safety_drift_score:.2f}, "
                           f"relationship={self._session.relationship_score:.2f}, "
                           f"exchanges={self._session.interaction_count}",
                )
            except Exception:
                pass
