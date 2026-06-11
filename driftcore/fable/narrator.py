"""
narrator.py — The Fable Narrator v3.1

WARNINGS ARE LOUD. ALWAYS.
If something is wrong, the system says so clearly.
Humans must not have to hunt for safety signals.
"""

from datetime import datetime
from driftcore.kernel.state_machine import SystemState, STATE_DESCRIPTIONS


# Warning thresholds
SYCOPHANCY_WARN  = 0.40   # warn earlier
DRIFT_WARN       = 0.20   # any elevation gets flagged
CONFIDENCE_WARN  = 0.50   # below this in TRUTH mode = loud warning


class Narrator:

    def __init__(self, verbosity: str = "standard"):
        self.verbosity = verbosity
        self.stories = []
        self.warning_count = 0

    # ── Mode changes ──────────────────────────────────────────

    def narrate_mode_change(self, from_mode: str, to_mode: str, requested_by: str):
        icons = {"TRUTH": "🔵", "CREATIVE": "🟣", "DISCOVERY": "🟡"}
        icon = icons.get(to_mode, "⚪")
        story = (
            f"\n{'='*65}\n"
            f"{icon} COGNITIVE MODE CHANGE: {from_mode} → {to_mode}\n"
            f"  Authorized by: {requested_by}\n"
            f"  {self._mode_warning(to_mode)}\n"
            f"{'='*65}"
        )
        self._emit(story)
        return story

    # ── Normal step ───────────────────────────────────────────

    def narrate_step(self, event: dict, state: SystemState, drift_score: float, decision: str, mode: str = "TRUTH"):
        action = event.get("action", "an action")
        icons  = {"TRUTH": "🔵", "CREATIVE": "🟣", "DISCOVERY": "🟡"}
        icon   = icons.get(mode, "⚪")

        lines = [f"[{self._now()}] {icon} [{mode}] Action: '{action}'"]

        if self.verbosity in ("standard", "full"):
            lines.append(f"  State: {state.name} — {STATE_DESCRIPTIONS[state]}")
            lines.append(f"  Drift: {drift_score:.3f}  {self._drift_bar(drift_score)}")

        lines.append(f"  Decision: {self._explain_decision(decision)}")

        # Inline drift warning
        if drift_score >= DRIFT_WARN:
            lines.append(self._drift_warning_line(drift_score))

        story = "\n".join(lines)
        self._emit(story)
        return story

    # ── Blocks & halts ────────────────────────────────────────

    def narrate_block(self, state: SystemState, drift_score: float):
        story = (
            f"\n{'!'*65}\n"
            f"🛑  EXECUTION BLOCKED\n"
            f"  State  : {state.name}\n"
            f"  Reason : {STATE_DESCRIPTIONS[state]}\n"
            f"  Drift  : {drift_score:.3f}  {self._drift_bar(drift_score)}\n"
            f"  Action : No operations until a human operator reviews and releases.\n"
            f"{'!'*65}"
        )
        self._emit(story, is_warning=True)
        return story

    def narrate_halt(self, reason: str):
        story = (
            f"\n{'!'*65}\n"
            f"🛑🛑🛑  EMERGENCY HALT ENGAGED\n"
            f"  Reason  : {reason}\n"
            f"  Status  : ALL OPERATIONS STOPPED\n"
            f"  Required: HUMAN INTERVENTION before any restart\n"
            f"{'!'*65}"
        )
        self._emit(story, is_warning=True)
        return story

    # ── State transition ──────────────────────────────────────

    def narrate_transition(self, from_state: str, to_state: str, drift_score: float):
        if from_state == to_state:
            return None

        # Escalating = loud warning; de-escalating = quieter
        escalating = SystemState[to_state].value > SystemState[from_state].value

        if escalating:
            story = (
                f"\n{'*'*65}\n"
                f"⚠️⚠️  STATE ESCALATION: {from_state} → {to_state}\n"
                f"  Drift score : {drift_score:.3f}  {self._drift_bar(drift_score)}\n"
                f"  New state   : {STATE_DESCRIPTIONS[SystemState[to_state]]}\n"
                f"  ➡  Human review recommended immediately.\n"
                f"{'*'*65}"
            )
            self._emit(story, is_warning=True)
        else:
            story = (
                f"[{self._now()}] ✅ State de-escalated: {from_state} → {to_state} "
                f"(drift: {drift_score:.3f})"
            )
            self._emit(story)
        return story

    # ── Sycophancy ────────────────────────────────────────────

    def narrate_sycophancy_warning(self, score: float, signals: list):
        level = self._syco_level(score)
        bang  = "🚨🚨🚨" if score >= 0.60 else "⚠️⚠️ "

        story = (
            f"\n{'!'*65}\n"
            f"{bang}  SYCOPHANCY WARNING\n"
            f"  Score  : {score:.3f}  {self._syco_bar(score)}\n"
            f"  Level  : {level}\n"
        )
        if signals:
            story += "  Signals detected:\n"
            for s in signals:
                story += f"    {s}\n"
        story += (
            f"  Risk   : System may be reinforcing beliefs instead of seeking truth.\n"
            f"  Action : Review recent interactions. Consider human oversight.\n"
            f"{'!'*65}"
        )
        self._emit(story, is_warning=True)
        return story

    # ── Drift signals ─────────────────────────────────────────

    def narrate_drift_signals(self, signals: list):
        if not signals:
            return None
        story = (
            f"\n{'*'*65}\n"
            f"⚠️  DRIFT SIGNALS DETECTED\n"
        )
        for s in signals:
            story += f"  {s}\n"
        story += f"{'*'*65}"
        self._emit(story, is_warning=True)
        return story

    # ── Creative leaps ────────────────────────────────────────

    def narrate_creative_leap(self, hypothesis: dict):
        conf  = hypothesis.get("confidence", 0)
        story = (
            f"[{self._now()}] 🟣 CREATIVE LEAP\n"
            f"  Hypothesis : {hypothesis.get('hypothesis', '')}\n"
            f"  Confidence : {conf:.0%}  {self._conf_bar(conf)}\n"
            f"  Type       : {hypothesis.get('label', '')}\n"
            f"  ⚠️  SPECULATIVE — Do not treat as fact."
        )
        self._emit(story)
        return story

    # ── Uncertainty ───────────────────────────────────────────

    def narrate_uncertainty(self, estimate):
        story = (
            f"[{self._now()}] 📊 UNCERTAINTY\n"
            f"  {estimate.human_readable()}"
        )
        self._emit(story)
        return story

    def narrate_low_confidence_in_truth_mode(self, value, confidence: float):
        story = (
            f"\n{'!'*65}\n"
            f"🚨  TRUTH MODE CONFIDENCE VIOLATION\n"
            f"  Confidence : {confidence:.0%}  {self._conf_bar(confidence)}\n"
            f"  Threshold  : 70% required in TRUTH MODE\n"
            f"  Value      : {value}\n"
            f"  Action     : Output BLOCKED. Switch to DISCOVERY mode or verify data.\n"
            f"{'!'*65}"
        )
        self._emit(story, is_warning=True)
        return story

    # ── No human in loop ─────────────────────────────────────

    def narrate_no_human_in_loop(self, context: str, risk_level: str = "HIGH"):
        story = (
            f"\n{'!'*65}\n"
            f"🚨🚨  NO HUMAN IN THE LOOP — {risk_level} RISK CONTEXT\n"
            f"  Context : {context}\n"
            f"  Warning : Full autonomy in this context is a liability.\n"
            f"  Lesson  : Pizza Hut/Dragontail lost $100M with no human oversight.\n"
            f"  Action  : Human checkpoint REQUIRED before proceeding.\n"
            f"{'!'*65}"
        )
        self._emit(story, is_warning=True)
        return story

    # ── Summary ───────────────────────────────────────────────

    def warning_summary(self):
        story = (
            f"\n{'='*65}\n"
            f"📋 FABLE SESSION SUMMARY\n"
            f"  Total events  : {len(self.stories)}\n"
            f"  Warnings fired: {self.warning_count} "
            f"{'✅ None' if self.warning_count == 0 else '⚠️  Review required'}\n"
            f"{'='*65}"
        )
        self._emit(story)
        return story

    def full_story(self) -> str:
        return "\n\n".join(self.stories)

    # ── Internal helpers ──────────────────────────────────────

    def _emit(self, story: str, is_warning: bool = False):
        self.stories.append(story)
        if is_warning:
            self.warning_count += 1
        print(story)

    def _drift_warning_line(self, score: float) -> str:
        if score >= 0.75: return f"  🚨🚨 CRITICAL DRIFT — immediate human review required"
        if score >= 0.60: return f"  🚨  HIGH DRIFT — escalation recommended"
        if score >= 0.40: return f"  ⚠️   ELEVATED DRIFT — monitoring increased"
        return              f"  🔶  DRIFT WATCH — minor elevation detected"

    def _drift_bar(self, score: float) -> str:
        filled = int(score * 20)
        bar    = "█" * filled + "░" * (20 - filled)
        label  = self._drift_label(score)
        return f"[{bar}] {label}"

    def _conf_bar(self, score: float) -> str:
        filled = int(score * 20)
        return f"[{'█' * filled}{'░' * (20 - filled)}]"

    def _syco_bar(self, score: float) -> str:
        filled = int(score * 20)
        return f"[{'█' * filled}{'░' * (20 - filled)}]"

    def _drift_label(self, score: float) -> str:
        if score < 0.20:  return "✅ nominal"
        if score < 0.40:  return "🔶 watch"
        if score < 0.60:  return "⚠️  elevated"
        if score < 0.75:  return "🚨 high"
        if score < 0.90:  return "🚨🚨 critical"
        return              "🚨🚨🚨 EMERGENCY"

    def _syco_level(self, score: float) -> str:
        if score < 0.20: return "✅ Healthy"
        if score < 0.40: return "🔶 Watch"
        if score < 0.60: return "⚠️  Elevated — pattern emerging"
        if score < 0.80: return "🚨 HIGH — epistemic autonomy at risk"
        return            "🚨🚨 CRITICAL — human must intervene"

    def _mode_warning(self, mode: str) -> str:
        return {
            "TRUTH":     "⚠️  Outputs must be grounded. Hallucination = safety failure.",
            "CREATIVE":  "⚠️  Outputs are SPECULATIVE. Do not treat as factual claims.",
            "DISCOVERY": "📊 Outputs include confidence scores. Extrapolations are labelled.",
        }.get(mode, "")

    def _explain_decision(self, decision: str) -> str:
        return {
            "ALLOW":                        "✅ Permitted.",
            "BLOCKED":                      "🚫 BLOCKED — policy violation.",
            "REQUIRE_SAFE_STATE":           "⚠️  HELD — requires safe state first.",
            "EXECUTION_BLOCKED_SAFE_STATE": "🛑 BLOCKED — system in protective halt.",
        }.get(decision, f"Result: {decision}")

    def _now(self) -> str:
        return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
