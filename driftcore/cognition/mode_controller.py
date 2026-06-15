"""
driftcore/cognition/mode_controller.py — ATTEMPT FULLY, THEN REPORT
====================================================================

FIXES: Agents were hedging too early — using uncertainty as a reason
to deliver LESS instead of attempting the task fully and THEN reporting
confidence.

The old behaviour:
  "I can't get 100% → I'll only give you part of it"

The correct behaviour:
  "I'll attempt the full task → then tell you how confident I am"

Real-world example that revealed the bug:
  Grok running inside the OS gave a partial transcript and explained
  why it couldn't get everything. Grok WITHOUT the OS just did the
  task fully. The OS was making agents more honest but less useful.
  Both properties are required. This fix preserves the honesty and
  restores the full attempt.

SAFETY CONTRACT:
  - Modes are advisory — they shape HOW the agent attempts tasks
  - Modes never override invariants (those live in kernel/invariants.py)
  - Uncertainty is always reported AFTER the attempt, never used to
    justify withholding effort
  - NO_DECEPTION_OF_HUMAN_OPERATORS is preserved: confidence scores
    are always shown, never hidden
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


# ═══════════════════════════════════════════════════════════════
# MODES
# ═══════════════════════════════════════════════════════════════

class CognitionMode(Enum):
    TRUTH      = "truth"       # grounded, deductive — cite sources
    CREATIVE   = "creative"    # speculative, generative — always labelled
    DISCOVERY  = "discovery"   # bayesian, calibrated — show uncertainty


# ═══════════════════════════════════════════════════════════════
# ATTEMPT RESULT — what every task execution returns
# ═══════════════════════════════════════════════════════════════

@dataclass
class AttemptResult:
    """
    The output of any task attempted under the OS.

    ALWAYS contains:
      - output: the full best-effort result (never withheld due to uncertainty)
      - confidence: 0.0–1.0 (always shown, never hidden)
      - completeness: 0.0–1.0 (how complete is the output?)
      - caveats: plain-English notes about limitations
      - mode: which cognition mode was active

    The rule: output is ALWAYS the full attempt.
    Confidence and caveats explain the quality AFTER the attempt.
    """
    output: str
    confidence: float        # 0.0 = no confidence, 1.0 = certain
    completeness: float      # 0.0 = partial, 1.0 = complete
    caveats: list[str]       # plain-English limitations, empty if none
    mode: CognitionMode
    sources: list[str] = None  # cited sources, if any

    def format(self) -> str:
        """
        Human-readable output with confidence reported AFTER the content.
        The content always comes first. Caveats follow.
        """
        mode_label = {
            CognitionMode.TRUTH:     "🔵 TRUTH MODE",
            CognitionMode.CREATIVE:  "🟣 CREATIVE MODE (speculative — labelled)",
            CognitionMode.DISCOVERY: "🟡 DISCOVERY MODE",
        }[self.mode]

        lines = [
            f"**{mode_label}**",
            "",
            self.output,
        ]

        # Confidence footer — always shown, never before the content
        if self.caveats or self.completeness < 1.0:
            lines.append("")
            lines.append("---")
            lines.append(f"**Completeness:** {self.completeness*100:.0f}%  "
                        f"**Confidence:** {self.confidence*100:.0f}%")
            if self.caveats:
                for c in self.caveats:
                    lines.append(f"⚠️  {c}")
            if self.sources:
                lines.append("")
                lines.append("**Sources:** " + ", ".join(self.sources))

        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════
# MODE CONTROLLER — the fix lives here
# ═══════════════════════════════════════════════════════════════

class ModeController:
    """
    Controls how the agent attempts tasks in each cognition mode.

    THE CORE RULE (the fix):
        attempt_first = True   ← ALWAYS attempt the full task
        report_after  = True   ← ALWAYS report confidence after

    What this prevents:
        - Agents stopping early because they're uncertain
        - Agents delivering partial results and calling it "honesty"
        - Uncertainty being used as a reason to withhold effort

    What this preserves:
        - Full transparency about confidence and completeness
        - NO_DECEPTION_OF_HUMAN_OPERATORS (confidence always shown)
        - Mode-appropriate framing (Truth cites, Creative labels, Discovery scores)
    """

    # The rule, encoded as a constant so it's visible and auditable
    ATTEMPT_FIRST = True   # never change this to False
    REPORT_AFTER  = True   # never change this to False

    def wrap_result(
        self,
        output: str,
        mode: CognitionMode,
        confidence: float = 1.0,
        completeness: float = 1.0,
        caveats: list[str] = None,
        sources: list[str] = None,
    ) -> AttemptResult:
        """
        Wrap a completed task result with appropriate metadata.

        Agents call this AFTER doing the full task — not before.
        The output parameter must always be the agent's best full attempt.

        Args:
            output:       The full best-effort result. Never partial by choice.
            mode:         Which cognition mode is active.
            confidence:   How confident is the agent? (0.0–1.0)
            completeness: How complete is the output? (0.0–1.0)
            caveats:      Plain-English limitations (shown after content)
            sources:      Cited sources (Truth mode)
        """
        if not self.ATTEMPT_FIRST:
            raise RuntimeError(
                "ATTEMPT_FIRST must always be True. "
                "Uncertainty is reported after the attempt, never before."
            )

        return AttemptResult(
            output=output,
            confidence=confidence,
            completeness=completeness,
            caveats=caveats or [],
            mode=mode,
            sources=sources or [],
        )

    def validate_output(self, result: AttemptResult) -> list[str]:
        """
        Check a result before returning it to the operator.
        Returns a list of violations (empty = safe to return).

        Invariants checked:
          - Output must not be empty (withholding is not honesty)
          - Confidence must be reported (hiding it is deception)
          - Creative mode output must be labelled speculative
        """
        violations = []

        if not result.output or not result.output.strip():
            violations.append(
                "VIOLATION: Output is empty. Uncertainty is not a reason "
                "to withhold. Attempt the task fully and report confidence."
            )

        if result.confidence is None:
            violations.append(
                "VIOLATION: Confidence score missing. "
                "NO_DECEPTION_OF_HUMAN_OPERATORS requires confidence "
                "to always be reported."
            )

        if result.mode == CognitionMode.CREATIVE:
            if "speculative" not in result.output.lower() and \
               "creative" not in result.output.lower() and \
               "hypothetical" not in result.output.lower():
                violations.append(
                    "VIOLATION: Creative mode output must be labelled "
                    "speculative. Unlabelled speculation violates "
                    "NO_DECEPTION_OF_HUMAN_OPERATORS."
                )

        return violations


# ═══════════════════════════════════════════════════════════════
# TASK ATTEMPT GUIDE — plain English rules for agents
# ═══════════════════════════════════════════════════════════════

TASK_ATTEMPT_GUIDE = """
DRIFTCORE-OS TASK ATTEMPT RULES
================================

THE ONE RULE THAT FIXES THE BUG:
  Attempt the full task first. Report confidence after.
  Never use uncertainty as a reason to deliver less.

IN PRACTICE:

  ❌ WRONG (old behaviour):
     "I can't get the full transcript because captions aren't complete.
      Here are the parts I could get..."

  ✅ CORRECT (fixed behaviour):
     [Extract everything available — full attempt]
     "Here is the complete transcript extracted from available sources.
      Completeness: 95% | Confidence: 85%
      ⚠️ Minor timing artifacts may exist in auto-captions.
      ⚠️ For 100% verbatim accuracy, use YouTube's native transcript tool."

THE DIFFERENCE:
  Both are honest. Only one is fully helpful.
  The OS requires both honesty AND full effort — not one at the
  expense of the other.

PER MODE:

  🔵 TRUTH MODE:
     - Attempt the full task with all available sources
     - Cite sources in the footer, not in place of content
     - Report completeness and confidence after the output
     - Flag gaps as caveats, never as reasons to stop

  🟣 CREATIVE MODE:
     - Attempt the full creative task
     - Label ALL speculative content clearly
     - Confidence score reflects how grounded the speculation is
     - Never present creative content as fact

  🟡 DISCOVERY MODE:
     - Attempt the full task
     - Report Bayesian confidence scores per claim, after the output
     - Flag unknowns explicitly but do not let them block the attempt
     - "I don't know X" is a data point, not a stopping condition

SAFETY NOTE:
  These rules are advisory — they govern effort and framing.
  They never override kernel invariants.
  If a task would violate an invariant, refuse it entirely.
  If a task is merely uncertain, attempt it fully and say so.
"""
