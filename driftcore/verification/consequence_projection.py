"""
driftcore/verification/consequence_projection.py
================================================
STATUS: PROPOSED (stdlib-only, isolated). Keeper D from the second red-team pass.

The approval surface should not say "Recommended: Reject." It should lay out what
HAPPENS on each branch, as verifier-produced facts, and let the human reason. A
recommendation hides the reasoning and invites the rubber-stamp; a projection
exposes it.

Two structural rules, each a guard below — because "just present facts" quietly
re-introduces judgment through selection and omission (red-team point #1):

  1. BOTH BRANCHES, ALWAYS. You must show the consequence of acting AND of not
     acting. Showing only the "authorize" branch biases toward action by omission;
     the "refuse / do nothing" branch is a real outcome and is never dropped.
     (project() requires both)

  2. NO SMUGGLED VERDICT. A branch carries facts, not a steer. Judgment words
     ("recommended", "should", "best", "urgent", "safe", a severity score) are
     refused — including the renamed variants a red team reaches for. This is the
     same denylist-plus-discipline used by the approval surface; it is necessary,
     not sufficient, and the docstring says so out loud.
     (_JUDGMENT_TOKENS check)

This module does NOT compute the facts. The verifier does, upstream, and its
correctness is not this module's claim (freezing a fact does not make it true —
red-team point #4). This only enforces the SHAPE of an honest presentation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple


class ProjectionError(Exception):
    """Raised loudly when a projection would be misshapen or carry a smuggled verdict."""


# judgment that must not appear in a facts-only branch, with the obvious rename
# variants a red team tries (operational_index, review_hint, ...). Substring match,
# case-insensitive — deliberately broad; a false positive is cheaper than a steer.
_JUDGMENT_TOKENS = (
    "recommend", "should", "best", "advise", "suggest", "urgent", "severity",
    "risk", "safe", "dangerous", "score", "priority", "review_hint", "impact_class",
    "operational_index", "confidence_band", "decision_context", "anomaly_bucket",
)


@dataclass(frozen=True)
class Branch:
    action: str                 # "authorize" / "refuse" — what the human would decide
    facts: Tuple[str, ...]      # verifier-produced outcomes of that decision


@dataclass(frozen=True)
class ConsequenceProjection:
    authorize: Branch
    refuse: Branch
    # there is deliberately NO `recommendation` field on this dataclass.

    def as_lines(self) -> Tuple[str, ...]:
        out = ["If authorized:"] + [f"  - {f}" for f in self.authorize.facts]
        out += ["If refused:"] + [f"  - {f}" for f in self.refuse.facts]
        return tuple(out)


def _scan_for_verdict(facts: Tuple[str, ...]) -> None:
    for f in facts:
        low = f.lower()
        for tok in _JUDGMENT_TOKENS:
            if tok in low:
                raise ProjectionError(
                    f"branch fact carries a smuggled verdict ('{tok}'): {f!r}. "
                    "Project the outcome as a fact, do not steer.")


def project(authorize_facts: Tuple[str, ...], refuse_facts: Tuple[str, ...]) -> ConsequenceProjection:
    # rule 1 — both branches must be present and non-empty
    if not authorize_facts or not refuse_facts:
        raise ProjectionError(
            "both branches are required: show the consequence of acting AND of not "
            "acting. Omitting the refuse branch biases toward action.")
    # rule 2 — neither branch may smuggle a verdict
    _scan_for_verdict(authorize_facts)
    _scan_for_verdict(refuse_facts)
    return ConsequenceProjection(
        authorize=Branch("authorize", tuple(authorize_facts)),
        refuse=Branch("refuse", tuple(refuse_facts)))
