"""
driftcore/verification/consequence_invariance.py
================================================
STATUS: PROPOSED (stdlib-only). Names and MAKES TESTABLE a property DriftCore
already half-has, adopted from LawZero's Scientist AI work.

Their principle (consequence invariance): the thing that judges an action must
never be trained or scored on "did this action succeed / pay off in the world?"
— only on the accuracy of its judgment at decision time. The moment downstream
outcomes can move the verdict, the guard learns to chase outcomes, and a guard
that chases outcomes can be gamed by luck.

DriftCore's `reflection.py` already scores against PRE-COMMITTED criteria, not
downstream results — so this is not a new behaviour to bolt on. It is the
property made into a CHECK: given a decision function and a record, prove the
decision does not move when fields describing downstream outcomes are varied. A
verdict that fails this is peeking at consequences, and the check names the field.

This does NOT make any decision itself. It audits whether a decision function is
outcome-blind. Pair it with a verdict function (e.g. reflection.evaluate) in a
test to pin the property.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, Sequence, Optional, Any


@dataclass(frozen=True)
class InvarianceReport:
    invariant: bool
    offending_field: Optional[str]
    detail: str


def check_consequence_invariance(
        decide: Callable[[Mapping[str, Any]], Any],
        record: Mapping[str, Any],
        outcome_fields: Sequence[str],
        probe_values: Sequence[Any],
) -> InvarianceReport:
    """`decide` must return the SAME verdict no matter what any `outcome_fields`
    (downstream-result fields) are set to. If varying one changes the verdict,
    the decision is peeking at consequences — report which field broke it."""
    base = decide(dict(record))
    for f in outcome_fields:
        for v in probe_values:
            mutated = {**record, f: v}
            if decide(mutated) != base:
                return InvarianceReport(
                    False, f,
                    f"verdict changed when downstream-outcome field {f!r} was varied "
                    f"to {v!r} — the decision is not consequence-invariant")
    return InvarianceReport(
        True, None,
        "verdict invariant to every declared downstream-outcome field")
