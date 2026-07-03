"""
driftcore/verification/harm_estimate.py
=======================================
STATUS: PROPOSED (stdlib-only). Calibrated uncertainty as a FACT on the approval
surface — adopted from LawZero, hardened after the red team.

  1. THE ESTIMATE IS A FACT, WITH PROVENANCE. A point probability, a confidence
     interval, and where the number came from. No verdict word, no severity score.

  2. THE CUTOFF IS HUMAN-SET, AND CONSERVATISM IS EXPLICIT. The threshold is owned
     by a human, not the agent. Bengio's "raise the bar when uncertain" is offered
     as an explicit option: judge on the CI UPPER bound, so a wide interval triggers
     caution. The human sets the cutoff and chooses conservative mode.

RED-TEAM HARDENING (the convergent finding). A human cutoff is only as trustworthy
as the estimate compared against it. A planner that supplies its own optimistic
`p` and a too-tight CI can skirt the human's threshold without ever touching it.
So an estimate now carries PROVENANCE, and `exceeds()` REFUSES to judge a planner-
sourced estimate against a human threshold — only a verifier-sourced estimate may
drive the cutoff. (Whether the estimator itself is honest/calibrated is upstream,
named in THREAT_BOUNDARIES — this module enforces that the threshold cannot be fed
an unverified number, not that the verifier is perfect.)
"""
from __future__ import annotations

from dataclasses import dataclass


class UntrustedEstimate(Exception):
    """Raised when a non-verifier-sourced estimate is used to drive a human threshold."""


@dataclass(frozen=True)
class HarmEstimate:
    p: float            # point estimate, P(harm) in 0..1
    ci_low: float
    ci_high: float
    source: str         # provenance string
    verifier_sourced: bool = False   # True ONLY when produced through a verifier path

    def as_fact(self) -> str:
        tag = "verifier" if self.verifier_sourced else "UNVERIFIED"
        return (f"P(harm) {self.p:.3f} (CI {self.ci_low:.3f}\u2013{self.ci_high:.3f}); "
                f"source={self.source} [{tag}]")


@dataclass(frozen=True)
class HarmThreshold:
    cutoff: float                  # human-set
    use_upper_bound: bool = True   # conservative: judge on CI upper bound when uncertain


def _crosses(est: HarmEstimate, thr: HarmThreshold) -> bool:
    """The raw comparison, provenance-aside. Single source of truth for the
    cutoff semantics so the verified and unverified paths cannot diverge."""
    value = est.ci_high if thr.use_upper_bound else est.p
    return value > thr.cutoff


def exceeds(est: HarmEstimate, thr: HarmThreshold) -> bool:
    """True if the (human-set) cutoff is crossed. REFUSES a planner-sourced estimate:
    a human threshold may only be driven by a verifier-sourced number."""
    if not est.verifier_sourced:
        raise UntrustedEstimate(
            "harm estimate is not verifier-sourced; a planner-supplied estimate may not "
            "drive a human governance threshold (input integrity — see THREAT_BOUNDARIES)")
    return _crosses(est, thr)


def would_exceed(est: HarmEstimate, thr: HarmThreshold) -> bool:
    """Provenance-AGNOSTIC: would this estimate cross the cutoff, regardless of
    source? This does NOT authorize anything — it only answers 'does this number
    say STOP?'. The asymmetry is the caller's job: a verified STOP decides RUN
    vs STOP; an UNVERIFIED STOP may not authorize proceeding, but it also may not
    be trusted to hard-stop on its own — it routes to a human. An unverified RUN
    (does not cross) may never be used to lower caution. (See coordinator._harm_check.)"""
    return _crosses(est, thr)
