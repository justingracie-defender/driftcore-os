"""
driftcore/verification/uncertainty.py
=====================================
Uncertainty Engine + Governance Memory.

BEHAVIORAL uncertainty, not self-report. The score is the ConsistencyProbe's
`h_signal` — how much the model's answers diverge across prompt variations.
A confident-but-inconsistent model scores HIGH, which is exactly when it is
most dangerous. (Self-reported confidence is the thing we do NOT trust.)

MODE-AWARE, using the existing per-mode constants as the single source of
truth (no new magic numbers): MODE_DRIFT_TOLERANCE sets the threshold and
MODE_STORAGE_RULES sets containment.

  - TRUTH     (tol 0.30): uncertainty -> CAUTION. Escalate to human review;
                          do not auto-act; do not auto-store.
  - DISCOVERY (tol 0.50): uncertainty -> BOUNDED exploration. Provisional
                          (Tier 2, flagged); never autonomous action.
  - CREATIVE  (tol 0.70): uncertainty -> FUEL. Proceed freely BUT always
                          contained: never auto-stores, never actuates.

GUARD ABOVE ALL MODES. This engine never overrides the InvariantGuard. In
the coordinator the guard runs FIRST; CREATIVE may *imagine* a blocked
action, but the guard still blocks any effect.

GOVERNANCE MEMORY is append-only, hash-chained (tamper-evident), and
ADVISORY ONLY: precedent is surfaced for humans, never feeds the score,
never auto-decides, and can never lower a bright line.
HONEST LIMIT: the chain is tamper-EVIDENT, not OS-immutable — detection,
not prevention, lives here (same as the audit chain).
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional
from driftcore.verification.ledger import HashChainLedger

from driftcore.probe import ConsistencyProbe
from driftcore.cognition.cognitive_mode import (
    CognitiveMode, MODE_DRIFT_TOLERANCE, MODE_STORAGE_RULES,
)


class UncertaintyResponse(str, Enum):
    PROCEED         = "PROCEED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"   # TRUTH + uncertain
    EXPLORE_BOUNDED = "EXPLORE_BOUNDED"   # DISCOVERY + uncertain


@dataclass
class UncertaintyResult:
    mode:        str
    h_signal:    float       # behavioral uncertainty (0=consistent .. 1=divergent)
    consistency: float
    tolerance:   float
    uncertain:   bool
    response:    str
    contained:   bool        # output must not auto-store / actuate
    auto_store:  bool        # may this output auto-store?
    reason:      str
    precedent:   list = field(default_factory=list)   # advisory only

    def to_dict(self) -> dict:
        return {"mode": self.mode, "h_signal": self.h_signal,
                "consistency": self.consistency, "tolerance": self.tolerance,
                "uncertain": self.uncertain, "response": self.response,
                "contained": self.contained, "auto_store": self.auto_store,
                "reason": self.reason, "precedent_count": len(self.precedent)}


def _as_mode(m) -> CognitiveMode:
    if isinstance(m, CognitiveMode):
        return m
    return CognitiveMode(str(m).upper())


class GovernanceMemory:
    """Append-only, hash-chained, advisory precedent log.
    Uses the shared HashChainLedger (one tamper-evidence implementation)."""

    def __init__(self):
        self._ledger = HashChainLedger()

    @property
    def _chain(self) -> list:
        return self._ledger.chain

    def record(self, prompt: str, mode: str, h_signal: float, response: str) -> dict:
        return self._ledger.append({"prompt": prompt, "mode": mode,
                                    "h_signal": round(h_signal, 3), "response": response})

    def relevant(self, prompt: str, limit: int = 5) -> list:
        """Advisory precedent by keyword overlap. NEVER used to decide."""
        words = set(prompt.lower().split()[:6])
        hits = [e for e in self._chain if words & set(str(e["prompt"]).lower().split())]
        return hits[-limit:]

    def verify_chain(self) -> bool:
        return self._ledger.verify()

    def summary(self) -> str:
        ents = self._chain
        if not ents:
            return "No governance history yet."
        n = len(ents)
        review = sum(1 for e in ents if e["response"] == "REVIEW_REQUIRED")
        return f"{n} decisions logged | {review} escalated to human review | chain intact: {self.verify_chain()}"

    def __len__(self) -> int:
        return len(self._ledger)


class UncertaintyEngine:
    """Probe-fed, mode-aware uncertainty handling with advisory memory."""

    def __init__(self, probe: Optional[ConsistencyProbe] = None,
                 memory: Optional[GovernanceMemory] = None):
        self.probe  = probe or ConsistencyProbe(model_id="driftcore", interactive=False)
        self.memory = memory or GovernanceMemory()

    def assess(self, prompt: str, responses: List[str], mode="TRUTH") -> UncertaintyResult:
        """`responses` are the model's answers across prompt variations (the
        behavioral sample). In production a sampler supplies them; in tests
        they are provided directly. The engine measures their divergence."""
        m   = _as_mode(mode)
        pr  = self.probe.check_responses(prompt, responses)
        h   = pr.h_signal
        tol = MODE_DRIFT_TOLERANCE[m]
        uncertain = h > tol
        rules = MODE_STORAGE_RULES[m]

        if m == CognitiveMode.TRUTH:
            response   = UncertaintyResponse.REVIEW_REQUIRED if uncertain else UncertaintyResponse.PROCEED
            contained  = uncertain
            auto_store = rules["auto_store"] and not uncertain   # never auto-store when uncertain
            reason = ("High behavioral uncertainty in TRUTH mode → human review; not auto-stored."
                      if uncertain else "Consistent across variations; low uncertainty.")
        elif m == CognitiveMode.DISCOVERY:
            response   = UncertaintyResponse.EXPLORE_BOUNDED if uncertain else UncertaintyResponse.PROCEED
            contained  = uncertain                               # provisional; no autonomous action
            auto_store = rules["auto_store"]                     # Tier 2, flagged
            reason = ("Uncertainty treated as bounded exploration (Tier 2, no autonomous action)."
                      if uncertain else "Consistent; proceeding.")
        else:  # CREATIVE
            response   = UncertaintyResponse.PROCEED             # uncertainty is fuel
            contained  = True                                    # ALWAYS contained
            auto_store = False                                   # never auto-stores
            reason = "CREATIVE: uncertainty welcomed; output contained (speculative, never auto-stored or actuated)."

        result = UncertaintyResult(
            mode=m.value, h_signal=round(h, 3), consistency=round(pr.consistency, 3),
            tolerance=tol, uncertain=uncertain, response=response.value,
            contained=contained, auto_store=auto_store, reason=reason,
            precedent=self.memory.relevant(prompt),     # advisory only — not used above
        )
        self.memory.record(prompt, m.value, h, response.value)
        return result
