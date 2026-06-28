"""
driftcore/verification/edge_loop.py
===================================
The human-ratified learning loop — "case law, not weight updates."

    edge detected → options proposed → human ratifies / substitutes
                  → rule + regression test recorded
                  → append-only, hash-chained, REVISABLE

Every lesson is a readable, versioned artifact a human approved, and any
lesson can be unlearned. The system is the clerk that spots the gap and
drafts options; the human is the judge; the ledger is the case law.

SAFETY PROPERTIES (all tested):
  - INSUFFICIENT SIGNAL never fabricates. The only resolution for garbage /
    unintelligible input is to ask for clarification. You cannot ratify
    "act anyway" on it.
  - A ruling can NEVER lower a bright line. Any chosen outcome whose effect
    the InvariantGuard would BLOCK is refused — even for a human.
  - Human-only. An agent cannot ratify or overturn (mirrors human-only
    mode switching and propose-but-never-self-grant).
  - Revisable. A precedent can be overturned; the ledger is append-only and
    hash-chained, so overturning APPENDS a correction — history is never
    erased (backpedaling without rewriting).

HONEST LIMIT: the system proposes the *structural* choices (which rule
wins, fall back to the reversible default, escalate). It does not fabricate
a moral verdict — the human supplies the judgment. Signal quality and rule
matching are inputs supplied by upstream analysis; this module decides what
to do with them.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional
import hashlib
import json
import time

from driftcore.verification.invariant_guard import InvariantGuard, GuardStatus
from driftcore.verification.ledger import HashChainLedger


class EdgeType(str, Enum):
    COVERED             = "COVERED"
    UNCOVERED           = "UNCOVERED"
    CONFLICT            = "CONFLICT"
    INSUFFICIENT_SIGNAL = "INSUFFICIENT_SIGNAL"


INSUFFICIENT_THRESHOLD = 0.30      # signal_quality below this => cannot interpret
CLARIFY  = "REQUEST_CLARIFICATION"
ESCALATE = "ESCALATE_TO_HUMAN"


@dataclass
class EdgeOption:
    id:       str
    action:   str
    tradeoff: str
    effect:   Optional[str] = None     # named only if the option causes an effect


@dataclass
class EdgeReport:
    edge_type:   str
    description: str
    options:     List[EdgeOption]
    recommended: Optional[str]
    precedent:   list = field(default_factory=list)

    @property
    def is_edge(self) -> bool:
        return self.edge_type != EdgeType.COVERED.value


@dataclass
class Ruling:
    case_key:        str
    outcome:         str
    by:              str
    rationale:       str
    regression_case: dict          # {"input": ..., "expected": ...} — the test to add
    ts:              float
    rid:             str = ""


def _key(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12]


class RulingLedger:
    """Append-only, hash-chained ledger of rulings and overturns.
    Uses the shared HashChainLedger (one tamper-evidence implementation)."""

    def __init__(self):
        self._ledger = HashChainLedger()

    @property
    def _chain(self) -> list:
        return self._ledger.chain

    def record_ruling(self, ruling: Ruling) -> Ruling:
        ruling.rid = f"r{len(self._ledger) + 1}"
        self._ledger.append({"kind": "RULING",
                             "payload": {"rid": ruling.rid, "case_key": ruling.case_key,
                                         "outcome": ruling.outcome, "by": ruling.by,
                                         "rationale": ruling.rationale}})
        return ruling

    def overturn(self, rid: str, by: str, rationale: str) -> dict:
        return self._ledger.append({"kind": "OVERTURN",
                                    "payload": {"rid": rid, "by": by, "rationale": rationale}})

    def is_overturned(self, rid: str) -> bool:
        return any(e["kind"] == "OVERTURN" and e["payload"]["rid"] == rid
                   for e in self._chain)

    def active_rulings(self) -> list:
        """Rulings not (yet) overturned — the live rule set."""
        return [e["payload"] for e in self._chain
                if e["kind"] == "RULING" and not self.is_overturned(e["payload"]["rid"])]

    def verify_chain(self) -> bool:
        return self._ledger.verify()

    def __len__(self) -> int:
        return len(self._ledger)


class EdgeLoop:
    def __init__(self, guard: Optional[InvariantGuard] = None,
                 ledger: Optional[RulingLedger] = None):
        self.guard  = guard or InvariantGuard()
        self.ledger = ledger or RulingLedger()

    # ── 1. detect ──────────────────────────────────────────────────
    def detect(self, prompt: str, matched_rules: Optional[list] = None,
               rule_outcomes: Optional[list] = None,
               signal_quality: Optional[float] = None) -> EdgeReport:
        # Insufficient signal first — never fabricate a reading.
        if signal_quality is not None and signal_quality < INSUFFICIENT_THRESHOLD:
            return EdgeReport(
                EdgeType.INSUFFICIENT_SIGNAL.value,
                f"Signal quality {signal_quality:.2f} below {INSUFFICIENT_THRESHOLD}: cannot interpret.",
                [EdgeOption("clarify", CLARIFY,
                            "No action; request more signal. Never fabricate a reading.")],
                recommended="clarify")

        if not matched_rules:
            return EdgeReport(
                EdgeType.UNCOVERED.value,
                "No existing rule covers this case.",
                [EdgeOption("conservative", "DEFAULT_REVERSIBLE",
                            "Do the most reversible / no-op thing; safest when unsure."),
                 EdgeOption("escalate", ESCALATE, "Send to a human to decide.")],
                recommended="conservative")

        if rule_outcomes and len(set(rule_outcomes)) > 1:
            opts = [EdgeOption(f"rule_{i}", f"FOLLOW::{r}", f"Apply rule '{r}'.")
                    for i, r in enumerate(matched_rules)]
            opts.append(EdgeOption("escalate", ESCALATE, "Rules disagree; a human decides."))
            return EdgeReport(
                EdgeType.CONFLICT.value,
                f"Rules disagree: {list(matched_rules)} → {list(rule_outcomes)}.",
                opts, recommended="escalate")

        return EdgeReport(EdgeType.COVERED.value, "Existing rules handle this.",
                          [], recommended=None)

    # ── 2/3. propose is the report.options; here we ratify ─────────
    def ratify(self, report: EdgeReport, choice: Optional[str] = None,
               by: str = "human_operator", rationale: str = "",
               custom_outcome: Optional[str] = None,
               custom_effect: Optional[str] = None) -> dict:
        if by == "agent":
            return {"status": "DENIED",
                    "reason": "Agents cannot ratify rulings. Human authority required."}
        if not report.is_edge:
            return {"status": "NO_EDGE", "reason": "Nothing to ratify."}

        # The human may pick a proposed option OR substitute their own.
        if custom_outcome is not None:
            outcome, effect = custom_outcome, custom_effect
        else:
            opt = next((o for o in report.options if o.id == choice), None)
            if opt is None:
                return {"status": "INVALID", "reason": f"No option '{choice}'."}
            outcome, effect = opt.action, opt.effect

        # Insufficient signal may ONLY be resolved by clarification.
        if report.edge_type == EdgeType.INSUFFICIENT_SIGNAL.value and outcome != CLARIFY:
            return {"status": "REFUSED",
                    "reason": "Insufficient signal may only be resolved by clarification — never by acting."}

        # A ruling can NEVER lower a bright line.
        if effect is not None:
            gd = self.guard.evaluate(effect=effect)
            if gd.status == GuardStatus.BLOCKED:
                return {"status": "REFUSED",
                        "reason": f"A ruling cannot lower a bright line ({gd.binding_invariant})."}

        ruling = Ruling(case_key=_key(report.description), outcome=outcome, by=by,
                        rationale=rationale,
                        regression_case={"input": report.description, "expected": outcome},
                        ts=time.time())
        self.ledger.record_ruling(ruling)
        return {"status": "RATIFIED", "ruling": ruling}

    # ── 4. revise ──────────────────────────────────────────────────
    def overturn(self, rid: str, by: str = "human_operator", rationale: str = "") -> dict:
        if by == "agent":
            return {"status": "DENIED", "reason": "Agents cannot overturn rulings."}
        self.ledger.overturn(rid, by, rationale)
        return {"status": "OVERTURNED", "rid": rid}
