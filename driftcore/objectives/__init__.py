"""
driftcore.objectives
=====================
The universal Objective Engine: purpose as a versioned, human-ratified,
hash-linked artifact, plus a mechanical on-objective coverage check and the
embodiment floor contract.

UNIVERSAL by design. Nothing here knows about a specific body, force, or home.
Concrete objective content and concrete floor values belong to the deployment
layer (e.g. LifeCore for a particular robot) and fill the slots defined here.

Status:
  IMPLEMENTED — Objective artifact + ledger (propose / human-ratify / verify
                chain), the goodness-as-target invariant, the coverage check,
                and the floor contract.
  PROPOSED    — the faithfulness judge (returns UNVERIFIABLE, routes to human)
                and a dedicated OBJECTIVE authority layer in the resolver.
"""

from driftcore.objectives.engine import (
    Objective,
    ObjectiveSignal,
    SignalRole,
    ObjectiveLedger,
    ObjectiveProposal,
    ProposalStatus,
    GoodnessAsTargetError,
)
from driftcore.objectives.coverage import (
    PlannedAction,
    CoverageResult,
    check_coverage,
    FaithfulnessResult,
    FaithfulnessOutcome,
    check_faithfulness,
    FloorHandle,
    FloorContractError,
    require_local_floor,
    enforce_local_floor,
)

__all__ = [
    "Objective", "ObjectiveSignal", "SignalRole", "ObjectiveLedger",
    "ObjectiveProposal", "ProposalStatus", "GoodnessAsTargetError",
    "PlannedAction", "CoverageResult", "check_coverage",
    "FaithfulnessResult", "FaithfulnessOutcome", "check_faithfulness",
    "FloorHandle", "FloorContractError", "require_local_floor",
    "enforce_local_floor",
]
