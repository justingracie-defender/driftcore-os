"""
driftcore/recovery
==================
The "digital save state" — assume-breach recovery for data and state.

Consequential actions are preceded by a snapshot the agent can create but
can never delete or alter (append-only, tamper-evident ledger). Restore is a
human-only authority. A monitor halt freezes further mutation and preserves
the save-states; a human decides whether to roll back.

Covers data/state under the system's control. Truly external irreversible
effects (a sent wire, a read email) have no rollback and are handled by the
prevention gate + human authorisation instead, not here.
"""

from driftcore.recovery.store import (
    CheckpointStore,
    RestoreAuthority,
    Checkpoint,
    CheckpointContext,
    CheckpointStatus,
    CheckpointEvent,
    EventKind,
)
from driftcore.recovery.manager import (
    RecoveryManager,
    ResourceSnapshotter,
    InMemorySnapshotter,
)

__all__ = [
    "CheckpointStore", "RestoreAuthority", "Checkpoint", "CheckpointContext",
    "CheckpointStatus", "CheckpointEvent", "EventKind",
    "RecoveryManager", "ResourceSnapshotter", "InMemorySnapshotter",
]
