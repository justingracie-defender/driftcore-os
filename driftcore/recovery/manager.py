"""
driftcore/recovery/manager.py
=============================
Ties the checkpoint ledger to the action flow and the monitor.

Flow:
  1. before_action(...)  -> snapshot the affected resources, write a save-state,
                            return the checkpoint id. Refused while frozen.
  2. agent performs the action.
  3. if things go sideways:
       - the monitor (or a human) calls trigger_halt(...) -> FREEZE: no further
         mutating actions / checkpoints proceed, save-states preserved, alert.
       - a HUMAN calls restore(...) -> routed to RestoreAuthority. The agent
         cannot restore; auto-restore is deliberately NOT done (a wrong
         rollback is its own incident). The system halts automatically;
         a human decides to roll back.

The actual reading/writing of resources is an injected ResourceSnapshotter.
A real backend snapshots files / DB rows / object versions (ideally to WORM
storage). The in-memory backend here exists so the behaviour is testable.
"""

from __future__ import annotations

from typing import Iterable, Optional, Tuple

from driftcore.recovery.store import (
    CheckpointStore, RestoreAuthority, _is_human,
)


# ── Snapshotter interface + a real in-memory implementation ───────

class ResourceSnapshotter:
    """
    Captures and restores the state of named resources. Injected.
    Real backends: filesystem copy, DB dump, versioned object store, etc.
    """
    def snapshot(self, resource_ids: Iterable[str]) -> bytes:
        raise NotImplementedError

    def restore(self, data: bytes, resource_ids: Iterable[str]) -> bool:
        raise NotImplementedError


class InMemorySnapshotter(ResourceSnapshotter):
    """
    Reference backend over an in-memory key->value store. Enough to prove the
    full snapshot -> mutate -> restore round-trip in tests.
    """
    def __init__(self, state: Optional[dict] = None):
        self.state = dict(state or {})

    def snapshot(self, resource_ids) -> bytes:
        import json
        subset = {k: self.state.get(k) for k in resource_ids}
        return json.dumps(subset, sort_keys=True).encode()

    def restore(self, data: bytes, resource_ids) -> bool:
        import json
        subset = json.loads(data.decode())
        for k in resource_ids:
            if k in subset:
                self.state[k] = subset[k]
        return True


# ── Recovery manager ──────────────────────────────────────────────

class RecoveryManager:
    def __init__(self, store: CheckpointStore, snapshotter: ResourceSnapshotter,
                 restore_authority: Optional[RestoreAuthority] = None):
        self._store = store
        self._snapshotter = snapshotter
        self._authority = restore_authority or RestoreAuthority(store, snapshotter)
        self._frozen = False
        self._freeze_reason = ""

    @property
    def frozen(self) -> bool:
        return self._frozen

    @property
    def freeze_reason(self) -> str:
        return self._freeze_reason

    # -- pre-action checkpoint (agent path) --------------------------

    def before_action(self, action_label: str, resource_ids,
                      triggered_by: str = "agent",
                      context=None) -> Tuple[bool, str]:
        """
        Snapshot the resources an action is about to affect, BEFORE it runs.
        Returns (ok, checkpoint_id_or_reason). Refused while frozen so a halted
        system cannot keep mutating data. `context` (CheckpointContext) records
        the decision path — domain / skill / version / profile / mode — so an
        incident can be traced back to what produced the action.
        """
        if self._frozen:
            return False, f"system frozen ({self._freeze_reason}) — no new actions"
        resource_ids = tuple(resource_ids)
        if not resource_ids:
            return False, "no resource_ids supplied — nothing to checkpoint"
        snapshot = self._snapshotter.snapshot(resource_ids)
        cp = self._store.create(action_label, resource_ids, snapshot,
                                triggered_by, context=context)
        return True, cp.checkpoint_id

    # -- monitor / halt hook -----------------------------------------

    def trigger_halt(self, reason: str, severity: str = "critical") -> dict:
        """
        Called by the review module / anomaly detection (or a human) when
        something goes sideways. Freezes mutating actions and preserves all
        save-states. Does NOT auto-restore — that stays a human decision.
        """
        self._frozen = True
        self._freeze_reason = reason
        self._audit("RECOVERY_HALT", "monitor",
                    f"severity={severity} reason={reason}")
        return {
            "frozen": True,
            "reason": reason,
            "severity": severity,
            "checkpoints_available": len(self._store.list()),
            "action_required": "human review + restore decision",
        }

    def unfreeze(self, authorised_by: str) -> Tuple[bool, str]:
        """Resuming after a halt is a human-only act, like mode switching."""
        if not _is_human(authorised_by):
            return False, "unfreeze requires a human authoriser"
        self._frozen = False
        prev, self._freeze_reason = self._freeze_reason, ""
        self._audit("RECOVERY_UNFROZEN", authorised_by, f"was: {prev}")
        return True, "unfrozen"

    # -- restore (human only, routed) --------------------------------

    def restore(self, checkpoint_id: str, authorised_by: str) -> Tuple[bool, str]:
        """
        Delegates to RestoreAuthority. The agent calling this with a non-human
        authoriser is rejected there. Restore is permitted even while frozen —
        rolling back is exactly what you do during a halt — but a restore made
        during an active halt is itself high-stakes, so it is audited distinctly.
        """
        if self._frozen:
            self._audit("RESTORE_DURING_HALT", authorised_by or "system",
                        f"id={checkpoint_id} during freeze: {self._freeze_reason}")
        return self._authority.restore(checkpoint_id, authorised_by)

    @staticmethod
    def _audit(action: str, by: str, detail: str):
        try:
            from driftcore.audit import record
            record(action=action, memory_text="recovery",
                   authorised_by=by or "system", detail=detail)
        except Exception:
            pass
