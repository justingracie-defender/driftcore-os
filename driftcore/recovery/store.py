"""
driftcore/recovery/store.py
===========================
Immutable, tamper-evident checkpoint ledger — the "digital save state".

The premise is assume-breach: prevention fails eventually, so consequential
actions on data are preceded by a snapshot that can be restored. The single
property that makes this worth anything (and that most setups get wrong) is
that the agent can CREATE save-states but can never DELETE or ALTER them.
Otherwise a compromised agent — or a virus riding in through a tool — wipes
the backups first, then does the damage. That is the modern ransomware
playbook, and the defence is recovery state the agent cannot reach.

So this module splits into two surfaces:

  * CheckpointStore   — the AGENT-FACING api. create / get / list / verify.
                        There is deliberately no delete or modify method.
  * RestoreAuthority  — the PRIVILEGED api. restore / prune. Both require a
                        human authoriser and are audited.

The ledger is an append-only, hash-linked event log (CREATE / RESTORE /
PRUNE), exactly like the audit chain, so removing or altering a save-state
out of band is detectable via verify_integrity(). Snapshot bytes are stored
separately so prune() can reclaim space while the immutable RECORD that a
checkpoint existed and was pruned by whom, when remains in the ledger.

NOTE ON ENFORCEMENT: true immutability ultimately rests on the storage
backend (WORM / append-only object storage / a separate-privilege restore
process). This module models the authority boundary and makes tampering
detectable; it does not by itself stop a compromised host root. That is the
integrator's deployment responsibility and is called out in UPDATE_NOTES.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

# ── human identity ──────────────────────────────────────────────────────────
# (red-team, external) This module used to carry its OWN copy of a reserved-word
# blacklist, so `_is_human("mallory")` returned True and any caller that chose its
# own `authorised_by` string self-authorized. Three modules carried identical
# copies. The single shared implementation supports registered principals and
# signed attestations: driftcore/authority/human_identity.py
#
# The import is LOCAL (deferred) to break the authority <-> skills import cycle —
# the same idiom coordinator.py uses for interpretation_guard.
def _is_human(authorised_by) -> bool:
    from driftcore.authority.human_identity import is_human
    return is_human(authorised_by)



class EventKind(Enum):
    CREATE  = "create"
    RESTORE = "restore"
    PRUNE   = "prune"


class CheckpointStatus(Enum):
    ACTIVE   = "active"
    RESTORED = "restored"   # has been used to restore at least once
    PRUNED   = "pruned"     # snapshot bytes reclaimed; ledger record remains


@dataclass(frozen=True)
class CheckpointEvent:
    seq:           int
    kind:          EventKind
    checkpoint_id: str
    at:            float
    by:            str
    detail:        str
    payload_hash:  str   # hash of snapshot bytes (CREATE) else ""
    prev_hash:     str
    entry_hash:    str


@dataclass(frozen=True)
class CheckpointContext:
    """
    The decision-path context active when a checkpoint was taken, so an
    incident can be traced back to which domain / skill / version / profile /
    mode produced the action. All optional; hashed into the ledger entry, so
    the context is part of the immutable record.
    """
    domain:        str = ""
    skill:         str = ""
    skill_version: str = ""
    profile:       str = ""
    mode:          str = ""

    def summary(self) -> str:
        parts = [f"{k}={v}" for k, v in (
            ("domain", self.domain), ("skill", self.skill),
            ("skill_version", self.skill_version),
            ("profile", self.profile), ("mode", self.mode)) if v]
        return ",".join(parts) if parts else "no-context"


@dataclass(frozen=True)
class Checkpoint:
    checkpoint_id: str
    created_at:    float
    action_label:  str
    resource_ids:  tuple
    triggered_by:  str
    payload_hash:  str
    status:        CheckpointStatus
    context:       CheckpointContext = field(default_factory=CheckpointContext)


def _hash_event(fields: dict) -> str:
    return hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()


# ── Agent-facing store: create / read only ─────────────────────────

class CheckpointStore:
    """
    Append-only ledger of checkpoints. The agent may create and read; it has
    NO method to delete or modify. Deletion happens only via RestoreAuthority
    (human) and is itself an audited, append-only PRUNE event.
    """

    def __init__(self):
        self._events: List[CheckpointEvent] = []
        self._snapshots: Dict[str, bytes] = {}     # id -> snapshot bytes
        self._create_meta: Dict[str, dict] = {}    # id -> create metadata
        self._last_hash = "GENESIS"
        self._seq = 0
        self._lock = threading.RLock()             # serialise appends

    # -- create (agent may call) -------------------------------------

    def create(self, action_label: str, resource_ids, snapshot_bytes: bytes,
               triggered_by: str = "agent",
               context: "CheckpointContext" = None) -> Checkpoint:
        resource_ids = tuple(resource_ids)
        if not resource_ids:
            raise ValueError("create requires at least one resource_id")
        context = context or CheckpointContext()
        with self._lock:
            cid = uuid.uuid4().hex[:16]
            payload_hash = hashlib.sha256(snapshot_bytes).hexdigest()
            self._snapshots[cid] = snapshot_bytes
            self._create_meta[cid] = {
                "action_label": action_label,
                "resource_ids": resource_ids,
                "triggered_by": triggered_by,
                "created_at": time.time(),
                "payload_hash": payload_hash,
                "context": context,
            }
            # context is folded into the (hashed) event detail, so it is part
            # of the immutable, tamper-evident record — not editable later.
            self._append(EventKind.CREATE, cid, triggered_by,
                         f"action={action_label} resources={list(resource_ids)} "
                         f"context=[{context.summary()}]",
                         payload_hash)
        self._audit("CHECKPOINT_CREATED", triggered_by,
                    f"id={cid} action={action_label} context=[{context.summary()}]")
        return self.get(cid)

    # -- read (agent may call) ---------------------------------------

    def get(self, checkpoint_id: str) -> Optional[Checkpoint]:
        meta = self._create_meta.get(checkpoint_id)
        if not meta:
            return None
        return Checkpoint(
            checkpoint_id=checkpoint_id,
            created_at=meta["created_at"],
            action_label=meta["action_label"],
            resource_ids=meta["resource_ids"],
            triggered_by=meta["triggered_by"],
            payload_hash=meta["payload_hash"],
            status=self._status_of(checkpoint_id),
            context=meta.get("context", CheckpointContext()),
        )

    def list(self) -> List[Checkpoint]:
        return [self.get(cid) for cid in self._create_meta]

    def snapshot_bytes(self, checkpoint_id: str) -> Optional[bytes]:
        return self._snapshots.get(checkpoint_id)

    # -- integrity ---------------------------------------------------

    def verify_integrity(self) -> Tuple[bool, str]:
        """Recompute the event hash chain. Detects removal or alteration."""
        prev = "GENESIS"
        for i, e in enumerate(self._events):
            if e.seq != i + 1:
                return False, f"sequence gap at position {i + 1}"
            if e.prev_hash != prev:
                return False, f"broken link at seq {e.seq}"
            recomputed = _hash_event({
                "seq": e.seq, "kind": e.kind.value, "checkpoint_id": e.checkpoint_id,
                "at": e.at, "by": e.by, "detail": e.detail,
                "payload_hash": e.payload_hash, "prev_hash": e.prev_hash,
            })
            if recomputed != e.entry_hash:
                return False, f"altered event at seq {e.seq}"
            prev = e.entry_hash
        return True, "intact"

    def events(self) -> List[CheckpointEvent]:
        return list(self._events)

    # -- internal ----------------------------------------------------

    def _status_of(self, cid: str) -> CheckpointStatus:
        kinds = [e.kind for e in self._events if e.checkpoint_id == cid]
        if EventKind.PRUNE in kinds:
            return CheckpointStatus.PRUNED
        if EventKind.RESTORE in kinds:
            return CheckpointStatus.RESTORED
        return CheckpointStatus.ACTIVE

    def _append(self, kind: EventKind, cid: str, by: str, detail: str,
                payload_hash: str = ""):
        self._seq += 1
        at = time.time()
        entry_hash = _hash_event({
            "seq": self._seq, "kind": kind.value, "checkpoint_id": cid,
            "at": at, "by": by, "detail": detail,
            "payload_hash": payload_hash, "prev_hash": self._last_hash,
        })
        self._events.append(CheckpointEvent(
            seq=self._seq, kind=kind, checkpoint_id=cid, at=at, by=by,
            detail=detail, payload_hash=payload_hash,
            prev_hash=self._last_hash, entry_hash=entry_hash))
        self._last_hash = entry_hash

    @staticmethod
    def _audit(action: str, by: str, detail: str):
        try:
            from driftcore.audit import record
            record(action=action, memory_text="recovery",
                   authorised_by=by or "system", detail=detail)
        except Exception:
            pass

    # Privileged operations are intentionally NOT on this class. They live on
    # RestoreAuthority below, which requires a human authoriser. _restore_event
    # and _prune_event are the append hooks RestoreAuthority uses; they are not
    # part of the agent-facing surface.
    def _restore_event(self, cid: str, by: str, detail: str):
        with self._lock:
            self._append(EventKind.RESTORE, cid, by, detail)

    def _prune_event(self, cid: str, by: str, detail: str):
        with self._lock:
            self._append(EventKind.PRUNE, cid, by, detail)
            self._snapshots.pop(cid, None)  # reclaim space; ledger record remains


# ── Privileged authority: restore / prune (human only) ────────────



class RestoreAuthority:
    """
    The only path to restore or prune. Both require a human authoriser. The
    agent has no reference to this object in a correct deployment; it lives
    behind the human/admin privilege boundary.
    """

    def __init__(self, store: CheckpointStore, snapshotter):
        self._store = store
        self._snapshotter = snapshotter

    def restore(self, checkpoint_id: str, authorised_by: str) -> Tuple[bool, str]:
        if not _is_human(authorised_by):
            self._store._audit("RESTORE_DENIED", authorised_by or "system",
                               f"id={checkpoint_id} — human authoriser required")
            return False, "restore requires a human authoriser"

        ok, reason = self._store.verify_integrity()
        if not ok:
            self._store._audit("RESTORE_DENIED", authorised_by,
                               f"id={checkpoint_id} — ledger integrity failed: {reason}")
            return False, f"refusing to restore: checkpoint ledger compromised ({reason})"

        cp = self._store.get(checkpoint_id)
        if cp is None:
            return False, "no such checkpoint"
        if cp.status is CheckpointStatus.PRUNED:
            return False, "checkpoint snapshot was pruned; cannot restore"

        data = self._store.snapshot_bytes(checkpoint_id)
        if data is None:
            return False, "snapshot data unavailable"
        # integrity of the snapshot bytes themselves
        if hashlib.sha256(data).hexdigest() != cp.payload_hash:
            self._store._audit("RESTORE_DENIED", authorised_by,
                               f"id={checkpoint_id} — snapshot hash mismatch")
            return False, "snapshot integrity check failed"

        ok = self._snapshotter.restore(data, cp.resource_ids)
        self._store._restore_event(checkpoint_id, authorised_by,
                                   f"restored resources={list(cp.resource_ids)} ok={ok}")
        self._store._audit("RESTORE_PERFORMED" if ok else "RESTORE_FAILED",
                           authorised_by, f"id={checkpoint_id} ok={ok}")
        return ok, "restored" if ok else "restore backend failed"

    def prune(self, checkpoint_id: str, authorised_by: str) -> Tuple[bool, str]:
        if not _is_human(authorised_by):
            return False, "prune requires a human authoriser"
        if self._store.get(checkpoint_id) is None:
            return False, "no such checkpoint"
        self._store._prune_event(checkpoint_id, authorised_by, "snapshot reclaimed")
        self._store._audit("CHECKPOINT_PRUNED", authorised_by, f"id={checkpoint_id}")
        return True, "pruned (ledger record retained)"
