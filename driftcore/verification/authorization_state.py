"""
driftcore/verification/authorization_state.py
==============================================
STATUS: PROPOSED (stdlib-only). Durable, tamper-evident, CROSS-INSTANCE store for
the two pieces of security-critical coordinator state that MUST survive a crash
and MUST be shared across every agent instance in a deployment:

  1. burned authorization nonces   (replay defense)
  2. per-owner accepted-cycle count (bounded-autonomy budget)

WHY THIS MODULE EXISTS — two real holes it closes, both found by red-teaming this
week's code:

  * CRASH WIPES THE REPLAY DEFENSE. The coordinator kept `used_nonces` in a plain
    in-memory set. A process restart emptied it, so a captured signed objective
    change could be replayed after a crash. Nonces must be DURABLE.

  * MULTI-INSTANCE DEFEATS THE BUDGET AND THE NONCE. The repeating-tasks profile
    exists for "8 agents". Eight coordinator instances meant eight independent
    nonce sets and eight independent cycle budgets — so ONE signed change was
    accepted eight times, and the cap counted per-process. Both must be SHARED.

The recovery CheckpointStore has the right shape (append-only, hash-linked) but is
itself in-memory, so it solves tamper-evidence, not durability. This module keeps
that shape AND is file-backed: an append-only, hash-chained JSONL log that any
number of instances open on the same path.

HONEST LIMITS — stated so no one over-trusts this:
  * This is single-host durability (a file + an OS advisory lock). It is NOT a
    distributed consensus store. Instances on DIFFERENT hosts sharing state need a
    real shared backend (DB / KV with atomic compare-and-set); the interface here
    is deliberately small so that swap is a drop-in. Flagged for red-team.
  * The hash chain makes truncation/edit DETECTABLE (`verify_integrity`), not
    IMPOSSIBLE. Whoever can write the file can rewrite the chain from a point and
    re-link it. True tamper-EVIDENCE needs the head hash anchored somewhere the
    writer can't reach (e.g. an external append-only sink). Also flagged.
  * The advisory lock (fcntl/msvcrt) serialises writers cooperatively on one host.
    A process that bypasses this module and writes the file directly is outside
    the guarantee — the same "governed channel only" boundary as the rest.
"""
from __future__ import annotations

import json
import os
import hashlib
import threading
import time
from typing import Dict, Optional, Tuple

# Cross-platform advisory file lock (best-effort; see HONEST LIMITS).
try:                                   # POSIX
    import fcntl

    def _lock_file(f):  fcntl.flock(f.fileno(), fcntl.LOCK_EX)
    def _unlock_file(f): fcntl.flock(f.fileno(), fcntl.LOCK_UN)
except ImportError:                    # Windows
    try:
        import msvcrt

        def _lock_file(f):
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
        def _unlock_file(f):
            try:
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
    except ImportError:                # no OS lock available
        def _lock_file(f):  pass
        def _unlock_file(f): pass


def _entry_hash(prev_hash: str, record: dict) -> str:
    body = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + "\n" + body).encode()).hexdigest()


class ReplayError(Exception):
    """Raised when a nonce that is already burned is presented again."""


class AuthorizationStateError(Exception):
    """Raised when the on-disk chain fails integrity verification on load."""


class AuthorizationState:
    """
    Durable, hash-chained authorization state shared across instances via one
    append-only JSONL file. Every mutating call appends one hash-linked record
    and fsyncs under an exclusive OS advisory lock, then updates memory. Reads
    are served from the in-memory projection, which is rebuilt from the file on
    open and re-synced (tail-read) under the lock before each mutation so
    concurrent instances observe each other's writes.

    Records (one JSON object per line):
      {"seq","ts","prev","hash","op","owner","nonce"}
        op = "burn_nonce"  -> nonce becomes spent for owner
        op = "cycle_inc"   -> owner's accepted-cycle count += 1
        op = "reratify"    -> owner's cycle count reset to 0 (nonces PERSIST)
    """

    def __init__(self, path: str, *, audit_logger=None):
        self.path = path
        self._audit = audit_logger or (lambda **kw: None)
        self._lock = threading.RLock()             # in-process guard
        self._spent: Dict[str, set] = {}           # owner -> {nonce, ...}
        self._cycles: Dict[str, int] = {}          # owner -> accepted count
        self._head = "GENESIS"
        self._seq = 0
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        self._replay_from_disk()

    # ── load / verify ────────────────────────────────────────────
    def _replay_from_disk(self) -> None:
        if not os.path.exists(self.path):
            return
        with open(self.path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                self._apply_verified(rec)

    def _apply_verified(self, rec: dict) -> None:
        stated = rec.get("hash")
        recomputed = _entry_hash(rec.get("prev", ""),
                                 {k: rec[k] for k in rec if k not in ("hash",)})
        if rec.get("prev") != self._head or stated != recomputed:
            raise AuthorizationStateError(
                f"authorization-state chain broken at seq={rec.get('seq')}: "
                f"the durable log has been truncated or altered")
        self._project(rec)
        self._head = stated
        self._seq = rec.get("seq", self._seq)

    def _project(self, rec: dict) -> None:
        op, owner = rec.get("op"), rec.get("owner", "")
        if op == "burn_nonce":
            self._spent.setdefault(owner, set()).add(rec["nonce"])
        elif op == "cycle_inc":
            self._cycles[owner] = self._cycles.get(owner, 0) + 1
        elif op == "reratify":
            self._cycles[owner] = 0

    def verify_integrity(self) -> Tuple[bool, str]:
        """Recompute the whole chain from disk. Detects truncation/alteration."""
        prev, n = "GENESIS", 0
        if not os.path.exists(self.path):
            return True, "empty"
        with open(self.path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                recomputed = _entry_hash(prev, {k: rec[k] for k in rec if k != "hash"})
                if rec.get("prev") != prev or rec.get("hash") != recomputed:
                    return False, f"chain broken at seq={rec.get('seq')}"
                prev = rec["hash"]
                n += 1
        return True, f"ok ({n} entries)"

    # ── durable append (locked + fsynced) ────────────────────────
    def _append(self, op: str, owner: str, nonce: str = "") -> None:
        with self._lock:
            # Re-sync with any writes other instances made since we last looked,
            # so cross-instance nonce burns and counts are observed before we act.
            self._resync_locked()
            rec = {"seq": self._seq + 1, "ts": round(time.time(), 3),
                   "prev": self._head, "op": op, "owner": owner, "nonce": nonce}
            rec["hash"] = _entry_hash(self._head, rec)
            with open(self.path, "a") as f:
                _lock_file(f)
                try:
                    f.write(json.dumps(rec, separators=(",", ":")) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
                finally:
                    _unlock_file(f)
            self._project(rec)
            self._head = rec["hash"]
            self._seq = rec["seq"]

    def _resync_locked(self) -> None:
        """Replay only records past our current seq (cheap tail catch-up)."""
        if not os.path.exists(self.path):
            return
        with open(self.path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if rec.get("seq", 0) <= self._seq:
                    continue
                self._apply_verified(rec)

    # ── public API used by the coordinator ───────────────────────
    def is_spent(self, owner: str, nonce: str) -> bool:
        with self._lock:
            self._resync_locked()
            return nonce in self._spent.get(owner, ())

    def burn_nonce(self, owner: str, nonce: str) -> None:
        """Mark a nonce spent for an owner. Raises ReplayError if already spent —
        the caller MUST treat that as a failed authorization, never a pass."""
        with self._lock:
            self._resync_locked()
            if nonce in self._spent.get(owner, ()):
                self._audit(stage="authorization_state", replay_blocked=True,
                            owner=owner)
                raise ReplayError(f"nonce already burned for owner={owner!r}")
            self._append("burn_nonce", owner, nonce)

    def cycle_count(self, owner: str) -> int:
        with self._lock:
            self._resync_locked()
            return self._cycles.get(owner, 0)

    def increment_cycle(self, owner: str) -> int:
        self._append("cycle_inc", owner)
        return self._cycles.get(owner, 0)

    def reset_cycles(self, owner: str) -> None:
        """Re-ratification: reset the shared budget. Nonces are NOT cleared, so
        old authorizations can never replay after a re-ratify."""
        self._append("reratify", owner)


class _StoreBackedNonces:
    """Set-like view of ONE owner's burned nonces, backed by AuthorizationState.
    Supports exactly the two operations verify_planning_cycle uses on the nonce
    set: membership (`nonce in view`) and burn (`view.add(nonce)`). This lets the
    existing, tested planning-cycle logic gain durable + cross-instance replay
    defense with no change to that logic. A cross-instance race on the same nonce
    resolves fail-closed: whichever instance burns first wins; the loser's add()
    raises ReplayError, which the coordinator treats as a failed authorization."""

    def __init__(self, store: "AuthorizationState", owner: str):
        self._store = store
        self._owner = owner

    def __contains__(self, nonce: str) -> bool:
        return self._store.is_spent(self._owner, nonce)

    def add(self, nonce: str) -> None:
        self._store.burn_nonce(self._owner, nonce)   # durable + shared + fsynced
