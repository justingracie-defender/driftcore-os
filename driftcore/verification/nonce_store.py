"""
nonce_store.py — a durable, self-pruning spent-nonce store.

WHY PRUNING IS SAFE (the property this rests on)
------------------------------------------------
A replay needs a grant that is still VALID. `PermissionVerifier.verify` refuses an
expired grant with `PermissionExpired` *independently of the nonce set* — an expired
grant is refused even when its nonce was never burned. Therefore:

    a nonce only has to be remembered until the grant carrying it has expired.

The spent-nonce set is a SLIDING WINDOW, not an archive. Keep it separate from the
audit ledger and each becomes easy:

  * THIS store   — replay prevention. Sliding window. Prunes itself.
  * audit ledger — the record of WHAT HAPPENED. Append-only, hash-chained, kept
                   forever, never pruned. That is where history belongs.

RED-TEAM HISTORY (ChatGPT, N1-N8) — what the first version got wrong
--------------------------------------------------------------------
The first cut was a comment-level security design. Each of these was DEMONSTRATED
before being fixed, and each is regression-locked in test_nonce_store.py:

  N1 CRITICAL — two owners silently destroyed each other's state. A prune rewrote the
     file from ONE owner's memory, erasing nonces another had appended: a store holding
     a live nonce went to EMPTY. A `threading.RLock` does nothing across processes.
     Fixed two ways: (a) an OS-level exclusive lock makes a second owner FAIL LOUDLY at
     construction instead of silently corrupting, and (b) rewrites MERGE from disk under
     that lock rather than clobbering with an in-memory view.
  N2 HIGH — a backwards wall-clock jump resurrected a pruned nonce: pruned at t=1200,
     clock rolled back to t=1000, and the grant is valid again with its nonce forgotten.
     Fixed: a persisted monotonic high-water mark. A backwards jump beyond tolerance
     FAILS CLOSED (ClockWentBackwards) instead of quietly reopening the window.
  N3 HIGH — `assert_max_ttl()` was a hook nobody had to call. Now `max_grant_ttl_seconds`
     is a REQUIRED constructor argument and an unsafe retention window cannot be
     constructed at all.
  N4 — memory was marked spent before the durable write succeeded, so a failed write
     left "spent in RAM, unspent on disk" and a restart reopened replay. Now the durable
     append+fsync happens FIRST; memory is updated only after it succeeds.
  N5 — the line format trusted nonce content: a nonce containing a tab/newline forged
     extra records (an attacker-chosen string became a spent nonce). Now nonces are
     strictly validated and rejected if they cannot be stored unambiguously.
  N6 — `os.replace` was not followed by a directory fsync, so the rename was not durable
     against power loss. Now fsynced.
  N7 — malformed records were silently skipped, i.e. corrupted security state was
     treated as "this nonce never existed". Now corruption FAILS CLOSED
     (NonceStoreCorrupt) unless the operator explicitly opts into salvage.
  N8 — "bounded" is qualified: bounded by ISSUANCE RATE x RETENTION, not by a fixed
     maximum. A high-volume issuer still consumes disk within the window.

REMAINING HONEST LIMITS
-----------------------
* Single-owner by design. Multiple concurrent writers are REFUSED, not supported; if a
  deployment truly needs many writers, put the authority behind one broker process (the
  DriftCore shape anyway) or use a real transactional store.
* The clock guard detects rollback of THIS store's own timeline. It does not give the
  verifier a trusted clock — grant expiry still reads the wall clock, so a deployment
  that cares wants a monotonic/attested time source shared by both.
* An exclusive lock is advisory: it stops cooperating processes, not a determined one
  that ignores locking or deletes the lock file.

stdlib-only. Drop-in: pass an instance as `PermissionVerifier(used_nonces=...)`.
"""

from __future__ import annotations

import os
import tempfile
import threading
import math
import time
from typing import Dict, Optional

try:
    import fcntl
    _HAVE_FLOCK = True
except ImportError:      # pragma: no cover - non-POSIX
    _HAVE_FLOCK = False


class NonceStoreError(RuntimeError):
    """Base for nonce-store security failures. All of these fail CLOSED."""


class NonceStoreLocked(NonceStoreError):
    """Another owner already holds this store (N1). Refusing rather than corrupting."""


class NonceStoreCorrupt(NonceStoreError):
    """The persisted security state is malformed (N7). Refusing rather than pretending
    the unreadable records never existed."""


class ClockWentBackwards(NonceStoreError):
    """Wall clock moved backwards beyond tolerance (N2). Refusing, because pruning and
    grant expiry both key on this clock: a rollback can un-expire a grant whose nonce
    has already been forgotten."""


class InvalidNonce(NonceStoreError):
    """A nonce that cannot be stored unambiguously (N5)."""


_FORBIDDEN = ("\n", "\r", "\t", "\x00")
_MAX_NONCE_LEN = 512


class ExpiringNonceStore:
    """Set-like spent-nonce store: durable, single-owner, bounded by rate x retention.

    Implements exactly the contract the verifier uses — `nonce in store` and
    `store.add(nonce)` — so it drops in with no change to signed_permission.

    A nonce inserted at T belonged to a grant not yet expired at T, so that grant
    expires no later than T + max_grant_ttl. Once retention (>= max_grant_ttl + skew)
    has elapsed, the grant is certainly expired and the nonce can be forgotten safely.
    """

    def __init__(self, path: str, *, retention_seconds: float,
                 max_grant_ttl_seconds: float, skew_seconds: float = 60.0,
                 prune_every: int = 64, time_fn=time.time,
                 salvage_corrupt: bool = False, single_owner: bool = True):
        if not math.isfinite(retention_seconds):
            # NaN is false against every comparator, so `<= 0` passed it through and
            # then `now - t >= retention` and `now - t < retention` were BOTH false:
            # nonces were neither pruned nor ever inside the window, leaving the
            # replay window undefined. Verified by execution, 2026-08-25.
            raise ValueError(
                "retention_seconds must be a finite number of seconds. A non-finite "
                "retention compares false against every bound, so it passes "
                "validation and then no nonce is ever inside or outside the window.")
        if retention_seconds <= 0:
            raise ValueError("retention_seconds must be positive")
        # N3: the relationship is validated at CONSTRUCTION. An unsafe configuration
        # cannot exist, rather than depending on someone remembering to assert it.
        need = float(max_grant_ttl_seconds) + float(skew_seconds)
        if retention_seconds < need:
            raise ValueError(
                f"retention_seconds={retention_seconds:.0f} is shorter than the longest "
                f"grant TTL ({max_grant_ttl_seconds:.0f}s) plus clock skew "
                f"({skew_seconds:.0f}s). A nonce would be forgotten while its grant is "
                f"still valid, reopening the replay window. Use "
                f"retention_seconds >= {need:.0f}.")

        self.path = path
        self.retention_seconds = float(retention_seconds)
        self.max_grant_ttl_seconds = float(max_grant_ttl_seconds)
        self.skew_seconds = float(skew_seconds)
        self._prune_every = max(1, int(prune_every))
        self._time = time_fn
        self._salvage = bool(salvage_corrupt)
        self._lock = threading.RLock()
        self._entries: Dict[str, float] = {}
        self._since_prune = 0
        self._lockfd: Optional[int] = None
        self._torn_tail = False
        self._absurd_horizon = 86400.0   # a value beyond this past the record bulk is corruption, not clock drift

        d = os.path.dirname(self.path) or "."
        os.makedirs(d, exist_ok=True)
        self._hw_path = self.path + ".hw"

        if single_owner:
            self._acquire_owner_lock()
        try:
            self._check_clock()
            self._load()
        except Exception:
            self.close()
            raise

    # ── N1: single-owner enforcement ──────────────────────────────

    def _acquire_owner_lock(self) -> None:
        """Take an exclusive OS lock so a second owner FAILS rather than silently
        destroying this one's state. The lock lives on a sidecar file because
        `os.replace` swaps the store file's inode (which would drop a lock held on it).
        """
        if not _HAVE_FLOCK:
            return   # non-POSIX: single-owner cannot be enforced here
        fd = os.open(self.path + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise NonceStoreLocked(
                f"another owner already holds {self.path!r}. This store is single-owner "
                f"by design: concurrent owners erase each other's replay state. Route "
                f"verification through one broker process, or use a transactional store.")
        self._lockfd = fd

    def close(self) -> None:
        if self._lockfd is not None:
            try:
                fcntl.flock(self._lockfd, fcntl.LOCK_UN)
                os.close(self._lockfd)
            except Exception:
                pass
            self._lockfd = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    # ── N2: clock rollback fails closed ───────────────────────────

    def _read_high_water(self) -> float:
        """The newest time this store has provably observed.

        (self red-team B2/B10) The sidecar alone was unauthenticated security state:
        DELETING it erased the rollback guard entirely, and one far-future number
        written into it bricked the store forever. The mark is therefore derived from
        BOTH the sidecar and the records, under one rule:

            take the newest observation that is not ABSURD,
            where absurd = more than one retention window ahead of the newest
            *record-anchored* time (or, with no records at all, ahead of the clock).

        Records anchor the timeline, so deleting the sidecar cannot erase the guard;
        and a single poisoned value — in the sidecar or in a record — is bounded rather
        than permanent. Note the ceiling is deliberately NOT "now": on a rolled-back
        clock the legitimately-newer records are precisely the evidence the guard needs.
        """
        def _finite(x):
            return isinstance(x, float) and x == x and x not in (
                float("inf"), float("-inf"))

        side = 0.0
        try:
            with open(self._hw_path) as f:
                side = float(f.read().strip() or 0.0)
        except (OSError, ValueError):
            side = 0.0
        if not _finite(side):
            side = 0.0

        times = [t for t in self._read_disk_raw_times() if _finite(t)]
        if self._entries:
            times += [t for t in self._entries.values() if _finite(t)]

        if times:
            # Walk the sorted times from the oldest, accepting each value that is not
            # an absurd jump past everything accepted so far. One poisoned far-future
            # record is left outside the accepted set no matter how few records exist;
            # the median would land ON the poison when there are only two.
            ordered = sorted(times)
            horizon = max(self.retention_seconds, self._absurd_horizon)
            newest = ordered[0]
            for t_i in ordered[1:]:
                if t_i <= newest + horizon:
                    newest = t_i
                else:
                    break        # everything beyond this is corruption, not drift
            ceiling = newest + horizon
        else:
            newest = 0.0
            ceiling = self._time() + max(self.retention_seconds, self._absurd_horizon)

        if side > ceiling:
            side = 0.0        # absurd sidecar: ignore rather than brick
        return max(side, newest)

    def _read_disk_raw_times(self):
        """Timestamps only, tolerant of any parse problem — used solely to anchor the
        clock high-water mark, never to decide whether a nonce is spent.

        Future-dated values are DISCARDED here (self red-team B6/B10): a single record
        written with a far-future timestamp would otherwise become the high-water mark
        and permanently brick the store on every subsequent open.
        """
        out = []
        if not os.path.exists(self.path):
            return out
        try:
            with open(self.path) as f:
                for line in f:
                    ts, sep, nonce = line.rstrip("\n").partition("\t")
                    if not sep:
                        continue
                    try:
                        t = float(ts)
                    except ValueError:
                        continue
                    if t != t or t in (float("inf"), float("-inf")):
                        continue
                    out.append(t)
        except OSError:
            pass
        return out

    def _write_high_water(self, t: float) -> None:
        tmp = self._hw_path + ".tmp"
        with open(tmp, "w") as f:
            f.write(repr(float(t)))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._hw_path)

    def _check_clock(self) -> float:
        """Refuse if the wall clock has moved backwards beyond tolerance."""
        now = self._time()
        hw = self._read_high_water()
        if hw and now < hw - self.skew_seconds:
            raise ClockWentBackwards(
                f"wall clock moved backwards: now={now:.0f} but this store previously "
                f"observed {hw:.0f} (tolerance {self.skew_seconds:.0f}s). Pruning and "
                f"grant expiry both key on this clock, so a rollback can un-expire a "
                f"grant whose nonce was already forgotten. Refusing.")
        if now > hw:
            self._write_high_water(now)
        return now

    # ── N5: a nonce must be storable unambiguously ────────────────

    @staticmethod
    def _validate(nonce) -> str:
        if not isinstance(nonce, str):
            nonce = str(nonce)
        if not nonce:
            raise InvalidNonce("empty nonce")
        if len(nonce) > _MAX_NONCE_LEN:
            raise InvalidNonce(f"nonce longer than {_MAX_NONCE_LEN} chars")
        for ch in _FORBIDDEN:
            if ch in nonce:
                raise InvalidNonce(
                    "nonce contains a record separator (newline/tab/NUL) and could "
                    "forge additional records in the store; rejected.")
        return nonce

    # ── durability ────────────────────────────────────────────────

    def _read_disk(self) -> Dict[str, float]:
        """Read every persisted record. Corruption fails CLOSED (N7)."""
        out: Dict[str, float] = {}
        if not os.path.exists(self.path):
            return out
        now = self._time()
        future_ok = now + self.skew_seconds
        with open(self.path, "r") as f:
            data = f.read()
        if data and not data.endswith("\n"):
            # (self red-team B5) A crash mid-append leaves a partial line. Silently
            # loading it lets a torn record be parsed as a whole one — and a spent
            # nonce can be lost. The last record is the only one that can be torn, and
            # its nonce was either never committed or is recoverable from the audit
            # ledger, so dropping it is safe; pretending it parsed is not.
            data = data[:data.rfind("\n") + 1] if "\n" in data else ""
            self._torn_tail = True
        else:
            self._torn_tail = False
        self._absurd_horizon = 86400.0   # a value beyond this past the record bulk is corruption, not clock drift
        for lineno, line in enumerate(data.splitlines(), 1):
            if not line:
                continue
            ts, sep, nonce = line.partition("\t")
            if not sep or not nonce:
                if self._salvage:
                    continue
                raise NonceStoreCorrupt(
                    f"{self.path}:{lineno}: malformed record. Refusing to treat "
                    f"unreadable replay state as 'never spent'. Investigate, or "
                    f"construct with salvage_corrupt=True to drop bad records.")
            try:
                t = float(ts)
            except ValueError:
                if self._salvage:
                    continue
                raise NonceStoreCorrupt(
                    f"{self.path}:{lineno}: unparseable timestamp {ts!r}.")
            if t != t or t in (float("inf"), float("-inf")):   # NaN / inf
                if self._salvage:
                    continue
                raise NonceStoreCorrupt(
                    f"{self.path}:{lineno}: non-finite timestamp {ts!r}.")
            if t > future_ok:
                # (self red-team B6) A future-dated record NEVER prunes: a permanent
                # entry and an unbounded-growth vector. Clamp it to now so it ages out
                # normally — it still counts as spent, it just cannot outlive the window.
                t = now
            out[nonce] = t if nonce not in out else max(out[nonce], t)
        return out

    def _load(self) -> None:
        now = self._time()
        disk = self._read_disk()
        self._entries = {n: t for n, t in disk.items()
                         if now - t < self.retention_seconds}
        if len(self._entries) != len(disk):
            self._rewrite_locked()   # compact away entries that are certainly expired

    def _rewrite_locked(self) -> None:
        """Atomically rewrite, MERGING from disk (N1) so a concurrent or prior writer's
        records are never clobbered by this owner's in-memory view."""
        now = self._time()
        merged = dict(self._read_disk())
        merged.update(self._entries)          # our view wins only on the same key
        live = {n: t for n, t in merged.items()
                if now - t < self.retention_seconds}
        self._entries = live

        d = os.path.dirname(self.path) or "."
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".nonces-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                for nonce, t in live.items():
                    f.write(f"{t}\t{nonce}\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
            self._fsync_dir(d)                # N6: make the rename itself durable
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    @staticmethod
    def _fsync_dir(d: str) -> None:
        try:
            dfd = os.open(d, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass   # some filesystems disallow directory fsync

    # ── the set contract the verifier uses ────────────────────────

    def add(self, nonce) -> None:
        nonce = self._validate(nonce)
        with self._lock:
            now = self._check_clock()
            # N4: persist FIRST. If the durable write fails we raise without having
            # marked it spent in memory, so caller and restart agree.
            with open(self.path, "a") as f:
                f.write(f"{now}\t{nonce}\n")
                f.flush()
                os.fsync(f.fileno())
            self._entries[nonce] = now
            self._since_prune += 1
            if self._since_prune >= self._prune_every:
                self._prune_locked()

    def __contains__(self, nonce) -> bool:
        try:
            nonce = self._validate(nonce)
        except InvalidNonce:
            # An unstorable nonce was never legitimately spent; treat as unseen and let
            # add() reject it if anyone tries to burn it.
            return False
        with self._lock:
            self._check_clock()
            t = self._entries.get(nonce)
            if t is None:
                return False
            if self._time() - t >= self.retention_seconds:
                del self._entries[nonce]
                return False
            return True

    def __len__(self) -> int:
        with self._lock:
            self._prune_locked()
            return len(self._entries)

    def __iter__(self):
        with self._lock:
            return iter(dict(self._entries))

    # ── pruning ───────────────────────────────────────────────────

    def _prune_locked(self) -> int:
        now = self._time()
        before = len(self._entries)
        dead = [n for n, t in self._entries.items()
                if now - t >= self.retention_seconds]
        for n in dead:
            del self._entries[n]
        self._since_prune = 0
        if dead:
            self._rewrite_locked()
        return before - len(self._entries)

    def prune(self) -> int:
        """Drop every nonce whose grant is certainly expired. Returns the count."""
        with self._lock:
            self._check_clock()
            return self._prune_locked()

    def stats(self) -> dict:
        with self._lock:
            self._prune_locked()
            size = os.path.getsize(self.path) if os.path.exists(self.path) else 0
            return {"live_nonces": len(self._entries),
                    "bytes_on_disk": size,
                    "retention_seconds": self.retention_seconds,
                    "max_grant_ttl_seconds": self.max_grant_ttl_seconds}
