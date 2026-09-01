"""
nonce_store_sqlite.py — the spent-nonce store, backed by SQLite.

WHY THIS EXISTS
---------------
`nonce_store.ExpiringNonceStore` is a hand-rolled append-log. It works and is heavily
tested, but the red-team history says something uncomfortable: of the eleven findings
against it, most were not about replay logic at all. They were about PLUMBING —

    torn trailing writes (B5)          a crash mid-append leaves a partial record
    record-separator injection (N5)    a nonce containing \\t or \\n forges records
    write ordering (N4)                RAM said spent, disk said not
    rename durability (N6)             os.replace without a directory fsync
    corrupt-record handling (N7)       unreadable state read as "never spent"
    multi-owner clobber (N1 CRITICAL)  one owner's rewrite erased another's nonces

Every one of those is a database's job, solved decades ago. Keeping them as our problem
means keeping them correct forever, and the record on that is not good: fixing seven
findings introduced four more, and the clock guard was broken three times in a row while
being patched. So this module hands the plumbing to SQLite and keeps only the part that
is genuinely ours.

WHAT SQLITE DELETES BY CONSTRUCTION (not by vigilance)
------------------------------------------------------
  * torn writes        — a transaction is atomic; there is no partial row
  * injection          — parameterised binding stores the nonce as an opaque value
  * write ordering     — INSERT is atomic and durable before it returns
  * multi-writer       — row-level semantics + WAL; a prune is a DELETE, not a
                         read-modify-rewrite, so no owner can clobber another's records.
                         The single-owner LOCK of the append-log version is therefore
                         unnecessary here, and `single_owner` is accepted and ignored
                         for API compatibility.
  * corruption         — SQLite detects and reports it rather than silently skipping

WHAT IT DOES NOT FIX (still ours, and still the hard part)
----------------------------------------------------------
SQLite has no opinion about time. The clock-rollback guard (N2 / B2 / B10) — the exact
place every self-inflicted bug happened — is still hand-written, and is carried over
here deliberately unchanged in shape: a high-water mark anchored on the RECORDS
themselves, so deleting or poisoning a single value can neither erase the guard nor
brick the store. Likewise `retention_seconds >= max_grant_ttl + skew` (N3) is a policy
invariant enforced at construction, and nothing here can stop a caller from passing a
plain `set()` to the verifier instead (B9) — that is a deployment invariant, which is
what `preflight.ReplayDefenseSurvivesRestart` exists to check.

The safety argument for pruning is unchanged and is the whole reason this is bounded:
`verify()` refuses an expired grant INDEPENDENTLY of the nonce set, so a nonce only has
to be remembered until its grant expires. Sliding window, not an archive. The audit
ledger — append-only, hash-chained, never pruned — remains where history lives.

Drop-in: `PermissionVerifier(used_nonces=SqliteNonceStore(path, ...))`.
stdlib-only (sqlite3).
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from typing import Optional

from driftcore.verification.nonce_store import (
    NonceStoreError, NonceStoreCorrupt, ClockWentBackwards, InvalidNonce,
    NonceStoreLocked,
)

_FORBIDDEN = ("\n", "\r", "\t", "\x00")
_MAX_NONCE_LEN = 512


class SqliteNonceStore:
    """Set-like spent-nonce store on SQLite: durable, multi-writer-safe, bounded by
    issuance rate x retention.

    Implements exactly the contract the verifier uses — `nonce in store` and
    `store.add(nonce)` — so it drops in with no change to signed_permission.
    """

    def __init__(self, path: str, *, retention_seconds: float,
                 max_grant_ttl_seconds: float, skew_seconds: float = 60.0,
                 prune_every: int = 64, time_fn=time.time,
                 salvage_corrupt: bool = False, single_owner: bool = True,
                 busy_timeout_ms: int = 5000):
        if retention_seconds <= 0:
            raise ValueError("retention_seconds must be positive")
        # N3: the policy invariant is enforced at CONSTRUCTION — an unsafe window
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
        self._time = time_fn
        self._salvage = bool(salvage_corrupt)
        self._prune_every = max(1, int(prune_every))
        self._since_prune = 0
        self._absurd_horizon = 86400.0
        self._lock = threading.RLock()
        # `single_owner` is accepted for API compatibility and deliberately ignored:
        # SQLite's row semantics make the multi-owner clobber (N1) impossible, so
        # refusing a second owner would be a restriction with no safety purpose.
        self._single_owner_requested = bool(single_owner)

        d = os.path.dirname(self.path) or "."
        os.makedirs(d, exist_ok=True)
        try:
            self._db = sqlite3.connect(self.path, timeout=busy_timeout_ms / 1000.0,
                                       isolation_level=None, check_same_thread=False)
            self._db.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
            self._db.execute("PRAGMA journal_mode=WAL")     # concurrent readers+writer
            self._db.execute("PRAGMA synchronous=FULL")     # durability over speed
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS nonces ("
                "  nonce TEXT PRIMARY KEY,"
                "  ts    REAL NOT NULL"
                ")")
            self._db.execute(
                "CREATE INDEX IF NOT EXISTS nonces_ts ON nonces(ts)")
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v REAL NOT NULL)")
        except sqlite3.DatabaseError as e:
            # N7: a damaged database FAILS CLOSED. Unreadable replay state must never be
            # treated as "these nonces were never spent".
            raise NonceStoreCorrupt(
                f"could not open the nonce database at {self.path!r}: {e}. Refusing to "
                f"treat unreadable replay state as 'never spent'.") from e

        try:
            self._integrity_check()
            self._check_clock()
            self._prune_locked()
        except Exception:
            self.close()
            raise

    # ── lifecycle ─────────────────────────────────────────────────

    def _integrity_check(self) -> None:
        try:
            row = self._db.execute("PRAGMA quick_check").fetchone()
        except sqlite3.DatabaseError as e:
            raise NonceStoreCorrupt(f"{self.path}: integrity check failed: {e}") from e
        if row and str(row[0]).lower() != "ok" and not self._salvage:
            raise NonceStoreCorrupt(
                f"{self.path}: database integrity check reported {row[0]!r}. Refusing "
                f"to operate on damaged replay state; construct with "
                f"salvage_corrupt=True only after investigating.")

    def close(self) -> None:
        try:
            self._db.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    # ── N2/B2/B10: clock rollback fails closed ────────────────────

    def _read_high_water(self) -> float:
        """The newest time this store has provably observed.

        Carried over unchanged in shape from the append-log version, because this is
        the part SQLite does not solve. The mark is derived from BOTH the stored meta
        value and the RECORDS themselves, taking the newest observation that is not
        absurd — absurd being judged against the bulk of real records, walking up from
        the oldest. So deleting or poisoning any single value can neither erase the
        rollback guard nor brick the store permanently.
        """
        def _finite(x):
            return isinstance(x, float) and x == x and x not in (
                float("inf"), float("-inf"))

        side = 0.0
        try:
            row = self._db.execute(
                "SELECT v FROM meta WHERE k='high_water'").fetchone()
            if row:
                side = float(row[0])
        except (sqlite3.DatabaseError, TypeError, ValueError):
            side = 0.0
        if not _finite(side):
            side = 0.0

        try:
            times = [float(r[0]) for r in
                     self._db.execute("SELECT ts FROM nonces ORDER BY ts").fetchall()]
        except sqlite3.DatabaseError:
            times = []
        times = [t for t in times if _finite(t)]

        # (red-team #1) Two quantities, not one. Trying to make a single number serve
        # both jobs is what broke: capping records at the clock killed the rollback
        # evidence (B2), and not capping them let an attacker-inserted future row
        # ratchet the mark and BRICK the store permanently (+40000s row, demonstrated).
        #
        #   side    — the durable meta value. Written by THIS store under the lock, so
        #             an attacker cannot forge it by inserting a row. It is the
        #             authority on how far time has advanced.
        #   newest  — the newest record. Corroborating evidence only, used when meta is
        #             missing or absurd, and never trusted beyond `side` unless meta is
        #             absent entirely.
        horizon = max(self.retention_seconds, self._absurd_horizon)
        if times:
            newest = times[0]
            for t_i in times[1:]:
                if t_i <= newest + horizon:
                    newest = t_i
                else:
                    break     # beyond this is corruption, not clock drift
        else:
            newest = 0.0

        if side > 0.0:
            # Meta is present and is the authority. Records can never push the mark
            # past it, so a future row inserted by an attacker has no ratchet power.
            if side > newest + horizon and newest > 0.0:
                side = newest      # absurd meta: fall back to the record evidence
            return side
        # Meta is missing (dropped/erased). Records are all we have, so they carry the
        # rollback guard — this is what stops B2 from erasing the defence.
        return newest

    def _write_high_water(self, t: float) -> None:
        self._db.execute(
            "INSERT INTO meta(k,v) VALUES('high_water',?) "
            "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (float(t),))

    def _check_clock(self) -> float:
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
    # SQLite would store any of these safely (parameterised binding makes content
    # opaque), but the validation is KEPT: a nonce containing a record separator means
    # something upstream is malformed, and the two backends should agree on what is a
    # legal nonce rather than diverging on acceptance.

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
                    "nonce contains a record separator (newline/tab/NUL); rejected so "
                    "both backends agree on what a legal nonce is.")
        return nonce

    # ── the set contract the verifier uses ────────────────────────

    def consume(self, nonce) -> bool:
        """Atomically claim a nonce. True if THIS caller won it, False if already spent.

        (red-team, ChatGPT 2026-08-14.) `__contains__` followed by `add` is two
        statements. Inside one process a lock makes them indivisible; across
        PROCESSES sharing this file it is a race — both check, both see absent, both
        insert, and one human approval authorises two physical actions. The store
        already had the mechanism (a PRIMARY KEY on `nonce` and BEGIN IMMEDIATE); what
        was missing was an API that lets the DATABASE decide the winner instead of the
        caller deciding after asking.

        So: a plain INSERT inside one immediate transaction. The primary key makes a
        second inserter fail, and the failure IS the answer — no ON CONFLICT clause,
        because "update the timestamp of a nonce someone else already spent" is
        exactly the behaviour that must not exist here.

        Expiry is deliberately NOT uniqueness. A nonce older than `retention_seconds`
        may have been pruned, in which case the insert succeeds — correct, because a
        grant that old is no longer valid on its own terms and is refused elsewhere.
        The clock decides when something expires; the primary key decides whether it
        was already used. Those are different jobs and this method only does the second.
        """
        nonce = self._validate(nonce)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                now = self._check_clock()
                cutoff = now - self.retention_seconds
                # Clear a pruned-but-present row first so a genuinely expired nonce
                # does not permanently block reuse of the same string.
                self._db.execute("DELETE FROM nonces WHERE nonce=? AND ts <= ?",
                                 (nonce, cutoff))
                try:
                    self._db.execute(
                        "INSERT INTO nonces(nonce, ts) VALUES(?,?)", (nonce, now))
                except sqlite3.IntegrityError:
                    self._db.execute("COMMIT")
                    return False
                self._db.execute("COMMIT")
            except Exception:
                try:
                    self._db.execute("ROLLBACK")
                except Exception:
                    pass
                raise
            self._since_prune += 1
            if self._since_prune >= self._prune_every:
                self._prune_locked()
            return True

    def add(self, nonce) -> None:
        nonce = self._validate(nonce)
        with self._lock:
            # (red-team #2) The clock high-water update and the nonce INSERT used to be
            # two autocommit transactions. A kill in between advanced the clock mark
            # while LOSING the spent nonce — demonstrably: high_water written, zero
            # rows — which is a replay window if the grant is still live. They are now
            # one atomic transaction: either both land or neither does.
            self._db.execute("BEGIN IMMEDIATE")
            try:
                now = self._check_clock()
                self._db.execute(
                    "INSERT INTO nonces(nonce, ts) VALUES(?,?) "
                    "ON CONFLICT(nonce) DO UPDATE SET ts=MAX(ts, excluded.ts)",
                    (nonce, now))
                self._db.execute("COMMIT")
            except Exception:
                try:
                    self._db.execute("ROLLBACK")
                except Exception:
                    pass
                raise
            self._since_prune += 1
            if self._since_prune >= self._prune_every:
                self._prune_locked()

    def __contains__(self, nonce) -> bool:
        try:
            nonce = self._validate(nonce)
        except InvalidNonce:
            return False
        with self._lock:
            self._check_clock()
            # (red-team #3) Presence and age used to be two steps — SELECT the row, then
            # compare its timestamp in Python. A concurrent prune landing between them
            # is a TOCTOU that can report a still-live nonce as absent, which the
            # verifier would read as "not spent" and accept a replay. One statement
            # decides both, so there is no window between them.
            cutoff = self._time() - self.retention_seconds
            row = self._db.execute(
                "SELECT 1 FROM nonces WHERE nonce=? AND ts > ?",
                (nonce, cutoff)).fetchone()
            return row is not None

    def __len__(self) -> int:
        with self._lock:
            self._prune_locked()
            return int(self._db.execute(
                "SELECT COUNT(*) FROM nonces").fetchone()[0])

    def __iter__(self):
        with self._lock:
            return iter([r[0] for r in
                         self._db.execute("SELECT nonce FROM nonces").fetchall()])

    # ── pruning: one statement, no read-modify-rewrite ────────────

    def _prune_locked(self) -> int:
        cutoff = self._time() - self.retention_seconds
        cur = self._db.execute("DELETE FROM nonces WHERE ts <= ?", (cutoff,))
        self._since_prune = 0
        return int(cur.rowcount or 0)

    def prune(self) -> int:
        """Drop every nonce whose grant is certainly expired. Returns the count."""
        with self._lock:
            self._check_clock()
            return self._prune_locked()

    def stats(self) -> dict:
        with self._lock:
            self._prune_locked()
            size = os.path.getsize(self.path) if os.path.exists(self.path) else 0
            return {"live_nonces": int(self._db.execute(
                        "SELECT COUNT(*) FROM nonces").fetchone()[0]),
                    "bytes_on_disk": size,
                    "retention_seconds": self.retention_seconds,
                    "max_grant_ttl_seconds": self.max_grant_ttl_seconds,
                    "backend": "sqlite"}
