# SPDX-License-Identifier: Apache-2.0
"""SQLite startup contention: bounded retry, real concurrency, and fail-closed errors."""
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from driftcore.verification.nonce_store import NonceStoreCorrupt, NonceStoreLocked
from driftcore.verification.nonce_store_sqlite import SqliteNonceStore


class ConnectionFault:
    def __init__(self, real, code, count=1, message="injected startup error"):
        self.real, self.code, self.count = real, code, count
        self.message = message
        self.attempts = 0
        self.closed = False

    def execute(self, sql, *args):
        if sql == "PRAGMA journal_mode=WAL":
            self.attempts += 1
            if self.attempts <= self.count:
                error = sqlite3.OperationalError(self.message)
                if self.code is not None:
                    error.sqlite_errorcode = self.code
                raise error
        return self.real.execute(sql, *args)

    def close(self):
        self.closed = True
        self.real.close()


class NonceStartupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "nonces.db")

    def store(self, **kwargs):
        return SqliteNonceStore(self.path, retention_seconds=3600,
            max_grant_ttl_seconds=300, **kwargs)

    def test_transient_startup_lock_retries_and_preserves_single_use(self):
        # CLAIMS: driftcore/verification/nonce_store_sqlite.py:startup-lock-is-bounded
        real = sqlite3.connect(self.path, isolation_level=None)
        fault = ConnectionFault(real, 5)  # SQLITE_BUSY
        self.addCleanup(fault.close)
        error = None
        with patch("driftcore.verification.nonce_store_sqlite.sqlite3.connect", return_value=fault):
            try:
                store = self.store()
            except Exception as exc:
                error = exc
        self.assertIsNone(error, f"transient lock must permit a successful retry: {error!r}")
        self.addCleanup(store.close)
        self.assertEqual(fault.attempts, 2)
        self.assertTrue(store.consume("one-approval"))
        self.assertFalse(store.consume("one-approval"))

    def test_exhausted_budget_refuses_and_closes_connection(self):
        # CLAIMS: driftcore/verification/nonce_store_sqlite.py:startup-lock-is-bounded
        real = sqlite3.connect(self.path, isolation_level=None)
        fault = ConnectionFault(real, 5, count=100)  # SQLITE_BUSY
        with patch("driftcore.verification.nonce_store_sqlite.sqlite3.connect", return_value=fault), \
                patch("driftcore.verification.nonce_store_sqlite.time.monotonic", side_effect=[0.0, 0.0, 1.0]):
            with self.assertRaises(NonceStoreLocked):
                self.store(busy_timeout_ms=10)
        self.assertEqual(fault.attempts, 1)
        self.assertTrue(fault.closed)

    def test_corruption_is_not_retried_or_treated_as_an_empty_store(self):
        real = sqlite3.connect(self.path, isolation_level=None)
        fault = ConnectionFault(real, 11)  # SQLITE_CORRUPT
        with patch("driftcore.verification.nonce_store_sqlite.sqlite3.connect", return_value=fault):
            with self.assertRaises(NonceStoreCorrupt):
                self.store()
        self.assertEqual(fault.attempts, 1)
        self.assertTrue(fault.closed)

    def test_legacy_exact_lock_message_can_retry_without_errorcode(self):
        real = sqlite3.connect(self.path, isolation_level=None)
        fault = ConnectionFault(real, None, message="database is locked")
        self.addCleanup(fault.close)
        with patch("driftcore.verification.nonce_store_sqlite.sqlite3.connect", return_value=fault):
            with self.store() as store:
                self.assertTrue(store.consume("legacy-approval"))
        self.assertEqual(fault.attempts, 2)

    def test_legacy_unknown_error_message_is_not_retried(self):
        real = sqlite3.connect(self.path, isolation_level=None)
        fault = ConnectionFault(real, None, message="database is locked: unknown failure")
        with patch("driftcore.verification.nonce_store_sqlite.sqlite3.connect", return_value=fault):
            with self.assertRaises(NonceStoreCorrupt):
                self.store()
        self.assertEqual(fault.attempts, 1)
        self.assertTrue(fault.closed)

    def test_zero_budget_allows_an_uncontended_store(self):
        with self.store(busy_timeout_ms=0) as store:
            self.assertTrue(store.consume("valid"))

    def test_zero_budget_refuses_a_real_exclusive_lock(self):
        held = sqlite3.connect(self.path, isolation_level=None)
        held.execute("CREATE TABLE placeholder(value)")
        held.execute("BEGIN EXCLUSIVE")
        try:
            with self.assertRaises(NonceStoreLocked):
                self.store(busy_timeout_ms=0)
        finally:
            held.rollback()
            held.close()
        with self.store() as store:
            self.assertTrue(store.consume("works-after-unlock"))

    def test_invalid_wait_budgets_are_rejected(self):
        for timeout in (-1, True, float("nan"), float("inf"), 1.5, 2**31):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                self.store(busy_timeout_ms=timeout)

    def test_concurrent_cold_start_produces_one_nonce_winner(self):
        code = """
import sys
from driftcore.verification.nonce_store_sqlite import SqliteNonceStore
with SqliteNonceStore(sys.argv[1], retention_seconds=3600, max_grant_ttl_seconds=300) as s:
    print('WON' if s.consume('contested') else 'LOST')
"""
        children = [subprocess.Popen([sys.executable, "-c", code, self.path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(12)]
        outputs = []
        for child in children:
            stdout, stderr = child.communicate(timeout=30)
            self.assertEqual(child.returncode, 0, stderr)
            outputs.append(stdout.strip())
        self.assertEqual(outputs.count("WON"), 1)
        self.assertEqual(outputs.count("LOST"), 11)
        with self.store() as store:
            self.assertFalse(store.consume("contested"))


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(NonceStartupTests))
    failed = len(result.failures) + len(result.errors)
    print(f"{result.testsRun-failed}/{result.testsRun} tests passed")
    raise SystemExit(0 if result.wasSuccessful() else 1)
