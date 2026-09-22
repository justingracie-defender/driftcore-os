# SPDX-License-Identifier: Apache-2.0
"""Fresh sequence and process-death checks after the initial repair selection."""
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

from driftcore.verification.nonce_store import (
    ExpiringNonceStore, ClockWentBackwards, NonceStoreError)
from driftcore.verification.nonce_store_sqlite import SqliteNonceStore


class FreshClockContract:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "nonces"
        self.clock = [300000.0]

    def make(self, **kwargs):
        options = dict(retention_seconds=100, max_grant_ttl_seconds=30,
                       skew_seconds=10, time_fn=lambda: self.clock[0])
        options.update(kwargs)
        store = self.backend(str(self.path), **options)
        self.addCleanup(store.close)
        return store

    def test_infinite_clock_cannot_delete_spent_records(self):
        store = self.make()
        store.add("spent")
        self.clock[0] = float("inf")
        with self.assertRaises(NonceStoreError):
            len(store)
        self.clock[0] = 300000.0
        self.assertIn("spent", store)

    def test_nan_retention_is_refused(self):
        with self.assertRaises(ValueError):
            self.make(retention_seconds=float("nan"))

    def test_zero_skew_and_exact_retention_boundary_work(self):
        store = self.make(retention_seconds=30, max_grant_ttl_seconds=30, skew_seconds=0)
        store.add("spent")
        self.clock[0] += 29
        self.assertIn("spent", store)
        self.clock[0] += 1
        self.assertEqual(store.prune(), 1)
        self.assertNotIn("spent", store)
        self.clock[0] -= 1
        with self.assertRaises(ClockWentBackwards):
            store.stats()

    def test_seeded_operation_sequences_match_clock_and_expiry_contract(self):
        # Fixed seeds make failures reproducible; no timing or model randomness.
        for seed in (73, 241, 901):
            with self.subTest(seed=seed):
                self.path = Path(self.temp.name) / str(seed)
                self.clock[0] = 300000.0
                store = self.make(prune_every=1)
                newest, entries = self.clock[0], {}
                rng = random.Random(seed)
                for step in range(70):
                    now = newest + rng.choice((-35, -9, 0, 3, 20, 130))
                    self.clock[0] = now
                    action = rng.choice(("add", "contains", "len", "stats", "prune"))
                    nonce = f"n-{step}" if action == "add" else f"n-{max(0, step-1)}"
                    operations = {
                        "add": lambda: store.add(nonce),
                        "contains": lambda: nonce in store,
                        "len": lambda: len(store),
                        "stats": lambda: store.stats()["live_nonces"],
                        "prune": store.prune,
                    }
                    if now < newest - 10:
                        with self.assertRaises(ClockWentBackwards, msg=f"seed={seed}, step={step}, action={action}"):
                            operations[action]()
                        continue
                    newest = max(newest, now)
                    expected_live = {n: t for n, t in entries.items() if now - t < 100}
                    result = operations[action]()
                    if action == "add":
                        entries = {**expected_live, nonce: now}
                    elif action == "contains":
                        self.assertEqual(result, nonce in expected_live)
                        if nonce not in expected_live:
                            entries.pop(nonce, None)
                    else:
                        expected = len(entries) - len(expected_live) if action == "prune" else len(expected_live)
                        self.assertEqual(result, expected, f"seed={seed}, step={step}, action={action}")
                        entries = expected_live
                store.close()


class AppendLogFreshTests(FreshClockContract, unittest.TestCase):
    backend = ExpiringNonceStore


class SqliteFreshTests(FreshClockContract, unittest.TestCase):
    backend = SqliteNonceStore


class SqliteCleanupCrashTests(unittest.TestCase):
    def crash_at(self, statement_prefix):
        with tempfile.TemporaryDirectory() as temporary:
            path = str(Path(temporary) / "nonce.db")
            code = r'''
import os, sys
from driftcore.verification.nonce_store_sqlite import SqliteNonceStore
clock = [300000.0]
s = SqliteNonceStore(sys.argv[1], retention_seconds=100, max_grant_ttl_seconds=30,
                     skew_seconds=10, time_fn=lambda: clock[0])
s.add('spent')
class Connection:
    def execute(self, sql, *args):
        result = real.execute(sql, *args)
        if sql.startswith(sys.argv[2]):
            os._exit(9)
        return result
    def close(self):
        real.close()
real = s._db
s._db = Connection()
clock[0] = 300200.0
len(s)
raise SystemExit(0)
'''
            result = subprocess.run([sys.executable, "-c", code, path, statement_prefix],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 9, result.stderr)
            with SqliteNonceStore(path, retention_seconds=100, max_grant_ttl_seconds=30,
                                  skew_seconds=10, time_fn=lambda: 300000.0) as store:
                self.assertIn("spent", store, "uncommitted cleanup must not survive process death")

    def test_process_death_after_watermark_write_keeps_original_nonce(self):
        self.crash_at("INSERT INTO meta")

    def test_process_death_after_delete_keeps_original_nonce(self):
        self.crash_at("DELETE FROM nonces WHERE ts <=")


if __name__ == "__main__":
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls)
        for cls in (AppendLogFreshTests, SqliteFreshTests, SqliteCleanupCrashTests))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    failed_ids = {getattr(test, "test_case", test).id() for test, _ in result.failures + result.errors}
    print(f"{result.testsRun - len(failed_ids)}/{result.testsRun} tests passed")
    raise SystemExit(0 if result.wasSuccessful() else 1)
