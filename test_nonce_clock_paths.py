# SPDX-License-Identifier: Apache-2.0
"""Replay protection through every cleanup path, with real signed-grant controls.

These tests are fixed before selecting a repair. No model or external service runs.
"""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from driftcore.verification.nonce_store import (
    ExpiringNonceStore, ClockWentBackwards, NonceStoreError)
from driftcore.verification.nonce_store_sqlite import SqliteNonceStore
from driftcore.verification.signed_permission import Grant, PermissionVerifier


class ClockPathContract:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state" / "nonces"
        self.clock = [5000.0]
        self.store = self.open_store()
        self.addCleanup(self.store.close)
        self.binding = PermissionVerifier.bind_action("test-device", "record", {})
        self.verifier = self.make_verifier()
        self.grant = self.mint("spent")
        self.verifier.reserve(self.grant, required_scope=("test:record",),
                              action_binding=self.binding)
        self.verifier.commit(self.grant)

    def open_store(self, **kwargs):
        params = dict(retention_seconds=100, max_grant_ttl_seconds=30,
                      skew_seconds=10, time_fn=lambda: self.clock[0])
        params.update(kwargs)
        return self.backend(str(self.path), **params)

    def make_verifier(self):
        v = PermissionVerifier(used_nonces=self.store, clock=lambda: self.clock[0])
        v.register_key("test", "local-test-key", unrestricted=True)
        return v

    def mint(self, nonce):
        return Grant.issue("local-test-key", key_id="test", role="operator",
            scope=("test:record",), subject="test", ttl_seconds=30,
            nonce=nonce, action_binding=self.binding, now=self.clock[0])

    def cleanup(self, route):
        return len(self.store) if route == "len" else self.store.stats()["live_nonces"]

    def check_cleanup_replay(self, route, reopen=False):
        # CLAIMS: driftcore/verification/nonce_store.py:checked-cleanup-clock
        # CLAIMS: driftcore/verification/nonce_store_sqlite.py:checked-cleanup-clock
        self.clock[0] = 5200.0
        self.assertEqual(self.cleanup(route), 0)
        self.clock[0] = 5000.0
        if reopen:
            self.store.close()
            with self.assertRaises(ClockWentBackwards):
                reopened = self.open_store()
                self.addCleanup(reopened.close)
        else:
            with self.assertRaises(ClockWentBackwards):
                self.verifier.reserve(self.grant, required_scope=("test:record",),
                                      action_binding=self.binding)

    def test_len_cleanup_blocks_signed_grant_replay(self):
        self.check_cleanup_replay("len")

    def test_stats_cleanup_blocks_signed_grant_replay(self):
        self.check_cleanup_replay("stats")

    def test_len_cleanup_rollback_is_refused_after_reopen(self):
        self.check_cleanup_replay("len", reopen=True)

    def test_stats_cleanup_rollback_is_refused_after_reopen(self):
        self.check_cleanup_replay("stats", reopen=True)

    def test_membership_uses_the_checked_clock_sample(self):
        samples = iter([5000.0, 5200.0])
        self.store._time = lambda: next(samples, 5200.0)
        self.assertIn("spent", self.store,
                      "a second unchecked clock read must not forget a live nonce")

    def test_explicit_prune_never_forgets_on_an_unrecorded_timeline(self):
        samples = iter([5000.0, 5200.0])
        self.store._time = lambda: next(samples, 5200.0)
        self.store.prune()
        self.store._time = lambda: self.clock[0]
        try:
            remembered = "spent" in self.store
        except ClockWentBackwards:
            return
        self.assertTrue(remembered, "forgotten nonce without recorded rollback barrier")

    def test_automatic_prune_never_forgets_on_an_unrecorded_timeline(self):
        self.store._prune_every = 1
        samples = iter([5000.0, 5200.0])
        self.store._time = lambda: next(samples, 5200.0)
        self.store.add("another")
        self.store._time = lambda: self.clock[0]
        try:
            remembered = "spent" in self.store
        except ClockWentBackwards:
            return
        self.assertTrue(remembered, "automatic cleanup lost the replay barrier")

    def test_invalid_clock_refuses_and_preserves_spent_state(self):
        # CLAIMS: driftcore/verification/nonce_store.py:finite-nonce-clock
        routes = [lambda: len(self.store), self.store.stats, self.store.prune,
                  lambda: "spent" in self.store, lambda: self.store.add("new")]
        if hasattr(self.store, "consume"):
            routes.append(lambda: self.store.consume("new"))
        for bad in (float("nan"), float("inf"), float("-inf"), True, "5000", None):
            for i, route in enumerate(routes):
                with self.subTest(value=repr(bad), route=i):
                    self.clock[0] = bad
                    try:
                        with self.assertRaises(NonceStoreError):
                            route()
                    finally:
                        self.clock[0] = 5000.0
                    self.assertIn("spent", self.store)

    def test_invalid_clock_at_startup_does_not_erase_existing_state(self):
        self.store.close()
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=repr(bad)):
                self.clock[0] = bad
                try:
                    with self.assertRaises(NonceStoreError):
                        opened = self.open_store()
                        opened.close()
                finally:
                    self.clock[0] = 5000.0
                with self.open_store() as restored:
                    self.assertIn("spent", restored)

    def test_invalid_policy_is_rejected_before_files_are_created(self):
        # CLAIMS: driftcore/verification/nonce_store.py:finite-nonce-window
        normal = dict(retention_seconds=100, max_grant_ttl_seconds=30, skew_seconds=10)
        for field in normal:
            for bad in (float("nan"), float("inf"), float("-inf"), True, -1, "30", None):
                with self.subTest(field=field, value=repr(bad)):
                    path = Path(self.temp.name) / "invalid" / "nonces"
                    values = {**normal, field: bad}
                    with self.assertRaises(ValueError):
                        opened = self.backend(str(path), **values)
                        opened.close()
                    self.assertFalse(path.parent.exists())

    def test_nonpositive_windows_and_overflow_are_rejected(self):
        for params in (dict(retention_seconds=0, max_grant_ttl_seconds=30, skew_seconds=0),
                       dict(retention_seconds=100, max_grant_ttl_seconds=0, skew_seconds=0),
                       dict(retention_seconds=1e308, max_grant_ttl_seconds=1e308, skew_seconds=1e308)):
            with self.subTest(params=params), self.assertRaises(ValueError):
                self.open_store(**params).close()

    def test_watermark_write_failure_prevents_cleanup(self):
        self.clock[0] = 5200.0
        with patch.object(self.store, "_write_high_water", side_effect=OSError("disk fault")):
            with self.assertRaises(OSError):
                len(self.store)
        self.clock[0] = 5000.0
        self.assertIn("spent", self.store)

    def test_valid_grant_and_small_clock_jitter_still_work(self):
        self.clock[0] = 5200.0
        self.assertEqual(self.cleanup("stats"), 0)
        self.clock[0] = 5195.0
        g = self.mint("fresh")
        self.verifier.reserve(g, required_scope=("test:record",), action_binding=self.binding)
        self.verifier.commit(g)
        self.assertIn("fresh", self.store)
        self.assertEqual(len(self.store), 1)


class AppendLogClockTests(ClockPathContract, unittest.TestCase):
    backend = ExpiringNonceStore


class SqliteClockTests(ClockPathContract, unittest.TestCase):
    backend = SqliteNonceStore


if __name__ == "__main__":
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls)
        for cls in (AppendLogClockTests, SqliteClockTests))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    # Subtest failures may outnumber test methods. Count failing methods once.
    failed_ids = {getattr(test, "test_case", test).id() for test, _ in result.failures + result.errors}
    print(f"{result.testsRun - len(failed_ids)}/{result.testsRun} tests passed")
    raise SystemExit(0 if result.wasSuccessful() else 1)
