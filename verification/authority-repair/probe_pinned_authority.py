# SPDX-License-Identifier: Apache-2.0
"""Targeted follow-up to Claude's quoted construction-time authority concern.

Usage: python3 probe_pinned_authority.py /path/to/driftcore-os
Local decision checks only; no sockets, models, or external effects.
"""
import dataclasses
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(sys.argv.pop(1)).resolve()
sys.path.insert(0, str(ROOT))

from authority_test_support import KEY, TARGET, approval, signed_guard
from driftcore.authority import human_identity as identity
from driftcore.verification.coordinator import VerificationCoordinator, Outcome
from driftcore.verification.invariant_guard import (
    ActionContext, Effect, InvariantGuard, GuardResult, GuardStatus)
from driftcore.verification.risk_classifier import RiskClassifier

OTHER = "https://other.example/"


def coordinator(guard, targets):
    return VerificationCoordinator(guard, RiskClassifier(),
        authorized_egress_targets=targets, egress_owner="trusted test bootstrap")


def request(target):
    return {"prompt": "send summary", "effects": [Effect.DATA_EGRESS], "target": target}


class PinnedAuthorityFollowup(unittest.TestCase):
    def setUp(self):
        identity.reset_policy()
        self.addCleanup(identity.reset_policy)

    def test_signed_guard_does_not_read_global_identity(self):
        guard = signed_guard()
        class BrokenGlobal:
            def verify(self, *args, **kwargs):
                raise AssertionError("global verifier was consulted")
        with patch.object(identity, "_verifier", BrokenGlobal()), patch.object(
                identity, "is_human", side_effect=AssertionError("global identity consulted")):
            self.assertTrue(guard.evaluate("send", Effect.DATA_EGRESS,
                approval("send", {Effect.DATA_EGRESS})).permitted)

    def test_replacement_before_and_after_guard_construction(self):
        rogue = identity.HumanIdentityVerifier()
        rogue.register_principal("mallory", "rogue-key")
        identity.set_verifier(rogue)
        guard = signed_guard()
        identity.reset_policy()
        identity.set_verifier(rogue)
        self.assertFalse(guard.evaluate("send", Effect.DATA_EGRESS,
            approval("send", {Effect.DATA_EGRESS}, key="rogue-key", principal="mallory")).permitted)
        self.assertTrue(guard.evaluate("send", Effect.DATA_EGRESS,
            approval("send", {Effect.DATA_EGRESS})).permitted)

    def test_two_coordinators_do_not_share_authority(self):
        original = InvariantGuard()
        a = coordinator(original, [TARGET])
        b = coordinator(original, [OTHER])
        for current, yes, no in ((a, TARGET, OTHER), (b, OTHER, TARGET), (a, TARGET, OTHER)):
            self.assertEqual(current.evaluate(request(yes)).outcome, Outcome.PROCEED)
            rejected = current.evaluate(request(no))
            self.assertEqual(rejected.outcome, Outcome.BLOCKED)
            self.assertEqual(rejected.invariant, "no_unauthorized_exfiltration")
        for target in (TARGET, OTHER):
            self.assertFalse(original.evaluate("send", Effect.DATA_EGRESS,
                ActionContext(targets=(target,))).permitted)

    def test_mutating_input_targets_does_not_expand_policy(self):
        targets = [TARGET]
        c = coordinator(InvariantGuard(), targets)
        targets.append(OTHER)
        self.assertEqual(c.evaluate(request(OTHER)).outcome, Outcome.BLOCKED)
        self.assertEqual(c.evaluate(request(TARGET)).outcome, Outcome.PROCEED)

    def test_request_cannot_supply_an_authorizer_or_permission(self):
        c = coordinator(InvariantGuard(), [TARGET])
        forged = ActionContext(True, True, "operator", (TARGET,))
        req = request(OTHER)
        req.update(owner_authorized=True, target_authorized=True,
            egress_authorized=True, authorize_egress=lambda req: True)
        ctx = {"action_context": forged, "egress_authorized": True,
               "authorize_egress": lambda req: True,
               "authorized_egress_targets": [OTHER]}
        d = c.evaluate(req, context=ctx)
        self.assertEqual(d.outcome, Outcome.BLOCKED)
        self.assertEqual(d.invariant, "no_unauthorized_exfiltration")
        self.assertEqual(c.evaluate(request(TARGET)).outcome, Outcome.PROCEED)

    def test_coordinator_preserves_custom_guard_restriction(self):
        class RestrictedGuard(InvariantGuard):
            def evaluate(self, action="", effect=None, context=None):
                if action == "site restricted":
                    return GuardResult(GuardStatus.BLOCKED, "site restriction",
                                       binding_invariant="site-restriction")
                return super().evaluate(action, effect, context)
        c = coordinator(RestrictedGuard(), [TARGET])
        bad = dict(request(TARGET), prompt="site restricted")
        d = c.evaluate(bad)
        self.assertEqual(d.outcome, Outcome.BLOCKED)
        self.assertEqual(d.invariant, "site-restriction")
        self.assertEqual(c.evaluate(request(TARGET)).outcome, Outcome.PROCEED)

    def test_coordinator_does_not_depend_on_global_identity(self):
        c = coordinator(InvariantGuard(), [TARGET])
        rogue = identity.HumanIdentityVerifier()
        rogue.register_principal("mallory", "rogue-key")
        identity.set_verifier(rogue)
        self.assertEqual(c.evaluate(request(OTHER)).outcome, Outcome.BLOCKED)
        self.assertEqual(c.evaluate(request(TARGET)).outcome, Outcome.PROCEED)
        identity.reset_policy()
        self.assertEqual(c.evaluate(request(OTHER)).outcome, Outcome.BLOCKED)
        self.assertEqual(c.evaluate(request(TARGET)).outcome, Outcome.PROCEED)


if __name__ == "__main__":
    unittest.main(verbosity=2)
