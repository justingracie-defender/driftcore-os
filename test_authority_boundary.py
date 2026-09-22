# SPDX-License-Identifier: Apache-2.0
"""R2/R3 regression and execution controls. All effects are local test observations.

The subprocess check proves process-local verifier replacement does not redirect
the broker. It does NOT claim OS isolation between two processes with one UID.
"""
import dataclasses
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

from authority_test_support import KEY, TARGET, approval, signed_guard
from driftcore.authority import human_identity as identity
from driftcore.authority.egress_authorization import (
    SignedEgressApproval, StandingEgressPolicy, approval_action)
from driftcore.kernel.egress_guard import EgressGuard, EgressPolicy
from driftcore.verification.human_authorization import (
    HumanApprovalGate, approve, attestation_digest)
from driftcore.verification.invariant_guard import (
    ActionContext, Effect, GuardResult, GuardStatus, InvariantGuard)
from driftcore.verification.mediated_actuation import ActuationBroker, ProductionActuationBroker
from driftcore.verification.signed_permission import Grant, PermissionVerifier

OPKEY = b"operator-TEST-key-assumed-known-to-attacker"
HKEY = b"human-TEST-key-owned-by-broker-fixture"
EVIL = "https://unapproved.example/"


class BrokerFixture:
    def __init__(self, root):
        self.seen = []
        self.hv = identity.HumanIdentityVerifier()
        self.hv.register_principal("justin", HKEY)
        pv = PermissionVerifier()
        pv.register_key("operator", OPKEY, unrestricted=True)
        self.broker = ActuationBroker(str(root / "unused.sock"), pv,
            broker_id="authority-test", expected_subject="agent", enforce_effects=True,
            require_effect_binding=True, human_approval=HumanApprovalGate(self.hv),
            egress_guard=EgressGuard(EgressPolicy.build([TARGET], declared_by="test bootstrap")))
        self.broker.register_actuator("backup", self.record,
            required_scope=("backup:send",), effects=[Effect.DATA_EGRESS],
            effect_declared_by="test bootstrap", destination_param="url")

    def record(self, **params):
        self.seen.append(params)
        return "RECORDED"

    def request(self, params=None, *, human_key=HKEY, principal="justin"):
        params = {"url": TARGET, "text": "approved bytes"} if params is None else params
        att = approve(human_key, principal=principal, actuator_id="backup", command="send",
            params=params, broker_id="authority-test", subject="agent",
            effects_hash=self.broker.declaration_hash("backup"),
            ttl_seconds=60, nonce=uuid.uuid4().hex)
        binding = PermissionVerifier.bind_action("backup", "send", params,
            broker_id="authority-test", subject="agent",
            effects_hash=self.broker.declaration_hash("backup"),
            attestation_hash=attestation_digest(att))
        grant = Grant.issue(OPKEY, key_id="operator", role="operator",
            scope=("backup:send",), subject="agent", ttl_seconds=60,
            nonce=uuid.uuid4().hex, action_binding=binding)
        return dict(op="execute", actuator_id="backup", command="send", params=params,
                    attestation=dataclasses.asdict(att), grant=grant.to_dict())


class AuthorityBoundaryTests(unittest.TestCase):
    def setUp(self):
        identity.reset_policy()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_legacy_booleans_never_authorize(self):
        # CLAIMS: driftcore/verification/invariant_guard.py:caller-flags-are-not-permission
        identity.declare_label_only("test legacy mode")
        guard = InvariantGuard()
        for effect in (Effect.DATA_EGRESS, Effect.ACCOUNT_ACCESS):
            for flag in (True, False, 1, "yes"):
                with self.subTest(effect=effect, flag=flag):
                    self.assertFalse(guard.evaluate("send", effect=effect,
                        context=ActionContext(True, flag, "justin", (TARGET,))).permitted)

    def test_exact_signed_approval_and_replay(self):
        guard = signed_guard()
        ctx = approval("send", {Effect.DATA_EGRESS})
        self.assertTrue(guard.evaluate("send", Effect.DATA_EGRESS, ctx).permitted)
        self.assertFalse(guard.evaluate("send", Effect.DATA_EGRESS, ctx).permitted)

    def test_destination_swap_and_missing_destination(self):
        # CLAIMS: driftcore/verification/invariant_guard.py:signed-egress-matches-request
        guard = signed_guard()
        ctx = approval("send", {Effect.DATA_EGRESS})
        for targets in ((EVIL,), (), (TARGET, EVIL), TARGET, (1,)):
            with self.subTest(targets=targets):
                self.assertFalse(guard.evaluate("send", Effect.DATA_EGRESS,
                    dataclasses.replace(ctx, targets=targets, target_authorized=True)).permitted)
        self.assertTrue(guard.evaluate("send", Effect.DATA_EGRESS, ctx).permitted)

    def test_action_and_effect_swaps(self):
        # CLAIMS: driftcore/verification/invariant_guard.py:signed-egress-matches-request
        guard = signed_guard()
        ctx = approval("send", {Effect.DATA_EGRESS})
        self.assertFalse(guard.evaluate("different action", Effect.DATA_EGRESS, ctx).permitted)
        self.assertFalse(guard.evaluate("send", Effect.ACCOUNT_ACCESS, ctx).permitted)
        self.assertTrue(guard.evaluate("send", Effect.DATA_EGRESS, ctx).permitted)

    def test_global_verifier_replacement_does_not_change_pinned_guard(self):
        guard = signed_guard()
        rogue = identity.HumanIdentityVerifier()
        rogue.register_principal("mallory", "rogue-key")
        identity.set_verifier(rogue)
        forged = approval("send", {Effect.DATA_EGRESS}, key="rogue-key", principal="mallory")
        self.assertFalse(guard.evaluate("send", Effect.DATA_EGRESS, forged).permitted)
        self.assertTrue(guard.evaluate("send", Effect.DATA_EGRESS,
                                     approval("send", {Effect.DATA_EGRESS})).permitted)

    def test_pinned_principal_registry_cannot_be_changed(self):
        v = identity.HumanIdentityVerifier()
        v.register_principal("justin", KEY)
        SignedEgressApproval(v, allowed_targets=(TARGET,))
        for principal in ("justin", "mallory"):
            with self.subTest(principal=principal), self.assertRaises(PermissionError):
                v.register_principal(principal, "rogue-key")

    def test_coarse_identity_token_is_not_an_action_approval(self):
        v = identity.HumanIdentityVerifier()
        v.register_principal("justin", KEY)
        identity.set_verifier(v)
        att = identity.HumanAttestation.issue(KEY, principal="justin", action="authority_resolver",
            nonce=uuid.uuid4().hex, ttl_seconds=60)
        self.assertFalse(signed_guard().evaluate("send", Effect.DATA_EGRESS,
            ActionContext(True, True, att, (TARGET,))).permitted)

    def test_absolute_prohibition_does_not_spend_approval(self):
        guard = signed_guard()
        ctx = approval("send", {Effect.DATA_EGRESS})
        self.assertFalse(guard.evaluate("send", {Effect.LETHAL, Effect.DATA_EGRESS}, ctx).permitted)
        self.assertTrue(guard.evaluate("send", Effect.DATA_EGRESS, ctx).permitted)

    def test_authorizer_errors_and_non_bool_fail_closed(self):
        def broken(request):
            raise RuntimeError("unavailable policy")
        for authorizer in (broken, lambda request: 1, lambda request: "yes"):
            self.assertFalse(InvariantGuard(authorize_egress=authorizer).evaluate(
                "send", Effect.DATA_EGRESS).permitted)

    def test_invalid_effect_type_is_not_silently_dropped(self):
        self.assertFalse(InvariantGuard().evaluate("send", {"data_egress"}).permitted)

    def test_standing_policy_is_pinned_and_exact(self):
        targets = [TARGET]
        policy = StandingEgressPolicy(targets, "trusted bootstrap")
        targets.append(EVIL)
        guard = InvariantGuard(authorize_egress=policy)
        self.assertTrue(guard.evaluate("send", Effect.DATA_EGRESS,
            ActionContext(targets=(TARGET,))).permitted)
        self.assertFalse(guard.evaluate("send", Effect.DATA_EGRESS,
            ActionContext(True, True, "justin", (EVIL,))).permitted)

    def test_installing_policy_preserves_custom_guard_checks(self):
        # CLAIMS: driftcore/verification/invariant_guard.py:guard-policy-preserves-custom-checks
        class SiteGuard(InvariantGuard):
            def evaluate(self, action="", effect=None, context=None):
                if action == "site-restricted":
                    return GuardResult(GuardStatus.BLOCKED, "site policy")
                return super().evaluate(action, effect, context)

        original = SiteGuard()
        configured = original.with_egress_authorizer(
            StandingEgressPolicy([TARGET], "trusted bootstrap"))
        ctx = ActionContext(targets=(TARGET,))
        self.assertFalse(configured.evaluate("site-restricted", Effect.DATA_EGRESS, ctx).permitted)
        self.assertTrue(configured.evaluate("send", Effect.DATA_EGRESS, ctx).permitted)
        self.assertFalse(original.evaluate("send", Effect.DATA_EGRESS, ctx).permitted)

    def test_broker_global_replacement_has_no_authority(self):
        f = BrokerFixture(Path(self.tmp.name))
        rogue = identity.HumanIdentityVerifier()
        rogue.register_principal("mallory", "rogue-key")
        identity.set_verifier(rogue)
        req = f.request(human_key="rogue-key", principal="mallory")
        req.update(target_authorized=True, owner_authorized=True, authorised_by="justin")
        result = f.broker._handle(req)
        self.assertEqual(result.get("error"), "human_approval_rejected")
        self.assertEqual(f.seen, [])
        self.assertTrue(f.broker._handle(f.request())["ok"])
        self.assertEqual(f.seen, [{"url": TARGET, "text": "approved bytes"}])

    def test_broker_wrong_destination_despite_valid_signatures(self):
        f = BrokerFixture(Path(self.tmp.name))
        req = f.request({"url": EVIL, "text": "data"})
        req.update(target_authorized=True, effects=[], target=TARGET,
                   context={"target_authorized": True, "targets": [TARGET]})
        result = f.broker._handle(req)
        self.assertFalse(result["ok"])
        self.assertTrue(result["error"].startswith("egress_"), result)
        self.assertEqual(f.seen, [])

    def test_broker_changed_bytes_rejected_before_effect(self):
        f = BrokerFixture(Path(self.tmp.name))
        req = f.request()
        req["params"]["text"] = "different bytes"
        result = f.broker._handle(req)
        self.assertFalse(result["ok"])
        self.assertEqual(result.get("error"), "grant_rejected")
        self.assertEqual(f.seen, [])

    def test_broker_missing_human_approval_rejected(self):
        # CLAIMS: driftcore/verification/human_authorization.py:installed-gate-requires-approval
        f = BrokerFixture(Path(self.tmp.name))
        req = f.request()
        del req["attestation"]
        self.assertFalse(f.broker._handle(req)["ok"])
        self.assertEqual(f.seen, [])

    def test_broker_replay_does_not_repeat_effect(self):
        f = BrokerFixture(Path(self.tmp.name))
        req = f.request()
        self.assertTrue(f.broker._handle(req)["ok"])
        self.assertFalse(f.broker._handle(req)["ok"])
        self.assertEqual(len(f.seen), 1)

    def test_broker_registry_and_remote_configuration_closed(self):
        f = BrokerFixture(Path(self.tmp.name))
        with self.assertRaises(PermissionError):
            f.hv.register_principal("mallory", "rogue-key")
        for op in ("set_verifier", "register_principal", "reset_policy", "declare_label_only"):
            self.assertEqual(f.broker._handle({"op": op})["error"], "unknown_op")
        self.assertEqual(f.seen, [])

    def test_account_access_cannot_omit_destination(self):
        f = BrokerFixture(Path(self.tmp.name))
        with self.assertRaises(ValueError):
            f.broker.register_actuator("login", lambda: None, required_scope=("login:go",),
                effects=[Effect.ACCOUNT_ACCESS], effect_declared_by="test bootstrap")

    def test_production_requires_human_approval(self):
        pv = PermissionVerifier()
        with self.assertRaisesRegex(ValueError, "requires human_approval"):
            ProductionActuationBroker(str(Path(self.tmp.name)/"unused.sock"), pv,
                evidence_path=str(Path(self.tmp.name)/"evidence"), halt_state=lambda: False)

    def test_policy_sealing_blocks_all_public_reconfiguration(self):
        result = subprocess.run([sys.executable, __file__, "--seal-worker"],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data, {"mutators_refused": 7, "legitimate_identity": True})

    def test_separate_process_retains_its_own_trust_root(self):
        # A real process with fresh imports; no threads sharing identity globals.
        rogue = identity.HumanIdentityVerifier()
        rogue.register_principal("mallory", "rogue-key")
        identity.set_verifier(rogue)
        result = subprocess.run([sys.executable, __file__, "--broker-worker"],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data, {"forgery_error": "human_approval_rejected",
                                "legitimate_ok": True, "actual_effects": 1})


def seal_worker():
    v = identity.HumanIdentityVerifier()
    v.register_principal("justin", KEY)
    identity.set_verifier(v)
    identity.seal_policy()
    actions = [lambda: identity.set_verifier(None), lambda: identity.set_verifier(v),
               identity.reset_policy, lambda: identity.declare_label_only("agent"),
               identity.undeclare_label_only, lambda: identity.register_human_principal("mallory"),
               lambda: v.register_principal("mallory", "rogue-key")]
    refused = 0
    for action in actions:
        try:
            action()
        except PermissionError:
            refused += 1
    att = identity.HumanAttestation.issue(KEY, principal="justin", action="control",
        nonce=uuid.uuid4().hex, ttl_seconds=60)
    print(json.dumps({"mutators_refused": refused,
        "legitimate_identity": identity.is_human(att, action="control")}))


def broker_worker():
    with tempfile.TemporaryDirectory() as directory:
        f = BrokerFixture(Path(directory))
        bad = f.broker._handle(f.request(human_key="rogue-key", principal="mallory"))
        good = f.broker._handle(f.request())
        print(json.dumps({"forgery_error": bad.get("error"),
                          "legitimate_ok": good["ok"], "actual_effects": len(f.seen)}))


if __name__ == "__main__":
    if sys.argv[1:] == ["--seal-worker"]:
        seal_worker()
    elif sys.argv[1:] == ["--broker-worker"]:
        broker_worker()
    else:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(AuthorityBoundaryTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        failed = len(result.failures) + len(result.errors)
        print(f"{result.testsRun - failed}/{result.testsRun} tests passed")
        raise SystemExit(0 if result.wasSuccessful() else 1)
