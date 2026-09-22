# SPDX-License-Identifier: Apache-2.0
"""Policy provenance at the actual broker entry point, without socket privileges."""
import dataclasses
import hashlib
import hmac
import json
from pathlib import Path
import tempfile
import unittest
import uuid

from driftcore.authority.human_identity import HumanIdentityVerifier
from driftcore.kernel.egress_guard import EgressGuard, EgressPolicy
from driftcore.verification.human_authorization import HumanApprovalGate
from driftcore.verification.invariant_guard import Effect
from driftcore.verification.mediated_actuation import ActuationBroker, ProductionActuationBroker
from driftcore.verification.policy_snapshot import PolicySnapshot
from driftcore.verification.signed_permission import (
    Grant, PermissionVerifier, InvalidSignature, PolicyMismatch, PermissionReplay,
)

KEY = b"policy-binding-public-TEST-key"
TARGET = "https://backup.example/"
A = PolicySnapshot({"revision": "A", "egress": [TARGET], "scope": ["backup:send"]})
B = PolicySnapshot({"revision": "B", "egress": [TARGET, "https://second.example/"],
                    "scope": ["backup:send"]})


def verifier():
    v = PermissionVerifier()
    v.register_key("operator", KEY, may_sign=("backup:send",))
    return v


def issue(snapshot=A, **overrides):
    args = dict(key_id="operator", role="operator", scope=("backup:send",),
                subject="agent", ttl_seconds=60, nonce=uuid.uuid4().hex,
                policy_hash=snapshot.policy_hash if snapshot is not None else None)
    args.update(overrides)
    return Grant.issue(KEY, **args)


class PolicyBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def broker(self, snapshot=A, **overrides):
        seen = []
        config = snapshot.to_dict() if snapshot is not None else A.to_dict()
        args = dict(policy_snapshot=snapshot, broker_id="policy-test", expected_subject="agent",
                    enforce_effects=True, egress_guard=EgressGuard(EgressPolicy.build(
                        config["egress"], declared_by="operator test bootstrap")))
        args.update(overrides)
        b = ActuationBroker(str(Path(self.tmp.name)/"unused.sock"), verifier(), **args)
        def send(**params):
            seen.append(params)
            return {"executed_args": params}
        b.register_actuator("backup", send, required_scope=tuple(config["scope"]),
                            effects=[Effect.DATA_EGRESS], effect_declared_by="test bootstrap",
                            destination_param="url")
        return b, seen

    def request(self, snapshot=A, **overrides):
        params = {"url": TARGET, "text": "approved"}
        binding = PermissionVerifier.bind_action("backup", "send", params, broker_id="policy-test")
        req = dict(op="execute", actuator_id="backup", command="send", params=params,
                   grant=issue(snapshot, action_binding=binding).to_dict())
        req.update(overrides)
        return req

    def test_canonical_order_and_content(self):
        self.assertEqual(PolicySnapshot({"a": 1, "b": [2]}).policy_hash,
                         PolicySnapshot({"b": [2], "a": 1}).policy_hash)
        self.assertNotEqual(A.policy_hash, B.policy_hash)
        self.assertNotEqual(PolicySnapshot({"x": [1, 2]}).policy_hash,
                            PolicySnapshot({"x": [2, 1]}).policy_hash)

    def test_snapshot_detaches_nested_inputs_and_exports(self):
        data = {"rules": [{"allow": ["backup:send"]}]}
        snapshot = PolicySnapshot(data)
        digest = snapshot.policy_hash
        data["rules"][0]["allow"].append("*")
        snapshot.to_dict()["rules"][0]["allow"].append("*")
        self.assertEqual(snapshot.to_dict(), {"rules": [{"allow": ["backup:send"]}]})
        self.assertEqual(snapshot.policy_hash, digest)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            snapshot._encoded = b"{}"

    def test_snapshot_rejects_ambiguous_or_non_json_data(self):
        for data in ({}, [], None, {1: "x"}, {"x": {1: "nested"}},
                     {"x": (1, 2)}, {"x": float("nan")}, {"x": float("inf")},
                     {"x": {1, 2}}):
            with self.subTest(data=data), self.assertRaises((ValueError, TypeError)):
                PolicySnapshot(data)
        cyclic = {"self": None}
        cyclic["self"] = cyclic
        with self.assertRaises(ValueError):
            PolicySnapshot(cyclic)

    def test_hash_survives_wire_roundtrip(self):
        grant = issue()
        decoded = Grant.from_dict(json.loads(json.dumps(grant.to_dict())))
        self.assertEqual(decoded, grant)
        self.assertIs(verifier().verify(decoded, required_scope=("backup:send",),
                      expected_policy_hash=A.policy_hash), decoded)

    def test_signed_hash_cannot_be_changed_removed_or_null(self):
        grant = issue()
        for operation in ("change", "remove", "null"):
            wire = grant.to_dict()
            if operation == "change":
                wire["policy_hash"] = B.policy_hash
            elif operation == "remove":
                del wire["policy_hash"]
            else:
                wire["policy_hash"] = None
            with self.subTest(operation=operation), self.assertRaises(InvalidSignature):
                verifier().verify(Grant.from_dict(wire), required_scope=("backup:send",),
                                  expected_policy_hash=A.policy_hash)

    def test_unsigned_hash_cannot_be_appended_to_legacy_grant(self):
        wire = issue(None).to_dict()
        wire["policy_hash"] = A.policy_hash
        with self.assertRaises(InvalidSignature):
            verifier().verify(Grant.from_dict(wire), required_scope=("backup:send",),
                              expected_policy_hash=A.policy_hash)

    def test_signature_binds_policy_independently_of_matching_check(self):
        # Present the altered grant to the policy it now names. Only its signature
        # distinguishes this forgery from a legitimate grant for B.
        altered = dataclasses.replace(issue(A), policy_hash=B.policy_hash)
        with self.assertRaises(InvalidSignature):
            verifier().verify(altered, required_scope=("backup:send",),
                              expected_policy_hash=B.policy_hash)

    def test_issue_rejects_malformed_digest(self):
        for value in ("", "x" * 64, "A" * 64, "0" * 63, "0" * 65, True, 1, [], {}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                issue(policy_hash=value)

    def test_valid_signature_does_not_excuse_malformed_digest(self):
        # Sign directly: a key holder can bypass issuance validation.
        grant = dataclasses.replace(issue(), policy_hash="not-a-digest")
        payload = json.dumps(grant._payload(), sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode()
        grant = dataclasses.replace(grant, sig=hmac.new(KEY, payload, hashlib.sha256).hexdigest())
        with self.assertRaises(PolicyMismatch):
            verifier().verify(grant, required_scope=("backup:send",),
                              expected_policy_hash=A.policy_hash)

    def test_missing_expected_policy_rejects_bound_grant(self):
        with self.assertRaises(PolicyMismatch):
            verifier().verify(issue(), required_scope=("backup:send",))

    def test_expected_policy_rejects_legacy_grant(self):
        with self.assertRaises(PolicyMismatch):
            verifier().verify(issue(None), required_scope=("backup:send",),
                              expected_policy_hash=A.policy_hash)

    def test_validly_signed_wrong_policy_rejected(self):
        # CLAIMS: driftcore/verification/signed_permission.py:policy-binding-matches
        with self.assertRaises(PolicyMismatch):
            verifier().verify(issue(A), required_scope=("backup:send",),
                              expected_policy_hash=B.policy_hash)

    def test_policy_refusal_does_not_reserve_or_burn_nonce(self):
        v, grant = verifier(), issue(A)
        with self.assertRaises(PolicyMismatch):
            v.reserve(grant, required_scope=("backup:send",), expected_policy_hash=B.policy_hash)
        self.assertIs(v.reserve(grant, required_scope=("backup:send",),
                               expected_policy_hash=A.policy_hash), grant)
        v.commit(grant)
        with self.assertRaises(PermissionReplay):
            v.reserve(grant, required_scope=("backup:send",), expected_policy_hash=A.policy_hash)

    def test_legacy_wire_signature_unchanged_in_development(self):
        grant = issue(None)
        self.assertNotIn("policy_hash", grant.to_dict())
        payload = {k: v for k, v in grant.to_dict().items() if k != "sig"}
        expected = hmac.new(KEY, json.dumps(payload, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode(), hashlib.sha256).hexdigest()
        self.assertEqual(grant.sig, expected)
        verifier().verify(grant, required_scope=("backup:send",))

    def test_new_policy_blocks_old_grant_before_effect_and_allows_new(self):
        broker, seen = self.broker(B)
        refused = broker._handle(self.request(A))
        self.assertEqual(refused.get("error"), "grant_rejected", refused)
        self.assertEqual(seen, [])
        accepted = broker._handle(self.request(B))
        self.assertTrue(accepted["ok"], accepted)
        self.assertTrue(accepted["execution_confirmed"])
        self.assertEqual(len(seen), 1)

    def test_wire_policy_cannot_select_broker_rules(self):
        broker, seen = self.broker(B)
        req = self.request(A, policy_hash=A.policy_hash, expected_policy_hash=A.policy_hash,
                           policy_snapshot=A.to_dict(), context={"policy_hash": A.policy_hash})
        self.assertEqual(broker._handle(req).get("error"), "grant_rejected")
        self.assertEqual(seen, [])
        self.assertEqual(broker.policy_hash, B.policy_hash)
        with self.assertRaises(AttributeError):
            broker.policy_hash = A.policy_hash

    def test_broker_rejects_legacy_grant_under_bound_policy(self):
        broker, seen = self.broker(A)
        self.assertEqual(broker._handle(self.request(None)).get("error"), "grant_rejected")
        self.assertEqual(seen, [])
        self.assertTrue(broker._handle(self.request(A))["ok"])

    def test_unconfigured_broker_does_not_silently_ignore_policy(self):
        broker, seen = self.broker(None)
        self.assertEqual(broker._handle(self.request(A)).get("error"), "grant_rejected")
        self.assertEqual(seen, [])
        self.assertTrue(broker._handle(self.request(None))["ok"])
        self.assertIn("policy_binding", {event["layer"] for event in broker.posture_events()})

    def test_bound_policy_does_not_replace_action_or_destination_checks(self):
        broker, seen = self.broker(A)
        req = self.request(A)
        req["params"]["text"] = "altered"
        self.assertEqual(broker._handle(req).get("error"), "grant_rejected")
        req = self.request(A)
        req["params"]["url"] = "https://evil.example/"
        self.assertFalse(broker._handle(req)["ok"])
        self.assertEqual(seen, [])
        self.assertTrue(broker._handle(self.request(A))["ok"])

    def test_bound_grant_replay_has_exactly_one_effect(self):
        broker, seen = self.broker(A)
        req = self.request(A)
        self.assertTrue(broker._handle(req)["ok"])
        self.assertEqual(broker._handle(req).get("error"), "grant_rejected")
        self.assertEqual(len(seen), 1)

    def test_evidence_identifies_current_policy_and_detects_tamper(self):
        path = Path(self.tmp.name)/"evidence.jsonl"
        broker, seen = self.broker(A, evidence_path=str(path), require_durable_evidence=True)
        self.assertTrue(broker._handle(self.request(A))["ok"])
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        self.assertEqual([row["phase"] for row in rows], ["INTENT", "COMPLETION"])
        self.assertTrue(all(row["policy_hash"] == A.policy_hash for row in rows))
        self.assertEqual(broker.records[-1].to_dict()["policy_hash"], A.policy_hash)
        self.assertTrue(broker.verify_evidence())
        rows[0]["policy_hash"] = B.policy_hash
        path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
        self.assertFalse(broker.verify_evidence())
        self.assertEqual(len(seen), 1)

    def test_production_requires_snapshot_and_rejects_duck_types(self):
        hv = HumanIdentityVerifier()
        hv.register_principal("human", KEY)
        kwargs = dict(human_approval=HumanApprovalGate(hv), halt_state=lambda: False,
                      evidence_path=str(Path(self.tmp.name)/"production.jsonl"))
        with self.assertRaisesRegex(ValueError, "requires policy_snapshot"):
            ProductionActuationBroker("unused.sock", verifier(), **kwargs)
        for snapshot in ({}, A.to_dict(), A.policy_hash, True):
            with self.subTest(snapshot=snapshot), self.assertRaises(TypeError):
                ProductionActuationBroker("unused.sock", verifier(), policy_snapshot=snapshot, **kwargs)
        broker = ProductionActuationBroker("unused.sock", verifier(), policy_snapshot=A, **kwargs)
        self.assertEqual(broker.policy_hash, A.policy_hash)


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(PolicyBindingTests))
    passed = result.testsRun - len(result.failures) - len(result.errors)
    print(f"{passed}/{result.testsRun} tests passed")
    raise SystemExit(0 if result.wasSuccessful() else 1)
