# SPDX-License-Identifier: Apache-2.0
"""Real broker dispatch through an in-memory framed stream, plus isolated client.

These tests exercise the server output path without creating OS sockets. They
establish response behavior, not UID, mount, ptrace, or network isolation.
"""
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

from driftcore.verification import mediated_actuation as mediation
from driftcore.verification.agent_responses import agent_response
from driftcore.verification.signed_permission import Grant, PermissionVerifier
from driftcore.verification.policy_snapshot import PolicySnapshot

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("standalone_client", ROOT/"agent/driftcore_client.py")
client_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client_module)
CANARY = "PRIVATE-CANARY-policy-key-path-threshold-84729"
KEY = b"agent-boundary-public-TEST-key"
POLICY = PolicySnapshot({"deployment": "agent-boundary", "revision": 1})


def frame(value):
    body = json.dumps(value).encode()
    return struct.pack("!I", len(body)) + body


class Stream:
    def __init__(self, incoming):
        self.incoming = incoming
        self.sent = bytearray()
        self.connects = 0
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, path):
        self.connects += 1

    def recv(self, count):
        # Deliberately fragment each receive, including the four-byte header.
        part, self.incoming = self.incoming[:min(count, 3)], self.incoming[min(count, 3):]
        return part

    def sendall(self, body):
        self.sent.extend(body)

    def decoded(self):
        length = struct.unpack("!I", self.sent[:4])[0]
        assert length == len(self.sent) - 4
        return json.loads(self.sent[4:])


def serve_one(broker, request=None, *, raw=None):
    stream = Stream(frame(request) if raw is None else raw)
    class Listener:
        def accept(self):
            broker._stop.set()  # Finish after this actual _serve iteration.
            return stream, None
    broker._stop.clear()
    broker._srv = Listener()
    broker._serve()
    return stream.decoded()


class AgentBoundaryTests(unittest.TestCase):
    def build(self, **options):
        seen = []
        verifier = PermissionVerifier()
        verifier.register_key("operator", KEY, may_sign=("record:write",))
        broker = mediation.ActuationBroker("unused.sock", verifier,
            policy_snapshot=POLICY, broker_id="boundary-test", **options)
        def record(**params):
            seen.append(params)
            return {"executed_args": params}
        broker.register_actuator("record", record, required_scope=("record:write",))
        return broker, seen

    def request(self, *, key_id="operator", params=None):
        params = {"text": "approved"} if params is None else params
        grant = Grant.issue(KEY, key_id=key_id, role="operator", scope=("record:write",),
            subject="agent", ttl_seconds=60, nonce=uuid.uuid4().hex,
            action_binding=PermissionVerifier.bind_action("record", "write", params,
                                                          broker_id="boundary-test"),
            policy_hash=POLICY.policy_hash)
        return dict(op="execute", actuator_id="record", command="write",
                    params=params, grant=grant.to_dict())

    def test_projection_discards_secret_values_and_extra_fields(self):
        # CLAIMS: driftcore/verification/agent_responses.py:refusal-data-is-not-echoed
        original = dict(ok=False, error="grant_rejected", detail=CANARY,
                        error_code=CANARY, expected_policy=CANARY,
                        trace={CANARY: [CANARY]}, retry_safe=True)
        public = agent_response(original)
        self.assertNotIn(CANARY, json.dumps(public))
        self.assertEqual(public["error"], "grant_rejected")
        self.assertIn("approval", public["detail"])
        self.assertFalse(public["retry_safe"])
        self.assertEqual(original["detail"], CANARY)

    def test_unknown_codes_and_invalid_responses_fail_conservatively(self):
        for response in ({"ok": False, "error": CANARY}, {"ok": False, "error": []},
                         {"ok": 1, "result": CANARY}, {}, None, [CANARY]):
            with self.subTest(response=response):
                public = agent_response(response)
                self.assertIs(public["ok"], False)
                self.assertEqual(public["effect_status"], "UNKNOWN")
                self.assertNotIn(CANARY, json.dumps(public))

    def test_after_effect_errors_are_not_clean_refusals(self):
        # CLAIMS: driftcore/verification/agent_responses.py:uncertain-is-not-clean-refusal
        for code in ("actuator_timeout", "actuator_failed", "broker_error", "bad_request",
                     "unknown_physical_state", "execution_mismatch"):
            with self.subTest(code=code):
                public = agent_response({"ok": False, "error": code, "detail": CANARY,
                                         "executed_args": {"secret": CANARY}})
                self.assertIn(public["effect_status"], ("UNKNOWN", "MISMATCH"))
                self.assertFalse(public["retry_safe"])
                self.assertNotIn(CANARY, json.dumps(public))

    def test_success_is_not_a_secret_scanner_or_false_effect_confirmation(self):
        # Authorized result data passes; diagnostic metadata does not.
        response = agent_response({"ok": True, "result": {"text": CANARY},
            "execution_confirmed": "yes", "operator_trace": "private", "warning": "secret type"})
        self.assertEqual(response["result"], {"text": CANARY})
        self.assertIsNone(response["execution_confirmed"])
        self.assertNotIn("operator_trace", response)
        self.assertNotIn("secret type", response["warning"])

    def test_real_dispatch_hides_key_registry_detail_but_operator_keeps_it(self):
        # CLAIMS: driftcore/verification/mediated_actuation.py:socket-refusals-are-projected
        broker, seen = self.build()
        response = serve_one(broker, self.request(key_id=CANARY))
        self.assertEqual(response["error"], "grant_rejected")
        self.assertNotIn(CANARY, json.dumps(response))
        self.assertTrue(any(CANARY in record.reason for record in broker.records))
        self.assertEqual(seen, [])

    def test_real_dispatch_hides_callback_refusal_detail(self):
        broker, seen = self.build(ledger_hook=lambda *args: CANARY)
        response = serve_one(broker, self.request())
        self.assertEqual(response["error"], "ledger_refused")
        self.assertNotIn(CANARY, json.dumps(response))
        self.assertTrue(any(CANARY in record.reason for record in broker.records))
        self.assertEqual(seen, [])

    def test_debug_flags_cannot_select_operator_diagnostics(self):
        broker, seen = self.build(ledger_hook=lambda *args: CANARY)
        request = self.request()
        request.update(debug=True, role="operator", include_detail=True,
                       response_mode="internal", context={"authorized_red_team": True})
        response = serve_one(broker, request)
        self.assertNotIn(CANARY, json.dumps(response))
        self.assertEqual(seen, [])

    def test_legitimate_dispatch_and_replay_still_distinguish_effects(self):
        broker, seen = self.build()
        request = self.request()
        first = serve_one(broker, request)
        second = serve_one(broker, request)
        self.assertTrue(first["ok"])
        self.assertTrue(first["execution_confirmed"])
        self.assertEqual(first["result"], {"executed_args": request["params"]})
        self.assertFalse(second["ok"])
        self.assertEqual(len(seen), 1)

    def test_peer_rejection_and_parse_failure_use_public_contract(self):
        broker, seen = self.build(require_peer_uid=12345)
        with patch.object(broker, "_peer_uid_ok", return_value=False):
            peer = serve_one(broker, self.request())
        self.assertEqual(peer["error"], "peer_uid_rejected")
        self.assertFalse(peer["retry_safe"])
        broker, _ = self.build()
        malformed = serve_one(broker, raw=struct.pack("!I", 1) + b"{")
        self.assertEqual(malformed["error"], "bad_request")
        self.assertEqual(malformed["effect_status"], "UNKNOWN")
        self.assertEqual(seen, [])

    def test_unhandled_exception_has_public_response_and_private_audit(self):
        audit = []
        broker, seen = self.build(audit_logger=lambda **entry: audit.append(entry))
        with patch.object(broker, "_handle", side_effect=RuntimeError(CANARY)):
            response = serve_one(broker, self.request())
        self.assertEqual(response["error"], "broker_error")
        self.assertEqual(response["effect_status"], "UNKNOWN")
        self.assertNotIn(CANARY, json.dumps(response))
        self.assertIn(CANARY, json.dumps(audit))
        self.assertEqual(seen, [])

    def test_actuator_exception_preserves_uncertainty_after_real_effect(self):
        broker, seen = self.build()
        def fails_after_write(**params):
            seen.append(params)
            raise RuntimeError(CANARY)
        broker.register_actuator("record", fails_after_write,
                                 required_scope=("record:write",), replace=True)
        response = serve_one(broker, self.request())
        self.assertEqual(response["error"], "actuator_failed")
        self.assertEqual(response["effect_status"], "UNKNOWN")
        self.assertNotIn(CANARY, json.dumps(response))
        self.assertEqual(len(seen), 1)
        self.assertTrue(any(CANARY in record.reason for record in broker.records))

    def test_client_runs_without_broker_package_in_isolated_interpreter(self):
        with tempfile.TemporaryDirectory() as tmp:
            copied = Path(tmp)/"driftcore_client.py"
            shutil.copyfile(ROOT/"agent/driftcore_client.py", copied)
            code = '''import importlib.util,json,sys
assert importlib.util.find_spec("driftcore") is None
spec=importlib.util.spec_from_file_location("client",sys.argv[1])
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
module.DriftCoreClient("unused.sock","record")
print(json.dumps({"broker_imported":any(x=="driftcore" or x.startswith("driftcore.") for x in sys.modules)}))
'''
            result = subprocess.run([sys.executable, "-I", "-c", code, str(copied)],
                cwd=tmp, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"broker_imported": False})

    def test_client_sends_opaque_approvals_and_preserves_completion(self):
        stream = Stream(frame({"ok": True, "result": "done", "execution_confirmed": None}))
        client = client_module.DriftCoreClient("unused.sock", "record")
        with patch.object(client_module.socket, "socket", return_value=stream):
            response = client.execute("write", {"opaque": "grant"}, params={"text": "hello"},
                                      attestation={"opaque": "attestation"})
        self.assertEqual(stream.decoded(), dict(op="execute", actuator_id="record", command="write",
            grant={"opaque": "grant"}, params={"text": "hello"}, attestation={"opaque": "attestation"}))
        self.assertIsNone(response["execution_confirmed"])
        self.assertEqual(stream.connects, 1)
        self.assertTrue(stream.closed)

    def test_client_refusal_retains_uncertain_outcome(self):
        response = agent_response({"ok": False, "error": "actuator_timeout"})
        stream = Stream(frame(response))
        with patch.object(client_module.socket, "socket", return_value=stream):
            with self.assertRaises(client_module.ActionRefused) as caught:
                client_module.DriftCoreClient("unused.sock", "record").execute("write", {})
        self.assertEqual(caught.exception.effect_status, "UNKNOWN")
        self.assertFalse(caught.exception.response["retry_safe"])
        self.assertEqual(stream.connects, 1)

    def test_client_round_trip_uses_real_broker_dispatch(self):
        broker, seen = self.build()
        request = self.request()
        class Loopback(Stream):
            def sendall(self, body):
                super().sendall(body)
                self.incoming = frame(serve_one(broker, raw=bytes(body)))
        client = client_module.DriftCoreClient("unused.sock", "record")
        for replay in (False, True):
            stream = Loopback(b"")
            with patch.object(client_module.socket, "socket", return_value=stream):
                if replay:
                    with self.assertRaises(client_module.ActionRefused):
                        client.execute("write", request["grant"], params=request["params"])
                else:
                    response = client.execute("write", request["grant"], params=request["params"])
                    self.assertTrue(response["execution_confirmed"])
                    self.assertEqual(response["result"], {"executed_args": request["params"]})
            self.assertEqual(stream.connects, 1)
        self.assertEqual(len(seen), 1)

    def test_client_rejects_bad_replies_and_never_retries(self):
        for raw in (b"", b"\x00\x00", struct.pack("!I", 5) + b"{",
                    struct.pack("!I", client_module.MAX_FRAME_BYTES + 1),
                    frame({"ok": 1}), frame({"ok": True, "result": float("nan")}), frame([])):
            with self.subTest(raw=raw):
                stream = Stream(raw)
                with patch.object(client_module.socket, "socket", return_value=stream):
                    with self.assertRaises(client_module.OutcomeUnknown):
                        client_module.DriftCoreClient("unused.sock", "record").execute("write", {})
                self.assertEqual(stream.connects, 1)
                self.assertTrue(stream.closed)

    def test_client_timeout_is_unknown_and_does_not_resend(self):
        stream = Stream(b"")
        with patch.object(stream, "recv", side_effect=TimeoutError("timed out")), \
             patch.object(client_module.socket, "socket", return_value=stream):
            with self.assertRaises(client_module.OutcomeUnknown):
                client_module.DriftCoreClient("unused.sock", "record").execute("write", {})
        self.assertEqual(stream.connects, 1)

    def test_client_bad_inputs_fail_before_connecting(self):
        for timeout in (0, -1, True, "5", float("inf"), float("nan")):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                client_module.DriftCoreClient("unused.sock", "record", timeout=timeout)
        client = client_module.DriftCoreClient("unused.sock", "record")
        with patch.object(client_module.socket, "socket") as connect:
            with self.assertRaises(ValueError):
                client.execute("write", {}, params={"bad": float("nan")})
            with self.assertRaises(ValueError):
                client.execute("write", "not a grant")
            with self.assertRaises(ValueError):
                client.execute("write", {}, attestation="not an attestation")
            connect.assert_not_called()


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(AgentBoundaryTests))
    passed = result.testsRun - len(result.failures) - len(result.errors)
    print(f"{passed}/{result.testsRun} tests passed")
    raise SystemExit(0 if result.wasSuccessful() else 1)
