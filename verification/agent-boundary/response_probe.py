# SPDX-License-Identifier: Apache-2.0
"""Run against an old or repaired source tree to observe the actual server frame."""
from pathlib import Path
import json
import struct
import sys

sys.path.insert(0, str(Path(sys.argv[1]).resolve()))
from driftcore.verification.mediated_actuation import ActuationBroker
from driftcore.verification.signed_permission import Grant, PermissionVerifier
from driftcore.verification.policy_snapshot import PolicySnapshot

canary = "PRIVATE-CANARY-policy-key-path-threshold-84729"
key = b"response-probe-PUBLIC-TEST-key"
verifier = PermissionVerifier()
verifier.register_key("operator", key, may_sign=("record:write",))
snapshot = PolicySnapshot({"deployment": "response-probe"})
seen = []
broker = ActuationBroker("unused.sock", verifier, policy_snapshot=snapshot,
                         ledger_hook=lambda *args: canary)
broker.register_actuator("record", lambda: seen.append("effect"), required_scope=("record:write",))
grant = Grant.issue(key, key_id="operator", role="operator", scope=("record:write",),
    subject="agent", ttl_seconds=60, nonce="probe-unused",
    action_binding=PermissionVerifier.bind_action("record", "write", {}),
    policy_hash=snapshot.policy_hash)
request = dict(op="execute", actuator_id="record", command="write", grant=grant.to_dict(), params={})
body = json.dumps(request).encode()


class Stream:
    incoming = struct.pack("!I", len(body)) + body
    sent = b""
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def settimeout(self, timeout): pass
    def recv(self, count):
        part, self.incoming = self.incoming[:count], self.incoming[count:]
        return part
    def sendall(self, data): self.sent += data


stream = Stream()


class Listener:
    def accept(self):
        broker._stop.set()
        return stream, None


broker._srv = Listener()
broker._serve()
response = json.loads(stream.sent[4:])
print(json.dumps(dict(request_contains_canary=canary in json.dumps(request),
    agent_received_canary=canary in json.dumps(response),
    operator_retained_canary=any(canary in item.reason for item in broker.records),
    actual_effects=len(seen), response=response), indent=2))
