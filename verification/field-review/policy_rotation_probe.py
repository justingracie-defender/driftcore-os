# SPDX-License-Identifier: Apache-2.0
"""Compare the existing and repaired API on the same policy-rotation scenario."""
import inspect
import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(sys.argv[1]).resolve()))
from driftcore.kernel.egress_guard import EgressGuard, EgressPolicy
from driftcore.verification.invariant_guard import Effect
from driftcore.verification.mediated_actuation import ActuationBroker
from driftcore.verification.signed_permission import Grant, PermissionVerifier

bound = "policy_snapshot" in inspect.signature(ActuationBroker).parameters
key = b"policy-rotation-PUBLIC-TEST-key"
config_a = {"revision": "A", "destinations": ["https://backup.example/"]}
config_b = {"revision": "B", "destinations": ["https://backup.example/", "https://second.example/"]}
options, grant_options = {}, {}
if bound:
    from driftcore.verification.policy_snapshot import PolicySnapshot
    options["policy_snapshot"] = PolicySnapshot(config_b)
    grant_options["policy_hash"] = PolicySnapshot(config_a).policy_hash
seen = []
verifier = PermissionVerifier()
verifier.register_key("operator", key, may_sign=("backup:send",))
with tempfile.TemporaryDirectory() as tmp:
    broker = ActuationBroker(str(Path(tmp)/"unused.sock"), verifier,
        broker_id="rotation-probe", expected_subject="agent", enforce_effects=True,
        egress_guard=EgressGuard(EgressPolicy.build(config_b["destinations"], declared_by="operator")),
        **options)
    broker.register_actuator("backup", lambda **params: seen.append(params),
        required_scope=("backup:send",), effects=[Effect.DATA_EGRESS],
        effect_declared_by="operator", destination_param="url")
    params = {"url": config_a["destinations"][0]}
    grant = Grant.issue(key, key_id="operator", role="operator", scope=("backup:send",),
        subject="agent", ttl_seconds=60, nonce="unused-under-policy-A",
        action_binding=PermissionVerifier.bind_action("backup", "send", params,
                                                      broker_id="rotation-probe"), **grant_options)
    result = broker._handle(dict(op="execute", actuator_id="backup", command="send",
                                params=params, grant=grant.to_dict()))
print(json.dumps(dict(policy_binding_supported=bound, actual_effects=len(seen), result=result), indent=2))
