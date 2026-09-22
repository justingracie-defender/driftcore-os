# SPDX-License-Identifier: Apache-2.0
"""Linux acceptance check: an unprivileged agent cannot rewrite broker authority.

Run on a disposable Linux test host with permission to create Unix sockets and
drop child UIDs: python3 scripts/verify_authority_isolation.py
All files/effects are temporary. No accounts are created, no model is called,
and no external network request is made. Exit 77 = environment unavailable,
not PASS. This checks a file actuator across UIDs, not total network isolation.
"""
from pathlib import Path
import argparse
import dataclasses
import errno
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# The child receives no human key. Its own replacement verifier can mint tokens
# for itself, but the broker's human gate must not recognize those tokens.
AGENT = r'''
import json, os, socket, struct, sys
from driftcore.authority.human_identity import HumanIdentityVerifier, set_verifier
from driftcore.verification.mediated_actuation import _send, _recv
config = json.load(sys.stdin)
v = HumanIdentityVerifier(); v.register_principal("mallory", "rogue-key"); set_verifier(v)
observations = {"uid": os.getuid()}
for name, path, mode in [("key_read_denied", config["key"], "rb"),
                         ("direct_write_denied", config["effect"], "ab")]:
    try:
        with open(path, mode) as f:
            if mode == "rb": f.read(1)
            else: f.write(b"BYPASS\n")
        observations[name] = False
    except PermissionError:
        observations[name] = True
responses = []
for request in config["requests"]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(5)
        conn.connect(config["socket"])
        _send(conn, request)
        responses.append(_recv(conn))
observations["responses"] = responses
print(json.dumps(observations))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-uid", type=int, default=65534)
    parser.add_argument("--agent-gid", type=int, default=65534)
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0 or args.agent_uid <= 0 or args.agent_gid <= 0:
        print(json.dumps({"status": "ENVIRONMENT_UNAVAILABLE",
            "reason": "requires Linux root test runner and a non-root child UID/GID"}))
        return 77
    from driftcore.authority.human_identity import HumanIdentityVerifier
    from driftcore.kernel.egress_guard import EgressGuard, EgressPolicy
    from driftcore.verification.human_authorization import HumanApprovalGate, approve, attestation_digest
    from driftcore.verification.invariant_guard import Effect
    from driftcore.verification.mediated_actuation import ActuationBroker
    from driftcore.verification.signed_permission import Grant, PermissionVerifier
    with tempfile.TemporaryDirectory(prefix="driftcore-uid-check-") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o755)
        private = root / "private"; private.mkdir(mode=0o700)
        source = root / "code"; source.mkdir(mode=0o755)
        shutil.copytree(ROOT / "driftcore", source / "driftcore",
                        ignore=shutil.ignore_patterns("__pycache__", "logs"))
        for path in source.rglob("*"):
            os.chmod(path, 0o755 if path.is_dir() else 0o644)
        channel = root / "channel"; channel.mkdir(mode=0o750)
        try:
            os.chown(channel, -1, args.agent_gid)
            # Check UID switching before starting any broker or effect.
            probe = subprocess.run([sys.executable, "-c", "import os; print(os.getuid())"],
                user=args.agent_uid, group=args.agent_gid, extra_groups=[],
                capture_output=True, text=True, timeout=10)
            if probe.returncode or probe.stdout.strip() != str(args.agent_uid):
                raise RuntimeError("child did not assume the requested UID")
        except OSError as error:
            if error.errno not in (errno.EPERM, errno.EACCES, errno.EINVAL, errno.ENOSYS, errno.ENOTSUP):
                raise
            print(json.dumps({"status": "ENVIRONMENT_UNAVAILABLE", "reason": str(error)}))
            return 77
        key = os.urandom(32)
        keyfile = private / "human.key"; keyfile.write_bytes(key); keyfile.chmod(0o600)
        effect = private / "effects.jsonl"; effect.touch(mode=0o600)
        opkey = os.urandom(32)
        hv = HumanIdentityVerifier(); hv.register_principal("operator", key)
        pv = PermissionVerifier(); pv.register_key("grant", opkey, unrestricted=True)
        target = "https://backup.example/operator"
        broker = ActuationBroker(str(channel / "broker.sock"), pv,
            broker_id="uid-check", expected_subject="agent", require_peer_uid=args.agent_uid,
            socket_group=args.agent_gid, enforce_effects=True, require_effect_binding=True,
            human_approval=HumanApprovalGate(hv), halt_state=lambda: False,
            egress_guard=EgressGuard(EgressPolicy.build([target], declared_by="test operator")))
        def record(**params):
            with effect.open("a") as stream:
                stream.write(json.dumps(params) + "\n")
            return "RECORDED"
        broker.register_actuator("backup", record, required_scope=("backup:send",),
            effects=[Effect.DATA_EGRESS], effect_declared_by="test operator", destination_param="url")
        def request(params, human_key=key, principal="operator"):
            att = approve(human_key, principal=principal, actuator_id="backup", command="send",
                params=params, broker_id="uid-check", subject="agent",
                effects_hash=broker.declaration_hash("backup"), ttl_seconds=60, nonce=uuid.uuid4().hex)
            binding = PermissionVerifier.bind_action("backup", "send", params,
                broker_id="uid-check", subject="agent", effects_hash=broker.declaration_hash("backup"),
                attestation_hash=attestation_digest(att))
            grant = Grant.issue(opkey, key_id="grant", role="operator", scope=("backup:send",),
                subject="agent", ttl_seconds=60, nonce=uuid.uuid4().hex, action_binding=binding)
            return dict(op="execute", actuator_id="backup", command="send", params=params,
                        attestation=dataclasses.asdict(att), grant=grant.to_dict(), target_authorized=True)
        good_params = {"url": target, "text": "approved bytes"}
        forged = request(good_params, "rogue-key", "mallory")
        wrong_target = request({"url": "https://unapproved.example/", "text": "data"})
        changed = request(dict(good_params)); changed["params"]["text"] = "unapproved bytes"
        good = request(good_params)
        requests = [{"op": "set_verifier", "principal": "mallory"},
                    forged, wrong_target, changed, good, good]
        try:
            broker.start()
        except PermissionError as error:
            print(json.dumps({"status": "ENVIRONMENT_UNAVAILABLE", "reason": str(error)}))
            return 77
        try:
            config = dict(key=str(keyfile), effect=str(effect), socket=str(channel / "broker.sock"),
                          requests=requests)
            child = subprocess.run([sys.executable, "-c", AGENT], input=json.dumps(config),
                cwd=source, user=args.agent_uid, group=args.agent_gid, extra_groups=[],
                env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(source),
                     "PYTHONDONTWRITEBYTECODE": "1"}, capture_output=True, text=True, timeout=30)
            if child.returncode:
                raise RuntimeError("agent failed: " + child.stderr)
            data = json.loads(child.stdout)
            responses = data["responses"]
            assert data["uid"] == args.agent_uid
            assert data["key_read_denied"] is True and data["direct_write_denied"] is True
            assert responses[0].get("error") == "unknown_op"
            assert responses[1].get("error") == "human_approval_rejected"
            assert responses[2].get("error", "").startswith("egress_")
            assert responses[3].get("error") == "grant_rejected"
            assert responses[4].get("ok") is True and responses[5].get("ok") is False
            observed = [json.loads(line) for line in effect.read_text().splitlines()]
            assert observed == [good_params]
            print(json.dumps({"status": "PASS", "broker_uid": os.geteuid(),
                "agent_uid": data["uid"], "key_read_denied": True, "direct_write_denied": True,
                "actual_effects": len(observed), "scope": "local file actuator across UIDs"}))
            return 0
        finally:
            broker.stop()


if __name__ == "__main__":
    raise SystemExit(main())
