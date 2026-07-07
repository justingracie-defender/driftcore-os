"""
test_broker_process.py
======================
The broker brick: signing key in a SEPARATE process, agent talks over a socket and
never sees the key. Red-team this for key custody, the key_id allowlist, and the
TTL replay defense — and note the documented ceiling (signing != enforcement; a
compromised agent can still refuse to ask).
"""
import os, json, time, tempfile, threading
from driftcore.verification.broker_process import ConfigBroker, BrokerClient
from driftcore.verification import signed_config as sc

p = 0
def ok(cond, label):
    global p
    assert cond, "FAIL: " + label
    p += 1
    print("  ok:", label)

tmp = tempfile.mkdtemp()
sock = os.path.join(tmp, "broker.sock")
KEY = "operator-key-material"
RULES = {"invariants": ["no_lethal", "no_exfil"], "max_cycles": 10}

# authorize_sign policy: only sign config whose 'requested_by' is the operator
def policy(req):
    return (req.get("config") or {}).get("requested_by") == "operator"

broker = ConfigBroker(sock, {"k1": KEY}, default_ttl_seconds=None,
                      authorize_sign=policy)
broker.start()
time.sleep(0.1)
try:
    client = BrokerClient(sock, key_id="k1")

    # 1. broker signs an AUTHORIZED request; key never crosses the wire
    resp = client.request_sign({"requested_by": "operator", **RULES})
    ok(resp["ok"] and "envelope" in resp and "sig" in resp["envelope"],
       "broker signs an authorized request and returns an envelope")
    env = resp["envelope"]
    ok("k1" not in json.dumps(resp) or KEY not in json.dumps(resp),
       "the signing key never appears in the broker's response")

    # 2. the agent-side client can VERIFY via the broker (still no key locally)
    v = client.verify(env)
    ok(v["ok"] and v["config"]["max_cycles"] == 10,
       "agent verifies config through the broker without holding the key")

    # 3. TAMPER the envelope -> broker rejects
    bad = dict(env); bad["config"] = {**env["config"], "max_cycles": 99999}
    v = client.verify(bad)
    ok(v["ok"] is False and v["error"] == "integrity",
       "tampered config is rejected by the broker (integrity)")

    # 4. KEY_ID ALLOWLIST: an unknown key_id can neither verify nor sign
    rogue = BrokerClient(sock, key_id="attacker-key")
    v = rogue.verify(env)
    ok(v["ok"] is False and v["error"] == "unknown_key_id",
       "unknown key_id is refused (allowlist) — a rogue key cannot mint or check trust")

    # 5. UNAUTHORIZED sign is DENIED (fail-closed default; policy gates signing)
    resp = client.request_sign({"requested_by": "the_agent_itself", **RULES})
    ok(resp["ok"] is False and resp["error"] == "unauthorized",
       "the agent cannot get arbitrary config signed (sign authorization is fail-closed)")

    # 6. the CLIENT CANNOT FORGE locally: it has no key, so signing is impossible here
    #    (there is no client-side sign path; the only way to a signature is the broker)
    ok(not hasattr(client, "sign"),
       "the agent-side client exposes no local signing capability (no key in this process)")

finally:
    broker.stop()

# 7. TTL / REPLAY: a stale signed config is rejected when ttl is enforced
sock2 = os.path.join(tmp, "broker2.sock")
broker2 = ConfigBroker(sock2, {"k1": KEY}, authorize_sign=lambda r: True)
broker2.start(); time.sleep(0.1)
try:
    c2 = BrokerClient(sock2, key_id="k1")
    # sign with an issued_at stamped by the broker
    env2 = c2.request_sign({"requested_by": "operator", **RULES})["envelope"]
    ok("issued_at" in env2["config"], "broker stamps issued_at into signed config")

    # fresh config verifies under a generous ttl
    ok(c2.verify(env2, ttl_seconds=3600)["ok"] is True,
       "fresh signed config passes within ttl")

    # forge an OLD issued_at and re-sign via broker to get a valid-but-stale envelope
    old_env = c2.request_sign({"requested_by": "operator", **RULES})["envelope"]
    # tampering issued_at would break the sig; instead ask broker to sign a config
    # we pre-stamped as old, disabling the broker's fresh stamp:
    old_env = c2.request_sign({"requested_by": "operator", "issued_at": time.time() - 10000,
                               **RULES}, stamp_issued_at=False)["envelope"]
    v = c2.verify(old_env, ttl_seconds=60)
    ok(v["ok"] is False and v["error"] == "stale",
       "TTL replay defense: an old signed config is rejected past ttl (can't replay permissive config)")

    # same old envelope with NO ttl enforced still verifies (ttl is opt-in)
    ok(c2.verify(old_env)["ok"] is True,
       "with no ttl enforced, the (valid) signature still verifies — ttl is opt-in")
finally:
    broker2.stop()

# 8. broker refuses to construct with no keys (no silent keyless broker)
try:
    ConfigBroker(os.path.join(tmp, "x.sock"), {}); ok(False, "empty keyset should raise")
except ValueError:
    ok(True, "broker refuses to start with an empty keyset")

print(f"\n{p}/{p} tests passed")
