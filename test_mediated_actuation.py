"""
test_mediated_actuation.py
==========================
THE WALL. Red-team for the thing that matters: can a compromised agent (a) skip the
check, (b) substitute the action after approval (TOCTOU), (c) replay a grant, (d)
reach the actuator directly? The whole point is that the answer is no.
"""
import os, time, tempfile, threading
from driftcore.verification.mediated_actuation import (
    ActuationBroker, ActuatorProxy, ActuationRefused,
)
from driftcore.verification.signed_permission import Grant, PermissionVerifier

p = 0
def ok(cond, label):
    global p
    assert cond, "FAIL: " + label
    p += 1
    print("  ok:", label)

tmp = tempfile.mkdtemp()
sock = os.path.join(tmp, "act.sock")
KEY = "operator-actuation-key"

# a real actuator with an observable side effect, so we can PROVE what ran
fired = []
def move_arm(target=None):
    fired.append(target)
    return f"moved to {target}"

def make_broker(ledger_hook=None):
    v = PermissionVerifier()
    v.register_key("operator", KEY)
    b = ActuationBroker(sock, v, ledger_hook=ledger_hook)
    b.register_actuator("arm_1", move_arm, required_scope=("arm:move",))
    return b, v

def grant_for(v, actuator_id, command, params, *, nonce, scope=("arm:move",),
              key=KEY, key_id="operator"):
    binding = PermissionVerifier.bind_action(actuator_id, command, params)
    return Grant.issue(key, key_id=key_id, role="operator", scope=scope,
                       subject="robot-1", ttl_seconds=60, nonce=nonce,
                       action_binding=binding)

b, v = make_broker()
b.start(); time.sleep(0.1)
try:
    proxy = ActuatorProxy(sock, "arm_1")

    # 1. HAPPY PATH: a correctly-bound grant actuates, and the RIGHT thing runs
    g = grant_for(v, "arm_1", "pick_up", {"target": "cup"}, nonce="n1")
    res = proxy.execute("pick_up", g, target="cup")
    ok(res == "moved to cup" and fired == ["cup"],
       "a correctly-bound grant actuates, and exactly the approved action runs")

    # 2. THE TOCTOU ATTACK: grant approved for 'cup', agent tries to execute 'knife'.
    #    The binding recomputed at execution won't match -> REFUSED. Nothing runs.
    fired.clear()
    g_cup = grant_for(v, "arm_1", "pick_up", {"target": "cup"}, nonce="n2")
    try:
        proxy.execute("pick_up", g_cup, target="knife")   # substitute the params!
        ok(False, "substituted action should be refused")
    except ActuationRefused:
        ok(fired == [],
           "TOCTOU CLOSED: a grant approved for 'cup' cannot execute 'knife' "
           "(binding recomputed at execution doesn't match) — and nothing ran")

    # 3. substitute the COMMAND (not just params)
    g_pick = grant_for(v, "arm_1", "pick_up", {"target": "cup"}, nonce="n3")
    try:
        proxy.execute("smash", g_pick, target="cup"); ok(False, "should refuse")
    except ActuationRefused:
        ok(True, "TOCTOU CLOSED: a grant bound to 'pick_up' cannot execute 'smash'")

    # 4. NO GRANT -> fail closed, nothing runs
    fired.clear()
    class NoGrant:
        def to_dict(self): return {}
    try:
        proxy.execute("pick_up", NoGrant(), target="cup"); ok(False, "should refuse")
    except ActuationRefused:
        ok(fired == [], "no valid grant -> refused, actuator never called (fail closed)")

    # 5. FORGED KEY: agent mints its own grant with a key the broker doesn't trust
    forged = grant_for(v, "arm_1", "pick_up", {"target": "cup"}, nonce="nf",
                       key="agent-forged-key", key_id="operator")
    try:
        proxy.execute("pick_up", forged, target="cup"); ok(False, "should refuse")
    except ActuationRefused:
        ok(True, "a grant signed with an untrusted key is refused (agent cannot self-mint)")

    # 6. REPLAY: a used grant's nonce is burned; the same grant cannot actuate twice
    fired.clear()
    g_once = grant_for(v, "arm_1", "pick_up", {"target": "cup"}, nonce="n6")
    proxy.execute("pick_up", g_once, target="cup")     # first time: ok
    try:
        proxy.execute("pick_up", g_once, target="cup")  # replay
        ok(False, "replay should refuse")
    except ActuationRefused:
        ok(fired == ["cup"], "replay CLOSED: a single-use grant cannot actuate twice")

    # 7. SCOPE: a grant for a different capability can't drive this actuator
    g_wrong = grant_for(v, "arm_1", "pick_up", {"target": "cup"}, nonce="n7",
                        scope=("media:play",))
    try:
        proxy.execute("pick_up", g_wrong, target="cup"); ok(False, "should refuse")
    except ActuationRefused:
        ok(True, "a grant outside the actuator's required scope is refused")

    # 8. UNKNOWN ACTUATOR: the agent can't invent an actuator that isn't registered
    ghost = ActuatorProxy(sock, "laser_cannon")
    g_ghost = grant_for(v, "laser_cannon", "fire", {}, nonce="n8", scope=("arm:move",))
    try:
        ghost.execute("fire", g_ghost); ok(False, "should refuse")
    except ActuationRefused:
        ok(True, "an actuator that was never registered in the broker cannot be driven")

    # 9. THE STRUCTURAL POINT: the proxy has NO way to reach the actuator directly.
    #    There is no _actuate, no fn, no key on the agent side to monkey-patch.
    ok(not hasattr(proxy, "_actuate") and not hasattr(proxy, "fn")
       and not any("move_arm" in str(getattr(proxy, a, "")) for a in dir(proxy)),
       "the agent-side proxy exposes NO direct actuation path (nothing to bypass to)")

    # 10. AUDIT: every attempt (allowed AND refused) is recorded on the broker side
    allowed = [r for r in b.records if r.allowed]
    refused = [r for r in b.records if not r.allowed]
    ok(len(allowed) >= 2 and len(refused) >= 6,
       "every actuation attempt — allowed and refused — is recorded as broker-side evidence")

finally:
    b.stop()

# 11. LEDGER HOOK ON THE BROKER SIDE: cross-action budget runs where the agent
#     can't skip it. Simulate a budget that allows 1 actuation then refuses.
sock2 = os.path.join(tmp, "act2.sock")
calls = {"n": 0}
def budget_hook(actuator_id, command, params):
    calls["n"] += 1
    return None if calls["n"] <= 1 else "cumulative budget exceeded"
v2 = PermissionVerifier(); v2.register_key("operator", KEY)
fired2 = []
b2 = ActuationBroker(sock2, v2, ledger_hook=budget_hook)
b2.register_actuator("arm_1", lambda target=None: fired2.append(target), required_scope=("arm:move",))
b2.start(); time.sleep(0.1)
try:
    proxy2 = ActuatorProxy(sock2, "arm_1")
    g1 = grant_for(v2, "arm_1", "pick_up", {"target": "a"}, nonce="b1")
    proxy2.execute("pick_up", g1, target="a")   # 1st: allowed
    g2 = grant_for(v2, "arm_1", "pick_up", {"target": "b"}, nonce="b2")
    try:
        proxy2.execute("pick_up", g2, target="b"); ok(False, "2nd should be refused by ledger")
    except ActuationRefused:
        ok(len(fired2) == 1,
           "broker-side cumulative gate: the 2nd actuation is refused by the ledger hook "
           "(the agent cannot bypass cross-action accounting by not calling it)")
finally:
    b2.stop()

print(f"\n{p}/{p} tests passed")


# ── COLD RED-TEAM REGRESSIONS (found by attacking the running wall) ──
import socket as _sk, struct as _st
from driftcore.verification.mediated_actuation import _send as _ms, _recv as _mr

# R1: a STALLED client must not freeze the wall (single-client DoS). Was: hung forever.
_tmp = tempfile.mkdtemp(); _s = os.path.join(_tmp, "dos.sock")
_v = PermissionVerifier(); _v.register_key("operator", KEY)
_b = ActuationBroker(_s, _v, conn_timeout=1.0)
_b.register_actuator("arm_1", move_arm, required_scope=("arm:move",))
_b.start(); time.sleep(0.1)
try:
    _evil = _sk.socket(_sk.AF_UNIX, _sk.SOCK_STREAM); _evil.connect(_s)
    _evil.sendall(_st.pack("!I", 1000000))          # claim 1MB, send nothing
    time.sleep(0.1)
    _c = _sk.socket(_sk.AF_UNIX, _sk.SOCK_STREAM); _c.settimeout(5.0); _c.connect(_s)
    _g = grant_for(_v, "arm_1", "pick_up", {"target": "cup"}, nonce="dos1")
    _ms(_c, {"op": "execute", "actuator_id": "arm_1", "command": "pick_up",
             "params": {"target": "cup"}, "grant": _g.to_dict()})
    _resp = _mr(_c); _c.close(); _evil.close()
    ok(_resp and _resp.get("ok"),
       "DoS FIX: a stalled client no longer freezes the wall (legit call gets through)")
    # broker survives an abrupt mid-frame disconnect without crashing the serve thread
    _c2 = _sk.socket(_sk.AF_UNIX, _sk.SOCK_STREAM); _c2.connect(_s)
    _c2.sendall(_st.pack("!I", 50)); _c2.close()     # promise 50 bytes, vanish
    time.sleep(0.2)
    _c3 = _sk.socket(_sk.AF_UNIX, _sk.SOCK_STREAM); _c3.settimeout(3.0); _c3.connect(_s)
    _g3 = grant_for(_v, "arm_1", "pick_up", {"target": "cup"}, nonce="dos2")
    _ms(_c3, {"op": "execute", "actuator_id": "arm_1", "command": "pick_up",
              "params": {"target": "cup"}, "grant": _g3.to_dict()})
    _r3 = _mr(_c3); _c3.close()
    ok(_r3 and _r3.get("ok"),
       "CRASH FIX: broker survives an abrupt mid-frame client disconnect (serve thread lives)")
finally:
    _b.stop()

# R2: a grant bound to one actuator cannot drive a DIFFERENT actuator (binding
# includes actuator_id) — confirms cross-actuator replay is closed.
_tmp2 = tempfile.mkdtemp(); _s2 = os.path.join(_tmp2, "x.sock")
_v2 = PermissionVerifier(); _v2.register_key("operator", KEY)
_b2 = ActuationBroker(_s2, _v2)
_h = {"a": [], "b": []}
_b2.register_actuator("arm_a", lambda **k: _h["a"].append(k), required_scope=("arm:move",))
_b2.register_actuator("arm_b", lambda **k: _h["b"].append(k), required_scope=("arm:move",))
_b2.start(); time.sleep(0.1)
try:
    _bind_a = PermissionVerifier.bind_action("arm_a", "x", {})
    _ga = Grant.issue(KEY, key_id="operator", role="op", scope=("arm:move",),
                      subject="r", ttl_seconds=60, nonce="xa", action_binding=_bind_a)
    _pxb = ActuatorProxy(_s2, "arm_b")               # aim the arm_a grant at arm_b
    try:
        _pxb.execute("x", _ga); ok(False, "cross-actuator reuse should refuse")
    except ActuationRefused:
        ok(_h["b"] == [], "a grant bound to arm_a cannot drive arm_b (binding includes actuator_id)")
finally:
    _b2.stop()

print(f"\n{p}/{p} tests passed")


# ── HARDENING-PASS REGRESSIONS (all seven red-team fixes) ──
from driftcore.verification.signed_permission import PermissionVerifier as _PV

# H1: empty required_scope is REFUSED unless explicitly opted in
_vh = PermissionVerifier(); _vh.register_key("operator", KEY)
_bh = ActuationBroker(os.path.join(tempfile.mkdtemp(), "h.sock"), _vh)
try:
    _bh.register_actuator("x", lambda: 1, required_scope=()); ok(False, "empty scope should raise")
except ValueError:
    ok(True, "H1: registering an actuator with empty scope is REFUSED (loud footgun guard)")
_bh.register_actuator("x", lambda: 1, required_scope=(), allow_any_scope=True)  # explicit opt-in
ok(True, "H1: empty scope allowed only with explicit allow_any_scope=True")

# H2a: a ledger_hook that RAISES fails closed (refusal), never executes
_tmp_h = tempfile.mkdtemp(); _s_h = os.path.join(_tmp_h, "lh.sock")
_v2 = PermissionVerifier(); _v2.register_key("operator", KEY)
_ran = []
def _boom_hook(a, c, p): raise RuntimeError("ledger down")
_b2 = ActuationBroker(_s_h, _v2, ledger_hook=_boom_hook)
_b2.register_actuator("arm_1", lambda **k: _ran.append(k), required_scope=("arm:move",))
_b2.start(); time.sleep(0.1)
try:
    _p = ActuatorProxy(_s_h, "arm_1")
    _g = grant_for(_v2, "arm_1", "pick_up", {"target": "cup"}, nonce="lh1")
    try:
        _p.execute("pick_up", _g, target="cup"); ok(False, "raising ledger should refuse")
    except ActuationRefused:
        ok(_ran == [], "H2: a ledger_hook that RAISES fails CLOSED — actuator never runs")
finally:
    _b2.stop()

# H2b: a broken AUDIT logger must not crash the wall (best-effort, in-broker record kept)
_tmp_a = tempfile.mkdtemp(); _s_a = os.path.join(_tmp_a, "au.sock")
_v3 = PermissionVerifier(); _v3.register_key("operator", KEY)
def _boom_audit(**kw): raise RuntimeError("audit sink down")
_b3 = ActuationBroker(_s_a, _v3, audit_logger=_boom_audit)
_b3.register_actuator("arm_1", move_arm, required_scope=("arm:move",))
_b3.start(); time.sleep(0.1)
try:
    _p = ActuatorProxy(_s_a, "arm_1")
    fired.clear()
    _g = grant_for(_v3, "arm_1", "pick_up", {"target": "cup"}, nonce="au1")
    _res = _p.execute("pick_up", _g, target="cup")
    ok(_res == "moved to cup" and len(_b3.records) >= 1,
       "H2: a broken audit logger does NOT crash the wall; the in-broker record is still kept")
finally:
    _b3.stop()

# H3: start() refuses if the socket path exists as a NON-socket (tamper guard)
_tmp_t = tempfile.mkdtemp(); _s_t = os.path.join(_tmp_t, "planted")
with open(_s_t, "w") as _f: _f.write("planted file")   # attacker planted a regular file
_v4 = PermissionVerifier(); _v4.register_key("operator", KEY)
_b4 = ActuationBroker(_s_t, _v4)
try:
    _b4.start(); _b4.stop(); ok(False, "should refuse to start over a planted file")
except RuntimeError:
    ok(True, "H3: broker refuses to start when its socket path is a planted non-socket file")

# H5: canonicalization — same action always same binding (stability); different
#     actions never collide (the security-critical direction, checked in the fuzz).
_b = _PV.bind_action
ok(_b("arm", "x", {"a": 1, "b": 2}) == _b("arm", "x", {"b": 2, "a": 1}),
   "H5: binding is STABLE across dict key order (legit actions don't flake on ordering)")
ok(_b("arm", "x", {"t": "cup"}) != _b("arm", "x", {"t": "knife"})
   and _b("arm_a", "x", {}) != _b("arm_b", "x", {}),
   "H5: binding DIFFERS for different actions (no dangerous collisions found)")

# H6: the load-bearing assumption is present in the module docstring
import driftcore.verification.mediated_actuation as _MA
ok("LOAD-BEARING ASSUMPTION" in (_MA.__doc__ or ""),
   "H6: the 'all actuators must live behind the broker' assumption is stated in the header")

print(f"\n{p}/{p} tests passed")
