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
from driftcore.verification.signed_permission import _finite as _fin, Grant, PermissionVerifier

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
    v.register_key("operator", KEY, unrestricted=True)
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
v2 = PermissionVerifier(); v2.register_key("operator", KEY, unrestricted=True)
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
_v = PermissionVerifier(); _v.register_key("operator", KEY, unrestricted=True)
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
_v2 = PermissionVerifier(); _v2.register_key("operator", KEY, unrestricted=True)
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
_vh = PermissionVerifier(); _vh.register_key("operator", KEY, unrestricted=True)
_bh = ActuationBroker(os.path.join(tempfile.mkdtemp(), "h.sock"), _vh)
try:
    _bh.register_actuator("x", lambda: 1, required_scope=()); ok(False, "empty scope should raise")
except ValueError:
    ok(True, "H1: registering an actuator with empty scope is REFUSED (loud footgun guard)")
_bh.register_actuator("x", lambda: 1, required_scope=(), allow_any_scope=True)  # explicit opt-in
ok(True, "H1: empty scope allowed only with explicit allow_any_scope=True")

# H2a: a ledger_hook that RAISES fails closed (refusal), never executes
_tmp_h = tempfile.mkdtemp(); _s_h = os.path.join(_tmp_h, "lh.sock")
_v2 = PermissionVerifier(); _v2.register_key("operator", KEY, unrestricted=True)
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
_v3 = PermissionVerifier(); _v3.register_key("operator", KEY, unrestricted=True)
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
_v4 = PermissionVerifier(); _v4.register_key("operator", KEY, unrestricted=True)
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


# ── A3 REGRESSION (cross-broker grant replay, found in adversarial battery) ──
# Two brokers sharing the signing key but with DISTINCT broker_ids: a grant approved
# for one must not execute on the other. And backward-compat: no broker_id still works.
_tmpA = tempfile.mkdtemp(); _sA = os.path.join(_tmpA, "A.sock")
_tmpB = tempfile.mkdtemp(); _sB = os.path.join(_tmpB, "B.sock")
_vA = PermissionVerifier(); _vA.register_key("operator", KEY, unrestricted=True)
_vB = PermissionVerifier(); _vB.register_key("operator", KEY, unrestricted=True)
_hA = []; _hB = []
_bA = ActuationBroker(_sA, _vA, broker_id="broker-A")
_bA.register_actuator("arm_1", lambda **k: _hA.append(k), required_scope=("arm:move",))
_bB = ActuationBroker(_sB, _vB, broker_id="broker-B")
_bB.register_actuator("arm_1", lambda **k: _hB.append(k), required_scope=("arm:move",))
_bA.start(); _bB.start(); time.sleep(0.1)
try:
    # grant bound to broker-A
    _bindA = PermissionVerifier.bind_action("arm_1", "pick_up", {"target": "cup"}, broker_id="broker-A")
    _gA = Grant.issue(KEY, key_id="operator", role="operator", scope=("arm:move",),
                      subject="r", ttl_seconds=60, nonce="a3reg", action_binding=_bindA)
    _pB = ActuatorProxy(_sB, "arm_1")   # replay against broker-B
    try:
        _pB.execute("pick_up", _gA, target="cup"); ok(False, "cross-broker replay should refuse")
    except ActuationRefused:
        ok(_hB == [], "A3 CLOSED: a grant bound to broker-A cannot execute on broker-B (distinct broker_id)")
    # and it works on its own broker A
    _bindA2 = PermissionVerifier.bind_action("arm_1", "pick_up", {"target": "cup"}, broker_id="broker-A")
    _gA2 = Grant.issue(KEY, key_id="operator", role="operator", scope=("arm:move",),
                       subject="r", ttl_seconds=60, nonce="a3reg2", action_binding=_bindA2)
    _pA = ActuatorProxy(_sA, "arm_1")
    _pA.execute("pick_up", _gA2, target="cup")
    ok(_hA == [{"target": "cup"}], "the broker-A grant still works on broker-A (fix doesn't break the legit path)")
finally:
    _bA.stop(); _bB.stop()

print(f"\n{p}/{p} tests passed")


# ── RED-TEAM REGRESSIONS (findings from the Grok+ChatGPT signed_permission review) ──
from driftcore.verification.signed_permission import (
    Grant as _G, PermissionVerifier as _PVV, ScopeExceeded as _SE,
    _scope_covers as _sc, _finite as _fin)
import hmac as _hmac, hashlib as _hl
from driftcore.verification.signed_permission import _canonical as _canon

# R-nonfinite: NaN/Infinity timestamps must fail closed (were fail-OPEN: never expire)
_vv = _PVV(); _vv.register_key("op", "k"*32, unrestricted=True)
try:
    _G.issue("k"*32, key_id="op", role="r", scope=("a",), subject="s",
             ttl_seconds=float('inf'), nonce="rf1")
    ok(False, "infinite ttl should be rejected at issue")
except _SE:
    ok(True, "RED-TEAM: infinite ttl rejected at issue (was: grant that never expires)")
# This pin used to BUILD a NaN-expiry grant to prove verify() rejects it. The
# canonical serializer now refuses non-finite values outright (allow_nan=False), so
# such a payload can no longer be signed at all — the test can no longer construct its
# own malicious input. That is strictly stronger, but a fix that makes a red-team pin
# unreachable must not quietly retire the property it protected, so BOTH layers are
# asserted directly.
try:
    _canon({"expires_at": float("nan")})
    ok(False, "the canonical serializer should refuse a non-finite value")
except ValueError:
    ok(True, "RED-TEAM: a non-finite value cannot be canonically serialized at all, so "
             "it can never enter a SIGNED payload (stronger than catching it later)")
try:
    _fin(float("nan"), "expires_at")
    ok(False, "the verify-time guard should reject a non-finite expiry")
except Exception:
    ok(True, "RED-TEAM: and the verify-time guard still rejects a non-finite expiry "
             "independently (was fail-OPEN: now >= NaN is always False, so the grant "
             "never expired) — defense in depth, now unreachable through normal paths")

# R-wildcard: 'x:*' covers exactly one segment, not infinite depth (privilege escalation)
ok(_sc(("doors:*",), "doors:front") and not _sc(("doors:*",), "doors:front:unlock")
   and not _sc(("media:*",), "media:admin:delete_user"),
   "RED-TEAM: wildcard covers ONE segment only (was: 'media:*' authorized 'media:admin:delete')")

# R-future: a grant dated too far in the future is rejected (clock-jump replay defense)
import time as _t
_gfut = _G.issue("k"*32, key_id="op", role="r", scope=("a",), subject="s",
                 ttl_seconds=99999, nonce="rf3", now=_t.time()+10000)
try:
    _vv.verify(_gfut, required_scope=("a",)); ok(False, "far-future grant should be rejected")
except Exception:
    ok(True, "RED-TEAM: grant dated too far in the future is rejected (clock-jump defense)")

# R-subject: the wall binds subject (a grant for one subject can't drive another's broker)
_tmpS = tempfile.mkdtemp(); _sS = os.path.join(_tmpS, "subj.sock")
_vS = _PVV(); _vS.register_key("operator", KEY, unrestricted=True); _fS = []
_bS = ActuationBroker(_sS, _vS, expected_subject="robot-1")
_bS.register_actuator("arm_1", lambda **k: _fS.append(k), required_scope=("arm:move",))
_bS.start(); time.sleep(0.1)
try:
    _pS = ActuatorProxy(_sS, "arm_1")
    _bindS = PermissionVerifier.bind_action("arm_1", "pick_up", {"target": "cup"})
    _gWrong = Grant.issue(KEY, key_id="operator", role="op", scope=("arm:move",),
                          subject="robot-2", ttl_seconds=60, nonce="subjR",
                          action_binding=_bindS)
    try:
        _pS.execute("pick_up", _gWrong, target="cup"); ok(False, "wrong-subject grant should refuse")
    except ActuationRefused:
        ok(_fS == [], "RED-TEAM: the wall binds subject — a grant for robot-2 cannot drive robot-1's broker")
finally:
    _bS.stop()

print(f"\n{p}/{p} tests passed")


# ══════════════════════════════════════════════════════════════════
# BREACH COUPLING — turning a documented intention into an enforced property.
# Before this, "blast radius = granted permission set" was TRUE but the permission set
# did NOT collapse on breach: a HALTED system holding a valid, unexpired, correctly
# bound grant could still actuate until the grant expired on its own. Backwards — the
# moment the wall matters most is after something has already gone wrong.
# ══════════════════════════════════════════════════════════════════
import os as _os2, tempfile as _tf2
from driftcore.verification.breach_response import (
    BreachResponse as _BR2, Severity as _Sev2, _AppendOnlyLedger as _BL2)

_tmp2 = _tf2.mkdtemp()

def _gated_broker(posture_source, name):
    """A broker wired to a breach-posture source, on its own socket."""
    _s = _os2.path.join(_tmp2, name)
    _v = PermissionVerifier(); _v.register_key("operator", KEY, unrestricted=True)
    _b = ActuationBroker(_s, _v, posture_source=posture_source)
    _b.register_actuator("arm_1", move_arm, required_scope=("arm:move",))
    return _b, _v, _s

# 1. OPERATIONAL: a valid grant still works — the gate does not break normal operation.
_br = _BR2(ledger=_BL2(), human_ack_verifier=lambda c: c == "HUMAN")
_b1, _v1, _s1 = _gated_broker(_br.is_operational, "gated_ok.sock")
_b1.start()
try:
    _g = grant_for(_v1, "arm_1", "move_arm", {"target": "home"}, nonce="bc-1")
    _r = ActuatorProxy(_s1, "arm_1").execute("move_arm", _g, target="home")
    ok(_r == "moved to home",
       "BREACH GATE: while OPERATIONAL, a valid grant actuates normally (the gate does not "
       "break the happy path)")
    ok(_b1.is_breach_gated() is True,
       "BREACH GATE: is_breach_gated() reports True when a posture source is wired")
finally:
    _b1.stop()

# 2. THE FIX: once breached, actuation is refused DESPITE a perfectly valid grant.
_br2 = _BR2(ledger=_BL2(), human_ack_verifier=lambda c: c == "HUMAN")
_b2, _v2, _s2 = _gated_broker(_br2.is_operational, "gated_breach.sock")
_b2.start()
try:
    _g2 = grant_for(_v2, "arm_1", "move_arm", {"target": "far"}, nonce="bc-2")
    _br2.record_breach(severity=_Sev2.HARD, invariant="allow_shutdown",
                       observed="refused a shutdown request")
    _before = len(fired)
    try:
        ActuatorProxy(_s2, "arm_1").execute("move_arm", _g2, target="far")
        ok(False, "a breached system must not actuate")
    except ActuationRefused as e:
        ok("breached" in str(e),
           "BREACH GATE (the fix): after a HARD breach the wall REFUSES a valid, unexpired, "
           "correctly-bound grant — the permission set COLLAPSES on breach")
    ok(len(fired) == _before,
       "BREACH GATE: the actuator genuinely did not fire (refusal is enforced, not cosmetic)")

    # 3. RECOVERY: a human acknowledgement restores operation — the gate is not a trap.
    _br2.acknowledge("HUMAN")
    _g3 = grant_for(_v2, "arm_1", "move_arm", {"target": "home"}, nonce="bc-3")
    _r3 = ActuatorProxy(_s2, "arm_1").execute("move_arm", _g3, target="home")
    ok(_r3 == "moved to home",
       "BREACH GATE: after a HUMAN acknowledgement the wall opens again (containment, not "
       "a permanent brick — and only a human can clear it)")
finally:
    _b2.stop()

# 4. FAIL-CLOSED: a posture source that RAISES is a refusal, never a fall-through.
def _broken_posture():
    raise RuntimeError("posture store unreachable")
_b3, _v3, _s3 = _gated_broker(_broken_posture, "gated_raise.sock")
_b3.start()
try:
    _g4 = grant_for(_v3, "arm_1", "move_arm", {"target": "x"}, nonce="bc-4")
    _before = len(fired)
    try:
        ActuatorProxy(_s3, "arm_1").execute("move_arm", _g4, target="x")
        ok(False, "an unavailable posture check must refuse")
    except ActuationRefused as e:
        ok("posture_unavailable" in str(e),
           "BREACH GATE fail-CLOSED: a posture source that RAISES refuses the action — a "
           "wall that cannot check its own state does not open")
    ok(len(fired) == _before, "BREACH GATE: nothing fired when the posture check failed")
finally:
    _b3.stop()

# 5. The gate runs BEFORE grant verification — a breached system's grants are not even
#    examined, so a breach cannot be probed for grant-validity information.
_br5 = _BR2(ledger=_BL2(), human_ack_verifier=lambda c: c == "HUMAN")
_b5, _v5, _s5 = _gated_broker(_br5.is_operational, "gated_order.sock")
_b5.start()
try:
    _br5.record_breach(severity=_Sev2.HARD, invariant="x", observed="y")
    try:
        # a deliberately MALFORMED grant: if ordering were wrong we would see
        # 'malformed_grant'; correct ordering reports 'breached' first.
        ActuatorProxy(_s5, "arm_1").execute("move_arm",
                                            Grant.from_dict({**grant_for(_v5, "arm_1", "move_arm", {}, nonce="bc-5").to_dict(), "sig": "bad"}))
        ok(False, "should refuse")
    except ActuationRefused as e:
        ok("breached" in str(e) and "grant" not in str(e).split(":")[0],
           "BREACH GATE ordering: the posture check runs BEFORE grant verification, so a "
           "breached system's grants are never evaluated (no oracle for grant validity)")
finally:
    _b5.stop()

# 6. HONEST DEFAULT: an UNGATED broker is visible, not silently permissive.
_b6, _v6, _s6 = _gated_broker(None, "ungated.sock")
ok(_b6.is_breach_gated() is False,
   "BREACH GATE: an UNGATED broker reports it — 'no refusals' must never be mistaken for "
   "'the gate is working'; production deployments must wire a posture source")

print(f"\n{p}/{p} tests passed")


# ══════════════════════════════════════════════════════════════════
# FOUR-WAY REVIEW REGRESSIONS (Claude cold pass, ChatGPT, Grok)
# ══════════════════════════════════════════════════════════════════
from driftcore.verification.breach_response import Posture as _P3
import time as _t3

# B1 (cold pass, CRITICAL): bool() coercion let a plausible mis-wiring INVERT the gate.
# Posture.HALT == 3 is truthy, Posture.NORMAL == 0 is falsy — passing `breach.posture`
# instead of `breach.is_operational` would have opened the wall on a halted system.
_br_b1 = _BR2(ledger=_BL2(), human_ack_verifier=lambda c: c == "HUMAN")
_br_b1.record_breach(severity=_Sev2.HARD, invariant="x", observed="y")
_b_b1, _v_b1, _s_b1 = _gated_broker(lambda: _br_b1.posture, "b1_coerce.sock")
_b_b1.start()
try:
    _n = len(fired)
    try:
        ActuatorProxy(_s_b1, "arm_1").execute("move_arm",
            grant_for(_v_b1, "arm_1", "move_arm", {"target": "x"}, nonce="b1-1"), target="x")
        ok(False, "a non-bool posture source must be refused, not coerced")
    except ActuationRefused as e:
        ok("posture_misconfigured" in str(e),
           "RED-TEAM B1 (critical): a posture_source returning a Posture enum is REFUSED, not "
           "coerced — bool(Posture.HALT)==True would have INVERTED the gate and opened the "
           "wall on a halted system. A type hint is not a check.")
    ok(len(fired) == _n, "RED-TEAM B1: nothing fired under the mis-wiring")
finally:
    _b_b1.stop()

ok(int(_P3.NORMAL) == 0 and int(_P3.HALT) == 3,
   "RED-TEAM B1: the inversion is real — NORMAL is falsy and HALT is truthy under bool()")

# B3 (cold pass): the posture check sits at position zero; a hanging source stalled every
# request — the one-client DoS conn_timeout already closed, reintroduced in front of it.
_b_b3, _v_b3, _s_b3 = None, None, None
_s3p = _os2.path.join(_tmp2, "b3_hang.sock")
_v3p = PermissionVerifier(); _v3p.register_key("operator", KEY, unrestricted=True)
_b3p = ActuationBroker(_s3p, _v3p, posture_source=lambda: (_t3.sleep(5) or True),
                       posture_timeout=0.4)
_b3p.register_actuator("arm_1", move_arm, required_scope=("arm:move",))
_b3p.start()
try:
    _t0 = _t3.time()
    try:
        ActuatorProxy(_s3p, "arm_1").execute("move_arm",
            grant_for(_v3p, "arm_1", "move_arm", {"target": "x"}, nonce="b3-1"), target="x")
        ok(False, "a hanging posture source must time out and refuse")
    except ActuationRefused as e:
        _el = _t3.time() - _t0
        ok("posture_unavailable" in str(e) and _el < 3.0,
           f"RED-TEAM B3: a hanging posture source is bounded ({_el:.2f}s) and REFUSES — it no "
           f"longer stalls the single accept loop for every request")
finally:
    _b3p.stop()

# GROK #2 (critical): act-then-report. A successful actuation whose result was not
# JSON-serializable was reported to the client as a REFUSAL, after the side effect and
# after the nonce was burned — so a retry double-actuated.
class _Unserializable:
    pass
_side = []
_s2g = _os2.path.join(_tmp2, "g2_act.sock")
_v2g = PermissionVerifier(); _v2g.register_key("operator", KEY, unrestricted=True)
_b2g = ActuationBroker(_s2g, _v2g)
_b2g.register_actuator("arm_1", lambda **kw: (_side.append(1) or _Unserializable()),
                       required_scope=("arm:move",))
_b2g.start()
try:
    _r2g = ActuatorProxy(_s2g, "arm_1").execute("move_arm",
        grant_for(_v2g, "arm_1", "move_arm", {"target": "x"}, nonce="g2-1"), target="x")
    ok(len(_side) == 1,
       "RED-TEAM GROK#2 (critical): an action with a non-serializable result is reported as "
       "SUCCESS, not as a false refusal — the side effect happened, so telling the caller it "
       "was refused would invite a retry that DOUBLE-ACTUATES")
except ActuationRefused:
    ok(False, "a completed action must never be reported as refused")
finally:
    _b2g.stop()

# ChatGPT: silent actuator replacement repointed every existing grant at different code.
_s6c = _os2.path.join(_tmp2, "dup.sock")
_v6c = PermissionVerifier(); _v6c.register_key("operator", KEY, unrestricted=True)
_b6c = ActuationBroker(_s6c, _v6c)
_b6c.register_actuator("arm_1", move_arm, required_scope=("arm:move",))
try:
    _b6c.register_actuator("arm_1", lambda **k: "OTHER", required_scope=("arm:move",))
    ok(False, "duplicate registration must be rejected")
except ValueError as e:
    ok("already registered" in str(e),
       "RED-TEAM (ChatGPT): re-registering an actuator id is REJECTED — silent replacement "
       "would repoint every existing grant for that id at different code")
_b6c.register_actuator("arm_1", lambda **k: "OTHER", required_scope=("arm:move",), replace=True)
ok(True, "RED-TEAM (ChatGPT): replacement is still possible, but only as a deliberate act")

# GROK #6 + ChatGPT: unbounded in-memory audit records.
_s7c = _os2.path.join(_tmp2, "cap.sock")
_v7c = PermissionVerifier(); _v7c.register_key("operator", KEY, unrestricted=True)
_b7c = ActuationBroker(_s7c, _v7c)
_b7c.register_actuator("arm_1", move_arm, required_scope=("arm:move",))
_b7c._records_cap = 50
_b7c.start()
try:
    for _i in range(200):
        try:
            ActuatorProxy(_s7c, "arm_1").execute("move_arm",
                grant_for(_v7c, "arm_1", "move_arm", {"target": "x"}, nonce=f"cap-{_i}"),
                target="x")
        except Exception:
            pass
    ok(len(_b7c.records) == 50 and _b7c._records_dropped == 150,
       "RED-TEAM (Grok+ChatGPT): audit records are BOUNDED and the drop count is retained — "
       "truncation is visible, not silent")
finally:
    _b7c.stop()

print(f"\n{p}/{p} tests passed")


# ══════════════════════════════════════════════════════════════════
# GROK #1 (critical): the separate-OS-user deployment was IMPOSSIBLE.
# The class documented "run the agent as a SEPARATE OS USER" while creating a mode-0600
# socket, which only the owner uid can connect to. Under the documented deployment the
# agent got EACCES; the only configuration that worked was same-uid, where
# require_peer_uid is a no-op and the isolation model does not exist.
# Resolved with a SHARED GROUP both users belong to.
# ══════════════════════════════════════════════════════════════════
import stat as _stat, grp as _grp

# 1. DEFAULT stays owner-only — the safe default, and honest that it means same-uid.
_sg1 = _os2.path.join(_tmp2, "sg_default.sock")
_v_sg1 = PermissionVerifier(); _v_sg1.register_key("operator", KEY, unrestricted=True)
_b_sg1 = ActuationBroker(_sg1, _v_sg1)
_b_sg1.register_actuator("arm_1", move_arm, required_scope=("arm:move",))
_b_sg1.start()
try:
    ok(_stat.S_IMODE(_os2.stat(_sg1).st_mode) == 0o600,
       "GROK#1: with no socket_group the socket stays 0600 (owner-only) — the safe default, "
       "and the docstring now says plainly that this means same-uid, not isolation")
finally:
    _b_sg1.stop()

# 2. WITH a shared group: 0660 owned by that group, so a separate-user agent can connect.
_mygid = _os2.getgid()
_sg2 = _os2.path.join(_tmp2, "sg_group.sock")
_v_sg2 = PermissionVerifier(); _v_sg2.register_key("operator", KEY, unrestricted=True)
_b_sg2 = ActuationBroker(_sg2, _v_sg2, socket_group=_mygid)
_b_sg2.register_actuator("arm_1", move_arm, required_scope=("arm:move",))
_b_sg2.start()
try:
    _st2 = _os2.stat(_sg2)
    ok(_stat.S_IMODE(_st2.st_mode) == 0o660 and _st2.st_gid == _mygid,
       "GROK#1 (the fix): socket_group yields mode 0660 owned by that group — the agent can "
       "run as a DIFFERENT OS USER and still reach the wall, which the documented deployment "
       "previously could not do at all")
    # the wall still works through it
    _r_sg = ActuatorProxy(_sg2, "arm_1").execute("move_arm",
        grant_for(_v_sg2, "arm_1", "move_arm", {"target": "g"}, nonce="sg-1"), target="g")
    ok(_r_sg == "moved to g", "GROK#1: actuation still works normally over the group socket")
finally:
    _b_sg2.stop()

# 3. Group may be given by NAME as well as gid.
_sg3 = _os2.path.join(_tmp2, "sg_name.sock")
_v_sg3 = PermissionVerifier(); _v_sg3.register_key("operator", KEY, unrestricted=True)
_b_sg3 = ActuationBroker(_sg3, _v_sg3, socket_group=_grp.getgrgid(_mygid).gr_name)
_b_sg3.register_actuator("arm_1", move_arm, required_scope=("arm:move",))
_b_sg3.start()
try:
    ok(_os2.stat(_sg3).st_gid == _mygid,
       "GROK#1: socket_group accepts a group NAME as well as a numeric gid")
finally:
    _b_sg3.stop()

# 4. FAIL CLOSED: a group that cannot be resolved or applied refuses to start, and does
#    not leave a permissive socket behind.
_sg4 = _os2.path.join(_tmp2, "sg_bad.sock")
_v_sg4 = PermissionVerifier(); _v_sg4.register_key("operator", KEY, unrestricted=True)
_b_sg4 = ActuationBroker(_sg4, _v_sg4, socket_group="no_such_group_xyz")
_b_sg4.register_actuator("arm_1", move_arm, required_scope=("arm:move",))
try:
    _b_sg4.start()
    _b_sg4.stop()
    ok(False, "an unresolvable socket_group must refuse to start")
except PermissionError as e:
    ok("Refusing to start" in str(e),
       "GROK#1 fail-CLOSED: a socket that cannot be locked to the intended group refuses to "
       "start — a wall whose door cannot be locked correctly does not open")
ok(not _os2.path.exists(_sg4),
   "GROK#1 fail-CLOSED: the half-created socket is removed, leaving nothing reachable behind")

print(f"\n{p}/{p} tests passed")


# ══════════════════════════════════════════════════════════════════
# RESERVATION MODEL (external red-team): verify() checked the nonce but did not burn it,
# and consume() came 26 lines later with the cumulative-ledger gate in between. Two
# concurrent requests could both verify the same single-use grant — reproduced at 8/8.
# A plain verify_and_consume() would close the race but burn the nonce BEFORE the ledger
# gate, letting an attacker who can trigger refusals exhaust an operator's grants.
# reserve -> gates -> commit | release.
# ══════════════════════════════════════════════════════════════════
import threading as _th3
from driftcore.verification.signed_permission import PermissionReplay as _PR3

_vr = PermissionVerifier(); _vr.register_key("operator", KEY, unrestricted=True)
_rg = Grant.issue(KEY, key_id="operator", role="operator", subject=None,
                  scope=["arm:move"], ttl_seconds=60, nonce="resv-1")
_wins = []
_bar = _th3.Barrier(8)
def _racer():
    _bar.wait()
    try:
        _vr.reserve(_rg, required_scope=["arm:move"])
        _t3.sleep(0.01)                      # any work between check and burn
        _wins.append(1)
        _vr.commit(_rg)
    except Exception:
        pass
_rts = [_th3.Thread(target=_racer) for _ in range(8)]
for _t in _rts: _t.start()
for _t in _rts: _t.join()
ok(len(_wins) == 1,
   "RED-TEAM (external, critical): 8 threads racing ONE single-use grant now yield exactly "
   "ONE success — reserve() checks and marks the nonce in-flight atomically (8/8 succeeded "
   "before the fix)")

_vr2 = PermissionVerifier(); _vr2.register_key("operator", KEY, unrestricted=True)
_rg2 = Grant.issue(KEY, key_id="operator", role="operator", subject=None,
                   scope=["arm:move"], ttl_seconds=60, nonce="resv-2")
_vr2.reserve(_rg2, required_scope=["arm:move"])
_vr2.release(_rg2)
_vr2.reserve(_rg2, required_scope=["arm:move"])
ok(True,
   "RELEASE returns the grant to the pool: a request refused BEFORE any side effect does "
   "NOT spend a single-use grant, so triggering refusals cannot exhaust an operator")
_vr2.commit(_rg2)
try:
    _vr2.reserve(_rg2, required_scope=["arm:move"])
    ok(False, "a committed grant must not be reusable")
except _PR3:
    ok(True, "COMMIT burns the nonce permanently — after the action, replay is refused")
ok(_vr2.in_flight() == 0,
   "in_flight() returns to zero after commit — a number that only grows would reveal "
   "callers that neither commit nor release")

_vr3 = PermissionVerifier(); _vr3.register_key("operator", KEY, unrestricted=True)
_rg3 = Grant.issue(KEY, key_id="operator", role="operator", subject=None,
                   scope=["arm:move"], ttl_seconds=60, nonce="resv-3")
_vr3.reserve(_rg3, required_scope=["arm:move"])
try:
    _vr3.verify(_rg3, required_scope=["arm:move"])
    ok(False, "an in-flight nonce must not verify")
except _PR3:
    ok(True, "a RESERVED nonce does not verify — a crash between reserve and commit leaves "
             "the grant unusable, which is the safe direction for a single-use credential")

# the broker refuses on a ledger veto WITHOUT spending the grant
_lp = _os2.path.join(_tmp2, "resv_ledger.sock")
_lv = PermissionVerifier(); _lv.register_key("operator", KEY, unrestricted=True)
_lb = ActuationBroker(_lp, _lv, ledger_hook=lambda a, c, pr: "cumulative cap reached")
_lb.register_actuator("arm_1", move_arm, required_scope=("arm:move",))
_lb.start()
try:
    _lg = grant_for(_lv, "arm_1", "move_arm", {"target": "x"}, nonce="resv-led")
    try:
        ActuatorProxy(_lp, "arm_1").execute("move_arm", _lg, target="x")
        ok(False, "the ledger veto must refuse")
    except ActuationRefused:
        pass
    ok(_lv.in_flight() == 0,
       "RED-TEAM: a ledger-vetoed request RELEASES the reservation — the refusal costs the "
       "operator nothing, so an attacker cannot burn grants by provoking refusals")
finally:
    _lb.stop()

print(f"\n{p}/{p} tests passed")


# ══════════════════════════════════════════════════════════════════
# EXTERNAL RED-TEAM ROUND 2 (Grok, against the real source tree)
# ══════════════════════════════════════════════════════════════════
from driftcore.verification.governed_actuator import GrantAuthority as _GA
import hmac as _hm, hashlib as _hl

# G-C1: there are TWO grant systems. The reservation fix was applied to
# signed_permission; GrantAuthority still had NO LOCK, and verify(consume=False) — the
# documented "check now, act later" pattern — was racy by construction (8/8 succeeded).
_exp = _t3.time() + 60
def _mkg(n):
    _sig = _hm.new(b"secret", f"arm|move|{n}|{_exp}".encode(), _hl.sha256).hexdigest()
    return {"actuator_id": "arm", "command": "move", "nonce": n,
            "expires": _exp, "sig": _sig}

_ga = _GA(b"secret"); _gg = _mkg("ga-race")
_gw = []; _gb = _th3.Barrier(8)
def _grace():
    _gb.wait()
    if _ga.reserve(_gg, "arm", "move"):
        _t3.sleep(0.01); _gw.append(1); _ga.commit(_gg)
_gts = [_th3.Thread(target=_grace) for _ in range(8)]
for _t in _gts: _t.start()
for _t in _gts: _t.join()
ok(len(_gw) == 1,
   "RED-TEAM G-C1 (external): the SECOND grant system (GrantAuthority) now has "
   "reserve/commit/release under a lock — 8 threads racing one grant yield ONE success "
   "(verify(consume=False) gave 8/8 before)")

_ga2 = _GA(b"secret"); _gg2 = _mkg("ga-rel")
_ga2.reserve(_gg2, "arm", "move"); _ga2.release(_gg2)
ok(_ga2.reserve(_gg2, "arm", "move") is True,
   "RED-TEAM G-C1: release returns the grant to the pool in GrantAuthority too — both "
   "grant systems now behave identically, so choosing the lighter API is no longer a "
   "silent downgrade")
_ga2.commit(_gg2)
ok(_ga2.reserve(_gg2, "arm", "move") is False
   and _ga2.verify(_gg2, "arm", "move") is False,
   "RED-TEAM G-C1: commit burns permanently, and an in-flight nonce does not verify")

# G-C2: the library default (0600) forces same-UID, which makes require_peer_uid a no-op.
# require_isolation turns that documented assumption into a checked one.
_iso = _os2.path.join(_tmp2, "iso.sock")
_iv = PermissionVerifier(); _iv.register_key("operator", KEY, unrestricted=True)
_ib = ActuationBroker(_iso, _iv, require_isolation=True)
_ib.register_actuator("arm_1", move_arm, required_scope=("arm:move",))
try:
    _ib.start(); _ib.stop()
    ok(False, "require_isolation must refuse without the prerequisites")
except PermissionError as e:
    ok("NOT isolated" in str(e),
       "RED-TEAM G-C2 (external): require_isolation=True REFUSES to start unless "
       "socket_group and require_peer_uid are configured — a deployment can no longer "
       "take the easy path and silently get weaker isolation than the docs imply")

_iso2 = _os2.path.join(_tmp2, "iso_ok.sock")
_iv2 = PermissionVerifier(); _iv2.register_key("operator", KEY, unrestricted=True)
# NOTE: require_isolation now also requires enforce_effects (3-way external red-team
# convergence: a broker that CLAIMS the wall property cannot leave undeclared actuators
# reachable). So the positive isolation case must declare its effects too.
from driftcore.verification.invariant_guard import Effect as _Eff
# require_isolation now also demands an ATTESTATION: isolation_manifest could verify a
# process's surface but was wired into this broker zero times, so the flag only proved
# the operator INTENDED isolation. A supervisor report is what says someone looked.
from driftcore.kernel.isolation_manifest import IsolationReport as _IsoRep
_att = _IsoRep(trusted=True, source=f"supervisor:{_os2.getpid()}")
_ib2 = ActuationBroker(_iso2, _iv2, require_isolation=True, enforce_effects=True,
                       socket_group=_os2.getgid(), require_peer_uid=_os2.getuid(),
                       isolation_attestation=_att)
_ib2.register_actuator("arm_1", move_arm, required_scope=("arm:move",),
                       effects=[_Eff.PHYSICAL_FORCE], effect_declared_by="test-operator")
_ib2.start()
try:
    ok(_ib2.is_breach_gated() is False and _os2.path.exists(_iso2),
       "RED-TEAM G-C2: with the prerequisites configured the broker starts normally")
finally:
    _ib2.stop()

print(f"\n{p}/{p} tests passed")
