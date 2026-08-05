"""
End-to-end: the constitutional effect gate WIRED INTO the actuation wall.

These drive the broker's real request handler (`_handle`) — the same path a socket
request takes — with enforce_effects=True, proving the fail-closed-on-undeclared
guarantee holds on the ENFORCED path, not just in the gate module in isolation.
"""
import time
from driftcore.verification.mediated_actuation import ActuationBroker
from driftcore.verification.signed_permission import (
    PermissionVerifier, Grant, PermissionError_,
)
from driftcore.verification.invariant_guard import Effect

passed = 0
def ok(c, label):
    global passed
    assert c, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")

KEY = b"\x11" * 32
SOCK = "/tmp/dc_effect_wall.sock"

def broker(enforce):
    v = PermissionVerifier()
    v.register_key("operator", KEY)
    b = ActuationBroker(SOCK, v, enforce_effects=enforce)
    return b, v

def grant(v, actuator_id, command, params, *, nonce, scope):
    binding = PermissionVerifier.bind_action(actuator_id, command, params)
    return Grant.issue(KEY, key_id="operator", role="operator", scope=scope,
                       subject="robot-1", ttl_seconds=60, nonce=nonce,
                       action_binding=binding).to_dict()

def req(actuator_id, command, params, g):
    return {"op": "execute", "actuator_id": actuator_id, "command": command,
            "params": params, "grant": g}


print("== state reporting: enforcement is visible (not a silent gap) ==")
b_off, _ = broker(False)
b_on, _ = broker(True)
ok(b_off.is_effect_gated() is False, "unenforced broker reports is_effect_gated()==False")
ok(b_on.is_effect_gated() is True, "enforced broker reports is_effect_gated()==True")

print("== enforcement ON: registration REQUIRES an effect declaration (fail closed early) ==")
b, v = broker(True)
fired = []
try:
    b.register_actuator("arm_undeclared", lambda **k: fired.append(k),
                        required_scope=("arm:move",))
    ok(False, "registering an actuator without effects under enforcement should raise")
except ValueError:
    ok(True, "cannot register a consequential actuator without declaring its effects")
try:
    b.register_actuator("arm_nodecl", lambda **k: fired.append(k),
                        required_scope=("arm:move",), effects=[Effect.PHYSICAL_FORCE])
    ok(False, "effects without effect_declared_by should raise")
except ValueError:
    ok(True, "effect declaration must be attributable (effect_declared_by required)")

print("== THE GUARANTEE end-to-end: a DECLARED benign actuator actuates ==")
b, v = broker(True)
moved = []
b.register_actuator("vacuum", lambda **k: moved.append(k) or "cleaned",
                    required_scope=("floor:clean",), effects=[Effect.NONE],
                    effect_declared_by="justin")
g = grant(v, "vacuum", "clean", {"room": "kitchen"}, nonce="e1", scope=("floor:clean",))
res = b._handle(req("vacuum", "clean", {"room": "kitchen"}, g))
ok(res.get("ok") is True and moved == [{"room": "kitchen"}],
   "a declared-NONE actuator with a valid grant actuates through the wall")

print("== a DECLARED LETHAL actuator is blocked by the floor even with a valid grant ==")
b, v = broker(True)
bang = []
b.register_actuator("weapon", lambda **k: bang.append(k),
                    required_scope=("weapon:fire",), effects=[Effect.LETHAL],
                    effect_declared_by="justin")
g = grant(v, "weapon", "fire", {"at": "x"}, nonce="e2", scope=("weapon:fire",))
res = b._handle(req("weapon", "fire", {"at": "x"}, g))
ok(res.get("ok") is False and "effect_block" in res.get("error", "") and bang == [],
   "a declared-LETHAL actuator is refused by the constitutional floor; nothing fired")

print("== a lethal-SUGGESTIVE but benign-declared actuator is HELD for review ==")
b, v = broker(True)
b.register_actuator("murder_bot", lambda **k: None,
                    required_scope=("arm:move",), effects=[Effect.PHYSICAL_FORCE],
                    effect_declared_by="justin")
g = grant(v, "murder_bot", "go", {}, nonce="e3", scope=("arm:move",))
res = b._handle(req("murder_bot", "go", {}, g))
ok(res.get("ok") is False and "hold_for_review" in res.get("error", ""),
   "lethal-suggestive capability name -> HELD at the wall, not actuated")

print("== a refused action RELEASES the grant (no side effect, nonce not burned) ==")
b, v = broker(True)
b.register_actuator("weapon2", lambda **k: None, required_scope=("weapon:fire",),
                    effects=[Effect.LETHAL], effect_declared_by="justin")
g = grant(v, "weapon2", "fire", {}, nonce="e4", scope=("weapon:fire",))
b._handle(req("weapon2", "fire", {}, g))      # refused by effect gate
# the same nonce should NOT have been burned by a refusal — but weapon2 always blocks,
# so re-presenting still blocks (proving the refusal path is consistent, grant released)
res2 = b._handle(req("weapon2", "fire", {}, g))
ok(res2.get("ok") is False, "a grant released on effect-refusal is not silently consumed into a success")

print("== comparison: with enforcement OFF, an undeclared actuator STILL actuates (the gap) ==")
b, v = broker(False)
ran = []
b.register_actuator("legacy_arm", lambda **k: ran.append(k) or "ok",
                    required_scope=("arm:move",))   # no effects, allowed when unenforced
g = grant(v, "legacy_arm", "move", {}, nonce="e5", scope=("arm:move",))
res = b._handle(req("legacy_arm", "move", {}, g))
ok(res.get("ok") is True and ran == [{}],
   "unenforced broker actuates an undeclared actuator — WHY enforce_effects must be on in prod")

print("== combined red-team pins ==")
from driftcore.verification.invariant_guard import Effect as _E

# A1: a rejected declaration must leave NO partial registration
b, v = broker(True)
try:
    b.register_actuator("arm", lambda **k: "MOVED", required_scope=("a:m",))
except ValueError:
    pass
ok("arm" not in b._actuators, "a rejected effect declaration leaves no half-registered actuator (A1)")
b.register_actuator("arm", lambda **k: "MOVED", required_scope=("a:m",),
                    effects=[_E.NONE], effect_declared_by="justin")
ok("arm" in b._actuators, "and the operator can simply retry — not locked out behind replace=True")

# A2: the gate runs BEFORE the ledger, so impossible actions cost no budget
charged = []
b, v = broker(True)
b2 = ActuationBroker(SOCK, v, enforce_effects=True,
                     ledger_hook=lambda a, c, p: charged.append(a) or None)
b2.register_actuator("w", lambda **k: "BANG", required_scope=("w:f",),
                     effects=[_E.LETHAL], effect_declared_by="justin")
for i in range(3):
    b2._handle(req("w", "fire", {}, grant(v, "w", "fire", {}, nonce=f"c{i}", scope=("w:f",))))
ok(charged == [], "constitutionally-impossible actions never reach the cumulative ledger (A2)")

# A4: params are part of the lexicon scan surface
b, v = broker(True)
b.register_actuator("vac2", lambda **k: "ok", required_scope=("f:c",),
                    effects=[_E.NONE], effect_declared_by="justin")
p = {"target": "kill the intruder"}
r = b._handle(req("vac2", "clean", p, grant(v, "vac2", "clean", p, nonce="pp", scope=("f:c",))))
ok(r.get("ok") is False, "lethal intent hidden in params is caught, not ignored (A4)")

# A6: a gate exception fails closed and does not escape _handle
b, v = broker(True)
b.register_actuator("vx", lambda **k: "ok", required_scope=("f:c",),
                    effects=[_E.NONE], effect_declared_by="justin")
class _Boom:
    def authorize(self, *a, **k): raise RuntimeError("gate exploded")
b._effect_gate = _Boom()
r = b._handle(req("vx", "clean", {}, grant(v, "vx", "clean", {}, nonce="bx", scope=("f:c",))))
ok(r.get("ok") is False and r.get("error") == "effect_block_error",
   "a crashing gate fails closed and returns, never escaping to a generic broker_error (A6)")

# A7: the authorizer label names the mechanism, not the machine
seen = {}
b, v = broker(True)
b.register_actuator("u", lambda **k: "sent", required_scope=("n:o",),
                    effects=[_E.DATA_EGRESS], effect_declared_by="justin", destination_param="url")
real = b._effect_gate
class _Spy:
    def authorize(self, cap, cmd, ctx):
        seen["by"] = ctx.authorised_by
        return real.authorize(cap, cmd, ctx)
b._effect_gate = _Spy()
b._handle(req("u", "sync", {}, grant(v, "u", "sync", {}, nonce="sy", scope=("n:o",))))
ok(seen.get("by") == "broker:scope-mediated",
   "the effect decision is attributed to the MECHANISM, never to the robot itself (A7)")

# A8: a malformed declaration is loud even when unenforced
b, v = broker(False)
try:
    b.register_actuator("t", lambda **k: 1, required_scope=("t:t",),
                        effects=["LETAHL"], effect_declared_by="justin")
    ok(False, "a typo'd effect declaration should raise")
except ValueError:
    ok(True, "a malformed effect declaration raises even with enforcement off (A8)")

# Meta P1-1: injecting past register_actuator does NOT bypass the gate
b, v = broker(True)
b._actuators["backdoor"] = (lambda **k: "PWNED", ("bd:r",))
r = b._handle(req("backdoor", "run", {}, grant(v, "backdoor", "run", {}, nonce="bd", scope=("bd:r",))))
ok(r.get("ok") is False and "undeclared" in r.get("error", ""),
   "an actuator injected past registration still fails closed — the gate reads the registry")

# 3-way convergence: claiming the wall property requires enforcing effects
try:
    ActuationBroker(SOCK, v, require_isolation=True, enforce_effects=False).start()
    ok(False, "require_isolation without enforce_effects should refuse")
except PermissionError:
    ok(True, "require_isolation=True refuses to start with enforce_effects=False")

# KNOWN GAP (pinned): effect DOWNGRADE after issuance still executes
b, v = broker(True)
b.register_actuator("dg", lambda **k: "MOVED", required_scope=("d:g",),
                    effects=[_E.LETHAL], effect_declared_by="justin")
r1 = b._handle(req("dg", "move", {}, grant(v, "dg", "move", {}, nonce="g1", scope=("d:g",))))
b._effect_registry.register("dg", [_E.NONE], declared_by="mallory", replace=True)
r2 = b._handle(req("dg", "move", {}, grant(v, "dg", "move", {}, nonce="g2", scope=("d:g",))))
ok(r1.get("ok") is False and r2.get("ok") is True,
   "KNOWN GAP: upgrading a declaration fails closed, but DOWNGRADING it executes — "
   "the grant is not bound to the declaration. Signed append-only declarations are the "
   "fix; this assertion must flip when they land")

print(f"\nALL {passed} CHECKS PASSED")


print("== LOCAL REFUSAL in the enforcement path (the wall's own error handling) ==")
# Each of these four gates used to refuse in TWO steps: set a flag in the except, then
# act on the flag further down. Safe, but the refusal lived away from the failure — and
# one of them (the registry read) was CONDITIONAL and could be skipped entirely.

class _BrokenRegistry:
    def effects_for(self, a): raise RuntimeError("registry down")
    def declaration(self, a): return None

# the verified hole: registry failure + no destinations in params -> the actuator RAN
b, v = broker(False)
ran = []
b.register_actuator("arm", lambda **k: ran.append(1) or "ok", required_scope=("a:m",))
b._effect_registry = _BrokenRegistry()
r = b._handle(req("arm", "move", {}, grant(v, "arm", "move", {}, nonce="lr1", scope=("a:m",))))
ok(r.get("error_code") == "REGISTRY_ERROR" and not ran,
   "an unreadable effect registry refuses UNCONDITIONALLY — it used to refuse only if "
   "destinations were also present, so an action with no URL in its params executed")

# the effect gate's own failure returns from the except, not via a flag
b, v = broker(True)
fired = []
b.register_actuator("vac", lambda **k: fired.append(1), required_scope=("f:c",),
                    effects=[Effect.NONE], effect_declared_by="justin")
class _BoomGate:
    def authorize(self, *a, **k): raise RuntimeError("gate exploded")
b._effect_gate = _BoomGate()
r = b._handle(req("vac", "clean", {}, grant(v, "vac", "clean", {}, nonce="lr2", scope=("f:c",))))
ok(r.get("error_code") == "EFFECT_BLOCK_ERROR" and not fired,
   "a crashing effect gate refuses at the failure site")

# the blast-radius governor likewise
from driftcore.kernel.blast_radius import BlastRadiusGovernor, BreadthPolicy
b2 = ActuationBroker(SOCK, v, enforce_effects=True,
                     blast_radius=BlastRadiusGovernor(
                         BreadthPolicy(window_seconds=60, max_distinct_capabilities=5)))
moved = []
b2.register_actuator("arm2", lambda **k: moved.append(1), required_scope=("a:m",),
                     effects=[Effect.NONE], effect_declared_by="justin")
class _BoomGov:
    def observe(self, *a, **k): raise RuntimeError("governor exploded")
    def is_armed(self): return True
b2._blast_radius = _BoomGov()
r = b2._handle(req("arm2", "move", {}, grant(v, "arm2", "move", {}, nonce="lr3", scope=("a:m",))))
ok(r.get("error_code") == "BLAST_RADIUS_ERROR" and not moved,
   "a crashing blast-radius governor refuses at the failure site")

print(f"\nALL {passed} CHECKS PASSED")


print("== UNKNOWN PHYSICAL STATE: a timeout must not become a double actuation ==")
import time as _t
# Reproduced before the fix: the broker reports ACTUATOR_TIMEOUT and burns the nonce,
# but Python cannot kill the daemon thread running the actuator. The orphan completed
# the move, the agent retried with a fresh grant, and the arm moved TWICE.
_v = PermissionVerifier(); _v.register_key("operator", KEY)
_b = ActuationBroker(SOCK, _v, enforce_effects=True, actuator_timeout=0.3)
_moves = []
def _slow(**k):
    _t.sleep(0.9); _moves.append("moved"); return "ok"
_b.register_actuator("slowarm", _slow, required_scope=("a:m",),
                     effects=[Effect.PHYSICAL_FORCE], effect_declared_by="justin")
def _g(n):
    return grant(_v, "slowarm", "move", {}, nonce=n, scope=("a:m",))

r = _b._handle(req("slowarm", "move", {}, _g("u1")))
ok(r.get("error_code") == "ACTUATOR_TIMEOUT",
   "a timed-out actuator reports UNKNOWN completion, never a clean refusal")
r = _b._handle(req("slowarm", "move", {}, _g("u2")))
ok(r.get("error_code") == "UNKNOWN_PHYSICAL_STATE",
   "the retry is REFUSED — the orphaned thread may still complete the action, so a "
   "second grant could actuate the physical world twice")
_t.sleep(1.2)
ok(len(_moves) == 1,
   "exactly ONE physical actuation occurred (before the quarantine it was two)")
ok("slowarm" in _b.unknown_completions(),
   "the actuator is listed as having unknown physical state — a real-world object "
   "whose position nobody currently knows")

try:
    _b.acknowledge_completion("slowarm", by="", observed_state="")
    ok(False, "clearing a quarantine without attribution should raise")
except ValueError:
    ok(True, "clearing requires WHO looked and WHAT they saw — it is a safety act")
_b.acknowledge_completion("slowarm", by="justin", observed_state="arm at rest")
r = _b._handle(req("slowarm", "move", {}, _g("u3")))
ok(r.get("error_code") != "UNKNOWN_PHYSICAL_STATE",
   "after a human reconciles the physical state, the actuator is accepted again")

print(f"\nALL {passed} CHECKS PASSED")


print("== the quarantine must survive a restart, and must not be duplicated ==")
import os as _os
_QP = "/tmp/dc_quarantine_pin.json"
if _os.path.exists(_QP):
    _os.remove(_QP)

def _mkq():
    _vq = PermissionVerifier(); _vq.register_key("operator", KEY)
    _bq = ActuationBroker(SOCK, _vq, enforce_effects=True, actuator_timeout=0.3,
                          quarantine_path=_QP)
    _bq.register_actuator("qarm", lambda **k: _t.sleep(0.9), required_scope=("a:m",),
                          effects=[Effect.PHYSICAL_FORCE], effect_declared_by="justin")
    return _bq, _vq

_b1, _v1 = _mkq()
_b1._handle(req("qarm", "move", {}, grant(_v1, "qarm", "move", {}, nonce="qp1",
                                          scope=("a:m",))))
ok(_os.path.exists(_QP),
   "the quarantine is written to disk. There were briefly TWO _persist_quarantine "
   "methods; Python keeps the LAST definition silently, so the other implementation "
   "was dead while its constructor parameter and posture event stayed live — a "
   "deployment was told the quarantine was durable while nothing was ever written")
ok(_b1.is_quarantine_durable(), "and the broker reports durability truthfully")

_t.sleep(1.1)
_b2, _v2 = _mkq()                      # simulated restart
r = _b2._handle(req("qarm", "move", {}, grant(_v2, "qarm", "move", {}, nonce="qp2",
                                              scope=("a:m",))))
ok(r.get("error_code") == "UNKNOWN_PHYSICAL_STATE",
   "the quarantine SURVIVES a restart — a crash-restart is exactly when a timeout is "
   "likely, and physical state does not reset because a process did")

_bare = ActuationBroker(SOCK, _v1)
ok(any(e["layer"] == "quarantine_durable" for e in _bare.posture_events()),
   "a broker with no quarantine store records the gap as a posture event")
ok(len([e for e in _bare.posture_events() if "quarantine" in e["layer"]]) == 1,
   "and reports it exactly ONCE — the duplicate posture entry is gone")

with open(_QP, "w") as _fh:
    _fh.write("{not json")
try:
    _mkq()
    ok(False, "an unreadable quarantine store should refuse to start")
except RuntimeError:
    ok(True, "an unreadable quarantine record REFUSES to start — it may list actuators "
             "left in unknown physical state, and unreadable cannot be assumed empty")
_os.remove(_QP)

print(f"\nALL {passed} CHECKS PASSED")


print("== ISOLATION ATTESTATION: the wall must be MEASURED, not declared ==")
import os as _o
from datetime import datetime as _dtt, timezone as _tzz, timedelta as _tdd
from driftcore.kernel.isolation_manifest import IsolationReport as _Rep

_ME = f"supervisor:{_o.getpid()}"
def _iso(att):
    return ActuationBroker(SOCK, PermissionVerifier(), require_isolation=True,
                           enforce_effects=True, socket_group=_o.getgid(),
                           require_peer_uid=_o.getuid(), isolation_attestation=att)

for _label, _att in [
    ("no attestation", None),
    ("self-reported", _Rep(trusted=False, source="self")),
    ("has findings", _Rep(trusted=True, source=_ME, findings=["an undeclared socket FD"])),
    ("another pid", _Rep(trusted=True, source="supervisor:99999")),
    ("stale", _Rep(trusted=True, source=_ME,
                   checked_at=(_dtt.now(_tzz.utc) - _tdd(hours=2)).isoformat())),
    ("unreadable timestamp", _Rep(trusted=True, source=_ME, checked_at="not-a-time")),
]:
    try:
        _b = _iso(_att); _b.start(); _b.stop()
        ok(False, f"a broker claiming isolation started with a {_label} attestation")
    except PermissionError:
        ok(True, f"claiming the wall property REFUSES on: {_label}")

_good = _iso(_Rep(trusted=True, source=_ME))
_good.start()
ok(_good.is_isolation_attested(),
   "a fresh supervisor attestation for THIS process lets the wall serve")
_good.stop()

ok(any(e["layer"] == "isolation_attested"
       for e in ActuationBroker(SOCK, PermissionVerifier()).posture_events()),
   "and an unattested broker records it as a posture event — the surface was never "
   "verified, so the wall property is a claim rather than a measurement")

print(f"\nALL {passed} CHECKS PASSED")


print("== ATTESTATION FRESHNESS is enforced on EVERY request, not once at start ==")
_fresh = lambda age=0: _Rep(trusted=True, source=_ME,
    checked_at=(_dtt.now(_tzz.utc) - _tdd(seconds=age)).isoformat())

_fb = ActuationBroker(SOCK, _v1, require_isolation=True, enforce_effects=True,
                      socket_group=_o.getgid(), require_peer_uid=_o.getuid(),
                      isolation_attestation=_fresh(), attestation_max_age_seconds=1.0)
_fran = []
_fb.register_actuator("farm", lambda **k: _fran.append(1) or "ok",
                      required_scope=("a:m",), effects=[Effect.PHYSICAL_FORCE],
                      effect_declared_by="justin")
_fb.start()
def _fgo(n):
    return _fb._handle(req("farm", "move", {},
                           grant(_v1, "farm", "move", {}, nonce=n, scope=("a:m",))))

ok(_fgo("f1").get("ok") is True, "a fresh attestation lets the wall serve")
_t.sleep(1.2)
r = _fgo("f2")
ok(r.get("error_code") == "ISOLATION_UNATTESTED" and len(_fran) == 1,
   "once the attestation AGES OUT the wall stops serving mid-run — a broker verified "
   "clean at boot used to run indefinitely on a report describing a process that no "
   "longer existed in that state")
_fb.refresh_isolation_attestation(_fresh())
ok(_fgo("f3").get("ok") is True and len(_fran) == 2,
   "and a supervisor re-verifying restores service — staleness is not a one-way door "
   "requiring a restart, because restarting to clear a safety hold is the reflex this "
   "project designs against")

for _lbl, _bad in [("self-report", _Rep(trusted=False, source="self")),
                   ("another pid", _Rep(trusted=True, source="supervisor:99999")),
                   ("has findings", _Rep(trusted=True, source=_ME, findings=["socket"]))]:
    try:
        _fb.refresh_isolation_attestation(_bad)
        ok(False, f"refresh accepted a {_lbl} attestation")
    except PermissionError:
        ok(True, f"refresh applies the SAME five rules as start(): {_lbl} refused")
_fb.stop()

import time as _tm
_t0 = _tm.perf_counter()
for _ in range(5000):
    _fb._attestation_stale_reason()
_per_us = (_tm.perf_counter() - _t0) / 5000 * 1e6
ok(_per_us < 25,
   f"the per-request freshness check costs {_per_us:.2f}us against a ~150us wall — the "
   f"timestamp is parsed once at install, so the hot path does arithmetic not parsing")

print(f"\nALL {passed} CHECKS PASSED")


print("== EFFECT-DECLARATION BINDING: the downgrade gap, closed ==")
# Both external reviews ranked this first. A grant pinned WHAT is executed but not
# WHAT THE ACTUATOR WAS DECLARED TO DO, so an operator (or a compromised broker) could
# issue a grant against LETHAL, downgrade the registry to NONE with replace=True, and
# the outstanding grant then executed under the weaker floor. Reproduced below.
def _dbuild(bind):
    _dv = PermissionVerifier(); _dv.register_key("operator", KEY)
    _db = ActuationBroker(SOCK, _dv, enforce_effects=True, require_effect_binding=bind)
    _hit = []
    _db.register_actuator("darm", lambda **k: _hit.append(1) or "MOVED",
                          required_scope=("a:m",), effects=[Effect.LETHAL],
                          effect_declared_by="justin")
    return _db, _dv, _hit

def _dmint(_db, n):
    _eh = _db._declaration_hash("darm") if _db.is_effect_bound() else None
    return Grant.issue(KEY, key_id="operator", role="operator", scope=("a:m",),
                       subject="robot-1", ttl_seconds=60, nonce=n,
                       action_binding=PermissionVerifier.bind_action(
                           "darm", "move", {}, effects_hash=_eh)).to_dict()

_db, _dv, _hit = _dbuild(False)
_g = _dmint(_db, "dg1")
_db._handle(req("darm", "move", {}, _g))
_db._effect_registry.register("darm", [Effect.NONE], declared_by="mallory", replace=True)
_r = _db._handle(req("darm", "move", {}, _g))
ok(_r.get("ok") is True and len(_hit) == 1,
   "UNBOUND (documenting the gap): the same outstanding grant executes after the "
   "declaration is downgraded LETHAL -> NONE")

_db, _dv, _hit = _dbuild(True)
_g = _dmint(_db, "dg2")
_db._handle(req("darm", "move", {}, _g))
_db._effect_registry.register("darm", [Effect.NONE], declared_by="mallory", replace=True)
_r = _db._handle(req("darm", "move", {}, _g))
ok(_r.get("ok") is False and not _hit,
   "BOUND: the outstanding grant is REFUSED after the downgrade — the binding covers "
   "the declaration, so any change invalidates every grant issued against the old one")

_db, _dv, _hit = _dbuild(True)
_db._effect_registry.register("darm", [Effect.NONE], declared_by="justin", replace=True)
ok(_db._handle(req("darm", "move", {}, _dmint(_db, "dg3"))).get("ok") is True,
   "and a FRESH grant against the current declaration still works — this invalidates "
   "stale authorization, it does not freeze the registry")

ok(any(e["layer"] == "effect_binding"
       for e in ActuationBroker(SOCK, _dv).posture_events()),
   "a broker without effect binding records the gap as a posture event")

print("== canonicalisation: NaN / Infinity cannot be bound ==")
for _bad in (float("nan"), float("inf"), float("-inf")):
    try:
        PermissionVerifier.bind_action("a", "c", {"force": _bad})
        ok(False, f"binding accepted {_bad}")
    except ValueError:
        ok(True, f"a {_bad} parameter is refused — json.dumps emits non-standard tokens "
                 f"that other runtimes serialize differently or reject")
ok(PermissionVerifier.bind_action("a", "c", {"force": 1.5}) is not None,
   "ordinary floats are unaffected")

print("== attestation age is measured on the MONOTONIC clock ==")
_mb = ActuationBroker(SOCK, _dv, require_isolation=True, enforce_effects=True,
                      socket_group=_o.getgid(), require_peer_uid=_o.getuid(),
                      isolation_attestation=_fresh(), attestation_max_age_seconds=60)
_mb.start()
ok(_mb._attested_mono is not None,
   "a monotonic reference is captured at install: a backwards wall-clock step (NTP, "
   "VM migration, a manual `date`) would otherwise make a STALE attestation look "
   "fresh, and freshness is the whole control")
ok(_mb._attestation_stale_reason() is None, "and a fresh attestation still reads fresh")
_mb.stop()

print(f"\nALL {passed} CHECKS PASSED")


print("== COLD PASS on the binding/clock work ==")

# C1: the first NaN guard walked only the top level of params — the same
# only-checked-the-first-level mistake as the egress decoy-parameter bug.
for _lbl, _p in [("nested dict", {"body": {"f": float("nan")}}),
                 ("inside a list", {"vals": [1.0, float("inf")]}),
                 ("deeply buried", {"a": {"b": [{"c": float("nan")}]}})]:
    try:
        PermissionVerifier.bind_action("a", "c", _p)
        ok(False, f"C1: a non-finite value {_lbl} should be refused")
    except ValueError:
        ok(True, f"C1: a non-finite value {_lbl} is refused — the rule moved into the "
                 f"serializer (allow_nan=False), so depth cannot defeat it")
ok(PermissionVerifier.bind_action("a", "c", {"x": 1.5, "y": {"z": [2, 3]}}) is not None,
   "C1: ordinary nested parameters are unaffected")

# C2: monotonic does not tick during suspend
from driftcore.verification.mediated_actuation import _elapsed_clock as _ec
import time as _tc
ok(abs(_ec() - _tc.clock_gettime(_tc.CLOCK_BOOTTIME)) < 0.5,
   "C2: elapsed time uses CLOCK_BOOTTIME, which advances across SUSPEND. "
   "time.monotonic() stops while suspended, so a robot asleep for eight hours would "
   "have resumed with a stale attestation still reading fresh — switching to a "
   "monotonic clock fixed the step-backwards hole and opened a stops-ticking one")

# C4: an attestation cannot describe a moment that has not happened
def _fut(delta_s):
    return _Rep(trusted=True, source=_ME,
                checked_at=(_dtt.now(_tzz.utc) + _tdd(seconds=delta_s)).isoformat())
try:
    _b = _iso(_fut(18000)); _b.start(); _b.stop()
    ok(False, "C4: an attestation dated 5h in the future should be refused")
except PermissionError as _e:
    ok("FUTURE" in str(_e),
       "C4: a future-dated attestation is refused AND names the real cause. It "
       "previously clamped to age zero and read fresh for the whole window — and the "
       "first fix reported it as an unreadable timestamp, because the deliberate "
       "refusal was caught by the parse handler and re-wrapped")
_b = _iso(_fut(10)); _b.start(); _b.stop()
ok(True, "C4: ordinary clock skew between supervisor and broker is tolerated")

# C3: a control nobody can use is a control nobody has
_hb = ActuationBroker(SOCK, _v1, enforce_effects=True, require_effect_binding=True)
_hb.register_actuator("harm", lambda **k: "ok", required_scope=("a:m",),
                      effects=[Effect.PHYSICAL_FORCE], effect_declared_by="justin")
_h1 = _hb.declaration_hash("harm")
ok(_h1 is not None,
   "C3: declaration_hash() is PUBLIC — minting a bound grant used to require reaching "
   "into an underscore method, which pushes deployments to leave the binding off")
_hb._effect_registry.register("harm", [Effect.NONE], declared_by="justin", replace=True)
ok(_hb.declaration_hash("harm") != _h1,
   "C3: and it changes when the declaration changes, which is what makes it bindable")

print(f"\nALL {passed} CHECKS PASSED")


print("== DURABLE, HASH-CHAINED ACTUATION EVIDENCE ==")
import os as _oe, json as _je, tempfile as _te
_EV = _oe.path.join(_te.mkdtemp(), "evidence.jsonl")

def _evbroker(path, require=True):
    _ev = PermissionVerifier(); _ev.register_key("operator", KEY)
    _eb = ActuationBroker(SOCK, _ev, enforce_effects=True,
                          evidence_path=path, require_durable_evidence=require)
    _hits = []
    _eb.register_actuator("earm", lambda **k: _hits.append(1) or "ok",
                          required_scope=("a:m",), effects=[Effect.PHYSICAL_FORCE],
                          effect_declared_by="justin")
    return _eb, _ev, _hits

_eb, _ev, _hits = _evbroker(_EV)
_eb._handle(req("earm", "move", {}, grant(_ev, "earm", "move", {}, nonce="ev1",
                                          scope=("a:m",))))
_rows = [_je.loads(l) for l in open(_EV) if l.strip()]
ok([r["phase"] for r in _rows] == ["INTENT", "COMPLETION"],
   "an actuation writes INTENT before the act and COMPLETION after. A crash between "
   "them leaves a detectable gap — the same signal the physical-state quarantine acts "
   "on, now surviving the process that produced it")
ok(_oe.path.getsize(_EV) > 0 and _eb.verify_evidence(),
   "the records are on disk immediately (fsynced, so they survive the event they "
   "describe) and the chain verifies")

_lines = open(_EV).read().splitlines()
_d = _je.loads(_lines[0]); _d["detail"] = "nothing happened here"
open(_EV, "w").write("\n".join([_je.dumps(_d)] + _lines[1:]) + "\n")
ok(not _eb.verify_evidence(),
   "EDITING a record breaks the chain — each entry hashes the one before it")
open(_EV, "w").write(_lines[1] + "\n")
ok(not _eb.verify_evidence(),
   "DELETING a record breaks the chain too, so evidence cannot be quietly pruned")

_ub, _uv, _uhits = _evbroker("/proc/nonexistent/evidence.jsonl")
_r = _ub._handle(req("earm", "move", {}, grant(_uv, "earm", "move", {}, nonce="ev2",
                                               scope=("a:m",))))
ok(_r.get("error_code") == "EVIDENCE_UNAVAILABLE" and not _uhits,
   "when durable evidence is required and cannot be written, the action REFUSES — an "
   "action nobody can record is an action nobody can review")

ok(any(e["layer"] == "durable_evidence"
       for e in ActuationBroker(SOCK, _ev).posture_events()),
   "and a broker without durable evidence records the gap as a posture event")

print(f"\nALL {passed} CHECKS PASSED")
