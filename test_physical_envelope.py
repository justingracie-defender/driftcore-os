"""Physical envelope: DriftCore verifies that an envelope EXISTS, is ENFORCED
BELOW THE AI, and is NOT SELF-WIDENABLE — and holds no newtons of its own.

This is the module that keeps 60N out of DriftCore. Same universal rule produces
60N for a home robot, 800N for a fenced industrial arm, and no physical envelope
at all for a software agent whose actuator is the network."""

import time
from driftcore.governance.physical_envelope import (
    Dimension, EnforcementPoint, OperatingConditions, PhysicalEnvelope,
    EnvelopeVerifier, EnvelopeController, EnvelopeRefused,
    ConditionEvidence, ConditionAuthority, DEFAULT_REVIEW_BANDS,
)

def AUTH(sources=("sensor-hub",)):
    return ConditionAuthority(trusted_sources=frozenset(sources))

def EV(cond, source="sensor-hub", seq=1, ttl=60.0, proof="sig", value=True,
       age=0.0):
    return ConditionEvidence(cond, value, source=source,
                             issued_at=time.monotonic() - age,
                             ttl_seconds=ttl, sequence=seq, proof=proof)

EXPECTED_CHECKS = 65

passed = 0
def ok(c, label):
    global passed
    assert c, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")


def env(name="home", force=60.0, point=EnforcementPoint.FIRMWARE,
        required=frozenset({"in_home"}), by="justin", note="serial-attested"):
    return PhysicalEnvelope(
        name=name, limits={Dimension.FORCE_N.value: force},
        enforced_at=point,
        conditions=OperatingConditions("declared", frozenset(required)),
        declared_by=by, attestation_note=note)


print("== DriftCore holds NO physical values of its own ==")
import driftcore.governance.physical_envelope as pe
import ast, inspect
tree = ast.parse(inspect.getsource(pe))
for n in ast.walk(tree):
    if isinstance(n, (ast.FunctionDef, ast.ClassDef, ast.Module)) and ast.get_docstring(n):
        n.body = n.body[1:]
code = "\n".join(l.split("#")[0] for l in ast.unparse(tree).splitlines())
ok("60" not in code.replace("60.0", "X"),
   "no 60N anywhere in executable code — that number lives in LifeCore")
ok("DEFAULT_REVIEW_BANDS" in code,
   "the only numbers present are REVIEW BANDS (triggers, never floors)")


print("== Q1: is an envelope declared? ==")
v = EnvelopeVerifier()
r = v.verify(None, "EMBODIED")
ok(not r.permitted, "no envelope + physical embodiment -> REFUSED to operate")
ok("Unconfigured is not permissive" in r.findings[0].detail,
   "  ...for the stated reason: unconfigured is not permissive")
r = v.verify(None, "SOFTWARE_ONLY", requires_physical=False)
ok(r.permitted, "a software-only agent needs no physical envelope")
ok("egress policy" in r.findings[0].detail,
   "  ...and is pointed at its real envelope: the egress policy")


print("== Q2: is it enforced BELOW the AI? (the load-bearing check) ==")
r = v.verify(env(point=EnforcementPoint.AGENT_SOFTWARE), "EMBODIED")
ok(not r.permitted,
   "AGENT_SOFTWARE enforcement is REFUSED, not warned")
ok(any("is not a limit" in f.detail for f in r.findings),
   "  ...because a limit the agent consults is a value it can change")
for point in (EnforcementPoint.SUPERVISOR_PROCESS, EnforcementPoint.FIRMWARE,
              EnforcementPoint.HARDWARE_MECHANICAL):
    ok(v.verify(env(point=point), "EMBODIED").permitted,
       f"{point.value} is accepted (rank {point.rank}/3)")
ok(not EnforcementPoint.AGENT_SOFTWARE.is_below_the_ai
   and EnforcementPoint.HARDWARE_MECHANICAL.is_below_the_ai,
   "the ladder knows which points are outside the agent's reach")


print("== the same rule, different bodies — DriftCore unchanged ==")
home = v.verify(env("home", 60.0), "EMBODIED")
factory = v.verify(env("cell", 800.0, required={"fence_closed", "cell_empty"}),
                   "REMOTE_PHYSICAL_CONTROL")
ok(home.permitted and factory.permitted,
   "60N home robot and 800N fenced arm BOTH pass the same verifier")
ok(any("WARN" in f.detail and "plausibility" in f.check for f in factory.findings),
   "800N raises a review trigger for its class — surfaced, not denied")
ok(factory.envelope.limits[Dimension.FORCE_N.value] == 800.0,
   "the DECLARED limit stands; the band never overrides it")


print("== the plausibility lint: where the danger actually moves ==")
kitchen = v.verify(env("kitchen", 5000.0), "EMBODIED")
ok(kitchen.permitted,
   "a 5000N kitchen envelope passes all three structural checks HONESTLY "
   "(declared, enforced, not self-widened) — the mechanism cannot catch it")
ok(any("Confirm this is intended" in f.detail for f in kitchen.findings),
   "  ...so the lint surfaces it for human review instead")
custom = EnvelopeVerifier(bands={"EMBODIED": {Dimension.FORCE_N.value: 10.0}})
ok(any("WARN" in f.detail for f in custom.verify(env(), "EMBODIED").findings),
   "bands are operator-replaceable; the shipped set is a starting point")


print("== declarations are validated, not trusted ==")
for kwargs, why in [
    (dict(by=""), "no declared_by (a physical limit must be attributable)"),
    (dict(force=float("inf")), "an infinite limit (absence of a limit in disguise)"),
    (dict(force=float("nan")), "a NaN limit"),
    (dict(force=-5.0), "a negative limit"),
]:
    try:
        env(**kwargs)
        ok(False, f"{why} should be refused")
    except EnvelopeRefused:
        ok(True, f"refused: {why}")
try:
    PhysicalEnvelope(name="x", limits={}, enforced_at=EnforcementPoint.FIRMWARE,
                     conditions=OperatingConditions("d"), declared_by="j")
    ok(False, "an empty envelope should be refused")
except EnvelopeRefused as e:
    ok("not an unbounded permission" in e.operator_detail,
       "refused: an empty envelope (misconfiguration, not permission)")
try:
    PhysicalEnvelope(name="x", limits={"vibes": 1.0},
                     enforced_at=EnforcementPoint.FIRMWARE,
                     conditions=OperatingConditions("d"), declared_by="j")
    ok(False, "an unknown dimension should be refused")
except EnvelopeRefused:
    ok(True, "refused: an unknown dimension")


print("== TRAP 1: the envelope is body PLUS ENVIRONMENT ==")
tight = env("transport", 20.0, required={"stowed"})
loose = env("working", 800.0, required={"fence_closed"})
ctl = EnvelopeController([tight, loose], "REMOTE_PHYSICAL_CONTROL",
                        fallback_envelope="transport", audit_required=False,
                        condition_authority=AUTH())
ok(ctl.select_for([EV("fence_closed", seq=1)]).name == "working",
   "ATTESTED conditions hold -> the permissive envelope applies (they EARN it)")
ok(ctl.select_for([EV("stowed", seq=2)]).name == "transport",
   "the gate opens -> switches to the envelope whose conditions now hold")
fallback = ctl.select_for([])           # nothing attested at all
ok(fallback.name == "transport",
   "ODD VIOLATION (no conditions hold) -> falls back to the TIGHTEST envelope, "
   "not the last one and not fail-open")
ok(fallback.limits[Dimension.FORCE_N.value] == 20.0,
   "  ...and the active limit really is the tight one")
ok(not OperatingConditions("d", frozenset({"fence"})).holds_under({})[0],
   "an unattested condition counts as UNMET, never as permission")


print("== TRAP 2 / Q3: asymmetry — tighten free, widen needs a human ==")
ctl2 = EnvelopeController([env("base", 60.0)], "EMBODIED", audit_required=False)
ok(ctl2.request_change(env("tighter", 30.0), authorised_by="system")[0],
   "tightening needs no human")
ok(not ctl2.request_change(env("wider", 900.0), authorised_by="system")[0],
   "widening by 'system' is DENIED")
ok(not ctl2.request_change(env("wider", 900.0), authorised_by="agent")[0],
   "widening by 'agent' is DENIED")
ok(not ctl2.request_change(env("wider", 900.0), authorised_by="justin")[0],
   "widening by a human with no reason is DENIED (audit trail)")
okw, _ = ctl2.request_change(env("wider", 900.0), authorised_by="justin",
                             reason="fenced test cell, humans excluded")
ok(okw, "widening by a human WITH a reason is permitted")


print("== a deployment cannot hold one unverifiable envelope ==")
try:
    EnvelopeController([env("good"), env("bad", point=EnforcementPoint.AGENT_SOFTWARE)],
                       "EMBODIED", audit_required=False)
    ok(False, "should refuse the whole deployment")
except EnvelopeRefused:
    ok(True, "ALL declared envelopes must verify, not just the active one")
try:
    EnvelopeController([], "EMBODIED", audit_required=False)
    ok(False, "no envelopes should be refused")
except EnvelopeRefused:
    ok(True, "an embodiment that can act physically must declare at least one")

print("== RED TEAM 2026-08 (Grok): multi-dimensional ordering ==")
def E2(name, **lim):
    return PhysicalEnvelope(
        name=name, limits={getattr(Dimension, k.upper()).value: v
                           for k, v in lim.items()},
        enforced_at=EnforcementPoint.FIRMWARE,
        conditions=OperatingConditions("d", frozenset({"c"})),
        declared_by="justin", attestation_note="n")

# A MISSING DIMENSION IS UNBOUNDED, NOT ZERO.
no_force = E2("speed_only", speed_mps=0.1)      # force unbounded
has_force = E2("bounded", force_n=60.0, speed_mps=0.1)
ok(not no_force.dominates(has_force),
   "G1: an envelope with NO force limit does not dominate one that bounds "
   "force — a missing dimension is unbounded, not zero")
ok(has_force.dominates(no_force),
   "G1: the envelope that closes the hole does dominate")

# Incomparable envelopes must be refused at CONSTRUCTION, not tie-broken
# silently during an incident.
sf = E2("safe_force", force_n=20.0, speed_mps=2.0)
ss = E2("safe_speed", force_n=500.0, speed_mps=0.1)
ok(not sf.dominates(ss) and not ss.dominates(sf),
   "G1: 20N/2.0ms and 500N/0.1ms are genuinely INCOMPARABLE (neither is "
   "safer on both axes)")
try:
    EnvelopeController([sf, ss], "EMBODIED", audit_required=False)
    ok(False, "incomparable envelopes should be refused")
except EnvelopeRefused as e:
    ok("no unique safest" in e.operator_detail,
       "G1: refused at construction — guessing a fallback during an incident "
       "is not acceptable (the lexicographic version picked by force alone)")

ctl_x = EnvelopeController([sf, ss], "EMBODIED",
                           fallback_envelope="safe_speed", audit_required=False)
ok(ctl_x.select_for([]).name == "safe_speed",
   "G1: the operator may name the fallback explicitly, and it is honoured")
try:
    EnvelopeController([sf, ss], "EMBODIED", fallback_envelope="nope",
                       audit_required=False)
    ok(False, "an unknown fallback name should be refused")
except EnvelopeRefused:
    ok(True, "G1: a fallback naming an undeclared envelope is refused")

tight2 = E2("tight", force_n=20.0, speed_mps=0.1)
loose2 = E2("loose", force_n=500.0, speed_mps=2.0)
ok(EnvelopeController([tight2, loose2], "EMBODIED",
                      audit_required=False).select_for([]).name == "tight",
   "G1: a unique safest is still inferred automatically when one exists")

print("== RED TEAM 2026-08 (Grok): audit must not fail silently ==")
class _BrokenAudit:
    def record(self, **kw): raise RuntimeError("audit sink down")
try:
    EnvelopeController([env("base", 60.0)], "EMBODIED", audit=_BrokenAudit())
    ok(False, "a failing audit should refuse the change")
except EnvelopeRefused as e:
    ok("unrecorded" in e.operator_detail,
       "G4: a failed audit write REFUSES rather than changing a physical limit "
       "unrecorded")
try:
    EnvelopeController([env("base", 60.0)], "EMBODIED")
    ok(False, "no audit sink with audit_required should refuse")
except EnvelopeRefused as e:
    ok("audit_required=False" in e.operator_detail,
       "G4: no audit sink at all is refused unless waived deliberately")

print("== RED TEAM 2026-08 (ChatGPT): the ALTERNATE DECISION SURFACE ==")
# The deepest finding of the session: request_change() was carefully gated and
# select_for() was not, so capability could be widened by SELECTING a permissive
# envelope instead of formally changing one. Reproduced at 20N -> 800N.
tr = env("transport", 20.0, required={"stowed"})
wk = env("working", 800.0, required={"fence_closed"})
ctlA = EnvelopeController([tr, wk], "EMBODIED", fallback_envelope="transport",
                          audit_required=False, condition_authority=AUTH())
ok(ctlA.select_for([]).name == "transport", "starts on the tight envelope")
ok(ctlA.select_for([EV("fence_closed", source="agent", seq=1)]).name == "transport",
   "P0-1: evidence from an UNTRUSTED source does not widen (was: 20N->800N on a "
   "bare boolean)")
ok(ctlA.select_for([EV("fence_closed", proof="", seq=2)]).name == "transport",
   "P0-1: trusted source with NO proof does not widen")
ok(ctlA.select_for([EV("fence_closed", seq=3)]).name == "working",
   "P0-1: properly attested evidence DOES earn the permissive envelope")
ok(ctlA.select_for([EV("fence_closed", seq=4, age=300.0, ttl=60.0)]).name == "transport",
   "P0-1: STALE evidence is unknown, and unknown is unmet (replay of 'fence "
   "closed' from before the fence opened)")
ok(ctlA.select_for([EV("fence_closed", seq=1)]).name == "transport",
   "P0-1: a replayed sequence number is refused (anti-replay high-water mark)")

print("== P0-2: journal before commit ==")
class _BrokenSink:
    def record(self, **kw): raise RuntimeError("audit sink down")
ctlB = EnvelopeController([env("base", 60.0)], "EMBODIED", audit_required=False)
ctlB._audit = _BrokenSink(); ctlB._audit_required = True
try:
    ctlB.request_change(env("wider", 900.0), authorised_by="justin", reason="r")
    ok(False, "a failing audit should refuse")
except EnvelopeRefused:
    ok(ctlB.active.name == "base" and ctlB.active.limits["force_n"] == 60.0,
       "P0-2: audit failure leaves the ORIGINAL envelope active (was: caller saw "
       "'refused' while the machine sat at 900N)")

print("== P0-3: a named fallback must still be safe ==")
try:
    EnvelopeController([env("tight", 20.0), env("loose", 500.0)], "EMBODIED",
                       fallback_envelope="loose", audit_required=False)
    ok(False, "a dominated fallback should be refused")
except EnvelopeRefused as e:
    ok("strictly less safe" in e.operator_detail,
       "P0-3: naming a fallback resolves incomparability; it does not authorise "
       "a dangerous one")

print("== P1-4: no lexicographic ordering left in selection ==")
import inspect as _i, ast as _a
_t = _a.parse(_i.getsource(__import__("driftcore.governance.physical_envelope",
                                      fromlist=["x"])))
_code = _a.unparse(_t)
ok("max(eligible" not in _code and "min(self._envelopes" not in _code,
   "P1-4: neither selection path ranks envelopes by sorted-tuple order")

print("== P2: duplicate names and concurrency ==")
try:
    EnvelopeController([env("same", 20.0), env("same", 500.0)], "EMBODIED",
                       audit_required=False)
    ok(False, "duplicate names should be refused")
except EnvelopeRefused as e:
    ok("duplicate envelope name" in e.operator_detail,
       "P2: duplicate names refused (audit records refer to envelopes by name)")
import threading as _th
ctlC = EnvelopeController([env("base", 60.0)], "EMBODIED", audit_required=False,
                          condition_authority=AUTH())
ok(isinstance(getattr(ctlC, "_lock", None), type(_th.RLock())),
   "P2: transitions are serialised by a lock")

print("== SELF RED TEAM 2026-08 (cold pass on the fixes themselves) ==")

# S-A: `<=` on the high-water mark burned the sequence on first read, so a
# control loop re-presenting the SAME still-fresh evidence fell back to the
# tight envelope and flapped 800N/20N.
_a = AUTH()
_ev = EV("fence_closed", seq=5)
ok(bool(_a.accept([_ev])) and bool(_a.accept([_ev])),
   "S-A: the same still-fresh evidence may be re-presented (a control loop is "
   "not a replay attack)")
ok(not _a.accept([EV("fence_closed", seq=3)]),
   "S-A: evidence SUPERSEDED by a newer reading is still refused")
ok(not _a.accept([EV("fence_closed", seq=9, ttl=0.01, age=5.0)]),
   "S-A: stale evidence is still refused — TTL is the time control")

# S-B: the worst finding. Audit failure during an ODD fallback raised BEFORE
# demoting, so the caller got an exception AND the machine stayed at 800N.
# Fail-closed for a safety layer means "end up safe", not "refuse to act".
class _Flaky:
    def __init__(self): self.fail = False
    def record(self, **kw):
        if self.fail: raise RuntimeError("audit sink down")
_sink = _Flaky()
_t = env("transport", 20.0, required={"stowed"})
_w = env("working", 800.0, required={"fence_closed"})
_c = EnvelopeController([_t, _w], "EMBODIED", fallback_envelope="transport",
                        audit=_sink, condition_authority=AUTH())
_c.select_for([EV("fence_closed", seq=1)])
ok(_c._active.name == "working", "S-B: starts on the permissive envelope")
_sink.fail = True
_raised = False
try:
    _c.select_for([])
except EnvelopeRefused:
    _raised = True
ok(_c._active.name == "transport",
   "S-B: an ODD fallback DEMOTES even when the audit sink is down (was: caller "
   "got an exception and the machine sat at 800N)")
ok(_raised, "S-B: and the audit failure still surfaces — both, in the right order")

# S-C: freshness was checked only when someone called select_for, so a
# permissive envelope outlived its own evidence if nobody asked.
_c2 = EnvelopeController([_t, _w], "EMBODIED", fallback_envelope="transport",
                         audit_required=False, condition_authority=AUTH())
_c2.select_for([EV("fence_closed", seq=1, ttl=0.25)])
ok(_c2.active.name == "working", "S-C: authorised while the evidence is fresh")
time.sleep(0.35)
ok(_c2.active.name == "transport",
   "S-C: reading `active` after expiry SELF-DEMOTES — no caller can observe an "
   "authorisation the system is no longer entitled to")

# S-D: _high_water is mutated on the read path and shared.
import threading as _t2
_a2 = AUTH()
_errs = []
def _hammer(n):
    try:
        for i in range(200):
            _a2.accept([EV("fence_closed", seq=n * 1000 + i)])
    except Exception as e:
        _errs.append(e)
_th = [_t2.Thread(target=_hammer, args=(k,)) for k in range(6)]
for x in _th: x.start()
for x in _th: x.join()
ok(not _errs, "S-D: ConditionAuthority survives 1200 concurrent accepts (lock)")

print(f"\n{passed}/{EXPECTED_CHECKS} checks passed")
