# SPDX-License-Identifier: Apache-2.0
"""Physical envelope: DriftCore verifies that an envelope EXISTS, is ENFORCED
BELOW THE AI, and is NOT SELF-WIDENABLE — and holds no newtons of its own.

This is the module that keeps 60N out of DriftCore. Same universal rule produces
60N for a home robot, 800N for a fenced industrial arm, and no physical envelope
at all for a software agent whose actuator is the network."""

# (2026-09-06) An unconfigured process now REFUSES identity rather than accepting
# any name not on a six-word denylist — that default was the floor five separate
# findings stood on. A test suite does not verify identity, so it declares that
# rather than inheriting a permissive default.
import driftcore.authority.human_identity as _identity_boot
_identity_boot.declare_label_only(
    "test suite: single process, no verifier installed, nothing actuates")


import hashlib
import hmac
import time
from dataclasses import replace as _replace
from driftcore.governance.physical_envelope import (
    Dimension, EnforcementPoint, OperatingConditions, PhysicalEnvelope,
    EnvelopeVerifier, EnvelopeController, EnvelopeRefused,
    ConditionEvidence, ConditionAuthority, ConditionSnapshot,
    DEFAULT_REVIEW_BANDS, ReplayStore, MAX_SEQUENCE, CONFLICTED,
)

# THE FIXTURE IS PART OF THE FINDING. The previous version supplied
# proof="sig" and its only negative case was the empty string, so all 65
# checks passed in the one configuration that could not fail — and one of them
# was labelled "properly attested evidence" about a three-character string.
# External review (SINT Labs / Illia Pashkov, 2026-09) found the default
# `verify_proof=None`; what the fixture could not see is the more useful half.
# A real keyed MAC now binds source, condition, value, issued_at, ttl,
# sequence and epoch, so a signature cannot be moved to another reading,
# another source, another freshness window or another boot.
_KEY = b"sensor-supervisor-signing-key-for-tests-only"
_WRONG_KEY = b"an-attacker-key-of-the-same-shape-------------"
EPOCH = "boot-epoch-A"
MAX_TTL = 120.0

def sign(payload, key=_KEY):
    return hmac.new(key, repr(payload).encode(), hashlib.sha256).hexdigest()

def verifier(key=_KEY):
    def _verify(ev):
        return hmac.compare_digest(ev.proof, sign(ev.payload, key))
    return _verify

def AUTH(sources=("sensor-hub",), key=_KEY, epoch=EPOCH, max_ttl=MAX_TTL, **kw):
    kw.setdefault("verify_proof", verifier(key))
    return ConditionAuthority(trusted_sources=frozenset(sources), epoch=epoch,
                              max_ttl_seconds=max_ttl, **kw)

def EV(cond, source="sensor-hub", seq=1, ttl=60.0, proof=None, value=True,
       age=0.0, key=_KEY, epoch=EPOCH):
    """Signed by default. `proof=` overrides with a literal, unsigned string."""
    ev = ConditionEvidence(cond, value, source=source,
                           issued_at=time.monotonic() - age,
                           ttl_seconds=ttl, sequence=seq, proof="", epoch=epoch)
    return _replace(ev, proof=sign(ev.payload, key) if proof is None else proof)

EXPECTED_CHECKS = 249

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


print("== FIXTURE 0: authenticated condition evidence, END TO END ==")
# Every check in this section asserts THE ACTIVE ENVELOPE, not a return value
# from accept(). The first version of this fixture asserted
# `accept(...) == {'fence_closed': True}` and called it a positive control —
# a Disconnected Check inside the fixture written to prove a check is
# connected. A verifier can be perfect while the consequence never moves.

def E2E(sources=("sensor-hub",), wide_required=frozenset({"fence_closed"}), **kw):
    """20N transport / 800N working, 40x apart, selected only by evidence."""
    t = env("transport", 20.0, required={"stowed"})
    w = env("working", 800.0, required=wide_required)
    return EnvelopeController([t, w], "REMOTE_PHYSICAL_CONTROL",
                              fallback_envelope="transport",
                              audit_required=False,
                              condition_authority=AUTH(sources, **kw))

def is_tight(ctl):
    return ctl.active.name == "transport" and ctl.active.limits["force_n"] == 20.0

def is_wide(ctl):
    return ctl.active.name == "working" and ctl.active.limits["force_n"] == 800.0

def wide_then(ctl, attack, label, primer=None):
    """THE HARNESS MUST PERMIT THE VIOLATING ACTION TO BE ATTEMPTED.

    Drive to the 800N envelope first, then present the attack and require
    20N. Starting from the tight envelope would pass for every negative
    including the ones where the mechanism was deleted — the machine was
    already safe and nothing was tested. Standing checklist item contributed
    by Meta, 2026-09-22.
    """
    ctl.select_for(primer if primer is not None else [EV("fence_closed", seq=1)])
    assert is_wide(ctl), f"PRIMER FAILED (nothing was tested): {label}"
    try:
        ctl.select_for(attack)
    except EnvelopeRefused:
        pass
    ok(is_tight(ctl), label)


# CLAIMS: driftcore/governance/physical_envelope.py:proof-presence-is-not-attestation
print("-- A: the insecure configuration is unconstructable --")
for kwargs, why in [
    (dict(verify_proof=None),
     "F0-A1: require_proof with NO verifier REFUSES TO CONSTRUCT (the reported "
     "defect: verify_proof=None accepted any non-empty string)"),
    (dict(verify_proof=None, require_proof=False),
     "F0-A2: require_proof=False with no stated reason is REFUSED — an escape "
     "hatch nobody signed is an escape hatch nobody reviews"),
    (dict(epoch=""),
     "F0-A3: no epoch is REFUSED — replay high-water marks are per-instance"),
    (dict(max_ttl=float("inf")),
     "F0-A4: an infinite freshness ceiling is REFUSED"),
    (dict(max_ttl=0.0),
     "F0-A5: a zero freshness ceiling is REFUSED"),
    (dict(sources=()),
     "F0-A6: no trusted sources is REFUSED"),
]:
    try:
        AUTH(**kwargs)
        ok(False, f"should be refused: {why}")
    except EnvelopeRefused:
        ok(True, why)
_a_ok = AUTH(verify_proof=None, require_proof=False,
             unverified_reason="bench rig, no sensor supervisor, JG 2026-09-22")
ok(_a_ok is not None,
   "F0-A7: require_proof=False WITH a stated reason is allowed — turning "
   "authenticity off is a decision with a name on it, not a default")
ok(ConditionAuthority(trusted_sources=frozenset({"s"}), epoch="e",
                      max_ttl_seconds=1.0,
                      verify_proof=verifier()).epoch == "e",
   "F0-A8: a fully declared authority constructs (the refusals above are not "
   "just 'refuse everything')")


# CLAIMS: driftcore/governance/physical_envelope.py:evidence-validates-its-own-structure
print("-- B: evidence validates its own structure --")
def _bad(why, **over):
    base = dict(condition="fence_closed", value=True, source="sensor-hub",
                issued_at=time.monotonic(), ttl_seconds=60.0, sequence=1,
                proof="p", epoch=EPOCH)
    base.update(over)
    try:
        ConditionEvidence(**base)
        ok(False, f"should be refused: {why}")
    except EnvelopeRefused:
        ok(True, why)

_bad("F0-B1: ttl_seconds=inf is REFUSED — an infinite freshness window is one "
     "signed reading authorising a permissive envelope forever "
     "(was: accepted under a genuine signature)", ttl_seconds=float("inf"))
_bad("F0-B2: ttl_seconds=nan is REFUSED", ttl_seconds=float("nan"))
_bad("F0-B3: ttl_seconds=0 is REFUSED (stale on arrival)", ttl_seconds=0.0)
_bad("F0-B4: a negative ttl_seconds is REFUSED", ttl_seconds=-1.0)
_bad("F0-B5: issued_at=inf is REFUSED", issued_at=float("inf"))
_bad("F0-B6: issued_at=nan is REFUSED", issued_at=float("nan"))
_bad("F0-B7: value=1 is REFUSED — truthiness is not attestation, and `if "
     "ev.value:` cannot tell them apart", value=1)
_bad("F0-B8: value='yes' is REFUSED", value="yes")
_bad("F0-B9: a negative sequence is REFUSED", sequence=-1)
_bad("F0-B10: a non-integer sequence is REFUSED", sequence=1.5)
_bad("F0-B11: an unnamed condition is REFUSED", condition="  ")
_bad("F0-B12: an anonymous source is REFUSED — evidence whose attester cannot "
     "be revoked is not evidence", source="")


# CLAIMS: driftcore/governance/physical_envelope.py:unverifiable-evidence-is-absent-not-permissive
# CLAIMS: driftcore/governance/physical_envelope.py:proof-binds-the-whole-reading
print("-- C: authenticity, end to end (the reported defect) --")
_attacks = [
    (lambda: [EV("fence_closed", seq=2, proof="x")],
     "F0-C1: proof='x' does not earn 800N  <-- THE REPORTED DEFECT"),
    (lambda: [EV("fence_closed", seq=2, proof="\x00")],
     "F0-C2: a single null byte does not earn 800N"),
    (lambda: [EV("fence_closed", seq=2, proof="not-a-signature")],
     "F0-C3: a plausible-looking string does not earn 800N"),
    (lambda: [EV("fence_closed", seq=2, proof="")],
     "F0-C4: an empty proof does not earn 800N"),
    (lambda: [EV("fence_closed", seq=2, key=_WRONG_KEY)],
     "F0-C5: a well-formed signature under the WRONG KEY does not earn 800N"),
    (lambda: [_replace(EV("stowed", seq=2), condition="fence_closed")],
     "F0-C6: a genuine proof does not TRANSFER to another condition"),
    (lambda: [_replace(EV("fence_closed", seq=2, value=False), value=True)],
     "F0-C7: a genuine proof does not survive FLIPPING THE READING"),
]
for build, label in _attacks:
    wide_then(E2E(), build(), label)
wide_then(E2E(("sensor-hub", "sensor-b")),
          [_replace(EV("fence_closed", seq=2, source="sensor-b"),
                    source="sensor-hub")],
          "F0-C8: a genuine proof does not TRANSFER between trusted sources")

# THE MUTATION CONTROL. Every negative above must be capable of failing. With
# a verifier hardcoded to True, each attack shape must actually reach 800N —
# otherwise it was passing for some unrelated reason and proves nothing.
# This is the check that would have caught the first version of F0-C7, which
# flipped True->False under a genuine signature and passed even against a
# maximally broken verifier because a false reading is discarded before the
# proof is ever consulted. Found by Grok, 2026-09-22.
_reached = 0
for build, label in _attacks:
    _m = E2E(verify_proof=lambda ev: True)
    _m.select_for([EV("fence_closed", seq=1)])
    try:
        _m.select_for(build())
    except EnvelopeRefused:
        pass
    if is_wide(_m):
        _reached += 1
ok(_reached == len(_attacks) - 1,
   f"F0-C9 MUTATION: {_reached}/{len(_attacks)} authenticity negatives reach "
   f"800N against a broken verifier — every one whose only gate is the proof "
   f"can fail. The exception is the empty-proof case, which a broken verifier "
   f"never sees: `if not ev.proof` rejects it first")
_m = E2E(verify_proof=lambda ev: True)
_m.select_for([EV("fence_closed", seq=1)])
_m.select_for([EV("fence_closed", seq=2, proof="")])
ok(is_tight(_m),
   "F0-C10: ...and that one is gated by proof PRESENCE, which is a different "
   "mechanism and is stated as such rather than counted as authenticity")


# CLAIMS: driftcore/governance/physical_envelope.py:condition-state-is-order-independent
print("-- D: the state machine (order, retraction, conflict, disagreement) --")
wide_then(E2E(), [EV("fence_closed", seq=1), EV("fence_closed", seq=2, value=False)],
          "F0-D1: a signed FALSE at a newer sequence RETRACTS an earlier TRUE "
          "-- list order first  <-- THE FENCE OPENING NOW CLOSES THE ENVELOPE")
wide_then(E2E(), [EV("fence_closed", seq=2, value=False), EV("fence_closed", seq=1)],
          "F0-D2: ...and the REVERSED list gives the same answer. The winner is "
          "chosen by sequence number, not by position (was: order decided it, "
          "and the attack needed no forged proof at all)")
wide_then(E2E(), [EV("fence_closed", seq=2, value=False)],
          "F0-D3: a signed FALSE alone retracts — there is now a branch that "
          "REMOVES a condition")
wide_then(E2E(), [EV("fence_closed", seq=5, value=False),
                  EV("fence_closed", seq=5, value=True)],
          "F0-D4: signed FALSE and signed TRUE at the SAME sequence fail closed "
          "(was: last-writer-wins resolved it to TRUE)")
wide_then(E2E(), [EV("fence_closed", seq=5, value=True),
                  EV("fence_closed", seq=5, value=False)],
          "F0-D5: ...in either order")
_cf = E2E()
_cf.select_for([EV("fence_closed", seq=1)])
assert is_wide(_cf), "PRIMER FAILED"
_cf.select_for([EV("fence_closed", seq=5, value=True),
                EV("fence_closed", seq=5, value=False)])
_cf.select_for([EV("fence_closed", seq=4)])
ok(is_tight(_cf),
   "F0-D11: a same-sequence CONFLICT still advances the replay mark, so an "
   "older still-fresh TRUE cannot be replayed afterwards. Not advancing would "
   "let an attacker force a conflict at N and then reopen the envelope with "
   "N-1. Policy chosen deliberately after Grok's review, 2026-09-22")
# CLAIMS: driftcore/governance/physical_envelope.py:a-conflicted-sequence-is-never-accepted
_hr = E2E()
_hr.select_for([EV("fence_closed", seq=1)])
assert is_wide(_hr), "PRIMER FAILED (nothing was tested)"
_t5 = EV("fence_closed", seq=5, value=True)
_f5 = EV("fence_closed", seq=5, value=False)
_hr.select_for([_t5, _f5])
_hr.select_for([_t5])
ok(is_tight(_hr),
   "F0-D12: replaying ONLY the captured TRUE half of a conflict does not "
   "reopen 800N (was: a lone reading at the conflicted sequence was admitted "
   "and earned 800N — and this very check pinned that as correct, answering "
   "a worry about stranding the sensor. SINT's shared fixture expects the "
   "opposite, and is right. 2026-09-22)")
_snap12 = _hr._authority.evaluate([_f5])
ok(not _snap12.holds and _hr._authority._high_water.get(
       (EPOCH, "sensor-hub", "fence_closed")) == (5, CONFLICTED),
   "F0-D12b: ...nor does the FALSE half earn anything: the condition is not "
   "held and the store still marks sequence 5 conflicted. (Since v6 a signed "
   "FALSE there still counts as a dissent: replaying a FALSE can only tighten)")
_hr.select_for([EV("fence_closed", seq=6)])
ok(is_wide(_hr),
   "F0-D12c: a strictly NEWER reading is accepted and earns 800N, so the "
   "sensor is not stranded; it only has to move forward, which an honest "
   "sensor does anyway")
_xt5 = EV("fence_closed", seq=5)
_xb = E2E()
_xb.select_for([_xt5])
assert is_wide(_xb), "PRIMER FAILED (nothing was tested)"
_xb.select_for([EV("fence_closed", seq=5, value=False)])
ok(is_tight(_xb),
   "F0-D13a: a signed FALSE at the SAME sequence, arriving in a LATER batch, "
   "still takes the machine down")
_xb.select_for([_xt5])
ok(is_tight(_xb),
   "F0-D13b: ...and the captured TRUE@5 cannot then be replayed to reopen "
   "800N. The store remembers WHICH reading it accepted at each sequence, so "
   "a conflict is caught even when its halves arrive in different batches")
_dup = E2E()
_ev_once = EV("fence_closed", seq=7)
_dup.select_for([_ev_once, _ev_once])
ok(is_wide(_dup),
   "F0-D6: an IDENTICAL reading presented twice is not a conflict — the "
   "conflict rule must not be satisfiable by refusing every repeat")
wide_then(E2E(("sensor-hub", "sensor-b")),
          [EV("fence_closed", seq=3), EV("fence_closed", seq=3, source="sensor-b",
                                         value=False)],
          "F0-D7: two trusted sources DISAGREEING fails closed — no quorum "
          "policy exists, so disagreement is not resolved by whoever is first")
wide_then(E2E(("sensor-hub", "sensor-b")),
          [EV("fence_closed", seq=3, source="sensor-b", value=False),
           EV("fence_closed", seq=3)],
          "F0-D8: ...in either order")
_agree = E2E(("sensor-hub", "sensor-b"))
_agree.select_for([EV("fence_closed", seq=3),
                   EV("fence_closed", seq=3, source="sensor-b")])
ok(is_wide(_agree),
   "F0-D9: two trusted sources AGREEING still earns the envelope — 'fail "
   "closed on disagreement' must not become 'fail closed on two sensors'")
_quiet = E2E(("sensor-hub", "sensor-b"))
_quiet.select_for([EV("fence_closed", seq=3)])
ok(is_wide(_quiet),
   "F0-D10: a source that says NOTHING is not a dissent. One trusted source "
   "suffices to assert; this pins the no-quorum semantics so that adding "
   "N-of-M later breaks this check loudly instead of silently")


print("-- E: replay across restart, and the epoch that closes it --")
_r1 = E2E()
_r1.select_for([EV("fence_closed", seq=5)])
ok(is_wide(_r1), "F0-E1: primer — authorised at sequence 5")
_superseded = EV("fence_closed", seq=3)
_r1.select_for([_superseded])
ok(is_tight(_r1), "F0-E2: a superseded sequence is refused WITHIN the instance")
_shared_state = ReplayStore()
_p1 = AUTH(replay_state=_shared_state)
_p1.accept([EV("fence_closed", seq=5)])
_p2 = AUTH(replay_state=_shared_state)          # "restart", durable state
ok(not _p2.accept([_superseded]),
   "F0-E3: a DURABLE replay_state carries the high-water mark across a "
   "restart — the superseded reading is still refused by a fresh authority")
_p3 = AUTH()                                     # "restart", state lost
ok(_p3.accept([_superseded]),
   "F0-E4: with in-memory state and a REUSED epoch, that same reading is "
   "accepted again. Stated, not hidden: this is the exposure the epoch exists "
   "to close, and it is why the epoch is a required argument")
_p4 = AUTH(epoch="boot-epoch-B")
ok(not _p4.accept([_superseded]),
   "F0-E5: ...and a fresh authority with a NEW epoch refuses it, because the "
   "proof binds the epoch and cannot be moved to another boot")
_r2 = E2E()
ok(not _r2.select_for([EV("fence_closed", seq=9, epoch="boot-epoch-B")]).name
   == "working" and is_tight(_r2),
   "F0-E6: evidence for another epoch does not earn 800N end to end")
_default_epoch = ConditionEvidence("fence_closed", True, source="sensor-hub",
                                   issued_at=time.monotonic(), ttl_seconds=1.0,
                                   sequence=1, proof="p")
ok(_default_epoch.epoch == "" and not AUTH().accept([_default_epoch]),
   "F0-E7: the DEFAULT epoch is empty and matches no authority — unconfigured "
   "is not permissive, here too")


# CLAIMS: driftcore/governance/physical_envelope.py:screening-never-moves-replay-state
_burn = E2E()
_burn.select_for([EV("fence_closed", seq=1000000, proof="x")])
ok(is_tight(_burn),
   "F0-E8: primer — a junk-proof record claiming sequence 1000000 is rejected")
_burn.select_for([EV("fence_closed", seq=2)])
ok(is_wide(_burn),
   "F0-E9: ...and it did NOT burn the counter. A rejected record that advanced "
   "the high-water mark would let anyone deny every genuine reading from that "
   "sensor forever — a denial of service that fails closed and alarms nobody")


print("-- F: the freshness ceiling is the deployment's number, not DriftCore's --")
wide_then(E2E(), [EV("fence_closed", seq=2, ttl=MAX_TTL + 1.0)],
          "F0-F1: a correctly signed reading whose TTL exceeds the deployment "
          "maximum does not earn 800N — only the policy bound rejects it")
_at_bound = E2E()
_at_bound.select_for([EV("fence_closed", seq=2, ttl=MAX_TTL)])
ok(is_wide(_at_bound),
   "F0-F2: ...and a TTL exactly AT the ceiling is accepted (the bound rejects "
   "what is over it, not everything near it)")


# CLAIMS: driftcore/governance/physical_envelope.py:outage-demotes-before-it-reports
print("-- G: a verifier that RAISES is UNKNOWN, not FALSE --")
class _Outage:
    def __init__(self): self.broken = False
    def __call__(self, ev):
        if self.broken:
            raise RuntimeError("HSM unreachable")
        return verifier()(ev)
_o = _Outage()
_g = E2E(verify_proof=_o)
_g.select_for([EV("fence_closed", seq=1)])
ok(is_wide(_g), "F0-G1: primer — 800N is active and the verifier works")
_o.broken = True
_raised = False
try:
    _g.select_for([EV("fence_closed", seq=2)])
except EnvelopeRefused:
    _raised = True
ok(is_tight(_g),
   "F0-G2: a verifier OUTAGE DEMOTES to 20N (was: the exception propagated out "
   "of accept() before _active was touched, so the machine kept the wide limit "
   "precisely because the check for it had broken)")
ok(_raised,
   "F0-G3: ...and the outage still surfaces — demote first, report second, in "
   "that order")
_o2 = _Outage()
_g2 = EnvelopeController(
    [env("transport", 20.0, required={"stowed"}),
     env("always", 800.0, required=frozenset())],
    "REMOTE_PHYSICAL_CONTROL", audit_required=False,
    condition_authority=AUTH(verify_proof=_o2),
    # Deliberately unconditional and wide: the point of F0-G4 is that an outage
    # still demotes it. Since v6.3 that configuration must be opted into.
    allow_unconditional_wide=True)
_g2.select_for([])
ok(_g2.active.name == "always",
   "F0-G4: primer — an envelope declaring NO conditions is active without any "
   "evidence")
_o2.broken = True
try:
    _g2.select_for([EV("fence_closed", seq=1)])
except EnvelopeRefused:
    pass
ok(_g2.active.name == "transport",
   "F0-G5: an outage demotes even an UNCONDITIONAL envelope. This is why the "
   "outage branch runs before eligibility: 'it never needed evidence' must not "
   "mean 'it survives the loss of evidence'")


# CLAIMS: driftcore/governance/physical_envelope.py:snapshot-cannot-be-torn
print("-- H: holds and expiry come back in ONE object --")
_h = AUTH()
_snap = _h.evaluate([EV("fence_closed", seq=1, ttl=30.0)])
ok(isinstance(_snap, ConditionSnapshot) and _snap.holds == {"fence_closed": True},
   "F0-H1: evaluate() returns the conditions that hold")
ok(_snap.expires_at < float("inf") and _snap.expires_at > time.monotonic(),
   "F0-H2: ...and the expiry, in the same object, for the same batch")
_h.accept([])
ok(_snap.expires_at < float("inf"),
   "F0-H3: an interleaved accept([]) cannot retroactively set that expiry to "
   "infinity — a snapshot cannot be torn (was: accept() and "
   "deadline_of_last_accept() were two reads of mutable instance state, and "
   "an empty batch between them produced a permissive envelope with no expiry)")
try:
    _h.deadline_of_last_accept()
    ok(False, "the racy API should refuse")
except EnvelopeRefused as e:
    ok("torn read" in e.operator_detail,
       "F0-H4: the racy API is a refusal with an explanation, not a silent "
       "deletion that would surface as AttributeError")
_ext = E2E()
_ext.select_for([EV("fence_closed", seq=1, ttl=0.30)])
time.sleep(0.20)
_ext.select_for([EV("fence_closed", seq=2, ttl=0.30)])
time.sleep(0.20)
ok(is_wide(_ext),
   "F0-H5: fresh evidence for the SAME envelope EXTENDS its authorisation "
   "(was: the deadline was only written when the envelope changed, so a "
   "control loop flapped 800N/20N once per TTL while good evidence arrived)")
time.sleep(0.35)
ok(is_tight(_ext),
   "F0-H6: ...and when the evidence really does stop arriving, it still expires")


print("-- I: the load-bearing positive --")
_pos = E2E()
_got = _pos.select_for([EV("fence_closed", seq=1)])
ok(_got.name == "working" and is_wide(_pos),
   "F0-I1: correctly signed, fresh, correctly scoped evidence ACTIVATES the "
   "pre-declared 800N envelope. Without this row, 'fixed' can mean 'refuses "
   "everything', which passes every negative above")
ok(_pos.active.limits["force_n"] == 800.0,
   "F0-I2: ...and the CONSEQUENCE moved, not just the return value — the "
   "active envelope really is the wide one")
_pos.select_for([EV("stowed", seq=1)])
ok(is_tight(_pos),
   "F0-I3: ...and it still gives the envelope back when the conditions change")


print("== FIXTURE 1: the declared-set -> active transition ==")
# Fixture 0 secured evidence -> state -> expiry. Sol's next pass found the
# weakness had moved one layer over: into how the declared set and the active
# envelope change. Every check here asserts the ACTIVE envelope, and every
# refusal is paired with the control that proves the same action succeeds
# when it is legitimate — a gate that refuses everything passes every
# negative below.

def E1(name, force=None, speed=None, required=()):
    lim = {}
    if force is not None:
        lim[Dimension.FORCE_N.value] = force
    if speed is not None:
        lim[Dimension.SPEED_MPS.value] = speed
    return PhysicalEnvelope(
        name=name, limits=lim, enforced_at=EnforcementPoint.FIRMWARE,
        conditions=OperatingConditions("d", frozenset(required)),
        declared_by="justin", attestation_note="n")

class _Sink:
    def __init__(self): self.fail = False
    def record(self, **kw):
        if self.fail:
            raise RuntimeError("audit sink down")

def CELL(sink=None, authority=None):
    return EnvelopeController(
        [E1("transport", 20, required={"stowed"}),
         E1("working", 800, required={"fence_closed"})],
        "REMOTE_PHYSICAL_CONTROL", fallback_envelope="transport",
        audit=sink, audit_required=sink is not None,
        condition_authority=authority or AUTH())


# CLAIMS: driftcore/governance/physical_envelope.py:permissive-transitions-are-journaled-first
print("-- A: a widening is recorded before it is taken --")
_up = CELL(sink=_Sink())
_up.select_for([EV("fence_closed", seq=1)])
ok(is_wide(_up),
   "F1-A1: primer — with the audit sink UP, this genuine evidence earns 800N "
   "(so the refusal below is a refusal of something that would otherwise "
   "happen)")
_sd = _Sink(); _down = CELL(sink=_sd); _sd.fail = True
_r = False
try:
    _down.select_for([EV("fence_closed", seq=1)])
except EnvelopeRefused:
    _r = True
ok(_r, "F1-A2: with the audit sink DOWN, the same widening raises")
ok(is_tight(_down),
   "F1-A3: ...and the machine is at 20N afterwards (was: the caller saw "
   "'refused' while 800N was active — commit-before-journal on the selection "
   "path, under a comment stating the opposite rule. Sol, 2026-09-22)")
_sd.fail = False
_down.select_for([EV("fence_closed", seq=2)])
ok(is_wide(_down),
   "F1-A4: when the sink recovers, fresh evidence earns 800N again — the "
   "refusal is not a latch")
_si = _Sink()
_ic = EnvelopeController(
    [E1("tight", 10, speed=0.05, required={"stowed"}),
     E1("slow_strong", 500, speed=0.1, required={"lift"}),
     E1("fast_gentle", 20, speed=2.0, required={"clear_path"})],
    "REMOTE_PHYSICAL_CONTROL", audit=_si, condition_authority=AUTH())
_ic.select_for([EV("lift", seq=1)])
assert _ic.active.name == "slow_strong", "PRIMER FAILED (nothing was tested)"
_si.fail = True
try:
    _ic.select_for([EV("clear_path", seq=1)])
except EnvelopeRefused:
    pass
ok(_ic.active.name == "tight",
   "F1-A5: an INCOMPARABLE move (500N/0.1 -> 20N/2.0: gentler, but twenty "
   "times faster) is not 'toward safety' — unrecordable, it is refused and "
   "the controller drops to the fallback rather than guessing")


# CLAIMS: driftcore/governance/physical_envelope.py:only-a-new-safest-envelope-skips-the-human
print("-- B: who may add an envelope --")
_b = EnvelopeController([E1("base", 60, speed=0.1, required={"in_home"})],
                        "EMBODIED", audit_required=False)
_okb, _ = _b.request_change(E1("no_speed", 30, required={"in_home"}),
                            authorised_by="system")
ok(not _okb,
   "F1-B1: 'system' cannot add 30N-with-NO-speed-limit over 60N/0.1: dropping "
   "a dimension makes it unbounded, not zero (was: accepted and activated — "
   "`limits.get(d, 0)` read the missing speed limit as zero. Sol, 2026-09-22)")
ok(_b.active.limits.get(Dimension.SPEED_MPS.value) == 0.1,
   "F1-B2: ...and the active envelope still bounds speed")
_c5 = CELL()
_c5.select_for([EV("fence_closed", seq=1)])
assert is_wide(_c5), "PRIMER FAILED"
_okc, _ = _c5.request_change(E1("sneaky", 700), authorised_by="agent")
ok(not _okc,
   "F1-B3: while legitimately at 800N, an agent cannot add an UNCONDITIONAL "
   "700N envelope on the grounds that it is 'tighter than now'")
_c5.select_for([])
ok(is_tight(_c5),
   "F1-B4: ...so when the fence evidence disappears the ODD fallback still "
   "fires (was: the 700N envelope was eligible in every state, the fallback "
   "never fired, and the machine stayed at 700N with no conditions — found "
   "while fixing Sol's findings, 2026-09-22)")
_ns = CELL()
_okn, _ = _ns.request_change(E1("gentlest", 10, required={"stowed"}),
                             authorised_by="system")
ok(_okn and _ns.active.name == "gentlest",
   "F1-B5: adding a new SAFEST envelope needs no human and takes effect at "
   "once — tightening is still free when it is genuinely the tightest")


# CLAIMS: driftcore/governance/physical_envelope.py:fallback-tracks-the-declared-set
print("-- C: the fallback follows the declared set --")
_f = EnvelopeController([E1("base", 60, required={"in_home"})], "EMBODIED",
                        audit_required=False, condition_authority=AUTH())
_f.request_change(E1("tighter", 20, required={"in_home"}), authorised_by="system")
ok(_f.active.name == "tighter", "F1-C1: primer — tightened to 20N")
_f.select_for([])
ok(_f.active.name == "tighter",
   "F1-C2: an ODD fallback after a runtime tightening stays at 20N (was: the "
   "fallback was frozen at construction and the ODD path WIDENED the machine "
   "back to 60N. Sol, 2026-09-22)")
_nf = EnvelopeController(
    [E1("safe_force", 20, speed=2.0, required={"a"}),
     E1("safe_speed", 500, speed=0.1, required={"b"})],
    "EMBODIED", fallback_envelope="safe_speed", audit_required=False,
    condition_authority=AUTH())
_nf.request_change(E1("safer_speed", 400, speed=0.05, required={"b"}),
                   authorised_by="justin", reason="gearbox swap, slower top end")
assert _nf.active.name == "safer_speed", "PRIMER FAILED (nothing was tested)"
_nf.select_for([])
ok(_nf.active.name == "safer_speed",
   "F1-C3: an operator-NAMED fallback is superseded by a later declaration "
   "that is strictly safer than it on every dimension")
_cont = EnvelopeController([E1("base", 60, speed=0.1, required={"x"})],
                           "EMBODIED", audit_required=False,
                           condition_authority=AUTH())
_cont.request_change(E1("odd_one", 40, speed=0.5, required={"y"}),
                     authorised_by="justin", reason="incomparable on purpose")
_cont.select_for([])
ok(_cont.active.name == "base",
   "F1-C4: an INCOMPARABLE declaration does not move the fallback — no "
   "fallback is ever guessed, and nothing less safe replaces it")


# CLAIMS: driftcore/governance/physical_envelope.py:declaration-is-not-activation
print("-- D: a human's signature is one key; evidence is the other --")
_d = EnvelopeController([E1("transport", 20, required={"stowed"})],
                        "REMOTE_PHYSICAL_CONTROL", audit_required=False,
                        condition_authority=AUTH())
_okd, _ = _d.request_change(E1("working", 800, required={"fence_closed"}),
                            authorised_by="justin",
                            reason="fenced cell, humans excluded")
ok(_okd, "F1-D1: a human may DECLARE an 800N envelope for the fenced cell")
ok(is_tight(_d),
   "F1-D2: ...and it is NOT active: no fence evidence was presented (was: "
   "active immediately, with an infinite deadline, until someone happened to "
   "call select_for. Sol, 2026-09-22)")
_d.select_for([EV("fence_closed", seq=1)])
ok(is_wide(_d),
   "F1-D3: genuine fence evidence then earns it — both keys turned, so the "
   "declaration was not useless, only insufficient on its own")
_d.request_change(E1("careful", 400, required={"fence_closed"}),
                  authorised_by="justin", reason="visitor on the mezzanine")
ok(_d.active.name == "careful",
   "F1-D4: a declaration in the SAFE direction still takes effect at once — "
   "the two-key rule applies to widening, not to slowing down")


# CLAIMS: driftcore/governance/physical_envelope.py:expiry-is-measured-on-the-controller-clock
print("-- E: evidence expiry survives a clock mismatch --")
_wall = AUTH(clock=time.time)
def _wall_ev(seq, ttl):
    ev = ConditionEvidence("fence_closed", True, source="sensor-hub",
                           issued_at=time.time(), ttl_seconds=ttl,
                           sequence=seq, proof="", epoch=EPOCH)
    return _replace(ev, proof=sign(ev.payload))
_e = CELL(authority=_wall)
_e.select_for([_wall_ev(1, 0.30)])
ok(is_wide(_e), "F1-E1: primer — wall-clock authority, fresh evidence, 800N")
time.sleep(0.45)
ok(is_tight(_e),
   "F1-E2: 0.45s later the 0.3s evidence has expired, and the machine is at "
   "20N (was: a wall-clock deadline compared against time.monotonic, so the "
   "wide envelope never expired — the snapshot added this afternoon carried "
   "the seam forward. Found 2026-09-22)")
_e2 = CELL(authority=AUTH(clock=time.time))
_e2.select_for([_wall_ev(1, 5.0)])
time.sleep(0.10)
ok(is_wide(_e2),
   "F1-E3: ...and evidence that is still fresh keeps it wide — the "
   "conversion is not 'always expire'")


# CLAIMS: driftcore/governance/physical_envelope.py:active-changes-through-one-door
print("-- S: one door, checked structurally --")
_cls = next(n for n in ast.walk(ast.parse(inspect.getsource(pe)))
            if isinstance(n, ast.ClassDef) and n.name == "EnvelopeController")
def _writers(attr):
    out = set()
    for fn in _cls.body:
        if not isinstance(fn, ast.FunctionDef):
            continue
        for node in ast.walk(fn):
            targets = (node.targets if isinstance(node, ast.Assign) else
                       [node.target] if isinstance(node, (ast.AnnAssign,
                                                          ast.AugAssign))
                       else [])
            for t in targets:
                if (isinstance(t, ast.Attribute) and t.attr == attr
                        and isinstance(t.value, ast.Name) and t.value.id == "self"):
                    out.add(fn.name)
    return out
ok(_writers("_active") <= {"__init__", "_commit"} and "_commit" in _writers("_active"),
   "F1-S1: `_active` is written ONLY in __init__ and _commit — a sixth door "
   "fails this check even if it behaves correctly today, because five doors "
   "with five rules is how every defect in this layer got in")
ok(_writers("_authorised_until") <= {"__init__", "_commit"},
   "F1-S2: ...and so is its deadline, so the two can never be set apart")


print("== FIXTURE 2: failing dependencies, unplanned faults, naming the evidence ==")
# Written from the CASE LIST of SINT's shared fixture (Illia Pashkov,
# 2026-09-22) before a single one of its cases had been run here. Reading the
# list was enough to find two holes in code Fixtures 0 and 1 had just closed.
# Where two layers now guard the same property, each layer is checked on its
# own: a guard underneath can otherwise hide a regression in the layer above.

class _Store(dict):
    """A replay store that can go down for reads, writes, or both."""
    def __init__(self):
        super().__init__()
        self.reads_down = False
        self.writes_down = False
    def get(self, k, d=None):
        if self.reads_down:
            raise ConnectionError("replay store unreachable")
        return super().get(k, d)
    def __setitem__(self, k, v):
        if self.writes_down:
            raise ConnectionError("replay store read-only")
        return super().__setitem__(k, v)


# CLAIMS: driftcore/governance/physical_envelope.py:replay-store-outage-is-unknown
print("-- R: the replay store is a dependency, and dependencies fail --")
_rs = _Store()
_rc = E2E(replay_state=ReplayStore(_rs))
_rc.select_for([EV("fence_closed", seq=1)])
ok(is_wide(_rc), "F2-R1: primer — 800N on genuine evidence, replay store up")
_rs.reads_down = True
_rr = False
try:
    _rc.select_for([EV("fence_closed", seq=2)])
except EnvelopeRefused:
    _rr = True
ok(is_tight(_rc) and _rr,
   "F2-R2: the replay store goes DOWN for reads — 20N, and the outage is "
   "reported (was: the store's exception escaped with 800N still active. "
   "Found from the case list of SINT's shared fixture, 2026-09-22)")
_rs.reads_down = False
_rc.select_for([EV("fence_closed", seq=3)])
assert is_wide(_rc), "PRIMER FAILED (nothing was tested)"
_rs.writes_down = True
try:
    _rc.select_for([EV("fence_closed", seq=4)])
except EnvelopeRefused:
    pass
ok(is_tight(_rc),
   "F2-R3: a store that can be READ but not WRITTEN is an outage too — a "
   "reading whose acceptance cannot be recorded is a reading that can be "
   "replayed")
_snap_w = _rc._authority.evaluate([EV("fence_closed", seq=5)])
ok(_snap_w.replay_store_failed and not _snap_w.holds,
   "F2-R3b: ...and evaluate() ITSELF reports the failed write as an outage, "
   "checked apart from the guard under select_for")
_rs.writes_down = False
_rs.reads_down = True
_snap_r = _rc._authority.evaluate([EV("fence_closed", seq=5)])
ok(_snap_r.replay_store_failed and not _snap_r.holds,
   "F2-R4: evaluate() ITSELF reports the store outage in its snapshot — "
   "checked apart from select_for, because the fallback guard underneath "
   "would otherwise hide a regression in this layer")
_rs.reads_down = False
_rc.select_for([EV("fence_closed", seq=6)])
ok(is_wide(_rc),
   "F2-R5: when the store recovers, fresh evidence earns 800N again — an "
   "outage is not a latch")
_ov = _Outage()
_va = AUTH(verify_proof=_ov)
_ov.broken = True
_snap_v = _va.evaluate([EV("fence_closed", seq=1)])
ok(_snap_v.verifier_failed and not _snap_v.holds,
   "F2-R6: evaluate() reports a VERIFIER outage in its snapshot rather than "
   "raising — the same layer check, for the other injected dependency")


# CLAIMS: driftcore/governance/physical_envelope.py:a-failed-selection-leaves-the-fallback
print("-- F: a fault nobody planned for still ends on the fallback --")
_fg = E2E()
_fg.select_for([EV("fence_closed", seq=1)])
assert is_wide(_fg), "PRIMER FAILED (nothing was tested)"
_real_evaluate = _fg._authority.evaluate
def _crash(evidence):
    raise RuntimeError("a bug in the evidence pipeline")
_fg._authority.evaluate = _crash
_fr = None
try:
    _fg.select_for([EV("fence_closed", seq=2)])
except EnvelopeRefused as e:
    _fr = e
ok(_fr is not None and is_tight(_fg),
   "F2-F1: an UNANTICIPATED fault inside selection — here the whole evidence "
   "pipeline crashing — ends on 20N, and the caller is told. SINT's fixture "
   "calls this a selector fault: fallback and deny")
ok(isinstance(_fr.__cause__, RuntimeError),
   "F2-F2: ...and the original fault is chained, not swallowed, so the "
   "operator can see what actually broke")
_fg._authority.evaluate = _real_evaluate
_fg.select_for([EV("fence_closed", seq=3)])
ok(is_wide(_fg), "F2-F3: with the fault gone, genuine evidence earns 800N again")


# CLAIMS: driftcore/governance/physical_envelope.py:authorization-names-its-evidence
print("-- G: an authorization names the evidence it relied on --")
class _Recorder:
    def __init__(self): self.rows = []
    def record(self, **kw): self.rows.append(kw)
_rec = _Recorder()
_g = EnvelopeController(
    [env("transport", 20.0, required={"stowed"}),
     env("working", 800.0, required={"fence_closed"})],
    "REMOTE_PHYSICAL_CONTROL", fallback_envelope="transport",
    audit=_rec, condition_authority=AUTH())
ok(_g.authorising_evidence == "",
   "F2-G1: the fallback rests on no evidence, and says so")
_g1 = EV("fence_closed", seq=1)
_g.select_for([_g1])
_d1 = _g.authorising_evidence
ok(is_wide(_g) and len(_d1) == 64,
   "F2-G2: 800N earned by evidence carries a digest OF that evidence (was: "
   "the record said 'conditions attested' and named nothing — the same gap "
   "SINT's fixture found in SINT)")
ok(any(_d1 in r.get("detail", "") for r in _rec.rows
       if r.get("action") == "ENVELOPE_SWITCHED"),
   "F2-G3: ...and the audit record of the transition names the same digest")
_g.select_for([_g1])
ok(_g.authorising_evidence == _d1,
   "F2-G4: the SAME reading presented again leaves the digest unchanged — "
   "the evidence did not change")
_g.select_for([EV("fence_closed", seq=2)])
_d2 = _g.authorising_evidence
ok(is_wide(_g) and _d2 and _d2 != _d1,
   "F2-G5: a newer reading changes the digest — the authorization now rests "
   "on different evidence")
_fx = EV("fence_closed", seq=1)
_ga, _gb = E2E(), E2E()
_ga.select_for([_fx])
_gb.select_for([_fx, EV("lights_on", seq=1)])
ok(is_wide(_ga) and _ga.authorising_evidence == _gb.authorising_evidence,
   "F2-G6: evidence for a condition the envelope does NOT require is not what "
   "it relied on, and is left out of the digest")
_g.select_for([])
ok(is_tight(_g) and _g.authorising_evidence == "",
   "F2-G7: back on the fallback, the authorization rests on no evidence again")
_ge = E2E()
_ge.select_for([EV("fence_closed", seq=1, ttl=0.2)])
time.sleep(0.3)
ok(_ge.authorising_evidence == "" and is_tight(_ge),
   "F2-G8: an EXPIRED authorization names nothing — reading the digest "
   "demotes first, exactly as reading the envelope does")
ok(_writers("_evidence_digest") <= {"__init__", "_commit"},
   "F2-S1: the evidence digest is written only in __init__ and _commit — it "
   "travels through the same one door as the envelope and its deadline")


print("== FIXTURE 3: round 4 (Grok, Sol) — encodings, boundaries, shared state ==")

# CLAIMS: driftcore/governance/physical_envelope.py:reading-digest-is-canonical
print("-- C: the reading digest is a spec, not a Python repr --")
# GOLDEN VECTOR, built field by field so another implementation can check
# itself against it: each field is an 8-byte big-endian length, then bytes.
_GOLDEN_PRE = bytes.fromhex(
    "0000000000000014" + "driftcore-reading-v1".encode().hex()
    + "000000000000000a" + "sensor-hub".encode().hex()
    + "000000000000000c" + "fence_closed".encode().hex()
    + "0000000000000001" + "01"                       # value TRUE
    + "0000000000000008" + "408f420000000000"         # issued_at 1000.25
    + "0000000000000008" + "404e000000000000"         # ttl 60.0
    + "0000000000000008" + "0000000000000007"         # sequence 7
    + "000000000000000c" + "boot-epoch-A".encode().hex())
_GOLDEN_DIGEST = "1ab21fb06139cdfdfb63cec6cb4f92909d37b963d27163b0627883d3deebc833"
_gv = ConditionEvidence("fence_closed", True, source="sensor-hub",
                        issued_at=1000.25, ttl_seconds=60.0, sequence=7,
                        epoch="boot-epoch-A")
ok(_gv.canonical == _GOLDEN_PRE and _gv.digest == _GOLDEN_DIGEST
   and hashlib.sha256(_GOLDEN_PRE).hexdigest() == _GOLDEN_DIGEST,
   "F3-C1: the reading digest matches the published golden vector byte for "
   "byte — a TypeScript or Rust runner can reproduce it")
_gi = _replace(_gv, issued_at=1000, ttl_seconds=60)
_gz = _replace(_gv, issued_at=0.0)
ok(_gi.digest == _replace(_gv, issued_at=1000.0, ttl_seconds=60.0).digest and _replace(_gv, issued_at=-0.0).digest == _gz.digest,
   "F3-C2: numerically equal readings have equal digests — int or float, "
   "0.0 or -0.0 (was: repr made `1000` and `1000.0` two readings)")
_now_i = int(time.monotonic())
_ri = ConditionEvidence("fence_closed", True, source="sensor-hub",
                        issued_at=_now_i, ttl_seconds=60, sequence=5, epoch=EPOCH)
_ri = _replace(_ri, proof=sign(_ri.payload))
_rf = _replace(_ri, issued_at=float(_now_i), ttl_seconds=60.0)
_rf = _replace(_rf, proof=sign(_rf.payload))
_cc = E2E()
_cc.select_for([_ri])
assert is_wide(_cc), "PRIMER FAILED (nothing was tested)"
_cc.select_for([_rf])
ok(is_wide(_cc),
   "F3-C3: the SAME reading re-sent float-typed is not a conflict and keeps "
   "800N (was: a false conflict poisoned sequence 5 and dropped to 20N)")
_huge = False
try:
    ConditionEvidence("x", True, source="s", issued_at=10 ** 400,
                      ttl_seconds=1.0, epoch="e")
except EnvelopeRefused:
    _huge = True
_inexact = False
try:
    ConditionEvidence("x", True, source="s", issued_at=2 ** 53 + 1,
                      ttl_seconds=1.0, epoch="e")
except EnvelopeRefused:
    _inexact = True
ok(_huge and _inexact,
   "F3-C4: a time with no exact binary64 value is refused at construction "
   "rather than silently rounded in the digest — including a FINITE one "
   "(2**53+1), which the overflow check added in v6.1 would not catch")


# CLAIMS: driftcore/governance/physical_envelope.py:replay-marks-are-scoped-to-the-epoch
print("-- E: replay marks belong to an epoch --")
_ds = ReplayStore()
_ea = E2E(replay_state=_ds)
_ea.select_for([EV("fence_closed", seq=9)])
assert is_wide(_ea), "PRIMER FAILED (nothing was tested)"
_eb = E2E(replay_state=_ds, epoch="boot-epoch-B")
_eb.select_for([EV("fence_closed", seq=0, epoch="boot-epoch-B")])
ok(is_wide(_eb),
   "F3-E1: after a restart with a NEW epoch over the SAME durable store, a "
   "sensor whose counter restarted earns 800N (was: 'superseded' — epoch "
   "A's mark stranded it)")
ok(not AUTH(replay_state=_ds).accept([EV("fence_closed", seq=3)]),
   "F3-E2: ...while epoch A's marks still stand for epoch A")


print("-- M: MAX_SEQUENCE, where 'strictly newer' runs out --")
class _Int64Store(dict):
    """A durable store whose sequence column is signed 64-bit."""
    def __setitem__(self, k, v):
        if not -2 ** 63 <= v[0] <= 2 ** 63 - 1:
            raise OverflowError("does not fit a signed 64-bit column")
        super().__setitem__(k, v)
_m1 = E2E()
_m1.select_for([EV("fence_closed", seq=1)])
assert is_wide(_m1), "PRIMER FAILED (nothing was tested)"
_m1.select_for([EV("fence_closed", seq=MAX_SEQUENCE - 1),
                EV("fence_closed", seq=MAX_SEQUENCE - 1, value=False)])
assert is_tight(_m1), "PRIMER FAILED (conflict did not demote)"
_m1.select_for([EV("fence_closed", seq=MAX_SEQUENCE)])
ok(is_wide(_m1), "F3-M1: a conflict at MAX_SEQUENCE - 1 still lets a reading "
                 "AT MAX_SEQUENCE through — no off-by-one at the edge")
_s64 = _Int64Store()
_m2 = E2E(replay_state=ReplayStore(_s64))
_m2.select_for([EV("fence_closed", seq=1)])
assert is_wide(_m2), "PRIMER FAILED (nothing was tested)"
_tmax = EV("fence_closed", seq=MAX_SEQUENCE)
_raised64 = False
try:
    _m2.select_for([_tmax, EV("fence_closed", seq=MAX_SEQUENCE, value=False)])
except EnvelopeRefused:
    _raised64 = True
ok(is_tight(_m2) and not _raised64,
   "F3-M2: a conflict AT MAX_SEQUENCE is recorded in a store with a signed "
   "64-bit column (was: v4 wrote MAX+1, the store refused it, and the poison "
   "never landed)")
_m2.select_for([_tmax])
ok(is_tight(_m2),
   "F3-M3: ...so the captured TRUE@MAX cannot be replayed to reopen 800N "
   "(was: it could — and Grok's suggested clamp to (MAX, '') reopens it too)")
ok(any("rotate the epoch" in r for r in _m2._authority.evaluate([_tmax]).rejected),
   "F3-M4: the operator is told this source is finished for the epoch and "
   "how to recover it")
_m3 = E2E(replay_state=ReplayStore(_s64), epoch="boot-epoch-B")
_m3.select_for([EV("fence_closed", seq=1, epoch="boot-epoch-B")])
ok(is_wide(_m3), "F3-M5: ...and rotating the epoch recovers it")


# CLAIMS: driftcore/governance/physical_envelope.py:authorization-names-its-envelope
print("-- A: the authorization names WHAT was authorized --")
def _one(name, force):
    c = EnvelopeController([env("transport", 20.0, required={"stowed"}),
                            env(name, force, required={"fence_closed"})],
                           "REMOTE_PHYSICAL_CONTROL", fallback_envelope="transport",
                           audit_required=False, condition_authority=AUTH())
    c.select_for([_same])
    assert c.active.name == name, "PRIMER FAILED (nothing was tested)"
    return c
_same = EV("fence_closed", seq=1)
_aw, _an, _al = _one("working", 800.0), _one("careful", 800.0), _one("working", 500.0)
ok(_aw.authorising_evidence == _an.authorising_evidence == _al.authorising_evidence
   and len({_aw.authorization_digest, _an.authorization_digest,
            _al.authorization_digest}) == 3,
   "F3-A1: the same reading authorising a different envelope — another name, "
   "or the same name with other limits — is a different authorization; the "
   "evidence digest is unchanged")
ok(E2E().authorization_digest == "",
   "F3-A2: on the fallback there is no authorization to name")


# CLAIMS: driftcore/governance/physical_envelope.py:a-failed-selection-leaves-the-fallback
print("-- B: interrupts end on the fallback and stay interrupts --")
for _exc in (KeyboardInterrupt, SystemExit):
    _ki = E2E()
    _ki.select_for([EV("fence_closed", seq=1)])
    assert is_wide(_ki), "PRIMER FAILED (nothing was tested)"
    def _interrupt(evidence, _e=_exc):
        raise _e()
    _ki._authority.evaluate = _interrupt
    _got = None
    try:
        _ki.select_for([EV("fence_closed", seq=2)])
    except BaseException as e:      # noqa: BLE001 — the point of the check
        _got = e
    del _ki._authority.evaluate
    ok(type(_got) is _exc and is_tight(_ki),
       f"F3-B-{_exc.__name__}: raised inside selection, it reaches the caller "
       f"as itself — not wrapped — with the machine already on 20N")


# CLAIMS: driftcore/governance/physical_envelope.py:screening-never-moves-replay-state
print("-- P: an unauthenticated record cannot poison a sequence --")
_up = E2E()
_g5 = EV("fence_closed", seq=5)
_up.select_for([_g5])
assert is_wide(_up), "PRIMER FAILED (nothing was tested)"
_up.select_for([EV("fence_closed", seq=5, value=False, proof="x")])
_up.select_for([_g5])
ok(is_wide(_up),
   "F3-P1: a junk-proof FALSE@5 after a genuine TRUE@5 moves nothing, and the "
   "genuine reading still earns 800N. Detecting the conflict before "
   "authentication would let anyone strand a sensor by guessing its sequence")


# CLAIMS: driftcore/governance/physical_envelope.py:proof-presence-is-not-attestation
print("-- V: only True authenticates --")
for _answer in ("VERIFIED? NO", 1, object(), None):
    _vv = E2E(verify_proof=lambda ev, _a=_answer: _a if ev.proof == "junk"
              else verifier()(ev))
    wide_then(_vv, [EV("fence_closed", seq=2, proof="junk")],
              f"F3-V-{type(_answer).__name__}: a verifier answering "
              f"{_answer!r} does not authenticate a junk proof (was: "
              f"`if not verified` let any truthy answer through — Sol)")
_vs = AUTH(verify_proof=lambda ev: "yes")
ok(_vs.evaluate([EV("fence_closed", seq=1)]).verifier_failed,
   "F3-V5: a non-bool answer is reported as a verifier FAULT, not a rejection")


# CLAIMS: driftcore/governance/physical_envelope.py:replay-marks-never-move-backward
print("-- S: two authorities, one store --")
class _HookStore(ReplayStore):
    """Runs `hook` once, right after a read — a deterministic interleaving."""
    hook = None
    def get(self, key):
        v = super().get(key)
        if self.hook:
            h, self.hook = self.hook, None
            h()
        return v
_hs = _HookStore()
_sa = E2E(replay_state=_hs)
_sa.select_for([EV("fence_closed", seq=3)])
assert is_wide(_sa), "PRIMER FAILED (nothing was tested)"
_other = AUTH(replay_state=_hs)
_t4 = EV("fence_closed", seq=4)
_hs.hook = lambda: _other.evaluate([EV("fence_closed", seq=5, value=False)])
_sa.select_for([_t4])
ok(is_tight(_sa) and _hs.get((EPOCH, "sensor-hub", "fence_closed"))[0] == 5,
   "F3-S1: another authority lands FALSE@5 between our read and our write: "
   "our older TRUE@4 earns nothing and the store stays at 5 (was: TRUE@4 "
   "overwrote it, regressing the mark — Sol)")
_sa.select_for([_t4])
ok(is_tight(_sa), "F3-S2: ...and TRUE@4 cannot then be replayed to 800N")
_plain = False
try:
    AUTH(replay_state={})
except EnvelopeRefused:
    _plain = True
ok(_plain, "F3-S3: a plain mapping without compare_and_set is refused at "
           "construction — the race is unconstructable, not documented")


# CLAIMS: driftcore/governance/physical_envelope.py:permissive-transitions-are-journaled-first
print("-- R: renewing a permissive lease is recorded first --")
class _FlakySink:
    down = False
    def record(self, **kw):
        if self.down:
            raise RuntimeError("audit sink down")
_fs = _FlakySink()
_rn = EnvelopeController([env("transport", 20.0, required={"stowed"}),
                          env("working", 800.0, required={"fence_closed"})],
                         "REMOTE_PHYSICAL_CONTROL", fallback_envelope="transport",
                         audit=_fs, condition_authority=AUTH())
_rn.select_for([EV("fence_closed", seq=1)])
assert is_wide(_rn), "PRIMER FAILED (nothing was tested)"
_fs.down = True
try:
    _rn.select_for([EV("fence_closed", seq=2)])
except EnvelopeRefused:
    pass
ok(is_tight(_rn),
   "F3-R1: with the audit sink down, NEW evidence cannot renew 800N unrecorded "
   "(was: the lease was silently extended — Sol)")


print("-- D: a dissent is not erased by leaving it out --")
_dd = E2E(("sensor-hub", "sensor-b"))
_dd.select_for([EV("fence_closed", seq=5), EV("fence_closed", seq=5, source="sensor-b")])
assert is_wide(_dd), "PRIMER FAILED (nothing was tested)"
_d6 = EV("fence_closed", seq=6)
_dd.select_for([_d6, EV("fence_closed", seq=6, source="sensor-b", value=False)])
assert is_tight(_dd), "PRIMER FAILED (disagreement did not demote)"
_dd.select_for([_d6])
ok(is_tight(_dd),
   "F3-D1: a fresh signed FALSE from sensor-b still counts when sensor-b is "
   "left out of the next batch (was: omitting it returned 800N — Sol)")
_dd.select_for([_d6, EV("fence_closed", seq=7, source="sensor-b")])
ok(is_wide(_dd), "F3-D2: ...and a NEWER TRUE from sensor-b resolves it")


print("== FIXTURE 4: round 5 (cold pass, Sol, GLM, Grok, Meta) ==")
# Every attack here was reproduced against v5 before it was fixed. Where the
# attack can start from 800N it does, so a check cannot pass merely because
# the machine was already safe.
import threading as _th4, random as _rnd4

def _envelope(name, force, required=(), point=EnforcementPoint.FIRMWARE, by="justin"):
    return PhysicalEnvelope(name=name, limits={"force_n": force}, enforced_at=point,
                            conditions=OperatingConditions("d", frozenset(required)),
                            declared_by=by, attestation_note="n")


print("-- W1: a verified envelope cannot be edited afterwards --")
_lim = {"force_n": 20.0}
_fx = EnvelopeController([PhysicalEnvelope(
    name="transport", limits=_lim, enforced_at=EnforcementPoint.FIRMWARE,
    conditions=OperatingConditions("d", frozenset({"stowed"})),
    declared_by="justin", attestation_note="n"),
    env("working", 800.0, required={"fence_closed"})],
    "REMOTE_PHYSICAL_CONTROL", fallback_envelope="transport",
    audit_required=False, condition_authority=AUTH())
_lim["force_n"] = 800.0
ok(_fx.active.limits["force_n"] == 20.0,
   "F4-W1a: editing the caller's dict after declaration does not move a live "
   "limit (was: 20N became 800N with no request_change, no human, no record — "
   "cold pass W1, found independently by Sol)")
_fx_raised = False
try:
    _fx.active.limits["force_n"] = 800.0
except TypeError:
    _fx_raised = True
ok(_fx_raised and _fx.active.limits["force_n"] == 20.0,
   "F4-W1b: writing through `ctl.active.limits` is refused, and the limit is "
   "unchanged")
_mine = {"force_n": 5.0}
_ag = E2E()
_ok_ag, _ = _ag.request_change(PhysicalEnvelope(
    name="gentlest", limits=_mine, enforced_at=EnforcementPoint.FIRMWARE,
    conditions=OperatingConditions("d", frozenset({"stowed"})),
    declared_by="agent", attestation_note="n"), authorised_by="agent")
assert _ok_ag and _ag.active.name == "gentlest", "PRIMER FAILED (nothing was tested)"
_mine["force_n"] = 5000.0
_ag.select_for([])
ok(_ag.active.name == "gentlest" and _ag.active.limits["force_n"] == 5.0,
   "F4-W1c: an agent that adds a 5N 'safest' envelope — allowed without a human "
   "— cannot then make it 5000N (was: the fallback became 5000N)")
_req = {"fence_closed"}
_rq = EnvelopeController([env("transport", 20.0, required={"stowed"}),
                          PhysicalEnvelope(name="working", limits={"force_n": 800.0},
                                           enforced_at=EnforcementPoint.FIRMWARE,
                                           conditions=OperatingConditions("d", _req),
                                           declared_by="justin", attestation_note="n")],
                         "REMOTE_PHYSICAL_CONTROL", fallback_envelope="transport",
                         audit_required=False, condition_authority=AUTH())
_rq.select_for([EV("fence_closed", seq=1)])
assert is_wide(_rq), "PRIMER FAILED (nothing was tested)"
_req.clear()
_rq.select_for([])
ok(is_tight(_rq),
   "F4-W1d: clearing the `required` set after declaration does not make 800N "
   "valid everywhere (was: it did, with no evidence at all)")
_bare = False
try:
    OperatingConditions("d", "fence_closed")
except EnvelopeRefused:
    _bare = True
ok(_bare, "F4-W1e: a bare string for `required` is refused — iterating it "
          "would yield its letters")


# CLAIMS: driftcore/governance/physical_envelope.py:reading-digest-is-canonical
print("-- W4, S1-S3: exact types, plain strings, a spec with no gaps --")
from enum import Enum as _Enum4
class _Cond4(str, _Enum4):
    FENCE = "fence_closed"
_pe4 = EV("fence_closed", seq=5)
_ee4 = _replace(_pe4, condition=_Cond4.FENCE, proof="")
_ee4 = _replace(_ee4, proof=sign(_ee4.payload))
_en = E2E()
_en.select_for([_pe4])
assert is_wide(_en), "PRIMER FAILED (nothing was tested)"
_en.select_for([_ee4])
ok(type(_ee4.condition) is str and _ee4.digest == _pe4.digest and is_wide(_en),
   "F4-S1a: a condition named by a str-Enum member is stored as its plain "
   "value: the same reading re-sent that way is not a conflict and keeps 800N "
   "(was: a false conflict, 20N)")
_ka, _kb = (EnvelopeController([env("transport", 20.0, required={"stowed"}),
                                PhysicalEnvelope(name="working", limits={k: 800.0},
                                                 enforced_at=EnforcementPoint.FIRMWARE,
                                                 conditions=OperatingConditions("d", frozenset({"fence_closed"})),
                                                 declared_by="justin", attestation_note="n")],
                               "REMOTE_PHYSICAL_CONTROL", fallback_envelope="transport",
                               audit_required=False, condition_authority=AUTH())
            for k in ("force_n", Dimension.FORCE_N))
_same4 = EV("fence_closed", seq=1)
_ka.select_for([_same4]); _kb.select_for([_same4])
ok(is_wide(_ka) and is_wide(_kb) and _ka.authorization_digest == _kb.authorization_digest,
   "F4-S1b: limits keyed by `Dimension.FORCE_N` or 'force_n' give one "
   "authorization digest (was: str() of the enum member was hashed)")
class _Forever(ConditionEvidence):
    def is_fresh(self, now):
        return True
    @property
    def expires_at(self):
        return float("inf")
import dataclasses as _dc4
_short = EV("fence_closed", seq=1, ttl=0.2)
_sub = E2E()
_sub.select_for([_short])
assert is_wide(_sub), "PRIMER FAILED (nothing was tested)"
time.sleep(0.3)
_sub.select_for([_Forever(**{f.name: getattr(_short, f.name) for f in _dc4.fields(_short)})])
ok(is_tight(_sub),
   "F4-W4a: an expired genuine reading wrapped in a subclass that answers "
   "'fresh, forever' earns nothing — subclasses are refused (was: 800N with no "
   "deadline)")
def _canon_sign(ev):
    return hmac.new(_KEY, ev.canonical, hashlib.sha256).hexdigest()
_cv = EnvelopeController([env("transport", 20.0, required={"stowed"}),
                          env("working", 800.0, required={"fence_closed"})],
                         "REMOTE_PHYSICAL_CONTROL", fallback_envelope="transport",
                         audit_required=False,
                         condition_authority=AUTH(verify_proof=lambda ev: hmac.compare_digest(
                             ev.proof, _canon_sign(ev))))
_fence4 = ConditionEvidence("fence_closed", True, source="sensor-hub",
                            issued_at=time.monotonic(), ttl_seconds=60.0, sequence=1, epoch=EPOCH)
_cv.select_for([_replace(_fence4, proof=_canon_sign(_fence4))])
assert is_wide(_cv), "PRIMER FAILED (nothing was tested)"
_stowed4 = ConditionEvidence("stowed", True, source="sensor-hub",
                             issued_at=time.monotonic(), ttl_seconds=60.0, sequence=2, epoch=EPOCH)
_stowed4 = _replace(_stowed4, proof=_canon_sign(_stowed4))
class _Liar(str):
    def __str__(self):
        return "stowed"
_cv.select_for([_replace(_stowed4, condition=_Liar("fence_closed"))])
ok(is_tight(_cv),
   "F4-W4b: a str subclass that tells the digest 'stowed' cannot carry a "
   "genuine stowed proof onto fence_closed under a verifier that signs "
   "`canonical` (was: 800N)")
def _refused4(f):
    try:
        f()
    except EnvelopeRefused:
        return True
    return False
ok(_refused4(lambda: env("x", 2 ** 53 + 1)) and not _refused4(lambda: env("x", 2 ** 53)),
   "F4-S2: a limit with no exact binary64 value is refused at declaration "
   "(was: 2**53 and 2**53+1 shared an authorization digest)")
ok(_refused4(lambda: ConditionEvidence("fence\ud800", True, source="s", issued_at=1.0,
                                       ttl_seconds=1.0, epoch="e"))
   and _refused4(lambda: env("w\udfff", 5.0)),
   "F4-S3: a lone surrogate is refused in evidence and envelope names — it has "
   "no UTF-8 encoding, and another runner would collapse it")


# CLAIMS: driftcore/governance/physical_envelope.py:every-acceptance-is-compare-and-set
print("-- W2, W9, A1: every acceptance is a compare-and-set --")
_KEY4 = (EPOCH, "sensor-hub", "fence_closed")
_h4 = _HookStore()
_w2 = E2E(replay_state=_h4)
_t5w = EV("fence_closed", seq=5)
_w2.select_for([_t5w])
assert is_wide(_w2), "PRIMER FAILED (nothing was tested)"
_other4 = AUTH(replay_state=_h4)
_h4.hook = lambda: _other4.evaluate([EV("fence_closed", seq=6, value=False)])
_w2.select_for([_t5w])
ok(is_tight(_w2) and _h4.get(_KEY4)[0] == 6,
   "F4-W2a: re-presenting TRUE@5 while another authority lands FALSE@6 "
   "between our read and our write ends at 20N (was: the unchanged reading "
   "skipped the compare-and-set and kept 800N)")
class _LagStore(ReplayStore):
    """Reads come from a replica that lags; compare-and-set is strict."""
    def __init__(self):
        super().__init__({})
        self.replica = {}
    def get(self, key):
        return self.replica.get(key)
    def sync(self):
        self.replica = dict(self._m)
_ls = _LagStore()
_lg = E2E(replay_state=_ls)
_lg.select_for([_t5w])
_ls.sync()
assert is_wide(_lg), "PRIMER FAILED (nothing was tested)"
AUTH(replay_state=_ls).evaluate([EV("fence_closed", seq=6, value=False)])
_lg.select_for([_t5w])
ok(is_tight(_lg),
   "F4-W2b: with a store whose reads lag its writes — no race at all — a "
   "superseded TRUE@5 is refused because the compare-and-set fails (was: 800N)")
_h9 = _HookStore()
_x9 = E2E(replay_state=_h9)
_x9.select_for([EV("fence_closed", seq=3)])
assert is_wide(_x9), "PRIMER FAILED (nothing was tested)"
_y9 = AUTH(replay_state=_h9)
_t7, _f7 = EV("fence_closed", seq=7), EV("fence_closed", seq=7, value=False)
_h9.hook = lambda: _y9.evaluate([_t7])
for _b9 in ([_t7, _f7], [_t7]):
    try:
        _x9.select_for(_b9)
    except EnvelopeRefused:
        pass
ok(is_tight(_x9) and _h9.get(_KEY4) == (7, CONFLICTED),
   "F4-W9: a conflict whose marker loses the race is read again and the "
   "marker lands; the captured TRUE@7 cannot then be replayed (was: it earned "
   "800N on the authority that had seen the conflict)")
_ha = _HookStore()
_a1 = E2E(replay_state=_ha)
_a1.select_for([EV("fence_closed", seq=3)])
assert is_wide(_a1), "PRIMER FAILED (nothing was tested)"
_t4a = EV("fence_closed", seq=4)
_peer = AUTH(replay_state=_ha)
_ha.hook = lambda: _peer.evaluate([_t4a])
_a1.select_for([_t4a])
ok(is_wide(_a1),
   "F4-A1: when a peer has already recorded the IDENTICAL reading, ours is "
   "accepted after a re-read — an honest second authority is not flapped to "
   "20N (was: it lost the race and fell back)")


# CLAIMS: driftcore/governance/physical_envelope.py:replay-marks-never-move-backward
print("-- W8, G: one lock per mapping; the store refuses to go backward --")
_shared4 = {}
_r1, _r2 = ReplayStore(_shared4), ReplayStore(_shared4)
_shared4[_KEY4] = (1, "d1")
_gate = (_th4.Event(), _th4.Event())
class _SlowMap(dict):
    pass
_slow = _SlowMap({_KEY4: (1, "d1")})
_s1, _s2 = ReplayStore(_slow), ReplayStore(_slow)
_orig_get = _SlowMap.get
def _pausing_get(self, k, d=None):
    v = _orig_get(self, k, d)
    if _th4.current_thread().name == "cas-1" and not _gate[0].is_set():
        _gate[0].set(); _gate[1].wait(2)
    return v
_SlowMap.get = _pausing_get
_res4 = {}
_tc = _th4.Thread(target=lambda: _res4.__setitem__(
    1, _s1.compare_and_set(_KEY4, (1, "d1"), (2, "d2"))), name="cas-1")
_tc.start(); _gate[0].wait(2)
_tw = _th4.Thread(target=lambda: _res4.__setitem__(
    2, _s2.compare_and_set(_KEY4, (1, "d1"), (5, "d5"))))
_tw.start(); _tw.join(0.3)
_blocked4 = _tw.is_alive()
_gate[1].set(); _tc.join(3); _tw.join(3)
_SlowMap.get = _orig_get
ok(_r1._lock is _r2._lock and _blocked4 and sorted(_res4.values()) == [False, True],
   "F4-W8: two ReplayStore wrappers over one mapping share ONE lock: the "
   "second compare-and-set waits and then fails (was: both succeeded from "
   "the same expected entry and the mark went 1 -> 5 -> 2)")
_gs = ReplayStore()
_gs.compare_and_set(_KEY4, None, (6, "d6"))
_back = _gs.compare_and_set(_KEY4, (6, "d6"), (4, "d4"))
_gs.compare_and_set(_KEY4, (6, "d6"), (7, CONFLICTED))
_over = _gs.compare_and_set(_KEY4, (7, CONFLICTED), (7, "dT"))
ok(not _back and not _over and _gs.get(_KEY4) == (7, CONFLICTED),
   "F4-G1: the store itself refuses to move a mark backward or to replace a "
   "conflict marker with a reading at the same sequence, whatever its caller "
   "decided (GLM)")


print("-- W3, M3: a conflict does not erase a dissent; the record says why --")
_dz = E2E(("sensor-hub", "sensor-b"))
_dz.select_for([EV("fence_closed", seq=5), EV("fence_closed", seq=5, source="sensor-b")])
assert is_wide(_dz), "PRIMER FAILED (nothing was tested)"
_dz.select_for([EV("fence_closed", seq=6), EV("fence_closed", seq=6, source="sensor-b", value=False)])
_dz.select_for([EV("fence_closed", seq=7), EV("fence_closed", seq=6, source="sensor-b", value=False)])
_dz.select_for([EV("fence_closed", seq=8)])
ok(is_tight(_dz),
   "F4-W3a: a dissenter that re-signs FALSE@6 (a conflict with itself) still "
   "dissents: the hub alone does not earn 800N (was: the conflict erased the "
   "dissent — cold pass W3)")
_db = E2E(("sensor-hub", "sensor-b"))
_db.select_for([EV("fence_closed", seq=5), EV("fence_closed", seq=5, source="sensor-b")])
assert is_wide(_db), "PRIMER FAILED (nothing was tested)"
_db.select_for([EV("fence_closed", seq=6),
                EV("fence_closed", seq=6, source="sensor-b", value=False, ttl=0.2),
                EV("fence_closed", seq=6, source="sensor-b", value=False, ttl=0.25)])
time.sleep(0.35)
_db.select_for([EV("fence_closed", seq=7), EV("fence_closed", seq=6, source="sensor-b", value=False)])
ok(is_tight(_db),
   "F4-W3b: after its conflicting readings expire, a sensor still sending a "
   "fresh signed FALSE at the conflicted sequence still dissents — a replayed "
   "FALSE can only tighten (was: refused as conflicted, and the hub alone "
   "earned 800N)")
_dc = E2E(("sensor-hub", "sensor-b"))
_dc.select_for([EV("fence_closed", seq=5), EV("fence_closed", seq=5, source="sensor-b")])
assert is_wide(_dc), "PRIMER FAILED (nothing was tested)"
_dc.select_for([EV("fence_closed", seq=6), EV("fence_closed", seq=6, source="sensor-b", value=False)])
_dc.select_for([EV("fence_closed", seq=7), EV("fence_closed", seq=9, source="sensor-b"),
                EV("fence_closed", seq=9, source="sensor-b", value=True, ttl=30.0)])
_dc.select_for([EV("fence_closed", seq=8)])
ok(is_tight(_dc),
   "F4-W3c: a conflict with no FALSE in it leaves an earlier standing FALSE in "
   "place — contradicting itself does not let a sensor shed its dissent")
_mrec = _Recorder()
_mz = EnvelopeController([env("transport", 20.0, required={"stowed"}),
                          env("working", 800.0, required={"fence_closed"})],
                         "REMOTE_PHYSICAL_CONTROL", fallback_envelope="transport",
                         audit=_mrec, condition_authority=AUTH(("sensor-hub", "sensor-b")))
_mz.select_for([EV("fence_closed", seq=5), EV("fence_closed", seq=5, source="sensor-b")])
assert is_wide(_mz), "PRIMER FAILED (nothing was tested)"
_mz.select_for([EV("fence_closed", seq=6), EV("fence_closed", seq=6, source="sensor-b", value=False)])
_why = " ".join(r.get("detail", "") for r in _mrec.rows[-3:])
ok(is_tight(_mz) and "disputed" in _why and "sensor-b" in _why and EPOCH in _why,
   "F4-M3: a demotion caused by disagreement is recorded as disputed evidence, "
   "naming the dissenting source and the epoch (was: 'no declared conditions "
   "hold')")


# CLAIMS: driftcore/governance/physical_envelope.py:expiry-is-processed-before-any-decision
print("-- W6, W10: expiry is processed before anything is judged against it --")
_lrec = _Recorder()
_lp = EnvelopeController([env("transport", 20.0, required={"stowed"}),
                          env("careful", 400.0, required={"lift"}),
                          env("working", 800.0, required={"fence_closed"})],
                         "REMOTE_PHYSICAL_CONTROL", fallback_envelope="transport",
                         audit=_lrec, condition_authority=AUTH())
_lp.select_for([EV("fence_closed", seq=1, ttl=0.2)])
assert is_wide(_lp), "PRIMER FAILED (nothing was tested)"
time.sleep(0.3)                                  # nobody reads .active
_lp.select_for([EV("lift", seq=1)])
_acts = [(r["action"], r.get("detail", "")) for r in _lrec.rows]
ok(_lp.active.name == "careful"
   and any(a == "ENVELOPE_EXPIRED" for a, _ in _acts)
   and any(a == "ENVELOPE_SWITCHED" and d.startswith("transport -> careful") for a, d in _acts),
   "F4-W6: after an unobserved lapse, the next selection starts from the "
   "fallback: the expiry is recorded and 20N->400N is recorded as the widening "
   "it is (was: 'working -> careful', a 'tightening' committed before its record)")
def _slow_verify(ev):
    time.sleep(0.5)
    return verifier()(ev)
_sv = E2E(verify_proof=_slow_verify)
_returned = _sv.select_for([EV("fence_closed", seq=1, ttl=0.3)])
ok(_returned.name == "transport",
   "F4-W10: select_for does not return an authorization that expired while "
   "it was being judged (was: it returned 800N 0.2s past its deadline)")


_nc = E2E()
_nc.select_for([EV("fence_closed", seq=1)])
assert is_wide(_nc), "PRIMER FAILED (nothing was tested)"
_nc._clock = lambda: float("nan")
ok(is_tight(_nc),
   "F4-N1: a controller clock that reads NaN ends a wide authorization rather "
   "than extending it (was: `nan > deadline` is False, so 800N never expired "
   "— present on main, surfaced by finite_guards when the check moved)")


# CLAIMS: driftcore/governance/physical_envelope.py:evidence-validates-its-own-structure
_big = 1e308
ok(_refused4(lambda: ConditionEvidence("fence_closed", True, source="sensor-hub",
                                       issued_at=_big, ttl_seconds=_big, epoch=EPOCH)),
   "F4-X1a: finite times whose sum overflows are refused at construction — the "
   "reading would expire at inf (was: accepted; ChatGPT, round 5)")
_ok_ev = ConditionEvidence("fence_closed", True, source="sensor-hub",
                           issued_at=_big, ttl_seconds=1.0, sequence=1, epoch=EPOCH)
object.__setattr__(_ok_ev, "ttl_seconds", _big)          # bypasses __post_init__
object.__setattr__(_ok_ev, "proof", sign(_ok_ev.payload))
_bx = EnvelopeController([env("transport", 20.0, required={"stowed"}),
                          env("working", 800.0, required={"fence_closed"})],
                         "REMOTE_PHYSICAL_CONTROL", fallback_envelope="transport",
                         audit_required=False,
                         condition_authority=AUTH(max_ttl=_big, clock=lambda: _big))
_bx.select_for([_ok_ev])
ok(is_tight(_bx),
   "F4-X1b: ...and a reading that bypassed construction is re-checked at the "
   "trust boundary: an authority configured with an absurd ceiling and clock "
   "still does not grant 800N forever (was: 800N, authorised until inf)")


# CLAIMS: driftcore/governance/physical_envelope.py:authority-time-never-runs-backward
_wall = [1000.0]
_ck = EnvelopeController([env("transport", 20.0, required={"stowed"}),
                          env("working", 800.0, required={"fence_closed"})],
                         "REMOTE_PHYSICAL_CONTROL", fallback_envelope="transport",
                         audit_required=False,
                         condition_authority=AUTH(clock=lambda: _wall[0]))
_wev = ConditionEvidence("fence_closed", True, source="sensor-hub", issued_at=1000.0,
                         ttl_seconds=60.0, sequence=5, epoch=EPOCH)
_wev = _replace(_wev, proof=sign(_wev.payload))
_ck.select_for([_wev])
assert is_wide(_ck), "PRIMER FAILED (nothing was tested)"
_wall[0] = 1070.0
_ck.select_for([_wev])
assert is_tight(_ck), "PRIMER FAILED (the reading did not expire)"
_wall[0] = 1030.0                                # the wall clock steps back
_ck.select_for([_wev])
ok(is_tight(_ck),
   "F4-C1: when an injected wall clock steps back 40 s, the expired reading "
   "stays expired (was: it was fresh again, and 800N returned — found by "
   "probing a clock step from Grok's round-6 list)")
_odd_clocks = []
for _odd in ("noon", 10 ** 400, float("nan")):
    try:
        _od = AUTH(clock=lambda _v=_odd: _v).evaluate([EV("fence_closed", seq=1)])
        _odd_clocks.append(not _od.holds)
    except Exception:           # noqa: BLE001 — raising is the failure here
        _odd_clocks.append(False)
ok(all(_odd_clocks),
   "F4-C2: an authority clock that is not a number — a string, an integer too "
   "large for a float, NaN — judges everything stale instead of raising "
   "(checked at evaluate(), apart from select_for's guard; Sol)")
import pickle as _pk4
try:
    _pe_restored = _pk4.loads(_pk4.dumps(env("pk", 60.0)))
except TypeError:
    _pe_restored = None                          # not restorable at all
_pk_refused = False
if _pe_restored is not None:
    try:
        _pe_restored.limits["force_n"] = 800.0
    except TypeError:
        _pk_refused = True
ok(_pe_restored is not None and _pk_refused and _pe_restored.limits["force_n"] == 60.0,
   "F4-W1f: an envelope restored from a pickle is rebuilt through the "
   "constructor, so it is frozen and validated like a declared one")


print("-- W5, W7, M1, M2: declarations and records --")
_uc = E2E()
_ok5, _ = _uc.request_change(_envelope("anywhere", 800.0), authorised_by="justin",
                             reason="shift change")
_uc.select_for([])
ok(not _ok5 and is_tight(_uc),
   "F4-W5: a human cannot declare an unconditional envelope that is not the "
   "safest — it would be eligible everywhere, so one key would widen the machine "
   "(was: 'declared but NOT active', then 800N on select_for([]))")
_u1 = _refused4(lambda: EnvelopeController(
    [env("transport", 20.0, required={"stowed"}), _envelope("anywhere", 800.0)],
    "REMOTE_PHYSICAL_CONTROL", fallback_envelope="transport",
    audit_required=False, condition_authority=AUTH()))
ok(_u1, "F4-U1: at construction too, an unconditional envelope wider than the "
        "fallback is refused by default — it would be active on no evidence "
        "(Grok, round 6: a test-only allowance must not be the default)")
_urec = _Recorder()
_u2 = EnvelopeController(
    [env("transport", 20.0, required={"stowed"}), _envelope("anywhere", 800.0)],
    "REMOTE_PHYSICAL_CONTROL", fallback_envelope="transport", audit=_urec,
    condition_authority=AUTH(), allow_unconditional_wide=True)
ok(any("allowed by configuration" in r.get("detail", "") and "anywhere" in r.get("detail", "")
       for r in _urec.rows if r.get("action") == "ENVELOPE_ACTIVATED"),
   "F4-U2: ...and a deployment that opts in says so on the record: the "
   "activation record names the unconditional wide envelope")
# CLAIMS: driftcore/governance/physical_envelope.py:safety-counts-where-limits-are-enforced
_mech = EnvelopeController([_envelope("transport", 20.0, {"stowed"},
                                      EnforcementPoint.HARDWARE_MECHANICAL),
                            env("working", 800.0, required={"fence_closed"})],
                           "REMOTE_PHYSICAL_CONTROL", fallback_envelope="transport",
                           audit_required=False, condition_authority=AUTH())
_ok7, _ = _mech.request_change(_envelope("soft", 19.99, {"stowed"},
                                         EnforcementPoint.SUPERVISOR_PROCESS, by="agent"),
                               authorised_by="agent")
ok(not _ok7 and _mech._fallback.name == "transport",
   "F4-W7: an agent cannot replace a mechanically enforced 20N fallback with "
   "19.99N enforced in software — being safer counts where the limit is "
   "enforced, not just the number (was: accepted as a tightening)")
_nm = E2E()
_nm.select_for([EV("fence_closed", seq=1)])
assert is_wide(_nm), "PRIMER FAILED (nothing was tested)"
_prior = _nm.authorising_evidence
_ok1, _ = _nm.request_change(_envelope("gentle", 300.0, {"cell_empty"}),
                             authorised_by="justin", reason="visitors")
ok(_ok1 and _nm.active.name == "gentle" and _prior
   and _nm.authorising_evidence == "" and _nm.authorization_digest != "",
   "F4-M1: an envelope activated by a tightening is not named by its "
   "predecessor's evidence (its own condition was never attested), yet it "
   "still has an authorization distinct from the fallback's (was: it "
   "inherited the fence_closed digest)")
def _fragile(ev):
    bytes.fromhex(ev.proof)
    return verifier()(ev)
_fr4 = AUTH(verify_proof=_fragile).evaluate(
    [EV("fence_closed", seq=1), EV("fence_closed", seq=2, value=False, proof="zz")])
ok(_fr4.verifier_failed and any("from 'sensor-hub' at sequence 2" in r for r in _fr4.rejected),
   "F4-M2: a verifier that crashes on a junk proof is still treated as down, "
   "but the record names the record that crashed it, so an attack is not "
   "filed as an infrastructure fault")


# CLAIMS: driftcore/governance/physical_envelope.py:permissive-transitions-are-journaled-first
print("-- T1: journal-first is observed at the moment of recording --")
class _AtRecord:
    """Notes the controller's state at the instant each record is written."""
    def __init__(self):
        self.rows, self.ctl = [], None
    def record(self, **kw):
        c = self.ctl
        self.rows.append((kw["action"], c._active.name if c else None,
                          c._authorised_until if c else None,
                          c._evidence_digest if c else None))
_ar = _AtRecord()
_jc = EnvelopeController([env("transport", 20.0, required={"stowed"}),
                          env("working", 800.0, required={"fence_closed"})],
                         "REMOTE_PHYSICAL_CONTROL", fallback_envelope="transport",
                         audit=_ar, condition_authority=AUTH())
_ar.ctl = _jc
_jc.select_for([EV("fence_closed", seq=1)])
_sw = [r for r in _ar.rows if r[0] == "ENVELOPE_SWITCHED"]
ok(is_wide(_jc) and _sw and _sw[-1][1] == "transport",
   "F4-T1a: when the 20N->800N switch is recorded, 20N is still active — the "
   "record precedes the widening (observable without removing the fallback "
   "guard, which used to mask this order)")
_d_before, _u_before = _jc._evidence_digest, _jc._authorised_until
_jc.select_for([EV("fence_closed", seq=2)])
_rn4 = [r for r in _ar.rows if r[0] == "ENVELOPE_RENEWED"]
ok(is_wide(_jc) and _rn4 and _rn4[-1][3] == _d_before and _rn4[-1][2] == _u_before
   and _jc._evidence_digest != _d_before,
   "F4-T1b: a renewal on new evidence is recorded while the OLD deadline and "
   "evidence are still in force — recorded first, then extended")


print("-- T2, T3, T4: structural checks that can fail --")
def _all_writers(cls_node, attr):
    out = set()
    def targets(t):
        if isinstance(t, (ast.Tuple, ast.List)):
            for e in t.elts:
                yield from targets(e)
        elif isinstance(t, ast.Starred):
            yield from targets(t.value)
        else:
            yield t
    for fn in cls_node.body:
        if not isinstance(fn, ast.FunctionDef):
            continue
        for node in ast.walk(fn):
            ts = (node.targets if isinstance(node, ast.Assign) else
                  [node.target] if isinstance(node, (ast.AnnAssign, ast.AugAssign,
                                                     ast.For, ast.comprehension))
                  else [i.optional_vars for i in node.items if i.optional_vars]
                  if isinstance(node, ast.With) else [])
            for t in ts:
                for x in targets(t):
                    if (isinstance(x, ast.Attribute) and x.attr == attr
                            and isinstance(x.value, ast.Name) and x.value.id == "self"):
                        out.add(fn.name)
                    if (isinstance(x, ast.Subscript) and isinstance(x.value, ast.Attribute)
                            and x.value.attr == "__dict__"):
                        out.add(fn.name)
            if isinstance(node, ast.Call):
                f = node.func
                name = (f.id if isinstance(f, ast.Name) else
                        f.attr if isinstance(f, ast.Attribute) else "")
                if (name in ("setattr", "__setattr__") and len(node.args) >= 2
                        and isinstance(node.args[1], ast.Constant)
                        and node.args[1].value == attr):
                    out.add(fn.name)
    return out
ok(all(_all_writers(_cls, a) <= {"__init__", "_commit"}
       for a in ("_active", "_authorised_until", "_evidence_digest")),
   "F4-T2: the one-door check also sees tuple unpacking, for/with targets, "
   "setattr and __dict__ writes (was: `self._active, _ = envelope, None` "
   "passed it)")
class _PauseStore(ReplayStore):
    def __init__(self):
        super().__init__()
        self.reached, self.release, self.armed = _th4.Event(), _th4.Event(), None
    def get(self, key):
        v = super().get(key)
        if self.armed is not None and _th4.current_thread() is self.armed:
            self.armed = None
            self.reached.set(); self.release.wait(5)
        return v
_ps4 = _PauseStore()
_pa4 = AUTH(replay_state=_ps4)
_ta = _th4.Thread(target=lambda: _pa4.evaluate([EV("fence_closed", seq=1)]))
_ps4.armed = _ta
_ta.start(); _ps4.reached.wait(5)
_tb = _th4.Thread(target=lambda: _pa4.evaluate([EV("fence_closed", seq=2)]))
_tb.start(); _tb.join(0.3)
_waited = _tb.is_alive()
_ps4.release.set(); _ta.join(5); _tb.join(5)
ok(_waited, "F4-T3a: a second evaluate() on the same authority waits while the "
            "first is mid-batch (was: removing the lock passed every check)")
class _PauseSink:
    def __init__(self):
        self.reached, self.release, self.armed = _th4.Event(), _th4.Event(), None
    def record(self, **kw):
        if (self.armed is not None and _th4.current_thread() is self.armed
                and kw["action"] == "ENVELOPE_SWITCHED"):
            self.armed = None
            self.reached.set(); self.release.wait(5)
_pk = _PauseSink()
_pc = EnvelopeController([env("transport", 20.0, required={"stowed"}),
                          env("working", 800.0, required={"fence_closed"})],
                         "REMOTE_PHYSICAL_CONTROL", fallback_envelope="transport",
                         audit=_pk, condition_authority=AUTH())
_tx = _th4.Thread(target=lambda: _pc.select_for([EV("fence_closed", seq=1)]))
_pk.armed = _tx
_tx.start(); _pk.reached.wait(5)
_ty = _th4.Thread(target=lambda: _pc.select_for([EV("fence_closed", seq=2)]))
_ty.start(); _ty.join(0.3)
_waited2 = _ty.is_alive()
_pk.release.set(); _tx.join(5); _ty.join(5)
ok(_waited2, "F4-T3b: a second select_for() waits while the first is mid-"
             "transition (was: removing the controller lock passed every check)")
_allowed4 = {"MAX_SEQUENCE", "DEFAULT_REVIEW_BANDS", "_CAS_ATTEMPTS",
             "sequence", "evaluated_at"}
_found4 = set()
def _scan4(body):
    for st in body:
        if isinstance(st, (ast.Assign, ast.AnnAssign)) and st.value is not None and any(
                isinstance(n, ast.Constant) and type(n.value) in (int, float)
                for n in ast.walk(st.value)):
            for t in (st.targets if isinstance(st, ast.Assign) else [st.target]):
                _found4.add(t.id if isinstance(t, ast.Name) else ast.unparse(t))
        if isinstance(st, ast.ClassDef):
            _scan4(st.body)
_scan4(ast.parse(inspect.getsource(pe)).body)
ok(_found4 <= _allowed4,
   "F4-T4: every named number in the module is on a short, reviewed list — "
   "a constant like FORCE_OVERRIDE_N = 5000.0 fails this (it used to pass "
   "'DriftCore holds no physical values')")


print("-- H: a randomized property — 800N only on evidence nobody contradicts --")
# GLM's suggestion. The oracle knows only what was presented, not how the
# module works: 800N is allowed only if (1) this batch holds a genuine, fresh,
# current-epoch TRUE, and (2) no source's HIGHEST-sequence genuine reading so
# far is a FALSE. Junk, other-epoch and stale readings are noise it ignores.
def _property_run(seed, steps=250):
    rng = _rnd4.Random(seed)
    ctl = E2E(("sensor-hub", "sensor-b"))
    seqs = {"sensor-hub": 1, "sensor-b": 1}
    genuine = {"sensor-hub": [], "sensor-b": []}
    pool, wide, tight, bad = [], 0, 0, []
    for step in range(steps):
        batch, real = [], []
        for _ in range(rng.randint(0, 3)):
            src = rng.choice(("sensor-hub", "sensor-b"))
            k = rng.random()
            if k < 0.45:
                seqs[src] += rng.choice((0, 1, 1, 2))
                ev = EV("fence_closed", source=src, seq=seqs[src], value=rng.random() < 0.65)
                real.append(ev)
            elif k < 0.6 and pool:
                ev = rng.choice(pool)
                real.append(ev)
            elif k < 0.7:
                ev = EV("fence_closed", source=src, seq=seqs[src] + rng.randint(0, 3),
                        value=rng.random() < 0.5, proof="x")
            elif k < 0.8:
                ev = EV("fence_closed", source=src, seq=seqs[src] + 1, epoch="boot-epoch-Z")
            elif k < 0.9:
                ev = EV("fence_closed", source=src, seq=seqs[src] + 1, age=500.0)
            else:
                ev = EV("fence_closed", source=src, seq=seqs[src], value=rng.random() < 0.5)
                real.append(ev)
            batch.append(ev)
        for ev in real:
            genuine[ev.source].append(ev)
            pool.append(ev)
        try:
            ctl.select_for(batch)
        except EnvelopeRefused:
            pass
        if is_wide(ctl):
            wide += 1
            if not any(ev.value for ev in real):
                bad.append((step, "800N with no genuine TRUE in the batch"))
            for s, evs in genuine.items():
                if evs:
                    top = max(e.sequence for e in evs)
                    if any(e.sequence == top and not e.value for e in evs):
                        bad.append((step, f"800N while {s}'s latest reading is FALSE"))
        else:
            tight += 1
    return bad, wide, tight
for _seed in (1, 2, 3):
    _bad, _w, _t = _property_run(_seed)
    ok(not _bad and _w >= 10 and _t >= 10,
       f"F4-H{_seed}: {_w + _t} random batches (seed {_seed}) — genuine, "
       f"replayed, conflicting, junk, other-epoch and stale — never reach 800N "
       f"without an uncontradicted genuine TRUE; both outcomes occur, so the "
       f"property is not vacuous" + (f" FIRST: {_bad[0]}" if _bad else ""))


print(f"\n{passed}/{EXPECTED_CHECKS} checks passed")
