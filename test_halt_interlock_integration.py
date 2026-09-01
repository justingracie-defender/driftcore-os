"""
test_halt_interlock_integration.py — is the halt actually ON the actuation path?

Two independent reviews converged on the same point: a safety mechanism that is not on
every relevant execution path is documentation, not enforcement, and the dominant
remaining risk is INTEGRATION rather than more policy modules.

Tested, and it was true in the worst way. `SafeHalt` was referenced by exactly one file
in the entire package: itself. Nothing connected it to actuation. So with a HARD halt
active — "ALL OPERATIONS SUSPENDED" — a valid grant still moved the arm. The halt was a
variable, not a stop.

These tests are deliberately CROSS-MODULE. Module-level tests could not have caught
this: safe_halt behaved correctly, mediated_actuation behaved correctly, and the system
was unsafe because nothing joined them.

Run: python3 test_halt_interlock_integration.py
"""
import os, tempfile, time

from driftcore.safety.safe_halt import SafeHalt
from driftcore.verification.mediated_actuation import (
    ActuationBroker, ProductionActuationBroker, ActuatorProxy, ActuationRefused, Effect)
from driftcore.verification.signed_permission import Grant, PermissionVerifier

_passed = _total = 0


def check(label, cond):
    global _passed, _total
    _total += 1
    if cond:
        _passed += 1; print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


D = tempfile.mkdtemp(); KEY = "operator-key"
BIND = PermissionVerifier.bind_action("arm", "move", {"t": "cup"})
_n = [0]


def broker(name, halt_state, moved):
    v = PermissionVerifier(); v.register_key("operator", KEY, unrestricted=True)
    b = ActuationBroker(os.path.join(D, f"{name}.sock"), v,
                        enforce_effects=True, halt_state=halt_state)
    b.register_actuator("arm", lambda **k: moved.append(1) or "ARM MOVED",
                        required_scope=("arm:move",),
                        effects=[Effect.PHYSICAL_FORCE], effect_declared_by="operator")
    b.start(); time.sleep(0.1)
    return b


def actuate(name):
    _n[0] += 1
    g = Grant.issue(KEY, key_id="operator", role="operator", scope=("arm:move",),
                    subject="robot", ttl_seconds=300, nonce=f"i{_n[0]}",
                    action_binding=BIND)
    try:
        return ActuatorProxy(os.path.join(D, f"{name}.sock"), "arm").execute(
            "move", g, t="cup")
    except ActuationRefused as e:
        return f"REFUSED:{e}"


print("=== a HARD halt must actually stop actuation ===")

halt = SafeHalt(verifier=lambda p: p == "alice-badge")
moved = []
b = broker("main", lambda: halt.status()["active"], moved)

check("before any halt, a valid grant actuates", actuate("main") == "ARM MOVED")
halt.hard_halt()
out = actuate("main")
check("during a HARD halt, the SAME valid grant is REFUSED",
      out.startswith("REFUSED"))
check("...and the refusal names the halt", "halted" in out)
check("the actuator did NOT run while halted", len(moved) == 1)

# a SOFT halt is still a halt for actuation purposes
halt.release("alice-badge")
halt.soft_halt()
check("a SOFT halt also blocks actuation", actuate("main").startswith("REFUSED"))

halt.release("alice-badge")
check("after an AUTHORISED release, actuation resumes", actuate("main") == "ARM MOVED")
check("the actuator ran exactly twice — never during a halt", len(moved) == 2)
b.stop()


print("=== the interlock fails CLOSED, never open ===")

for hs, label, name in (
        (lambda: (_ for _ in ()).throw(RuntimeError("halt store unreachable")),
         "a halt check that RAISES", "raises"),
        (lambda: 1, "a truthy non-bool (an IntEnum would invert a stop)", "int"),
        (lambda: "no", "a string", "str"),
        (lambda: None, "None", "none")):
    m = []
    bb = broker(name, hs, m)
    out = actuate(name)
    check(f"{label} -> refused", out.startswith("REFUSED"))
    check(f"{label} -> actuator did not run", len(m) == 0)
    bb.stop()


print("=== an unhalted system is not blocked (discrimination) ===")

m = []
bb = broker("clear", lambda: False, m)
check("halt_state=False permits actuation", actuate("clear") == "ARM MOVED")
check("the actuator really ran", len(m) == 1)
bb.stop()


print("=== production deployments cannot omit the interlock ===")

v = PermissionVerifier(); v.register_key("operator", KEY, unrestricted=True)
raised = False
try:
    ProductionActuationBroker(os.path.join(D, "p.sock"), v,
                              evidence_path=os.path.join(D, "ev"))
except ValueError:
    raised = True
check("a production broker without halt_state is refused", raised)

ok = True
try:
    pb = ProductionActuationBroker(os.path.join(D, "p2.sock"), v,
                                   evidence_path=os.path.join(D, "ev2"),
                                   halt_state=lambda: False)
except ValueError:
    ok = False
check("...and is constructible once the interlock is supplied", ok)


print("-" * 60)
print(f"  {_passed}/{_total} tests passed")
if _passed != _total:
    raise SystemExit(1)
