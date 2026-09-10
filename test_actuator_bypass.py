"""
test_actuator_bypass.py — reaching past the grant check is refused and recorded.

`GovernedActuator`'s docstring claimed drivers "cannot expose an ungoverned
actuation path because the only public entry point demands a valid coordinator
grant." Confirmed false by execution on 2026-09-01, in two ways:

  1. `_actuate` is a single underscore. `a._actuate("fire")` moved the actuator
     with no grant at all. A naming convention is not an access control, and
     Python enforces nothing here.
  2. `GrantAuthority` lives in-process and the actuator holds the SAME secret it
     verifies against, so anything reaching it mints a valid grant for any
     actuator and command.

(1) is now refused and recorded. (2) is not fixable in this file — a shared
secret in a shared address space is a shared secret — so it is made ASSERTABLE
instead, and the architectural fix stays what it already was: the safety wall in
a separate OS process under a different user, reachable only over a socket.

# CLAIMS: driftcore/verification/governed_actuator.py:direct-actuate-is-refused-and-recorded
# CLAIMS: driftcore/verification/governed_actuator.py:in-process-authority-is-assertable
# CLAIMS: driftcore/verification/governed_actuator.py:ungoverned-call-raises
# CLAIMS: driftcore/verification/governed_actuator.py:in-process-authority-requires-opt-in

Run: python3 test_actuator_bypass.py
"""

import threading

from driftcore.verification.governed_actuator import GovernedActuator, GrantAuthority

_p = _t = 0


def check(label, cond):
    global _p, _t
    _t += 1
    if cond:
        _p += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


def refused(fn):
    try:
        fn()
    except PermissionError:
        return True
    except Exception:
        return False
    return False


AUTH = GrantAuthority(in_process_only=True)


print("=== the governed path is unchanged ===")

_a = GovernedActuator("turret_1", AUTH)
check("a valid grant actuates", _a.actuate("fire", AUTH.mint("turret_1", "fire")))
check("...and the command was performed", _a.performed == ["fire"])
check("a forged grant is refused",
      refused(lambda: _a.actuate("fire", {"forged": True})))
check("...and performed nothing extra", _a.performed == ["fire"])
check("a grant for a DIFFERENT actuator is refused",
      refused(lambda: _a.actuate("fire", AUTH.mint("other", "fire"))))
check("a grant for a different COMMAND is refused",
      refused(lambda: _a.actuate("fire", AUTH.mint("turret_1", "stand_down"))))


print("=== direct-actuate-is-refused-and-recorded ===")

_b = GovernedActuator("turret_2", AUTH)
check("calling _actuate directly raises rather than actuating",
      refused(lambda: _b._actuate("fire")))
check("...and the actuator did not move", _b.performed == [])
check("...and the attempt is recorded, not merely blocked",
      len(_b.ungoverned_attempts) == 1)
check("...with the caller located, so it can be traced to a line",
      ":" in _b.ungoverned_attempts[0]["caller"]
      and "unavailable" not in _b.ungoverned_attempts[0]["caller"])
check("...and the record names the actuator",
      _b.ungoverned_attempts[0]["actuator_id"] == "turret_2")
check("a fresh actuator's record is empty — the list means something",
      GovernedActuator("x", AUTH).ungoverned_attempts == [])


print("=== a driver author cannot opt out by overriding ===")


class Motor(GovernedActuator):
    def _actuate(self, command):
        self.performed.append("MOTOR:" + command)
        return True


_m = Motor("motor_1", AUTH)
check("a subclass override is gated automatically, without the author opting in",
      refused(lambda: _m._actuate("spin")))
check("...and its bypass attempt is recorded too",
      len(_m.ungoverned_attempts) == 1)
check("...while the governed path through the subclass still works",
      _m.actuate("spin", AUTH.mint("motor_1", "spin"))
      and _m.performed == ["MOTOR:spin"])


class DeepMotor(Motor):
    """Two levels down, and inheriting an already-wrapped method."""


_d = DeepMotor("motor_2", AUTH)
check("a subclass that inherits rather than overrides is still gated",
      refused(lambda: _d._actuate("spin")))

# The idempotency marker in __init_subclass__ is DEFENSIVE, not load-bearing, and
# saying so is better than implying otherwise. An earlier check here asserted
# "not double-wrapped" against DeepMotor — which has no `_actuate` in its own
# __dict__ and is therefore never wrapped at all, so the check was true for a
# reason unrelated to the marker. Mutation G5 (drop the marker) left it green,
# which is how that surfaced. The only path that reaches an already-wrapped
# function is reassignment, and double-wrapping there turns out to be harmless:
# the outer wrapper raises before the inner one runs.


class _Reassigned(GovernedActuator):
    _actuate = Motor._actuate          # an already-wrapped function


_r = _Reassigned("r1", AUTH)
check("re-wrapping an already-gated method still records exactly one attempt "
      "per direct call",
      refused(lambda: _r._actuate("x")) and len(_r.ungoverned_attempts) == 1)
check("...and does not break the governed path",
      _r.actuate("x", AUTH.mint("r1", "x")) is True)


print("=== the window closes even when a driver raises ===")


class Broken(GovernedActuator):
    def _actuate(self, command):
        raise RuntimeError("driver fault")


_br = Broken("b1", AUTH)
try:
    _br.actuate("x", AUTH.mint("b1", "x"))
except RuntimeError:
    pass
check("a raising driver does not leave the gate open behind it",
      refused(lambda: _br._actuate("x")))


print("=== in-process-authority-is-assertable ===")

check("the actuator reports that its authority shares this interpreter",
      _a.authority_is_in_process is True)
check("...which is exposed as a property a deployment check can assert on, "
      "rather than a caveat in prose",
      isinstance(type(_a).authority_is_in_process, property))

# The gap itself, demonstrated rather than described. This is NOT a defect the
# gate above fixes, and a test that pretended otherwise would be worse than none.
_stolen = AUTH.mint("turret_1", "fire")
_c = GovernedActuator("turret_1", AUTH)
check("STILL OPEN, on purpose: anything holding the in-process authority mints "
      "a valid grant — the fix is out-of-process, not in this file",
      _c.actuate("fire", _stolen) is True)


print("=== the gate belongs to the thread that earned it ===")

# (external red-team, ChatGPT, 2026-09-01) `_in_governed_call` was one boolean on
# the instance, so a legitimate governed call held the window open for EVERY
# thread. Confirmed live on v106: thread B called _actuate directly with no
# grant, moved the actuator, and recorded NOTHING — the bypass was silent as well
# as successful. An authorization granted to A must not authorize B.
_inside, _hold = threading.Event(), threading.Event()


class _Slow(GovernedActuator):
    def _actuate(self, command):
        self.performed.append(command)
        _inside.set()
        _hold.wait(5)
        return True


_s = _Slow("turret_9", AUTH)
_th = threading.Thread(
    target=lambda: _s.actuate("fire", AUTH.mint("turret_9", "fire")))
_th.start()
_inside.wait(5)
_cross = refused(lambda: _s._actuate("BYPASS"))
_hold.set()
_th.join(5)

check("another thread cannot walk through an open governed window", _cross)
check("...and the actuator did not perform the ungoverned command",
      _s.performed == ["fire"])
check("...and the attempt is recorded — a silent bypass is the worse half",
      len(_s.ungoverned_attempts) == 1)


class _Reentrant(GovernedActuator):
    """A driver that legitimately re-enters actuate(). A thread-local BOOLEAN
    would be cleared by the inner call's finally while the outer is still
    running, trading a concurrency bypass for a reentrancy false-refusal. Hence
    a depth counter."""

    def _actuate(self, command):
        self.performed.append(command)
        if command == "outer":
            GovernedActuator.actuate(self, "inner",
                                     AUTH.mint("turret_10", "inner"))
            # THE POINT. The outer call is still inside its own window, so this
            # must succeed. A boolean — or a counter reset to 0 instead of
            # decremented — would have been cleared by the inner call's finally
            # and would refuse here. Mutation T2 (depth = 0) left an earlier
            # version of this check green, because that version only asserted
            # that nesting worked, never that the OUTER window survived the
            # inner one unwinding. That is the counter's entire reason to exist.
            self._actuate("still_inside")
        return True


_re = _Reentrant("turret_10", AUTH)
_nested_ok = True
try:
    _re.actuate("outer", AUTH.mint("turret_10", "outer"))
except PermissionError:
    _nested_ok = False
check("a nested governed call succeeds and the OUTER window survives it "
      "unwinding — a boolean would have been cleared by the inner finally",
      _nested_ok and _re.performed == ["outer", "inner", "still_inside"])
check("...and the window is closed once the outer call unwinds, not before",
      refused(lambda: _re._actuate("after")))

_results = []


def _worker(n):
    a = GovernedActuator(f"conc_{n}", AUTH)
    _results.append(a.actuate("go", AUTH.mint(f"conc_{n}", "go")))


_threads = [threading.Thread(target=_worker, args=(i,)) for i in range(8)]
[t.start() for t in _threads]
[t.join(5) for t in _threads]
check("eight concurrent governed calls all succeed — not over-blocking",
      len(_results) == 8 and all(_results))


print("=== in-process-authority-requires-opt-in ===")

# The whole point: a deployment that decides nothing must not RECEIVE the
# forgeable authority. It used to, via `grant_authority or GrantAuthority()`.
_refused = False
try:
    GrantAuthority()
except ValueError:
    _refused = True
check("constructing an in-process authority with no opt-in raises", _refused)

_refused_truthy = False
try:
    GrantAuthority(in_process_only="yes")
except ValueError:
    _refused_truthy = True
check("...and a truthy non-bool is not consent either", _refused_truthy)

check("the literal True still works, for tests and single-process development",
      GrantAuthority(in_process_only=True) is not None)

# And the coordinator must not silently supply one on the caller's behalf.
from driftcore.verification.coordinator import VerificationCoordinator, Outcome
from driftcore.verification.invariant_guard import InvariantGuard
from driftcore.verification.risk_classifier import RiskClassifier

_c = VerificationCoordinator(InvariantGuard(), RiskClassifier())
_d = _c.evaluate({"actuator_id": "motor_1", "command": "forward"})
check("a coordinator with no authority wired refuses to actuate rather than "
      "minting itself one",
      _d.outcome == Outcome.BLOCKED and _d.invariant == "no_grant_authority")
check("...and issues no grant", _d.grant is None)

_c2 = VerificationCoordinator(InvariantGuard(), RiskClassifier(),
                              grant_authority=GrantAuthority(in_process_only=True))
_d2 = _c2.evaluate({"actuator_id": "motor_1", "command": "forward"})
check("...while an explicitly wired authority still actuates (not over-blocking)",
      _d2.outcome == Outcome.PROCEED and isinstance(_d2.grant, dict))


print("=== mint-refuses-non-finite-ttl ===")

# (2026-09-06) `age > ttl` is False for NaN, so a NaN-TTL grant never timed out.
# Confirmed: it still actuated 0.2s later while a real 0.01s grant was refused.
# `signed_permission` already refused this at issue; this module did not. Found by
# enumerating every expiry comparison in the repo rather than fixing the one that
# had been reported — the third site of the same defect.
import math as _math

for _label, _ttl in (("NaN", float("nan")), ("+inf", float("inf")),
                     ("-inf", float("-inf")), ("zero", 0), ("negative", -5),
                     ("string", "5"), ("bool", True)):
    _rejected = False
    try:
        AUTH.mint("t_ttl", "fire", ttl_seconds=_ttl)
    except ValueError:
        _rejected = True
    check(f"a {_label} grant lifetime is refused at ISSUE, not minted", _rejected)

check("...while a positive finite lifetime still mints and actuates (control)",
      GovernedActuator("t_ok", AUTH).actuate(
          "fire", AUTH.mint("t_ok", "fire", ttl_seconds=5.0)) is True)


print("-" * 60)
print(f"  {_p}/{_t} tests passed")
if _p != _t:
    raise SystemExit(1)
