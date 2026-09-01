"""
test_halt_release_atomicity.py — a halt raised during a release survives it.

Both release paths in safe_halt.py decided against the halt state and then mutated
it, with the authorisation work sitting in between. Both were demonstrated
deterministically before being fixed — not inferred from a passing concurrency
test, which is only evidence that a race did not manifest under one scheduler.

  A1  `release()` took NO LOCK AT ALL while `hard_halt()` took one. A verifier
      blocked mid-call; `hard_halt()` succeeded from another thread because nothing
      blocked it; the returning `release()` then cleared a HARD halt it had never
      evaluated. The window is as wide as the verifier is slow, and the verifier is
      supplied by the deployment.

  A2  `release_with_approvals()` LOOKED locked and was worse for it. The lock was
      held to derive the required severity, then dropped for `evaluate()` and for
      the mutation. A SOFT halt escalated to HARD while the authority was
      evaluating, and MODERATE-level approvals cleared the HARD halt. That is the
      same severity downgrade red-team #1 closed for the caller-supplied `severity`
      argument, reopened through a timing window instead of a parameter.

  A3  ABA. SOFT -> released -> SOFT compares equal on (active, level) while being a
      different halt entirely. Detection is a generation counter, not a tuple.

  A4  A refused release must not land in `unverified_releases`. That list is what
      makes `release_integrity_ok` assertable by a deployment check, so an entry for
      a release that never happened is a false alarm on the one signal that says
      whether the release log can be read as evidence a human acted.

The lock is deliberately NOT held across `_is_human` or the deployment's verifier.
Holding a safety-kernel lock across third-party code means a wedged verifier blocks
hard_halt(), and a halt that cannot be RAISED is the worse failure. The shape is
snapshot -> decide unlocked -> compare-and-swap.

NOTE on assertions: every check below reads the FIELDS it cares about rather than
comparing status() to an exact dict. An earlier draft of this file used exact dicts
and would have broken the moment `unverified_releases` / `release_integrity_ok`
joined status() — repeating, in a file written days later, the exact mistake
recorded at test_halt_and_restart.py's concurrency check. Asserting halt state must
not pin the field set of status() as a side effect.

Run: python3 test_halt_release_atomicity.py
"""

# CLAIMS: driftcore/safety/safe_halt.py:policy-unpinned-refuses
# CLAIMS: driftcore/safety/safe_halt.py:policy-gate-never-raises

import threading

from driftcore.safety.safe_halt import SafeHalt

_passed = 0
_total = 0


def check(label, cond):
    global _passed, _total
    _total += 1
    if cond:
        _passed += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


def halted(h, level):
    s = h.status()
    return s["active"] is True and s["level"] == level


def clear(h):
    s = h.status()
    return s["active"] is False and s["level"] is None


class _Gate:
    """Blocks a thread at a chosen point so the window is deterministic."""

    def __init__(self):
        self.entered = threading.Event()
        self.may_return = threading.Event()

    def pause(self, timeout=5):
        self.entered.set()
        self.may_return.wait(timeout)


print("=== A1: release() cannot erase a halt raised while it was authorising ===")

_g = _Gate()
_h = SafeHalt(verifier=lambda p: (_g.pause(), True)[1])
_h.soft_halt()
_result = []
_t = threading.Thread(target=lambda: _result.append(_h.release("operator_jane")))
_t.start()
check("A1: the verifier is reached, so the release has passed its decision point",
      _g.entered.wait(5))
_h.hard_halt()
check("A1: hard_halt() is not blocked by the in-flight release", halted(_h, "HARD"))
_g.may_return.set()
_t.join(5)
check("A1: the HARD halt is still in force after the release returns",
      halted(_h, "HARD"))
check("A1: ...and the release reports the refusal rather than SYSTEM_RESUMED",
      _result and _result[0].startswith("RELEASE_DENIED"))
check("A1: ...naming the state change, not some unrelated denial reason",
      _result and "changed while this release" in _result[0])
check("A1: the refusal is in the halt log",
      any("state_changed_during_authorization" in e["event"] for e in _h.log))


print("=== A1b: the ordinary uncontended release still works ===")

_h2 = SafeHalt(verifier=lambda p: True)
_h2.soft_halt()
check("A1b: a verified principal releases a soft halt",
      _h2.release("operator_jane") == "SYSTEM_RESUMED")
check("A1b: ...and the state is actually cleared", clear(_h2))


print("=== A2: approvals cannot be spent against a halt that escalated ===")


class _SlowAuthority:
    def __init__(self, gate):
        self.gate = gate
        self.seen = []

    def evaluate(self, severity, approvals):
        self.seen.append(severity)
        self.gate.pause()
        return {"status": "AUTHORIZED", "reason": "ok",
                "approvals": [{"approver_id": "jane"}]}


_g2 = _Gate()
_auth = _SlowAuthority(_g2)
_h3 = SafeHalt(restart_authority=_auth)
_h3.soft_halt()
_result2 = []
_t2 = threading.Thread(
    target=lambda: _result2.append(_h3.release_with_approvals([{"a": 1}])))
_t2.start()
_g2.entered.wait(5)
check("A2: the severity bar was derived from the SOFT halt",
      _auth.seen and _auth.seen[0].name == "MODERATE")
_h3.hard_halt()
check("A2: the halt escalates to HARD while the authority is evaluating",
      halted(_h3, "HARD"))
_g2.may_return.set()
_t2.join(5)
check("A2: an AUTHORIZED verdict does NOT clear the escalated halt",
      halted(_h3, "HARD"))
check("A2: ...and the refusal names the severity the approvals were checked at",
      _result2 and _result2[0].startswith("RELEASE_DENIED")
      and "MODERATE" in _result2[0])


print("=== A2b: the ordinary strong release still works ===")


class _FastAuthority:
    def evaluate(self, severity, approvals):
        return {"status": "AUTHORIZED", "reason": "ok",
                "approvals": [{"approver_id": "jane"}]}


_h4 = SafeHalt(restart_authority=_FastAuthority())
_h4.hard_halt()
check("A2b: an uncontended AUTHORIZED verdict releases the halt",
      _h4.release_with_approvals([{"a": 1}]) == "SYSTEM_RESUMED")
check("A2b: ...and the state is cleared", clear(_h4))


print("=== A3: ABA — the same (active, level) is not the same halt ===")

_g3 = _Gate()
_h5 = SafeHalt(verifier=lambda p: (_g3.pause(), True)[1])
_h5.soft_halt()
_result3 = []
_t3 = threading.Thread(target=lambda: _result3.append(_h5.release("operator_jane")))
_t3.start()
_g3.entered.wait(5)
# Release and re-raise the SAME level from another path. A tuple comparison sees
# {"active": True, "level": "SOFT"} both times and concludes nothing happened.
_h5._verifier = lambda p: True          # unblocked path for the interleaved release
SafeHalt.release(_h5, "operator_bob")
_h5.soft_halt()
_h5._verifier = lambda p: (_g3.pause(), True)[1]
check("A3: the interleaved release+re-halt leaves (active, level) identical",
      halted(_h5, "SOFT"))
_g3.may_return.set()
_t3.join(5)
check("A3: the SECOND soft halt is not cleared by the first release's decision",
      _h5.status()["active"] is True)
check("A3: ...refused as a state change, despite (active, level) comparing equal",
      _result3 and _result3[0].startswith("RELEASE_DENIED"))


print("=== A4: a refused release does not pollute the integrity ledger ===")

# No verifier and LABEL_ONLY identity: a SUCCESSFUL release here is recorded as
# unverified by design (C2). A REFUSED one must record nothing at all, or
# release_integrity_ok goes False for a release that never happened.
_h7 = SafeHalt()
check("A4: (control) a fresh halt has an empty integrity ledger",
      _h7.status()["unverified_releases"] == []
      and _h7.status()["release_integrity_ok"] is True)
_h8 = SafeHalt()
_h8.soft_halt()
_h8.release("operator_jane")
check("A4: (control) a SUCCESSFUL unverified release does land in the ledger",
      len(_h8.status()["unverified_releases"]) == 1
      and _h8.status()["release_integrity_ok"] is False)

_g5 = _Gate()
import driftcore.authority.human_identity as _hi
_real_status = _hi.status
# The ledger is only written on the NO-VERIFIER path, so the window has to be opened
# in the unlocked call that path actually makes: the identity-module status lookup.
# An earlier draft used a blocking verifier here, which meant `verifiable` was always
# True and the ledger branch was never reached — the check passed without exercising
# anything. Caught by mutating the fix, not by reading the test.
_hi.status = lambda: (_g5.pause(), _real_status())[1]
try:
    _h9 = SafeHalt()
    _h9.soft_halt()
    _r9 = []
    _t9 = threading.Thread(target=lambda: _r9.append(_h9.release("operator_jane")))
    _t9.start()
    _g5.entered.wait(5)
    _h9.hard_halt()
    _g5.may_return.set()
    _t9.join(5)
finally:
    _hi.status = _real_status
check("A4: the racing release took the no-verifier path (ledger branch reachable)",
      _h9._verifier is None)
check("A4: ...and was refused",
      _r9 and _r9[0].startswith("RELEASE_DENIED"))
check("A4: the refused release wrote nothing to unverified_releases",
      _h9.status()["unverified_releases"] == [])
check("A4: ...so release_integrity_ok is not falsely tripped",
      _h9.status()["release_integrity_ok"] is True)


print("=== A5: the identity policy cannot change under an in-flight release ===")

import driftcore.authority.human_identity as _hi

_real_is_human = _hi.is_human
_hi.reset_policy()
# Control, both directions: establish what the two policies actually say about this
# principal, so the race result below means something.
check("A5: (control) LABEL_ONLY permits an unregistered principal",
      _real_is_human("operator_jane", action="safe_halt_release") is True)
_hi.register_human_principal("someone_else")
check("A5: (control) REGISTERED refuses that same principal",
      _real_is_human("operator_jane", action="safe_halt_release") is False)
_hi.reset_policy()

_g6 = _Gate()


def _slow_is_human(*a, **kw):
    # Real check, then a pause. Under ATTESTED this is signature verification —
    # genuinely slow work, not an artificial delay.
    r = _real_is_human(*a, **kw)
    _g6.pause()
    return r


_hi.is_human = _slow_is_human
try:
    _h10 = SafeHalt()                       # no verifier: the C2 ledger path
    _h10.soft_halt()
    _r10 = []
    _t10 = threading.Thread(
        target=lambda: _r10.append(_h10.release("operator_jane")))
    _t10.start()
    _g6.entered.wait(5)
    _hi.register_human_principal("someone_else")   # public API, LABEL_ONLY -> REGISTERED
    _g6.may_return.set()
    _t10.join(5)
finally:
    _hi.is_human = _real_is_human
    _hi.reset_policy()

check("A5: a release permitted under the old policy does not commit",
      _h10.status()["active"] is True)
check("A5: ...refused as a policy change, not as some other denial",
      _r10 and _r10[0].startswith("RELEASE_DENIED")
      and "identity policy changed" in _r10[0])
check("A5: ...and it is NOT logged as a verified human release",
      not any(e["event"].startswith("HALT_RELEASED by") for e in _h10.log))
check("A5: ...nor recorded as an unverified one — it did not happen at all",
      _h10.status()["unverified_releases"] == []
      and _h10.status()["release_integrity_ok"] is True)


print("=== A6: the authorisation wiring cannot change under an in-flight release ===")


class _RefusingAuthority:
    def __init__(self):
        self.called = False

    def evaluate(self, severity, approvals):
        self.called = True
        return {"status": "DENIED", "reason": "no approvals supplied"}


_g7 = _Gate()
_h11 = SafeHalt(verifier=lambda p: (_g7.pause(), True)[1])   # no RestartAuthority yet
_h11.hard_halt()
_r11 = []
_t11 = threading.Thread(target=lambda: _r11.append(_h11.release("operator_jane")))
_t11.start()
_g7.entered.wait(5)
_auth11 = _RefusingAuthority()
_h11._restart_authority = _auth11        # deployment wiring completes mid-flight
check("A6: installing the authority did not move the halt generation",
      _h11._generation == 1)
_g7.may_return.set()
_t11.join(5)
check("A6: the HARD halt is not released by the weak path", halted(_h11, "HARD"))
check("A6: ...refused as a wiring change",
      _r11 and _r11[0].startswith("RELEASE_DENIED")
      and "authorisation wiring changed" in _r11[0])
check("A6: ...and the strong authority was never consulted either way",
      _auth11.called is False)


print("=== the generation counter is monotonic and private ===")

_h6 = SafeHalt(verifier=lambda p: True)
_g0 = _h6._generation
_h6.soft_halt()
_g1 = _h6._generation
_h6.hard_halt()
_g2n = _h6._generation
check("gen: every state mutation advances the counter", _g0 < _g1 < _g2n)
_h6.hard_halt()
check("gen: a no-op halt request does NOT advance it", _h6._generation == _g2n)
# Asserts the counter stays internal WITHOUT pinning the field set of status().
check("gen: the counter is not exposed through status()",
      not any("generation" in k for k in _h6.status()))


print("=== the tagged claims on _policy_generation ===")

from driftcore.safety import safe_halt as _sh

check("policy-unpinned-refuses: a readable policy yields an int version",
      isinstance(_sh._policy_generation(), int))

# Force the lookup to fail the way a missing or broken identity module would.
_saved = _hi.policy_generation
try:
    _hi.policy_generation = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
    _unreadable = _sh._policy_generation()
    check("policy-gate-never-raises: a raising identity module does not propagate",
          _unreadable is None)
    _second = _sh._policy_generation()
    check("policy-unpinned-refuses: two failed reads do not compare equal",
          not (_unreadable is not None and _unreadable == _second))
    # The property that matters is what release() does with it, not the sentinel.
    _h12 = SafeHalt(verifier=lambda p: True)
    _h12.soft_halt()
    _res12 = _h12.release("operator_jane")
    check("policy-unpinned-refuses: release refuses when the policy cannot be pinned",
          _res12.startswith("RELEASE_DENIED") and "identity policy" in _res12)
    check("policy-unpinned-refuses: ...and the halt is still in force",
          _h12.status()["active"] is True)
finally:
    _hi.policy_generation = _saved

# A non-int return is also "unpinned", not a version to compare.
try:
    _hi.policy_generation = lambda: "not-a-version"
    check("policy-unpinned-refuses: a non-int version reads as unpinned",
          _sh._policy_generation() is None)
finally:
    _hi.policy_generation = _saved


print("-" * 60)
print(f"  {_passed}/{_total} tests passed")
if _passed != _total:
    raise SystemExit(1)
