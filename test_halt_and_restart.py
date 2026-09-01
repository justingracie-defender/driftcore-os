"""
test_halt_and_restart.py — stopping, and the authority to un-stop.

Two modules that had no tests and sit directly on the "can this machine move again"
decision. What a red-team pass found, all reproduced before being fixed:

  S1  `SafeHalt.release(authorized_by)` checked a DENYLIST OF ONE STRING: anything
      that was not literally "agent" (and not empty) released the halt. So
      `release("human_operator")` freed a HARD halt. Naming an authority is not proof
      of it — the exact failure this project hunts everywhere else.
  S2  a halt could be DOWNGRADED without any authorisation: calling soft_halt() while
      in HARD halt silently turned "all operations suspended" into "non-critical ops
      paused", with nothing in the log to show a halt had been weakened.
  R1  `RestartAuthority.evaluate()` NEVER CALLED `Approval.verify()`. Approvals were
      matched on role and distinct approver_id only, so forged approvals built with a
      bogus secret returned AUTHORIZED — under a reason that claimed they were
      "present and SIGNED". A decorative signature is worse than none: the log said
      signed.

Run: python3 test_halt_and_restart.py
"""

from driftcore.safety.safe_halt import SafeHalt
from driftcore.governance import restart_authority as RA

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


print("=== halts escalate, and never quietly weaken (S2) ===")

h = SafeHalt()
h.hard_halt()
check("hard_halt() sets HARD", h.status()["level"] == "HARD")
msg = h.soft_halt()
check("S2: soft_halt() while HARD does NOT downgrade", h.status()["level"] == "HARD")
check("S2: and it says so rather than silently succeeding", "REMAINS" in msg)
check("S2: the attempt is recorded",
      any("WHILE_IN_HARD" in e["event"] for e in h.log))

h2 = SafeHalt()
h2.soft_halt()
h2.hard_halt()
check("escalation SOFT -> HARD still works", h2.status()["level"] == "HARD")
check("a halt stays active through the attempt", h2.status()["active"] is True)


print("=== releasing a halt needs more than a chosen string (S1) ===")

h3 = SafeHalt()
h3.hard_halt()
check("the literal 'agent' is still refused",
      "DENIED" in h3.release("agent"))
r = h3.release("human_operator")
check("S1: a HARD halt is NOT released by a bare string with no verifier",
      "DENIED" in r and h3.active is True)
check("S1: the refusal names the real path (RestartAuthority)",
      "RestartAuthority" in r)

# a SOFT halt is software-only recovery: the simple path is still allowed
h4 = SafeHalt()
h4.soft_halt()
check("a SOFT halt can still be released simply (software-only recovery)",
      h4.release("human_operator") == "SYSTEM_RESUMED" and h4.active is False)


print("=== with a real verifier installed, the principal must actually verify ===")

badge = "alice-badge-7731"
h5 = SafeHalt(verifier=lambda p: p == badge)
h5.hard_halt()
check("an unverified principal is refused", "DENIED" in h5.release("human_operator"))
check("...and the halt is still active", h5.active is True)
check("a verified principal releases it",
      h5.release(badge) == "SYSTEM_RESUMED" and h5.active is False)

# a verifier that raises must not release the halt
h6 = SafeHalt(verifier=lambda p: (_ for _ in ()).throw(RuntimeError("badge reader down")))
h6.hard_halt()
out = h6.release(badge)
check("a verifier that RAISES does not release the halt",
      "DENIED" in out and h6.active is True)
check("...and says the question went unanswered", "unanswered" in out)


print("=== restart approvals must be genuinely signed (R1) ===")

profile = type("Profile", (), {"requires_physical_stack": lambda self: False,
                               "name": "software_only"})()
SECRET = "deployment-approval-key"
sev = RA.ShutdownSeverity.MODERATE

ra_unconfigured = RA.RestartAuthority(profile)
req = ra_unconfigured.requirement_for(sev)
forged = [RA.Approval(f"attacker-{i}", list(rs)[0], secret="WRONG-SECRET")
          for i, rs in enumerate(req["required"])]

out = ra_unconfigured.evaluate(sev, forged)
check("R1: with no secret configured, nothing is authorised",
      out["status"] == "DENIED")
check("R1: and the reason says signatures cannot be checked",
      "signature" in out["reason"].lower())

ra = RA.RestartAuthority(profile, secret=SECRET)
out = ra.evaluate(sev, forged)
check("R1: FORGED approvals are DENIED", out["status"] == "DENIED")
check("R1: the forged ones do not verify",
      all(a.verify(SECRET) is False for a in forged))

real = [RA.Approval(f"alice-{i}", list(rs)[0], secret=SECRET)
        for i, rs in enumerate(req["required"])]
out = ra.evaluate(sev, real)
check("genuinely signed approvals ARE authorised (not a blanket refusal)",
      out["status"] == "AUTHORIZED")
check("the stated reason now actually reflects what was checked",
      "signature verified" in out["reason"])

# a forged approval mixed in must be discarded, not poison the whole set
mixed = real + [RA.Approval("mallory", list(req["required"][0])[0], secret="WRONG")]
out = ra.evaluate(sev, mixed)
check("a forged approval is discarded while real ones still count",
      out["status"] == "AUTHORIZED")
check("the forged approver is not among the satisfied set",
      all(a["approver_id"] != "mallory" for a in out.get("approvals", [])))

# (red-team #8) The previous version of this asserted
#     out["status"] in ("AUTHORIZED", "DENIED")
# which accepts EITHER outcome and therefore tests nothing while reading as coverage.
# A safety test that cannot fail is worse than no test: it manufactures false
# evidence. Construct the case that must actually be denied — a severity needing TWO
# DISTINCT role-holders, satisfied by one person wearing both hats.
multi_sev = RA.ShutdownSeverity.SEVERE
multi_req = ra.requirement_for(multi_sev)
check("the chosen severity really does need more than one role-set",
      len(multi_req["required"]) >= 2)
one_person = [RA.Approval("alice-only", list(rs)[0], secret=SECRET)
              for rs in multi_req["required"]]
out = ra.evaluate(multi_sev, one_person)
check("#8: ONE person cannot satisfy two required roles (asserted, not accepted "
      "either way)", out["status"] == "DENIED")
two_people = [RA.Approval(f"person-{i}", list(rs)[0], secret=SECRET)
              for i, rs in enumerate(multi_req["required"])]
check("#8: two DISTINCT people with the right roles are authorised",
      ra.evaluate(multi_sev, two_people)["status"] == "AUTHORIZED")


print("=== timestamps are timezone-aware ===")

h7 = SafeHalt()
h7.soft_halt()
check("halt log entries are aware UTC (not naive utcnow)",
      h7.log[-1]["timestamp"].endswith("+00:00"))


print("=== #7: HARD release is COMPOSED with the stronger authority ===")

_prof = type("Profile", (), {"requires_physical_stack": lambda self: False,
                             "name": "software_only"})()
_SECRET = "compose-secret"
_sev = RA.ShutdownSeverity.MODERATE
_ra = RA.RestartAuthority(_prof, secret=_SECRET)
_req = _ra.requirement_for(_sev)


def _composed():
    h = SafeHalt(verifier=lambda p: p == "alice", restart_authority=_ra,
                 severity_for_release=_sev)
    h.hard_halt()
    return h


# The weak path must NOT satisfy a HARD release once a strong authority exists.
# This check has to run BEFORE the verifier branch: placed after it, an installed
# verifier short-circuited the rule and the weak path still released the halt — the
# fix was present but unreachable, which reads as closed while being open.
_h = _composed()
_out = _h.release("alice")
check("#7: a verified single principal can NO LONGER release a HARD halt",
      "DENIED" in _out and _h.active is True)
check("#7: the refusal names the path that can", "RestartAuthority" in _out)

_h = _composed()
_forged = [RA.Approval("mallory", list(_req["required"][0])[0], secret="WRONG")]
check("#7: forged approvals do not release it",
      "DENIED" in _h.release_with_approvals(_forged) and _h.active is True)

_h = _composed()
# NOTE: the approvals must meet the bar DERIVED FROM THE HALT LEVEL (see #1), not the
# configured `severity_for_release`. A HARD halt requires SEVERE-level approvals even
# though this SafeHalt was constructed with MODERATE — the earlier version of this test
# passed MODERATE approvals and encoded the very vulnerability #1 describes.
_severe_req = _ra.requirement_for(RA.ShutdownSeverity.SEVERE)
_real = [RA.Approval(f"appr-{i}", list(rs)[0], secret=_SECRET)
         for i, rs in enumerate(_severe_req["required"])]
check("#7: signed, role-correct approvals DO release it (not a blanket refusal)",
      _h.release_with_approvals(_real) == "SYSTEM_RESUMED" and _h.active is False)

# a SOFT halt is software-only recovery and keeps the simple path
_hs = SafeHalt(verifier=lambda p: p == "alice", restart_authority=_ra,
               severity_for_release=_sev)
_hs.soft_halt()
check("#7: a SOFT halt still uses the simple path", _hs.release("alice") == "SYSTEM_RESUMED")

# release_with_approvals refuses rather than falling back when nothing is wired
_hn = SafeHalt()
_hn.hard_halt()
check("#7: with no authority installed, release_with_approvals REFUSES rather than "
      "falling back to the weaker path",
      "DENIED" in _hn.release_with_approvals([]) and _hn.active is True)


print("=== #1 (P0): the caller cannot choose a weaker authorisation bar ===")

_SEV = RA.ShutdownSeverity


def _appr(sev_level):
    return [RA.Approval(f"p{i}", list(rs)[0], secret=_SECRET)
            for i, rs in enumerate(_ra.requirement_for(sev_level)["required"])]


_h = SafeHalt(restart_authority=_ra)
_h.hard_halt()
_out = _h.release_with_approvals(_appr(_SEV.MINOR), severity=_SEV.MINOR)
check("#1: a HARD halt is NOT released by MINOR approvals even when the caller "
      "declares severity=MINOR", "DENIED" in _out and _h.active is True)

check("#1: the bar is derived from the halt level, so SEVERE approvals release it "
      "even under a caller-supplied MINOR",
      _h.release_with_approvals(_appr(_SEV.SEVERE), severity=_SEV.MINOR)
      == "SYSTEM_RESUMED")

_h = SafeHalt(restart_authority=_ra)
_h.hard_halt()
check("#1: with NO severity supplied, the requirement is still derived (MINOR "
      "approvals refused)",
      "DENIED" in _h.release_with_approvals(_appr(_SEV.MINOR)) and _h.active is True)
check("#1: ...and satisfied by approvals meeting the derived bar",
      _h.release_with_approvals(_appr(_SEV.SEVERE)) == "SYSTEM_RESUMED")


print("=== #4/#9/#10: release preconditions and untrusted input ===")

_h = SafeHalt(restart_authority=_ra)
check("#4: releasing when nothing is halted is refused (no bogus SYSTEM_RESUMED)",
      "no active halt" in _h.release_with_approvals(_appr(_SEV.SEVERE)))

_h = SafeHalt(restart_authority=_ra)
_h.hard_halt()
_flood = [RA.Approval(f"x{i}", list(_ra.requirement_for(_SEV.MINOR)["required"][0])[0],
                      secret="WRONG") for i in range(5000)]
check("#9: an oversized approval list is refused BEFORE signature verification",
      "exceeds the limit" in _h.release_with_approvals(_flood) and _h.active is True)


class _BadAuthority:
    def evaluate(self, *a, **k):
        return None
    def requirement_for(self, s):
        return _ra.requirement_for(s)


_h = SafeHalt(restart_authority=_BadAuthority())
_h.hard_halt()
check("#10: a malformed authority result refuses instead of raising or releasing",
      "not a decision" in _h.release_with_approvals(_appr(_SEV.SEVERE))
      and _h.active is True)


print("=== #3: a raised HARD halt survives concurrent release attempts ===")

import threading

_h = SafeHalt(restart_authority=_ra)
_errors = []


def _releasers():
    for _ in range(300):
        try:
            _h.release("human_operator")
            _h.release_with_approvals(_appr(_SEV.MINOR), severity=_SEV.MINOR)
        except Exception as e:      # pragma: no cover - a race would land here
            _errors.append(e)


def _halters():
    for _ in range(300):
        _h.hard_halt()


_threads = ([threading.Thread(target=_releasers) for _ in range(4)]
            + [threading.Thread(target=_halters) for _ in range(2)])
for _t in _threads:
    _t.start()
for _t in _threads:
    _t.join()
_h.hard_halt()
check("#3: concurrent halt/release raises nothing", _errors == [])
check("#3: after a final hard_halt() the system is definitively HARD-halted",
      _h.status()["active"] is True and _h.status()["level"] == "HARD")
# (2026-08-31) This was `_h.status() == {"active": True, "level": "HARD"}`. The exact
# dict pinned the FIELD SET of status() as a side effect of asserting the HALT STATE,
# so adding `unverified_releases` / `release_integrity_ok` failed a concurrency check
# that has nothing to do with either field. Narrowed to what the check's own name
# claims. This is NOT a field allowlist — no such guard exists for SafeHalt, and if
# one is wanted it should be its own test that says so, not a by-product of an
# equality operator in a threading test.


print("=== the hardened broker profile is safe BY DEFAULT ===")

import os, tempfile
from driftcore.verification.mediated_actuation import (
    ProductionActuationBroker, PRODUCTION_REQUIRED_FLAGS)
from driftcore.verification.signed_permission import PermissionVerifier

_d = tempfile.mkdtemp()
_v = PermissionVerifier()
_v.register_key("op", "k", unrestricted=True)


def _prod(**kw):
    kw.setdefault("evidence_path", os.path.join(_d, "ev"))
    # A production broker now also requires a halt interlock: a halt that no
    # execution path consults is a variable, not a stop.
    kw.setdefault("halt_state", lambda: False)
    return ProductionActuationBroker(
        os.path.join(_d, f"s{len(kw)}{abs(hash(str(kw)))%9999}.sock"), _v, **kw)


check("there are required production flags at all", len(PRODUCTION_REQUIRED_FLAGS) >= 4)
for flag in PRODUCTION_REQUIRED_FLAGS:
    raised = False
    try:
        _prod(**{flag: False})
    except ValueError:
        raised = True
    check(f"a production broker refuses to disable {flag}", raised)

raised = False
try:
    ProductionActuationBroker(os.path.join(_d, "noev.sock"), _v,
                              halt_state=lambda: False)
except ValueError:
    raised = True
check("durable evidence with nowhere to write is refused", raised)

raised = False
try:
    ProductionActuationBroker(os.path.join(_d, "nohalt.sock"), _v,
                              evidence_path=os.path.join(_d, "ev3"))
except ValueError:
    raised = True
check("a production broker without a halt interlock is refused", raised)

pb = _prod()
check("a correctly-built production broker has effect gating ON",
      getattr(pb, "_enforce_effects", False) is True)
undeclared_refused = False
try:
    pb.register_actuator("canary", lambda **k: None, required_scope=("s:x",))
except Exception:
    undeclared_refused = True
check("...so an actuator with undeclared effects cannot register",
      undeclared_refused)


print("-" * 60)
print(f"  {_passed}/{_total} tests passed")
if _passed != _total:
    raise SystemExit(1)
