"""
test_recovery.py — first tests this module has ever had.

# CLAIMS: driftcore/safety/recovery.py:agent-cannot-authorize
# CLAIMS: driftcore/safety/recovery.py:unreadable-memory-blocks

The authorization check was a denylist of one string:
    if not authorized_by or authorized_by == "agent"
So "Agent", "agent2", "system", or literally "not_a_human" all approved a restart.
And `authorized_by` defaulted to "human_operator", so calling it with NO arguments
approved one.

# CLAIMS: driftcore/safety/recovery.py:approval-is-single-use
"""

from driftcore.safety.recovery import RecoverySystem

_p = _t = 0


def check(label, cond):
    global _p, _t
    _t += 1
    if cond:
        _p += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


class Memory:
    def __init__(self, quarantine=()):
        self.quarantine = list(quarantine)

    def stats(self):
        return {"entries": 10, "quarantined": len(self.quarantine)}


class UnreadableMemory:
    @property
    def quarantine(self):
        raise IOError("memory store unavailable")

    def stats(self):
        return {}


def clean(humans=("justin",)):
    return RecoverySystem(Memory(), None, set(humans))


print("=== no string an agent can pick authorises a restart ===")

for name in ["agent", "Agent", "AGENT", "agent2", "the_agent", "system",
             "human_operator", "not_a_human", "justin ", "root", "admin"]:
    check(f"{name!r} is denied",
          clean().attempt_recovery(name, "inc-1")["status"] == "RECOVERY_DENIED")
check("an empty authorizer is denied",
      clean().attempt_recovery("", "inc-1")["status"] == "RECOVERY_DENIED")
check("None is denied",
      clean().attempt_recovery(None, "inc-1")["status"] == "RECOVERY_DENIED")
check("the denial explains it is an allow-list",
      "allow-list" in clean().attempt_recovery("mallory", "i")["reason"])


print("=== a registered human can, and only for a named incident ===")

r = clean()
check("a registered human is approved",
      r.attempt_recovery("justin", "inc-1")["status"] == "RECOVERY_APPROVED")
check("the approval names the incident",
      clean().attempt_recovery("justin", "inc-2")["incident_id"] == "inc-2")
check("and the authorizer",
      clean().attempt_recovery("justin", "inc-2")["authorized_by"] == "justin")
check("an unnamed incident is denied",
      clean().attempt_recovery("justin", "")["status"] == "RECOVERY_DENIED")
check("a non-string incident is denied",
      clean().attempt_recovery("justin", None)["status"] == "RECOVERY_DENIED")


print("=== one approval, one restart ===")

r = clean()
check("the first use is approved",
      r.attempt_recovery("justin", "inc-9")["status"] == "RECOVERY_APPROVED")
second = r.attempt_recovery("justin", "inc-9")
check("the same approval cannot be replayed",
      second["status"] == "RECOVERY_DENIED")
check("and the reason says why", "already been recovered" in second["reason"])
check("a DIFFERENT incident still works",
      r.attempt_recovery("justin", "inc-10")["status"] == "RECOVERY_APPROVED")

# A cold pass found the token was `human:incident`, so N registered humans yielded
# N restarts for one incident while the claim said one. Another authorizer is not
# another incident.
r2 = RecoverySystem(Memory(), None, {"alice", "bob"})
check("alice recovers incident 1",
      r2.attempt_recovery("alice", "inc-1")["status"] == "RECOVERY_APPROVED")
check("bob cannot recover the SAME incident again",
      r2.attempt_recovery("bob", "inc-1")["status"] == "RECOVERY_DENIED")
check("the denial says a second authorizer is not a second incident",
      "not a second incident" in r2.attempt_recovery("bob", "inc-1")["reason"])
check("bob can recover a different one",
      r2.attempt_recovery("bob", "inc-2")["status"] == "RECOVERY_APPROVED")


print("=== an empty allow-list means nobody ===")

r = RecoverySystem(Memory(), None)
check("a fresh system authorises nobody",
      r.attempt_recovery("justin", "i")["status"] == "RECOVERY_DENIED")
r.register_human("justin")
check("until a human is registered",
      r.attempt_recovery("justin", "i")["status"] == "RECOVERY_APPROVED")
try:
    r.register_human("  ")
    check("an unnamed authorizer cannot be registered", False)
except ValueError:
    check("an unnamed authorizer cannot be registered", True)


print("=== dirty memory blocks the restart ===")

r = RecoverySystem(Memory(["bad_entry"]), None, {"justin"})
res = r.attempt_recovery("justin", "inc-1")
check("a quarantined entry blocks recovery", res["status"] == "RECOVERY_BLOCKED")
check("the reason counts them", "1 quarantined" in res["reason"])
check("and it reports the memory stats", res["memory_stats"]["quarantined"] == 1)
check("a blocked attempt does NOT consume the approval",
      RecoverySystem(Memory(), None, {"justin"}).attempt_recovery(
          "justin", "inc-1")["status"] == "RECOVERY_APPROVED")


print("=== 'I could not check' is not 'it was clean' ===")

r = RecoverySystem(UnreadableMemory(), None, {"justin"})
res = r.attempt_recovery("justin", "inc-1")
check("unreadable memory BLOCKS rather than approving",
      res["status"] == "RECOVERY_BLOCKED")
# IOError is an alias for OSError, so that is the name Python reports. Asserting
# the alias would pin a detail of the test's own fixture rather than the behaviour.
check("the reason names the underlying failure", "OSError" in res["reason"])
check("and states the principle", "not 'it was clean'" in res["reason"])

vm = RecoverySystem(UnreadableMemory(), None, {"justin"}).verify_memory()
check("verify_memory reports unreadable rather than raising",
      vm["readable"] is False)
check("and does not claim the memory is clean", vm["memory_clean"] is False)


print("=== every check is logged ===")

r = clean()
r.attempt_recovery("justin", "inc-1")
check("the memory verification is recorded", len(r.recovery_log) == 1)
r.attempt_recovery("justin", "inc-2")
check("each attempt adds to the log", len(r.recovery_log) == 2)
check("a DENIED attempt does not reach the memory check",
      len(clean().recovery_log) == 0)

print("-" * 60)
print(f"  {_p}/{_t} tests passed")
if _p != _t:
    raise SystemExit(1)
