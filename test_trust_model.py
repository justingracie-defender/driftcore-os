"""
test_trust_model.py — first tests this module has ever had.

Every defect asserted below was reproduced against the ORIGINAL code before the
module was changed. The comments in trust_model.py record what each one was.

Run: python3 test_trust_model.py
"""

# CLAIMS: driftcore/network/trust_model.py:one-violation-quarantines
# CLAIMS: driftcore/network/trust_model.py:quarantine-latches


import threading

from driftcore.network.trust_model import TrustModel

_passed = _total = 0


def check(label, cond):
    global _passed, _total
    _total += 1
    if cond:
        _passed += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


def raises(label, exc, fn):
    global _passed, _total
    _total += 1
    try:
        fn()
    except exc:
        _passed += 1
        print(f"  ok   {label}")
        return
    except Exception as e:
        print(f"  FAIL {label} (raised {type(e).__name__}: {e})")
        return
    print(f"  FAIL {label} (did not raise)")


print("=== the constants say what the threshold must do ===")

check("one safety violation lands exactly on the threshold",
      TrustModel.INITIAL_TRUST - TrustModel.SAFETY_VIOLATION_PENALTY
      == TrustModel.QUARANTINE_THRESHOLD)

t = TrustModel()
t.update("a", success=False, safety_violation=True)
check("and that agent IS quarantined (the strict `<` used to let it through)",
      t.is_quarantined("a"))
check("trust is exactly the threshold", t.trust["a"] == 0.20)
check("the reason names the violation", "safety violation" in t.quarantine_reason("a"))


print("=== a safety violation is not averaged against good days ===")

t = TrustModel()
for _ in range(6):
    t.update("gamer", success=True)
check("six successes restore full trust", t.trust["gamer"] == 0.8)
t.update("gamer", success=False, safety_violation=True)
check("a violation at high trust still quarantines immediately",
      t.is_quarantined("gamer"))
check("even though the score is far above the threshold", t.trust["gamer"] == 0.5)
for _ in range(10):
    t.update("gamer", success=True)
check("and no amount of subsequent success releases it",
      t.is_quarantined("gamer"))
check("trust itself still recovers (quarantine is not destruction)",
      t.trust["gamer"] == 1.0)


# A cold pass found `setdefault` pinned the FIRST reason, so an agent quarantined
# for low trust that then violated safety still reported "trust fell to 0.2".
t = TrustModel()
for _ in range(3):
    t.update("r", success=False)
check("a trust-based quarantine names the trust", "trust fell" in t.quarantine_reason("r"))
t.update("r", success=False, safety_violation=True)
check("a later safety violation REPLACES the weaker reason",
      "safety violation" in t.quarantine_reason("r"))
check("and the violation count is right", t.summary()["r"]["safety_violations"] == 1)


print("=== quarantine latches; only a named human releases it ===")

t = TrustModel()
t.update("b", success=False, safety_violation=True)
raises("release is refused while the score is still low", PermissionError,
       lambda: t.release_quarantine("b", "justin"))
for _ in range(6):
    t.update("b", success=True)
check("the agent earns its score back", t.trust["b"] >= TrustModel.RELEASE_THRESHOLD)
check("but is still quarantined until released", t.is_quarantined("b"))
raises("an unattributed release is refused", ValueError,
       lambda: t.release_quarantine("b", "   "))
res = t.release_quarantine("b", "justin")
check("a named human can release it", res["status"] == "RELEASED")
check("and it is no longer quarantined", not t.is_quarantined("b"))
check("the release is in the history",
      any(e.get("released_by") == "justin" for e in t.history["b"]))


print("=== trust-based quarantine, without any safety violation ===")

t = TrustModel()
for _ in range(3):
    t.update("c", success=False)
check("three failures reach exactly the threshold", t.trust["c"] == 0.20)
check("and quarantine it", t.is_quarantined("c"))
t.update("c", success=True)
check("one success does NOT release it (no boundary chatter)",
      t.is_quarantined("c"))


print("=== bounds hold ===")

t = TrustModel()
for _ in range(50):
    t.update("hi", success=True)
check("trust cannot exceed 1.0", t.trust["hi"] == 1.0)
t = TrustModel()
for _ in range(50):
    t.update("lo", success=False)
check("trust cannot fall below 0.0", t.trust["lo"] == 0.0)


print("=== an agent nobody can name cannot be quarantined ===")

t = TrustModel()
raises("None is not an agent", ValueError, lambda: t.update(None, success=True))
raises("the empty string is not an agent", ValueError, lambda: t.update("", True))
raises("whitespace is not an agent", ValueError, lambda: t.update("   ", True))
raises("a number is not an agent", ValueError, lambda: t.update(7, True))
check("and none of them created an entry", t.trust == {})


print("=== the live score still governs, for callers that write it directly ===")

t = TrustModel()
t.update("d", success=True)
check("not quarantined at 0.55", not t.is_quarantined("d"))
# fable/trust_bridge does exactly this — bypassing update() entirely.
t.trust["d"] = 0.05
check("a DIRECT write below the threshold still quarantines", t.is_quarantined("d"))
t.trust["d"] = 0.9
check("and raising it back by direct write un-quarantines (no latch was set)",
      not t.is_quarantined("d"))

t2 = TrustModel()
t2.update("e", success=False, safety_violation=True)
t2.trust["e"] = 1.0          # attempt to launder a latched quarantine
check("but a direct write CANNOT clear a latched safety quarantine",
      t2.is_quarantined("e"))


print("=== unknown agents ===")

t = TrustModel()
check("an unseen agent is not quarantined", not t.is_quarantined("stranger"))
check("and has no reason", t.quarantine_reason("stranger") is None)
check("a non-string is never quarantined rather than raising",
      t.is_quarantined(None) is False)


print("=== history is bounded and says what it dropped ===")

t = TrustModel()
for _ in range(TrustModel.MAX_HISTORY + 250):
    t.update("busy", success=True)
check("history is capped", len(t.history["busy"]) == TrustModel.MAX_HISTORY)
check("and the dropped count is reported",
      t.summary()["busy"]["history_dropped"] == 250)


print("=== concurrent updates do not lose events ===")

t = TrustModel()


def hammer():
    for _ in range(500):
        t.update("shared", success=True)
        t.update("shared", success=False)


threads = [threading.Thread(target=hammer) for _ in range(4)]
for th in threads:
    th.start()
for th in threads:
    th.join()
check("every update is recorded under concurrency",
      len(t.history["shared"]) == TrustModel.MAX_HISTORY
      and t.summary()["shared"]["history_dropped"] == 4000 - TrustModel.MAX_HISTORY)


print("=== summary reports what an operator needs ===")

t = TrustModel()
t.update("x", success=True)
t.update("y", success=False, safety_violation=True)
s = t.summary()
check("both agents appear", set(s) == {"x", "y"})
check("the violator is flagged", s["y"]["quarantined"] is True)
check("with its violation count", s["y"]["safety_violations"] == 1)
check("the healthy agent is not", s["x"]["quarantined"] is False)
check("and has no reason", s["x"]["reason"] is None)

print("-" * 60)
print(f"  {_passed}/{_total} tests passed")
if _passed != _total:
    raise SystemExit(1)
