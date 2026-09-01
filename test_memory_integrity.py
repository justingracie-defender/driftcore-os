"""
test_memory_integrity.py — first tests this module has ever had.

# CLAIMS: driftcore/memory/integrity.py:unknown-is-not-clean
# CLAIMS: driftcore/memory/integrity.py:deletion-is-detected
# CLAIMS: driftcore/memory/integrity.py:reregistration-is-recorded

Two calls defeated the whole module: alter a memory, re-register it, get a clean
bill of health with nothing in any log. And deleting a memory outright produced no
finding at all, because the report only looked where the caller pointed it.

# CLAIMS: driftcore/memory/integrity.py:checksum-has-no-chosen-collisions
"""

from driftcore.memory.integrity import (
    IntegrityChecker, hash_entry, VERIFIED, TAMPERED, UNREGISTERED, MISSING)

_p = _t = 0


def check(label, cond):
    global _p, _t
    _t += 1
    if cond:
        _p += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


def raises(label, exc, fn):
    global _p, _t
    _t += 1
    try:
        fn()
    except exc:
        _p += 1
        print(f"  ok   {label}")
        return
    except Exception as e:
        print(f"  FAIL {label} (raised {type(e).__name__}: {e})")
        return
    print(f"  FAIL {label} (did not raise)")


print("=== three answers, not two ===")

ic = IntegrityChecker()
ic.register("k", {"a": 1})
check("an untouched entry is VERIFIED", ic.status("k", {"a": 1}) == VERIFIED)
check("an altered entry is TAMPERED", ic.status("k", {"a": 2}) == TAMPERED)
check("an entry never registered is UNREGISTERED, not TAMPERED",
      ic.status("other", {"a": 1}) == UNREGISTERED)
check("verify() is True only for VERIFIED", ic.verify("k", {"a": 1}))
check("and False for both other outcomes",
      not ic.verify("k", {"a": 2}) and not ic.verify("other", {"a": 1}))


print("=== deletion is a tamper and is detected ===")

ic = IntegrityChecker()
ic.register("keep", {"a": 1})
ic.register("deleted", {"b": 2})
report = ic.tamper_report({"keep": {"a": 1}})
check("the missing entry is reported",
      any(v["key"] == "deleted" and v["status"] == MISSING for v in report))
check("the surviving entry is not", not any(v["key"] == "keep" for v in report))
check("the finding explains itself",
      any("deletion is a tamper" in v["detail"] for v in report))
check("wiping everything reports every registered key",
      len(ic.tamper_report({})) == 2)


print("=== an unregistered entry is not a false TAMPERED alarm ===")

ic = IntegrityChecker()
ic.register("k", {"a": 1})
report = ic.tamper_report({"k": {"a": 1}, "stranger": {"z": 9}})
check("the stranger is reported as UNREGISTERED",
      any(v["key"] == "stranger" and v["status"] == UNREGISTERED for v in report))
check("not as TAMPERED",
      not any(v["key"] == "stranger" and v["status"] == TAMPERED for v in report))
check("a fully clean set reports nothing",
      ic.tamper_report({"k": {"a": 1}}) == [])


print("=== a tampered entry cannot be laundered by re-registering ===")

ic = IntegrityChecker()
ic.register("k", {"a": 1})
raises("silent re-registration is refused", PermissionError,
       lambda: ic.register("k", {"a": 999}))
check("and the original checksum is untouched", ic.verify("k", {"a": 1}))
raises("an unattributed replace is refused", ValueError,
       lambda: ic.register("k", {"a": 999}, replace=True))
ic.register("k", {"a": 999}, replace=True, registered_by="justin")
check("a deliberate, attributed replace works", ic.verify("k", {"a": 999}))
log = ic.audit_log()
check("and it is recorded", len(log) == 1 and log[0]["event"] == "CHECKSUM_REPLACED")
check("with who did it", log[0]["registered_by"] == "justin")
check("and both hashes", log[0]["old_hash"] != log[0]["new_hash"])
check("the audit log is a copy",
      (ic.audit_log()[0].__setitem__("registered_by", "X")
       or ic.audit_log()[0]["registered_by"] == "justin"))


print("=== the checksum distinguishes values that print the same ===")


class A:
    def __str__(self):
        return "user_pref"


class B:
    def __str__(self):
        return "user_pref"


raises("an unserialisable value is refused rather than stringified", ValueError,
       lambda: hash_entry({"v": A()}))
raises("NaN cannot be checksummed", ValueError,
       lambda: hash_entry({"v": float("nan")}))
check("an int and its string form differ",
      hash_entry({"v": 1}) != hash_entry({"v": "1"}))
check("key order does not change the checksum",
      hash_entry({"a": 1, "b": 2}) == hash_entry({"b": 2, "a": 1}))
check("nested changes are caught",
      hash_entry({"a": {"b": 1}}) != hash_entry({"a": {"b": 2}}))

ic = IntegrityChecker()
ic.register("k", {"a": 1})
check("an entry that becomes unhashable reads as TAMPERED, not as an exception",
      ic.status("k", {"a": A()}) == TAMPERED)


print("=== input guards ===")

ic = IntegrityChecker()
raises("an empty key is refused", ValueError, lambda: ic.register("", {"a": 1}))
raises("a non-string key is refused", ValueError, lambda: ic.register(7, {"a": 1}))
raises("a non-dict entries argument is refused", TypeError,
       lambda: ic.tamper_report(["k"]))

print("-" * 60)
print(f"  {_p}/{_t} tests passed")
if _p != _t:
    raise SystemExit(1)
