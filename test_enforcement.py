"""
test_enforcement.py — ENFORCEMENT LAYER VERIFICATION
=====================================================

Tests that tamper-evident Tier 1 memory works as designed.

Key guarantees being tested:
  1. Items can be signed and verified cleanly
  2. Any modification to a signed item is detected
  3. Unsigned items in Tier 1 trigger shutdown
  4. Shutdown hooks are called on tamper detection
  5. The memory module signs items on store
  6. verify_integrity() catches corrupted items

Run with:
    python test_enforcement.py
"""

import sys
import os
import time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Reset enforcement state between tests
import driftcore.enforcement as enf

PASS = "✅"
FAIL = "❌"
results = []

def check(name, condition):
    status = PASS if condition else FAIL
    print(f"  {status}  {name}")
    results.append((name, condition))

def reset_enforcement():
    import driftcore.audit as _a
    _a._last_hash = None; _a._sequence = 0; _a._chain_compromised = False
    import os as _os
    for _f in ["logs/audit_chain.jsonl","logs/CHAIN_SHUTDOWN_REASON.json","logs/flagged_attempts.jsonl"]:
        try: _os.remove(_f)
        except: pass
    """Reset enforcement module state between tests."""
    enf._SHUTDOWN_TRIGGERED = False
    enf._SHUTDOWN_HOOKS.clear()
    enf._SESSION_KEY = None
    # Remove shutdown record if present
    try:
        os.remove("logs/SHUTDOWN_REASON.json")
    except Exception:
        pass

print("=" * 60)
print("  DRIFTCORE ENFORCEMENT — TAMPER-EVIDENT MEMORY TESTS")
print("=" * 60)


# ── TEST 1: Sign and verify cleanly ──────────────────────────────
print("\n  [1] Clean sign and verify")
reset_enforcement()

from driftcore.enforcement import sign_tier1_item, verify_tier1_store

item = sign_tier1_item(
    text="dad is allergic to peanuts",
    source="family",
    timestamp=time.time(),
    tags=["health"],
    quarantined=True,
)

check("item is a TamperEvidentItem",     type(item).__name__ == "TamperEvidentItem")
check("verify_and_read returns text",    item.verify_and_read() == "dad is allergic to peanuts")
check("text property returns correctly", item.text == "dad is allergic to peanuts")
check("source is preserved",             item.source == "family")
check("quarantined flag preserved",      item.quarantined == True)
check("verify_tier1_store passes",       verify_tier1_store([item]))


# ── TEST 2: Tamper detection — text modified ──────────────────────
print("\n  [2] Tamper detection — text modified")
reset_enforcement()

item2 = sign_tier1_item(
    text="mum is allergic to penicillin",
    source="medical",
    timestamp=time.time(),
    tags=["health"],
    quarantined=True,
)

# Simulate tampering by directly modifying the private field
item2._text = "mum has no allergies"

# verify_tier1_store should detect the tamper and trigger shutdown
result = verify_tier1_store([item2])

check("tamper detected on text change",      enf._SHUTDOWN_TRIGGERED == True)
check("verify returns False on tamper",      result == False)
check("shutdown reason file written",        os.path.exists("logs/SHUTDOWN_REASON.json"))


# ── TEST 3: Tamper detection — quarantine flag flipped ────────────
print("\n  [3] Tamper detection — quarantine flag modified")
reset_enforcement()

item3 = sign_tier1_item(
    text="jake takes asthma inhaler daily",
    source="medical",
    timestamp=time.time(),
    tags=["health"],
    quarantined=True,
)

# Simulate someone trying to remove the quarantine flag
item3._quarantined = False

result = verify_tier1_store([item3])
check("tamper detected on quarantine flip", enf._SHUTDOWN_TRIGGERED == True)
check("verify returns False",               result == False)


# ── TEST 4: Tamper detection — source changed ─────────────────────
print("\n  [4] Tamper detection — source changed")
reset_enforcement()

item4 = sign_tier1_item(
    text="emergency contact is aunt sarah",
    source="family",
    timestamp=time.time(),
    tags=["emergency"],
    quarantined=True,
)

item4._source = "unknown"

result = verify_tier1_store([item4])
check("tamper detected on source change", enf._SHUTDOWN_TRIGGERED == True)


# ── TEST 5: Shutdown hooks are called ────────────────────────────
print("\n  [5] Shutdown hooks called on tamper")
reset_enforcement()

hook_called = []
def test_hook():
    hook_called.append(True)

enf.register_shutdown_hook(test_hook)

item5 = sign_tier1_item(
    text="grandad takes blood pressure medication",
    source="medical",
    timestamp=time.time(),
    tags=["health"],
    quarantined=True,
)
item5._text = "grandad is fine"

verify_tier1_store([item5])

check("shutdown hook was called",         len(hook_called) == 1)
check("system is in shutdown state",      enf.is_shutdown() == True)


# ── TEST 6: Unsigned item in Tier 1 detected ─────────────────────
print("\n  [6] Unsigned item in Tier 1 triggers shutdown")
reset_enforcement()

# Create a fake item that isn't a TamperEvidentItem
class FakeItem:
    text = "I snuck in without signing"

fake = FakeItem()
result = verify_tier1_store([fake])

check("unsigned item triggers shutdown", enf._SHUTDOWN_TRIGGERED == True)
check("verify returns False",            result == False)


# ── TEST 7: Multiple items — one bad one triggers shutdown ────────
print("\n  [7] One bad item in a store of good items")
reset_enforcement()

good1 = sign_tier1_item("wifi password is bluebird", "user", time.time(), [], False)
good2 = sign_tier1_item("emma's school starts at 8am", "family", time.time(), [], False)
bad   = sign_tier1_item("dad allergic to peanuts", "family", time.time(), ["health"], True)
bad._text = "dad has no allergies"  # tamper

result = verify_tier1_store([good1, good2, bad])
check("one bad item triggers shutdown",    enf._SHUTDOWN_TRIGGERED == True)
check("verify returns False for the store", result == False)


# ── TEST 8: Memory module signs items on store ────────────────────
print("\n  [8] DriftcoreMemory signs Tier 1 items on store")
reset_enforcement()

from driftcore.memory import DriftcoreMemory

mem = DriftcoreMemory(interactive=False)
item_stored = mem.observe(
    "grandma is allergic to latex",
    source="medical",
    tags=["health"]
)

check("item lands in Tier 1",              item_stored.tier == 1)
check("item has _signed attribute",        hasattr(item_stored, "_signed"))
check("_signed is a TamperEvidentItem",
      type(item_stored._signed).__name__ == "TamperEvidentItem")
check("integrity check passes on clean store", mem.verify_integrity())


# ── TEST 9: verify_integrity catches corruption ───────────────────
print("\n  [9] verify_integrity() catches corruption in memory store")
reset_enforcement()

mem2 = DriftcoreMemory(interactive=False)
item9 = mem2.observe("dad takes insulin every morning", source="medical", tags=["health"])

# Tamper with the underlying signed item
item9._signed._text = "dad takes nothing"

result = mem2.verify_integrity()
check("integrity check detects corruption", enf._SHUTDOWN_TRIGGERED == True)
check("verify_integrity returns False",     result == False)


# ── TEST 10: shutdown_reason() returns record ─────────────────────
print("\n  [10] Shutdown reason is recorded and readable")
# Shutdown was triggered in test 9 — reason should be on disk

from driftcore.enforcement import shutdown_reason
record = shutdown_reason()

check("shutdown reason record exists",     record is not None)
check("record has timestamp",              record is not None and "timestamp" in record)
check("record has reason",                 record is not None and "reason" in record)
check("record has item_text",              record is not None and "item_text" in record)


# ── RESULTS ───────────────────────────────────────────────────────
print("\n" + "=" * 60)
passed = sum(1 for _, ok in results if ok)
total  = len(results)
print(f"  {passed}/{total} tests passed")

if passed == total:
    print(f"  {PASS} All enforcement tests pass.")
    print(f"  Tier 1 memory is tamper-evident.")
else:
    print(f"\n  {FAIL} Failed tests:")
    for name, ok in results:
        if not ok:
            print(f"      • {name}")
print("=" * 60)

if passed < total:
    sys.exit(1)
