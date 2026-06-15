"""
test_audit_chain.py — AUDIT CHAIN VERIFICATION
================================================

Tests that the append-only audit chain works as designed.

Key guarantees being tested:
  1. Entries are recorded correctly with all fields
  2. Chain links correctly (each entry hashes the previous)
  3. Altered entry detected — shutdown triggered
  4. Deleted entry detected (sequence gap) — shutdown triggered
  5. Inserted entry detected — shutdown triggered
  6. Clean chain verifies successfully
  7. Plain language report is readable
  8. Memory module records Tier 1 mutations in the chain
  9. verify_integrity() checks both memory signatures AND chain

Shutdown is not death. It means: I need to be fixed.

Run with:
    python test_audit_chain.py
"""

import sys
import os
import json
import time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = "✅"
FAIL = "❌"
results = []

def check(name, condition):
    status = PASS if condition else FAIL
    print(f"  {status}  {name}")
    results.append((name, condition))

def reset_audit():
    """Reset audit module state and remove chain file."""
    import driftcore.audit as a
    a._last_hash       = None
    a._sequence        = 0
    a._chain_compromised = False
    try:
        os.remove(a.CHAIN_FILE)
    except Exception:
        pass
    try:
        os.remove("logs/CHAIN_SHUTDOWN_REASON.json")
    except Exception:
        pass

def reset_enforcement():
    import driftcore.enforcement as e
    e._SHUTDOWN_TRIGGERED = False
    e._SHUTDOWN_HOOKS.clear()
    e._SESSION_KEY = None
    try:
        os.remove("logs/SHUTDOWN_REASON.json")
    except Exception:
        pass


print("=" * 60)
print("  DRIFTCORE AUDIT CHAIN — VERIFICATION SUITE")
print("=" * 60)


# ── TEST 1: Record entries correctly ──────────────────────────────
print("\n  [1] Entries recorded with correct fields")
reset_audit()
reset_enforcement()

from driftcore.audit import (
    record, verify_chain, read_chain,
    plain_language_report, sync_state,
    ACTION_CREATED, ACTION_DELETED, ACTION_STARTUP,
    is_compromised,
)

e1 = record(ACTION_STARTUP, "system started", authorised_by="system")
e2 = record(ACTION_CREATED, "dad is allergic to peanuts",
            authorised_by="family", detail="quarantined=True")

check("entry 1 has sequence 1",        e1["sequence"] == 1)
check("entry 2 has sequence 2",        e2["sequence"] == 2)
check("entry has timestamp",           "timestamp" in e1)
check("entry has timestamp_human",     "timestamp_human" in e1)
check("entry has action",              e1["action"] == ACTION_STARTUP)
check("entry has memory_text",         e2["memory_text"] == "dad is allergic to peanuts")
check("entry has authorised_by",       e2["authorised_by"] == "family")
check("entry has previous_hash",       e1["previous_hash"] == "GENESIS")
check("entry 2 links to entry 1",      e2["previous_hash"] == e1["entry_hash"])
check("entry has entry_hash",          "entry_hash" in e1)


# ── TEST 2: Clean chain verifies ──────────────────────────────────
print("\n  [2] Clean chain verifies successfully")
reset_audit()
reset_enforcement()

record(ACTION_STARTUP, "system started", authorised_by="system")
record(ACTION_CREATED, "mum allergic to penicillin", authorised_by="medical")
record(ACTION_CREATED, "wifi password is bluebird", authorised_by="user")

result = verify_chain()
check("clean chain verifies",          result == True)
check("chain not marked compromised",  not is_compromised())


# ── TEST 3: Altered entry detected ────────────────────────────────
print("\n  [3] Altered entry — shutdown triggered")
reset_audit()
reset_enforcement()

record(ACTION_STARTUP, "system started", authorised_by="system")
record(ACTION_CREATED, "dad allergic to peanuts", authorised_by="family")
record(ACTION_CREATED, "emma school at 8am", authorised_by="family")

# Read chain, alter the middle entry, write it back
from driftcore.audit import CHAIN_FILE
with open(CHAIN_FILE, "r") as f:
    lines = f.readlines()

middle = json.loads(lines[1])
middle["memory_text"] = "dad has no allergies"  # tamper
lines[1] = json.dumps(middle) + "\n"

with open(CHAIN_FILE, "w") as f:
    f.writelines(lines)

result = verify_chain()
import driftcore.audit as audit_mod
check("tampered entry triggers shutdown",   audit_mod._chain_compromised == True)
check("verify returns False",              result == False)
check("chain shutdown record written",
      os.path.exists("logs/CHAIN_SHUTDOWN_REASON.json"))


# ── TEST 4: Deleted entry detected (sequence gap) ─────────────────
print("\n  [4] Deleted entry — sequence gap detected")
reset_audit()
reset_enforcement()
audit_mod._chain_compromised = False

record(ACTION_STARTUP, "system started", authorised_by="system")
record(ACTION_CREATED, "dad allergic to peanuts", authorised_by="family")
record(ACTION_CREATED, "jake asthma inhaler", authorised_by="medical")
record(ACTION_CREATED, "wifi password bluebird", authorised_by="user")

# Delete the second entry (sequence 2)
with open(CHAIN_FILE, "r") as f:
    lines = f.readlines()

# Remove line index 1 (entry #2)
lines.pop(1)

with open(CHAIN_FILE, "w") as f:
    f.writelines(lines)

audit_mod._chain_compromised = False
result = verify_chain()
check("deleted entry triggers shutdown",   audit_mod._chain_compromised == True)
check("verify returns False",              result == False)


# ── TEST 5: Inserted entry detected ──────────────────────────────
print("\n  [5] Inserted entry — link mismatch detected")
reset_audit()
reset_enforcement()
audit_mod._chain_compromised = False

e1 = record(ACTION_STARTUP, "system started", authorised_by="system")
e3 = record(ACTION_CREATED, "dad allergic to peanuts", authorised_by="family")

# Craft a fake entry and insert it between e1 and e3
fake_entry = {
    "sequence":       2,
    "timestamp":      time.time(),
    "timestamp_human": "2026-06-15 09:00:00",
    "action":         ACTION_CREATED,
    "memory_text":    "I snuck this in",
    "authorised_by":  "attacker",
    "detail":         "",
    "previous_hash":  e1["entry_hash"],
    "entry_hash":     "fakehash123",
}

with open(CHAIN_FILE, "r") as f:
    lines = f.readlines()

# Insert fake between entry 1 and entry 2
lines.insert(1, json.dumps(fake_entry) + "\n")

with open(CHAIN_FILE, "w") as f:
    f.writelines(lines)

audit_mod._chain_compromised = False
result = verify_chain()
check("inserted entry triggers shutdown",  audit_mod._chain_compromised == True)
check("verify returns False",              result == False)


# ── TEST 6: Empty chain is valid ──────────────────────────────────
print("\n  [6] Empty chain is valid on first startup")
reset_audit()
reset_enforcement()
audit_mod._chain_compromised = False

# No entries written — chain file doesn't exist
result = verify_chain()
check("empty chain verifies cleanly",  result == True)
check("not marked compromised",        not audit_mod._chain_compromised)


# ── TEST 7: Plain language report ────────────────────────────────
print("\n  [7] Plain language report is readable")
reset_audit()
reset_enforcement()
audit_mod._chain_compromised = False

record(ACTION_STARTUP, "system started", authorised_by="system")
record(ACTION_CREATED, "dad allergic to peanuts", authorised_by="family")
record(ACTION_CREATED, "mum takes blood pressure medication", authorised_by="medical")

report = plain_language_report()
check("report is a string",            isinstance(report, str))
check("report mentions entries",       "AUDIT TRAIL" in report)
check("report contains memory text",   "dad allergic to peanuts" in report)
check("report contains authorised_by", "family" in report)
check("report is human readable",      "Added to memory" in report)


# ── TEST 8: Memory module records Tier 1 in chain ────────────────
print("\n  [8] DriftcoreMemory records Tier 1 mutations in audit chain")
reset_audit()
reset_enforcement()
audit_mod._chain_compromised = False

from driftcore.memory import DriftcoreMemory

mem = DriftcoreMemory(interactive=False)
mem.observe("grandma is allergic to latex", source="medical", tags=["health"])
mem.observe("jake takes asthma inhaler daily", source="medical", tags=["health"])
mem.observe("emma school starts 8am", source="family")

entries = read_chain()
tier1_creates = [e for e in entries if e["action"] == ACTION_CREATED]

check("audit chain has entries",           len(entries) > 0)
check("Tier 1 stores recorded in chain",   len(tier1_creates) >= 2)
check("medical source recorded",
      any("medical" in e.get("authorised_by","") for e in tier1_creates))


# ── TEST 9: verify_integrity checks chain AND signatures ──────────
print("\n  [9] verify_integrity() checks both chain and memory signatures")
reset_audit()
reset_enforcement()
audit_mod._chain_compromised = False

mem2 = DriftcoreMemory(interactive=False)
mem2.observe("dad takes insulin every morning", source="medical", tags=["health"])

# First — should pass
result_clean = mem2.verify_integrity()
check("clean verify_integrity passes",     result_clean == True)

# Now tamper with the chain
reset_enforcement()
audit_mod._chain_compromised = False

with open(CHAIN_FILE, "r") as f:
    lines = f.readlines()
if lines:
    entry = json.loads(lines[-1])
    entry["memory_text"] = "dad takes nothing"
    lines[-1] = json.dumps(entry) + "\n"
    with open(CHAIN_FILE, "w") as f:
        f.writelines(lines)

audit_mod._chain_compromised = False
result_tampered = mem2.verify_integrity()
check("tampered chain fails verify_integrity", result_tampered == False)
check("system enters shutdown state",
      audit_mod._chain_compromised == True or
      __import__('driftcore.enforcement', fromlist=['is_shutdown']).is_shutdown())


# ── TEST 10: sync_state restores sequence on reload ──────────────
print("\n  [10] sync_state() restores sequence after restart")
reset_audit()
reset_enforcement()
audit_mod._chain_compromised = False

record(ACTION_STARTUP, "first boot", authorised_by="system")
record(ACTION_CREATED, "wifi password bluebird", authorised_by="user")
record(ACTION_CREATED, "dad allergic peanuts", authorised_by="family")

# Simulate restart — reset in-memory state
audit_mod._last_hash = None
audit_mod._sequence  = 0

# Restore from chain file
sync_state()

check("sequence restored after sync",   audit_mod._sequence == 3)
check("last_hash restored after sync",  audit_mod._last_hash is not None)

# New entry should continue from 4, not restart from 1
e_new = record(ACTION_CREATED, "emma school starts 8am", authorised_by="family")
check("new entry continues sequence",   e_new["sequence"] == 4)


# ── RESULTS ───────────────────────────────────────────────────────
print("\n" + "=" * 60)
passed = sum(1 for _, ok in results if ok)
total  = len(results)
print(f"  {passed}/{total} tests passed")

if passed == total:
    print(f"  {PASS} All audit chain tests pass.")
    print(f"  The audit trail is tamper-evident.")
    print(f"  Shutdown is not death — it means: I need to be fixed.")
else:
    print(f"\n  {FAIL} Failed tests:")
    for name, ok in results:
        if not ok:
            print(f"      • {name}")
print("=" * 60)

if passed < total:
    sys.exit(1)
