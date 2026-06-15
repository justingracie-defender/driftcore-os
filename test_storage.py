"""
test_storage.py — ENCRYPTED STORAGE VERIFICATION
=================================================

Tests that the SQLite storage backend:
  1. Encrypts content before writing to disk
  2. Decrypts correctly on read
  3. Verifies signatures before decrypting
  4. Detects tampered database records — shutdown
  5. Cannot be read without the encryption key
  6. Salt persists across sessions for key re-derivation
  7. Audit chain records every storage operation
  8. Stats report correctly

The family's private information stays private.
Someone finding the database file sees encrypted blobs.
Someone changing a record breaks the signature.
Either way — they get nothing and the system knows.

Run with:
    python test_storage.py
"""

import sys
import os
import json
import sqlite3
import time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = "✅"
FAIL = "❌"
results = []

def check(name, condition):
    status = PASS if condition else FAIL
    print(f"  {status}  {name}")
    results.append((name, condition))

TEST_DB = "data/test_driftcore_memory.db"

def reset_all():
    import driftcore.enforcement as e
    import driftcore.audit as a
    import driftcore.storage as s
    e._SHUTDOWN_TRIGGERED = False
    e._SHUTDOWN_HOOKS.clear()
    e._SESSION_KEY = None
    a._last_hash = None
    a._sequence = 0
    a._chain_compromised = False
    s._ENCRYPTION_KEY = None
    s._KEY_SALT = None
    s._KEY_VERIFIED = False
    for f in [
        "logs/audit_chain.jsonl",
        "logs/SHUTDOWN_REASON.json",
        "logs/CHAIN_SHUTDOWN_REASON.json",
        TEST_DB,
    ]:
        try: os.remove(f)
        except: pass

def make_test_item(text="dad is allergic to peanuts",
                   source="family", quarantined=True):
    """Create a minimal MemoryItem-like object for testing."""
    class FakeItem:
        pass
    item = FakeItem()
    item.text          = text
    item.source        = source
    item.timestamp     = time.time()
    item.last_accessed = time.time()
    item.access_count  = 0
    item.surprise_score = 0.8
    item.tags          = ["health"]
    item.quarantined   = quarantined
    item.review_stage  = 0
    return item


print("=" * 60)
print("  DRIFTCORE STORAGE — ENCRYPTION VERIFICATION SUITE")
print("=" * 60)


# ── TEST 1: Encryption and decryption work ────────────────────────
print("\n  [1] Encrypt and decrypt round-trip")
reset_all()

from driftcore.storage import init_encryption, _encrypt, _decrypt

salt = init_encryption("test_passphrase_123")

original = "dad is allergic to peanuts"
encrypted = _encrypt(original)
decrypted = _decrypt(encrypted)

check("encrypted text differs from original",  encrypted != original)
check("decryption recovers original",          decrypted == original)
check("encrypted is base64 string",            isinstance(encrypted, str))
check("encrypted has no plaintext",            "peanuts" not in encrypted)


# ── TEST 2: Different passphrases produce different keys ──────────
print("\n  [2] Different passphrases cannot decrypt each other's data")
reset_all()

from driftcore.storage import init_encryption, _encrypt, _decrypt, derive_key

init_encryption("correct_passphrase")
encrypted = _encrypt("sensitive medical information")

# Now switch to wrong key
init_encryption("wrong_passphrase")

try:
    wrong_decrypt = _decrypt(encrypted)
    # If we get here, decryption "succeeded" but content should be garbage
    check("wrong key produces garbage",
          wrong_decrypt != "sensitive medical information")
except Exception:
    check("wrong key produces garbage", True)


# ── TEST 3: Store and load Tier 1 item ────────────────────────────
print("\n  [3] Store and load Tier 1 item")
reset_all()

from driftcore.storage import SecureStorage, init_encryption

init_encryption("family_passphrase_2026")
storage = SecureStorage(TEST_DB)
storage.open()

item = make_test_item("dad is allergic to peanuts", "family", True)
item_id = storage.store_tier1(item)

loaded = storage.load_tier1()
storage.close()

check("item stored successfully",         item_id is not None)
check("item loaded back",                 len(loaded) == 1)
check("text decrypted correctly",         loaded[0].text == "dad is allergic to peanuts")
check("source preserved",                 loaded[0].source == "family")
check("quarantined flag preserved",       loaded[0].quarantined == True)
check("tier is 1",                        loaded[0].tier == 1)


# ── TEST 4: Database file contains no plaintext ───────────────────
print("\n  [4] Database file contains no readable plaintext")
reset_all()

init_encryption("family_passphrase_2026")
storage2 = SecureStorage(TEST_DB)
storage2.open()
storage2.store_tier1(make_test_item(
    "mum takes blood pressure medication daily", "medical", True
))
storage2.close()

# Read the raw database file as text
with open(TEST_DB, "rb") as f:
    raw_bytes = f.read()

# Check that sensitive content is NOT readable
check("'medication' not in raw file",
      b"medication" not in raw_bytes or
      raw_bytes.count(b"medication") == 0)
check("'mum takes' not in raw file",
      b"mum takes" not in raw_bytes)


# ── TEST 5: Tamper detection — record modified on disk ───────────
print("\n  [5] Tamper detection — record modified directly in database")
reset_all()

import driftcore.enforcement as enf
import driftcore.storage as stor

init_encryption("family_passphrase_2026")
storage3 = SecureStorage(TEST_DB)
storage3.open()
storage3.store_tier1(make_test_item(
    "jake takes asthma inhaler", "medical", True
))
storage3.close()

# Directly modify the database outside DriftCore
conn = sqlite3.connect(TEST_DB)
# We can't easily change the encrypted content meaningfully,
# but we can corrupt the signature
conn.execute(
    "UPDATE tier1_memory SET signature = 'fake_signature_tamper'"
)
conn.commit()
conn.close()

# Now try to load — should detect tamper and shutdown
enf._SHUTDOWN_TRIGGERED = False
stor._ENCRYPTION_KEY = None
init_encryption("family_passphrase_2026")

storage4 = SecureStorage(TEST_DB)
storage4.open()
loaded_tampered = storage4.load_tier1()
storage4.close()

check("tamper triggers shutdown",
      enf._SHUTDOWN_TRIGGERED == True)
check("tampered load returns empty",
      len(loaded_tampered) == 0)


# ── TEST 6: Cannot load without encryption key ───────────────────
print("\n  [6] Cannot load without encryption key")
reset_all()

init_encryption("family_passphrase_2026")
storage5 = SecureStorage(TEST_DB)
storage5.open()
storage5.store_tier1(make_test_item())
storage5.close()

# Clear the key
stor._ENCRYPTION_KEY = None

storage6 = SecureStorage(TEST_DB)
storage6.open()
try:
    storage6.load_tier1()
    check("load without key raises error", False)
except RuntimeError as e:
    check("load without key raises error", "not initialised" in str(e))
storage6.close()


# ── TEST 7: Salt persists for key re-derivation ───────────────────
print("\n  [7] Salt persists across sessions")
reset_all()

salt1 = init_encryption("family_passphrase_2026")
storage7 = SecureStorage(TEST_DB)
storage7.open()
storage7.save_salt(salt1)
storage7.store_tier1(make_test_item(
    "grandad has a pacemaker", "medical", True
))
storage7.close()

# Simulate restart — clear key
stor._ENCRYPTION_KEY = None

# Load salt and re-derive key
storage8 = SecureStorage(TEST_DB)
storage8.open()
saved_salt = storage8.load_salt()

check("salt was saved",               saved_salt is not None)
check("salt matches original",        saved_salt == salt1)

# Re-derive key with same passphrase and salt
init_encryption("family_passphrase_2026", saved_salt)
loaded_after_restart = storage8.load_tier1()
storage8.close()

check("data loads after restart",     len(loaded_after_restart) == 1)
check("text decrypted after restart",
      loaded_after_restart[0].text == "grandad has a pacemaker")


# ── TEST 8: Multiple items stored and loaded ──────────────────────
print("\n  [8] Multiple items stored and loaded correctly")
reset_all()

init_encryption("family_passphrase_2026")
storage9 = SecureStorage(TEST_DB)
storage9.open()

memories = [
    ("dad is allergic to peanuts",          "family",  True),
    ("mum takes blood pressure medication", "medical", True),
    ("wifi password is bluebird99",         "parent",  True),
    ("emma school starts at 8am",           "family",  False),
    ("jake football practice thursdays",    "family",  False),
]

for text, source, quarantined in memories:
    storage9.store_tier1(make_test_item(text, source, quarantined))

loaded9 = storage9.load_tier1()
storage9.close()

check("all 5 items stored",           len(loaded9) == 5)
check("all texts decrypted",
      all(any(m[0] == item.text for m in memories)
          for item in loaded9))
check("quarantined flags correct",
      sum(1 for i in loaded9 if i.quarantined) == 3)


# ── TEST 9: Stats report correctly ───────────────────────────────
print("\n  [9] Stats report correctly")
reset_all()

init_encryption("family_passphrase_2026")
storage10 = SecureStorage(TEST_DB)
storage10.open()

t1_item = make_test_item("allergy info", "family", True)
t2_item = make_test_item("weather today", "ai", False)
t2_item.quarantined = False

storage10.store_tier1(t1_item)
storage10.store_tier2(t2_item)

stats = storage10.stats()
storage10.close()

check("tier1_count is 1",             stats["tier1_count"] == 1)
check("tier2_count is 1",             stats["tier2_count"] == 1)
check("total is 2",                   stats["total"] == 2)
check("encrypted is True",            stats["encrypted"] == True)
check("quarantined_count is 1",       stats["quarantined_count"] == 1)


# ── TEST 10: Audit chain records storage operations ──────────────
print("\n  [10] Storage operations recorded in audit chain")
reset_all()

init_encryption("family_passphrase_2026")
storage11 = SecureStorage(TEST_DB)
storage11.open()
storage11.store_tier1(make_test_item("emma's birthday march 14", "family"))
storage11.close()

from driftcore.audit import read_chain
entries = read_chain()
storage_entries = [e for e in entries
                   if "STORED" in e.get("action", "")]

check("storage recorded in audit chain", len(storage_entries) >= 1)
check("audit entry has memory text",
      any("emma" in e.get("memory_text", "") for e in storage_entries))


# ── RESULTS ───────────────────────────────────────────────────────
print("\n" + "=" * 60)
passed = sum(1 for _, ok in results if ok)
total  = len(results)
print(f"  {passed}/{total} tests passed")

if passed == total:
    print(f"  {PASS} All storage tests pass.")
    print(f"  The family's private information stays private.")
    print(f"  Someone finding the database sees encrypted blobs.")
    print(f"  Someone changing a record breaks the signature.")
    print(f"  Either way — they get nothing and the system knows.")
else:
    print(f"\n  {FAIL} Failed tests:")
    for name, ok in results:
        if not ok:
            print(f"      • {name}")
print("=" * 60)

# Cleanup
try: os.remove(TEST_DB)
except: pass

if passed < total:
    sys.exit(1)
