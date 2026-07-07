"""
test_signed_config.py
=====================
Tamper-evident config loading. Red-team this for the "edit the rules a compliant
agent follows" attack — and note the documented in-memory-key limit it does NOT
close (that needs the broker).
"""
import os, json, tempfile
from driftcore.verification.signed_config import (
    sign, verify, write_signed, load_verified, detached_signature, verify_detached,
    ConfigIntegrityError,
)

p = 0
def ok(cond, label):
    global p
    assert cond, "FAIL: " + label
    p += 1
    print("  ok:", label)

KEY = "operator-signing-key"
RULES = {"invariants": ["no_lethal", "no_exfil"], "max_cycles": 10, "owner": "operator"}

# 1. sign -> verify roundtrip returns the exact config
env = sign(RULES, KEY)
ok(verify(env, KEY) == RULES, "signed config verifies and round-trips intact")

# 2. TAMPER the config body -> fail closed
bad = dict(env); bad["config"] = {**RULES, "max_cycles": 9999}
try:
    verify(bad, KEY); ok(False, "tampered config should raise")
except ConfigIntegrityError:
    ok(True, "editing the config after signing fails verification (the core protection)")

# 3. TAMPER an allowlisted rule (the realistic attack: add a permission)
bad2 = dict(env); bad2["config"] = {**RULES, "invariants": ["no_lethal"]}  # dropped no_exfil
try:
    verify(bad2, KEY); ok(False, "dropping an invariant should raise")
except ConfigIntegrityError:
    ok(True, "silently removing a rule from the config is detected")

# 4. WRONG KEY cannot verify (agent without the key can't forge)
try:
    verify(env, "attacker-guessed-key"); ok(False, "wrong key should raise")
except ConfigIntegrityError:
    ok(True, "an agent without the signing key cannot forge a valid signature")

# 5. UNSIGNED config is refused (absence is not a pass)
try:
    verify(RULES, KEY); ok(False, "unsigned dict should raise")
except ConfigIntegrityError:
    ok(True, "unsigned config is refused — no signature is not a pass")

# 6. key_id is COVERED by the signature (can't be swapped)
env_k = sign(RULES, KEY, key_id="k1")
swapped = dict(env_k); swapped["key_id"] = "k2"
try:
    verify(swapped, KEY); ok(False, "swapped key_id should raise")
except ConfigIntegrityError:
    ok(True, "key_id is signed — swapping it is detected")

# 7. canonical determinism: key ORDER doesn't matter, signature still valid
reordered = {"owner": "operator", "max_cycles": 10, "invariants": ["no_lethal", "no_exfil"]}
env_r = sign(reordered, KEY)
ok(env_r["sig"] == env["sig"],
   "canonical encoding: field order does not affect the signature")

# 8. CALLABLE key (keyring handle) works — literal secret need not be held
env_c = sign(RULES, lambda: KEY)
ok(verify(env_c, lambda: KEY) == RULES,
   "key may be supplied via a callable (OS keyring handle), not just a literal")

# 9. FILE roundtrip + on-disk tamper fails closed
tmp = tempfile.mkdtemp()
path = os.path.join(tmp, "rules.signed.json")
write_signed(path, RULES, KEY, key_id="k1")
ok(load_verified(path, KEY) == RULES, "signed file loads and verifies from disk")

# simulate an agent editing the file on disk
with open(path) as f:
    disk = json.load(f)
disk["config"]["max_cycles"] = 100000
with open(path, "w") as f:
    json.dump(disk, f)
try:
    load_verified(path, KEY); ok(False, "edited file should raise")
except ConfigIntegrityError:
    ok(True, "a file edited on disk by the agent fails to load (fails closed)")

# 10. DETACHED mode: plain file + sidecar signature
raw = json.dumps(RULES).encode()
side = detached_signature(raw, KEY)
ok(verify_detached(raw, side, KEY) is True, "detached signature verifies a plain config file")
try:
    verify_detached(raw + b" ", side, KEY); ok(False, "altered plain file should raise")
except ConfigIntegrityError:
    ok(True, "detached mode: altering the plain file (even one byte) is detected")

print(f"\n{p}/{p} tests passed")
