"""
test_authorization_state.py
===========================
Durability + cross-instance + tamper-evidence for the shared authorization
state (burned nonces, cycle budget). This is the file to red-team for the
persistence/multi-agent holes found this week.
"""
import os, tempfile, json
from driftcore.verification.authorization_state import (
    AuthorizationState, ReplayError, AuthorizationStateError, _entry_hash,
)

p = 0
def ok(cond, label):
    global p
    assert cond, "FAIL: " + label
    p += 1
    print("  ok:", label)

tmp = tempfile.mkdtemp()
path = os.path.join(tmp, "authz.jsonl")

# 1. burn + spent
a = AuthorizationState(path)
ok(not a.is_spent("op", "n1"), "fresh nonce is not spent")
a.burn_nonce("op", "n1")
ok(a.is_spent("op", "n1"), "burned nonce reads as spent")

# 2. replay in same instance -> ReplayError
try:
    a.burn_nonce("op", "n1"); ok(False, "replay should raise")
except ReplayError:
    ok(True, "re-burning a nonce raises ReplayError")

# 3. DURABILITY: a NEW instance on the same path still sees the burn (survives 'crash')
b = AuthorizationState(path)
ok(b.is_spent("op", "n1"), "durability: a fresh instance sees the prior burn (crash-safe)")
try:
    b.burn_nonce("op", "n1"); ok(False, "cross-restart replay should raise")
except ReplayError:
    ok(True, "durability: replay blocked across a restart")

# 4. CROSS-INSTANCE: two live instances share nonce state
c1 = AuthorizationState(path)
c2 = AuthorizationState(path)
c1.burn_nonce("op", "shared-1")
ok(c2.is_spent("op", "shared-1"),
   "cross-instance: instance 2 sees instance 1's burn")
try:
    c2.burn_nonce("op", "shared-1"); ok(False, "cross-instance replay should raise")
except ReplayError:
    ok(True, "cross-instance: one signed change cannot be accepted twice across instances")

# 5. per-owner isolation
ok(not a.is_spent("other_owner", "n1"), "nonces are namespaced per owner")

# 6. SHARED CYCLE BUDGET across instances
d1 = AuthorizationState(path)
d2 = AuthorizationState(path)
base = d1.cycle_count("acct")
d1.increment_cycle("acct")
d1.increment_cycle("acct")
ok(d2.cycle_count("acct") == base + 2,
   "cross-instance: cycle count is shared (8 agents share one budget)")

# 7. re-ratify resets cycles but NOT nonces
d1.reset_cycles("acct")
ok(d2.cycle_count("acct") == 0, "re-ratify resets the shared cycle budget")
ok(d2.is_spent("op", "shared-1"), "re-ratify does NOT clear burned nonces (no replay after reratify)")

# 8. TAMPER-EVIDENCE: integrity holds, then detect an edit
good, msg = d1.verify_integrity()
ok(good, "intact chain verifies")

with open(path) as f:
    lines = f.readlines()
rec = json.loads(lines[0]); rec["nonce"] = "tampered"
lines[0] = json.dumps(rec, separators=(",", ":")) + "\n"
tampered = os.path.join(tmp, "tampered.jsonl")
with open(tampered, "w") as f:
    f.writelines(lines)
t = AuthorizationState.__new__(AuthorizationState)
t.path = tampered
ok(t.verify_integrity()[0] is False, "tamper-evidence: an edited entry breaks the chain")

# 9. TRUNCATION detected on load (raises rather than silently forgetting a burn)
trunc = os.path.join(tmp, "trunc.jsonl")
with open(trunc, "w") as f:
    f.writelines(lines[1:])   # drop the genesis-linked first entry
try:
    AuthorizationState(trunc); ok(False, "truncated chain should fail to load")
except AuthorizationStateError:
    ok(True, "truncation is detected on load (forgotten burns cannot pass silently)")

print(f"\n{p}/{p} tests passed")
