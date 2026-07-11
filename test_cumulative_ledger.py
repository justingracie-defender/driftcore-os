"""
test_cumulative_ledger.py  (v2)
===============================
Cross-action accounting hardened against concurrency + window attacks. Reserve/
commit/rollback model. Red-team this for the sequence-of-safe-actions class AND for
the race/window/enum/laundering attacks a fifth review found.
"""
import os, time, json, tempfile, threading
from driftcore.verification.cumulative_ledger import (
    CumulativeLedger, BudgetPolicy, ProposedAction, Reservation, LedgerVerdict,
    LedgerIntegrityError, UnknownEffect, OwnerNotAuthenticated,
)

p = 0
def ok(cond, label):
    global p
    assert cond, "FAIL: " + label
    p += 1
    print("  ok:", label)

def egress(n_bytes=0):
    return ProposedAction(effects=("data_egress",), egress_bytes=n_bytes)
def harm(pv, verified=True):
    return ProposedAction(effects=("physical_force",), harm_p=pv, harm_verifier_sourced=verified)

tmp = tempfile.mkdtemp()

def led(name, **pol_kw):
    return CumulativeLedger(os.path.join(tmp, name), BudgetPolicy(**pol_kw))

def take(l, owner, action, aid=None):
    """reserve+commit helper for the common 'action succeeds' path."""
    r = l.reserve(owner, action, action_id=aid)
    if r.verdict is not LedgerVerdict.DENY:
        l.commit(r)
    return r.verdict

# ── 1. FRAGMENTATION (core promise) ──
l = led("frag.jsonl", window_seconds=3600, max_egress_actions=3)
for i in range(3):
    ok(take(l, "op", egress()) == LedgerVerdict.OK, f"egress {i+1} within budget")
ok(l.reserve("op", egress()).verdict == LedgerVerdict.DENY,
   "fragmentation: 4th egress send DENIED by cumulative budget")

# ── 2. CUMULATIVE HARM SCORE ──
l = led("harm.jsonl", window_seconds=3600, max_harm_score=1.5)
for i in range(3):
    ok(take(l, "op", harm(0.49)) == LedgerVerdict.OK, f"harm action {i+1} ok")
ok(l.reserve("op", harm(0.49)).verdict == LedgerVerdict.DENY,
   "cumulative harm: summed score crosses budget though each action was under any per-action cutoff")

# ── 3. THE TOCTOU RACE (the v2 headline fix) ──
# Two reservations BEFORE either commits: the second must see the first's HOLD.
l = led("race.jsonl", window_seconds=3600, max_egress_actions=1)
r1 = l.reserve("op", egress())
r2 = l.reserve("op", egress())   # r1 not yet committed -- must still be blocked
ok(r1.verdict == LedgerVerdict.OK and r2.verdict == LedgerVerdict.DENY,
   "RACE FIXED: a second reservation sees the first's hold and is DENIED before commit")

# concurrency stress: N threads race for a budget of K; exactly K may win
l = led("race2.jsonl", window_seconds=3600, max_egress_actions=5)
wins = []
lockp = threading.Lock()
def worker():
    r = l.reserve("op", egress())
    if r.verdict is not LedgerVerdict.DENY:
        l.commit(r)
        with lockp: wins.append(1)
threads = [threading.Thread(target=worker) for _ in range(50)]
for t in threads: t.start()
for t in threads: t.join()
ok(sum(wins) == 5,
   f"RACE FIXED under load: exactly 5 of 50 concurrent reservers won (got {sum(wins)})")

# ── 4. ROLLBACK releases the hold (no undercount/overcount) ──
l = led("rb.jsonl", window_seconds=3600, max_egress_actions=1)
r = l.reserve("op", egress())
ok(r.verdict == LedgerVerdict.OK, "reserve granted")
l.rollback(r)   # action failed -> release
ok(l.reserve("op", egress()).verdict == LedgerVerdict.OK,
   "rollback: a released hold frees the budget for a real action")

# ── 5. UNCOMMITTED HOLD EXPIRES (crash between reserve and commit self-heals) ──
l = led("ttl.jsonl", window_seconds=3600, reservation_ttl=0.3, max_egress_actions=1)
r = l.reserve("op", egress())   # held, never committed (simulated crash)
ok(l.reserve("op", egress()).verdict == LedgerVerdict.DENY, "hold occupies budget")
time.sleep(0.35)
ok(l.reserve("op", egress()).verdict == LedgerVerdict.OK,
   "crash-heal: an uncommitted hold expires and frees the budget")

# ── 6. IDEMPOTENCY seam: same action_id doesn't double-count ──
l = led("idem.jsonl", window_seconds=3600, max_egress_actions=1)
r = l.reserve("op", egress(), action_id="email-42"); l.commit(r)
r2 = l.reserve("op", egress(), action_id="email-42")   # retry same action
ok(r2.verdict == LedgerVerdict.OK and l.usage("op")["egress_actions"] == 1,
   "idempotency: a committed action_id re-reserves as a no-op (retry safe)")

# ── 7. WINDOW-EDGE BURST attack closed by rolling burst cap ──
# coarse window is generous, but no more than 2 egress in any 0.4s burst
l = led("burst.jsonl", window_seconds=3600, max_egress_actions=100,
        burst_seconds=0.4, max_burst_egress_actions=2)
ok(take(l, "op", egress()) == LedgerVerdict.OK, "burst: 1st ok")
ok(take(l, "op", egress()) == LedgerVerdict.OK, "burst: 2nd ok")
ok(l.reserve("op", egress()).verdict == LedgerVerdict.DENY,
   "burst cap: 3rd egress within the rolling burst window is DENIED (spike blocked)")
time.sleep(0.45)
ok(take(l, "op", egress()) == LedgerVerdict.OK,
   "burst window slid: egress allowed again after the burst window passes")

# ── 8. EFFECT ENUM VALIDATION: aliases/typos rejected fail-closed ──
l = led("enum.jsonl", window_seconds=3600, max_egress_actions=1)
try:
    l.reserve("op", ProposedAction(effects=("data-egress",)))   # dash, not underscore
    ok(False, "aliased effect should raise")
except UnknownEffect:
    ok(True, "enum: an aliased/typo'd effect ('data-egress') is rejected, not silently uncounted")

# ── 9. OWNER AUTHENTICATION seam: budget-laundering closed when required ──
l = CumulativeLedger(os.path.join(tmp, "auth.jsonl"),
                     BudgetPolicy(window_seconds=3600, max_egress_actions=1),
                     require_authenticated_owner=True)
try:
    l.reserve("worker7", egress()); ok(False, "unregistered owner should raise")
except OwnerNotAuthenticated:
    ok(True, "laundering: an unregistered (unauthenticated) owner cannot reserve")
l.register_owner("worker7")   # broker binds identity
ok(take(l, "worker7", egress()) == LedgerVerdict.OK,
   "an authenticated owner (broker-registered) can reserve normally")

# ── 10. VERIFIER ASYMMETRY: unverified harm can't drive the score ──
l = led("unv.jsonl", window_seconds=3600, max_harm_score=1.0)
ok(take(l, "op", harm(5.0, verified=False)) == LedgerVerdict.OK
   and l.usage("op")["harm_score"] == 0.0,
   "asymmetry: an unverified harm number contributes 0 to the harm-score budget")

# ── 11. SOFT->REVIEW, HARD->DENY ──
l = led("soft.jsonl", window_seconds=3600, soft_egress_actions=2, max_egress_actions=4)
take(l, "op", egress()); take(l, "op", egress())
ok(l.reserve("op", egress()).verdict == LedgerVerdict.REVIEW_REQUIRED,
   "soft cap crossed -> REVIEW_REQUIRED")

# ── 12. CONSTRUCTOR VALIDATION: hard >= soft enforced (was only documented) ──
try:
    BudgetPolicy(max_egress_actions=2, soft_egress_actions=5); ok(False, "should raise")
except ValueError:
    ok(True, "constructor: hard < soft is rejected at construction")

# ── 13. DURABILITY + CROSS-INSTANCE: 8-agents share one budget, survive restart ──
shared = os.path.join(tmp, "shared.jsonl")
pol = BudgetPolicy(window_seconds=3600, max_egress_actions=3)
a1 = CumulativeLedger(shared, pol); a2 = CumulativeLedger(shared, pol)
take(a1, "op", egress()); take(a1, "op", egress()); take(a2, "op", egress())
ok(a2.reserve("op", egress()).verdict == LedgerVerdict.DENY,
   "cross-instance: two instances share one egress budget (8-agent fragmentation closed)")
a3 = CumulativeLedger(shared, pol)
ok(a3.reserve("op", egress()).verdict == LedgerVerdict.DENY,
   "durability: shared budget survives a restart")

# ── 14. TAMPER-EVIDENCE ──
ok(a1.verify_integrity() is True, "intact ledger verifies")
with open(shared) as f: lines = f.readlines()
rec = json.loads(lines[0]); rec["d_egress_actions"] = 0
lines[0] = json.dumps(rec, separators=(",", ":")) + "\n"
tampered = os.path.join(tmp, "tampered.jsonl")
with open(tampered, "w") as f: f.writelines(lines)
try:
    CumulativeLedger(tampered, pol); ok(False, "tampered chain should raise")
except LedgerIntegrityError:
    ok(True, "tamper-evidence: an edited ledger entry breaks the hash chain on load")

# ── 15. DENY reservation holds nothing (safe to ignore) ──
l = led("deny.jsonl", window_seconds=3600, max_egress_actions=0)
r = l.reserve("op", egress())
ok(r.verdict == LedgerVerdict.DENY, "over-cap reserve returns DENY")
l.commit(r)  # committing a DENY must be a no-op
ok(l.usage("op")["egress_actions"] == 0, "committing a DENY reservation records nothing")

print(f"\n{p}/{p} tests passed")
