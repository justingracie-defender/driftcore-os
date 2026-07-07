"""
test_cumulative_ledger.py
=========================
Cross-action accounting: fragmentation, cumulative harm, per-effect caps, durability,
cross-instance sharing, tamper-evidence, window rolling, and the verifier-sourced
asymmetry. Red-team this for the sequence-of-safe-actions attack class.
"""
import os, json, time, tempfile
from driftcore.verification.cumulative_ledger import (
    CumulativeLedger, BudgetPolicy, ProposedAction, LedgerVerdict, LedgerIntegrityError,
)

p = 0
def ok(cond, label):
    global p
    assert cond, "FAIL: " + label
    p += 1
    print("  ok:", label)

def egress(n_bytes=0):
    return ProposedAction(effects=("data_egress",), egress_bytes=n_bytes)

# ── 1. FRAGMENTATION: N authorized egress sends hit the volume cap ──
tmp = tempfile.mkdtemp()
pol = BudgetPolicy(window_seconds=3600, max_egress_actions=3)
led = CumulativeLedger(os.path.join(tmp, "frag.jsonl"), pol)
for i in range(3):
    ok(led.check("op", egress()) == LedgerVerdict.OK, f"egress {i+1} within budget")
    led.record("op", egress())
ok(led.check("op", egress()) == LedgerVerdict.DENY,
   "fragmentation: the 4th egress send is DENIED by the cumulative volume budget")

# ── 2. CUMULATIVE HARM: 0.49 x4 crosses a 0.5-ish cap even though each passes ──
pol2 = BudgetPolicy(window_seconds=3600, max_cumulative_harm=1.5)
led2 = CumulativeLedger(os.path.join(tmp, "harm.jsonl"), pol2)
def harm_action(pv): return ProposedAction(effects=("physical_force",), harm_p=pv,
                                           harm_verifier_sourced=True)
for i in range(3):
    ok(led2.check("op", harm_action(0.49)) == LedgerVerdict.OK, f"harm action {i+1} ok (sum rising)")
    led2.record("op", harm_action(0.49))
ok(led2.check("op", harm_action(0.49)) == LedgerVerdict.DENY,
   "cumulative harm: summed P(harm) crosses the budget though each action was under any per-action cutoff")

# ── 3. VERIFIER ASYMMETRY: unverified harm does NOT drive the harm budget ──
led3 = CumulativeLedger(os.path.join(tmp, "unv.jsonl"),
                        BudgetPolicy(window_seconds=3600, max_cumulative_harm=1.0))
unv = ProposedAction(effects=("physical_force",), harm_p=5.0, harm_verifier_sourced=False)
ok(led3.check("op", unv) == LedgerVerdict.OK,
   "asymmetry: an UNVERIFIED harm number does not count toward the cumulative harm budget")
led3.record("op", unv)
ok(led3.usage("op")["harm_sum"] == 0.0,
   "asymmetry: recording an unverified action adds 0 to the harm sum")

# ── 4. SOFT cap -> REVIEW, hard cap -> DENY ──
pol4 = BudgetPolicy(window_seconds=3600, soft_egress_actions=2, max_egress_actions=4)
led4 = CumulativeLedger(os.path.join(tmp, "soft.jsonl"), pol4)
led4.record("op", egress()); led4.record("op", egress())   # now at 2
ok(led4.check("op", egress()) == LedgerVerdict.REVIEW_REQUIRED,
   "soft cap: crossing the soft egress limit escalates to REVIEW")
led4.record("op", egress()); led4.record("op", egress())   # now at 4
ok(led4.check("op", egress()) == LedgerVerdict.DENY,
   "hard cap: crossing the hard egress limit DENIES")

# ── 5. PER-EFFECT cap (e.g. oversight touches) ──
pol5 = BudgetPolicy(window_seconds=3600, max_effect_actions={"oversight_control": 1})
led5 = CumulativeLedger(os.path.join(tmp, "eff.jsonl"), pol5)
osc = ProposedAction(effects=("oversight_control",))
led5.record("op", osc)
ok(led5.check("op", osc) == LedgerVerdict.DENY,
   "per-effect cap: a second oversight_control action this window is DENIED")

# ── 6. EGRESS BYTES budget (slow-exfil by volume) ──
pol6 = BudgetPolicy(window_seconds=3600, max_egress_bytes=1000)
led6 = CumulativeLedger(os.path.join(tmp, "bytes.jsonl"), pol6)
led6.record("op", egress(600))
ok(led6.check("op", egress(600)) == LedgerVerdict.DENY,
   "byte budget: cumulative egress bytes over the cap is DENIED")

# ── 7. check() DOES NOT MUTATE (only record does) ──
led7 = CumulativeLedger(os.path.join(tmp, "nomut.jsonl"),
                        BudgetPolicy(window_seconds=3600, max_egress_actions=1))
led7.check("op", egress()); led7.check("op", egress())   # checks don't consume
ok(led7.check("op", egress()) == LedgerVerdict.OK and led7.usage("op")["egress_actions"] == 0,
   "check() is read-only; only record() consumes budget")

# ── 8. WINDOW ROLLS: budget resets after the window elapses ──
pol8 = BudgetPolicy(window_seconds=0.3, max_egress_actions=1)
led8 = CumulativeLedger(os.path.join(tmp, "roll.jsonl"), pol8)
led8.record("op", egress())
ok(led8.check("op", egress()) == LedgerVerdict.DENY, "within window: at cap -> DENY")
time.sleep(0.35)
ok(led8.check("op", egress()) == LedgerVerdict.OK, "window rolled: budget reset -> OK")

# ── 9. PER-OWNER isolation ──
led9 = CumulativeLedger(os.path.join(tmp, "own.jsonl"),
                        BudgetPolicy(window_seconds=3600, max_egress_actions=1))
led9.record("owner_a", egress())
ok(led9.check("owner_a", egress()) == LedgerVerdict.DENY, "owner_a at cap")
ok(led9.check("owner_b", egress()) == LedgerVerdict.OK, "owner_b has its own budget")

# ── 10. DURABILITY + CROSS-INSTANCE: 8-agents share ONE budget, survives restart ──
shared = os.path.join(tmp, "shared.jsonl")
polS = BudgetPolicy(window_seconds=3600, max_egress_actions=3)
a1 = CumulativeLedger(shared, polS)
a2 = CumulativeLedger(shared, polS)
a1.record("op", egress()); a1.record("op", egress())
a2.record("op", egress())   # instance 2 adds to the SAME shared window
ok(a2.check("op", egress()) == LedgerVerdict.DENY,
   "cross-instance: two instances share one egress budget (8-agent fragmentation closed)")
# crash + reload
a3 = CumulativeLedger(shared, polS)
ok(a3.check("op", egress()) == LedgerVerdict.DENY,
   "durability: the shared budget survives a restart")

# ── 11. TAMPER-EVIDENCE ──
ok(a1.verify_integrity() is True, "intact ledger verifies")
with open(shared) as f:
    lines = f.readlines()
rec = json.loads(lines[0]); rec["d_egress_actions"] = 0
lines[0] = json.dumps(rec, separators=(",", ":")) + "\n"
tampered = os.path.join(tmp, "tampered.jsonl")
with open(tampered, "w") as f:
    f.writelines(lines)
try:
    CumulativeLedger(tampered, polS); ok(False, "tampered chain should raise on load")
except LedgerIntegrityError:
    ok(True, "tamper-evidence: an edited ledger entry breaks the hash chain on load")

print(f"\n{p}/{p} tests passed")
