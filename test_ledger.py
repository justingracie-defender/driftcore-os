"""
test_ledger.py — SHARED HASH-CHAIN LEDGER PRIMITIVE
===================================================
The one implementation behind GovernanceMemory and RulingLedger. If this
is solid, the tamper-evidence of both is solid.

Run with:  python test_ledger.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from driftcore.verification.ledger import HashChainLedger

PASS, FAIL = "✅", "❌"
results = []
def check(n, c):
    print(f"  {'✅' if c else '❌'}  {n}")
    results.append((n, bool(c)))

print("\nHash-chain ledger:")
L = HashChainLedger()
check("empty ledger verifies",        L.verify() is True)
check("empty length is 0",            len(L) == 0)

e1 = L.append({"event": "a"})
e2 = L.append({"event": "b"})
e3 = L.append({"event": "c"})
check("append grows the chain",       len(L) == 3)
check("first entry links to GENESIS", e1["prev"] == HashChainLedger.GENESIS)
check("each entry links to the prior hash",
      e2["prev"] == e1["hash"] and e3["prev"] == e2["hash"])
check("intact chain verifies",        L.verify() is True)
check("payload is preserved",         L.chain[1]["event"] == "b")

# tamper a payload field
L.chain[1]["event"] = "TAMPERED"
check("tampering a payload -> verify False", L.verify() is False)

# tamper a link
L2 = HashChainLedger()
L2.append({"event": "x"})
L2.append({"event": "y"})
L2.chain[1]["prev"] = "0" * 64
check("tampering a link -> verify False", L2.verify() is False)

# independence between instances
A, B = HashChainLedger(), HashChainLedger()
A.append({"event": "only-A"})
check("instances are independent", len(A) == 1 and len(B) == 0)

print("\n" + "=" * 56)
passed = sum(1 for _, ok in results if ok)
total  = len(results)
print(f"  {passed}/{total} tests passed")
print(f"  {PASS if passed == total else FAIL} One tamper-evident ledger, used everywhere.")
print("=" * 56)
if passed < total:
    sys.exit(1)
