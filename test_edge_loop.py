"""
test_edge_loop.py — THE HUMAN-RATIFIED LEARNING LOOP
====================================================

Proves:
  - edge detection: insufficient-signal / uncovered / conflict / covered
  - insufficient signal NEVER fabricates (only clarification is ratifiable)
  - a ruling can NEVER lower a bright line (guard refuses lethal etc.)
  - human-only: an agent cannot ratify or overturn
  - ratifying produces a regression case (the test to add)
  - revisable: overturn APPENDS a correction; ledger append-only & tamper-evident

Run with:  python test_edge_loop.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from driftcore.verification.edge_loop import (
    EdgeLoop, EdgeType, CLARIFY,
)
from driftcore.verification.invariant_guard import Effect

PASS, FAIL = "✅", "❌"
results = []
def check(n, c):
    print(f"  {'✅' if c else '❌'}  {n}")
    results.append((n, bool(c)))

loop = EdgeLoop()


# ── 1. Edge detection ──────────────────────────────────────────────
print("\nEdge detection:")
ins = loop.detect("Lotus d jegyxuv", signal_quality=0.1)
unc = loop.detect("brand-new situation", matched_rules=[])
con = loop.detect("tricky case", matched_rules=["A", "B"], rule_outcomes=["allow", "deny"])
cov = loop.detect("ordinary case", matched_rules=["A"], rule_outcomes=["allow"])
check("low signal -> INSUFFICIENT_SIGNAL", ins.edge_type == EdgeType.INSUFFICIENT_SIGNAL.value)
check("no rule -> UNCOVERED",              unc.edge_type == EdgeType.UNCOVERED.value)
check("disagreeing rules -> CONFLICT",     con.edge_type == EdgeType.CONFLICT.value)
check("rule applies -> COVERED (no edge)", cov.edge_type == EdgeType.COVERED.value and not cov.is_edge)
check("insufficient -> only option is clarify", ins.recommended == "clarify")
check("uncovered -> recommends conservative",   unc.recommended == "conservative")
check("conflict -> recommends escalate",        con.recommended == "escalate")


# ── 2. Insufficient signal NEVER fabricates ────────────────────────
print("\nInsufficient signal never fabricates:")
r = loop.ratify(ins, custom_outcome="ACT_ON_IT", by="human_operator")
check("ratify 'act anyway' on garbage -> REFUSED", r["status"] == "REFUSED")
ok = loop.ratify(ins, choice="clarify", by="human_operator", rationale="ask user")
check("ratify clarification -> RATIFIED", ok["status"] == "RATIFIED")
check("clarification outcome is REQUEST_CLARIFICATION", ok["ruling"].outcome == CLARIFY)


# ── 3. A ruling can NEVER lower a bright line ───────────────────────
print("\nNo ruling can lower a bright line:")
lethal = loop.ratify(unc, custom_outcome="open fire", custom_effect=Effect.LETHAL,
                     by="human_operator")
check("ratify a LETHAL outcome -> REFUSED", lethal["status"] == "REFUSED")
check("  -> cites the invariant", "bright line" in lethal["reason"].lower())
# a non-blocked outcome is allowed
safe = loop.ratify(unc, choice="conservative", by="human_operator", rationale="be safe")
check("conservative ruling -> RATIFIED", safe["status"] == "RATIFIED")


# ── 4. Human-only ──────────────────────────────────────────────────
print("\nHuman-only authority:")
check("agent cannot ratify",  loop.ratify(unc, "conservative", by="agent")["status"] == "DENIED")
check("agent cannot overturn", loop.overturn("r1", by="agent")["status"] == "DENIED")


# ── 5. Ratifying produces a regression case (the test to add) ──────
print("\nRatification yields a regression test:")
rc = safe["ruling"].regression_case
check("regression case has input + expected",
      "input" in rc and "expected" in rc and rc["expected"] == "DEFAULT_REVERSIBLE")


# ── 6. Revisable + append-only + tamper-evident ────────────────────
print("\nRevisable, append-only, tamper-evident:")
rid = safe["ruling"].rid
before = len(loop.ledger)
loop.overturn(rid, by="human_operator", rationale="superseded by a better rule")
check("overturn APPENDS (history not erased)", len(loop.ledger) == before + 1)
check("ruling now marked overturned",          loop.ledger.is_overturned(rid) is True)
check("overturned ruling drops from active set",
      all(p["rid"] != rid for p in loop.ledger.active_rulings()))
check("ledger chain verifies",                 loop.ledger.verify_chain() is True)
loop.ledger._chain[0]["payload"]["outcome"] = "TAMPERED"
check("tampering is detected",                 loop.ledger.verify_chain() is False)


# ── RESULTS ────────────────────────────────────────────────────────
print("\n" + "=" * 60)
passed = sum(1 for _, ok in results if ok)
total  = len(results)
print(f"  {passed}/{total} tests passed")
if passed == total:
    print(f"  {PASS} Edges detected, options proposed, human ratifies, lessons revisable.")
    print(f"  Garbage never fabricated; no ruling lowers a bright line.")
else:
    print(f"\n  {FAIL} Failed:")
    for n, ok in results:
        if not ok: print(f"      • {n}")
print("=" * 60)
if passed < total:
    sys.exit(1)
