"""Final scoped+on-demand tests, incl. the three closed holes. Real repo."""
import os, threading
for f in ["driftcore_daily_budget.json","driftcore_spent_tokens.json"]:
    if os.path.exists(f): os.remove(f)
from driftcore.authority.scoped_authorization import (
    OnDemandKeyIssuer, ScopedGate, ActionRequest, Area, ScopedAuthorization,
)
from driftcore.authority.authorization_gate import GateState

p=0
def ok(c,l):
    global p
    assert c, "FAIL: "+l
    p+=1; print("  ok:",l)

iss=OnDemandKeyIssuer(); g=ScopedGate(iss)

print("== on-demand: agent asks, only human grants ==")
r=iss.request_key(Area.PURCHASE, reason="buy ink", amount=25.0)
bad,_,_=iss.grant(r.request_id, admin="agent")
ok(not bad, "agent cannot grant its own key")
good,_,key=iss.grant(r.request_id, admin="justin", spend_cap=25.0, operator="justin")
ok(good and key is not None, "human admin grants one-time scoped key")

print("== key opens its door, once ==")
ok(g.check_action(key, ActionRequest(Area.PURCHASE,25.0), daily_cap=100.0).state is GateState.CLEARED, "valid purchase clears")
ok(g.check_action(key, ActionRequest(Area.PURCHASE,25.0), daily_cap=100.0).state is GateState.BLOCKED, "one-time key dead after one use")

print("== no skeleton keys ==")
r=iss.request_key(Area.CHORES, reason="fold")
_,_,ck=iss.grant(r.request_id, admin="justin", one_time=False, valid_for_seconds=3600)
ok(g.check_action(ck, ActionRequest(Area.PURCHASE,5.0)).state is GateState.BLOCKED, "chores key can't open purchase door")
ok(g.check_action(ck, ActionRequest(Area.CHORES)).state is GateState.CLEARED, "chores key opens chores door")

print("== CLOSED HOLE #1: money action with NO amount is blocked ==")
r=iss.request_key(Area.PURCHASE, reason="x", amount=10.0)
_,_,mk=iss.grant(r.request_id, admin="justin", spend_cap=10.0, operator="justin")
res=g.check_action(mk, ActionRequest(Area.PURCHASE, None), daily_cap=100.0)
ok(res.state is GateState.BLOCKED and "declare an amount" in res.reason, "purchase with amount=None is blocked, not free")

print("== daily budget stops 'ask 10 times' ==")
cleared=0
for i in range(10):
    rr=iss.request_key(Area.PURCHASE, reason=f"#{i}", amount=20.0)
    _,_,k=iss.grant(rr.request_id, admin="justin", spend_cap=20.0, operator="justin")
    res=g.check_action(k, ActionRequest(Area.PURCHASE,20.0), daily_cap=20.0)
    if res.state is GateState.CLEARED:
        cleared+=1; iss.record_spend(k, ActionRequest(Area.PURCHASE,20.0))
ok(cleared==1, f"only 1 of 10 cleared under $20/day budget (got {cleared})")

print("== spend cap enforced ==")
r=iss.request_key(Area.PURCHASE, reason="g", amount=18.0)
_,_,gk=iss.grant(r.request_id, admin="justin", one_time=False, spend_cap=20.0, operator="op2", valid_for_seconds=3600)
ok(g.check_action(gk, ActionRequest(Area.PURCHASE,18.0), daily_cap=1000.0).state is GateState.CLEARED, "within cap clears")
ok(g.check_action(gk, ActionRequest(Area.PURCHASE,500.0), daily_cap=1000.0).state is GateState.BLOCKED, "over cap blocked")

print("== CLOSED HOLE #2: facts-only approval surface hides the reason ==")
r=iss.request_key(Area.PURCHASE, reason="buy insulin for kid (a lie)", amount=5.0)
facts=iss.approval_facts(r.request_id)
ok("reason" not in facts and facts["area"]=="purchase", "approval facts contain area+amount, NOT the agent's reason")
ok(iss.request_reason_for_log(r.request_id) is not None, "reason still available for the audit log only")

print("== CLOSED HOLE #3: base lock verify() preserved (patch had dropped it) ==")
ok(hasattr(iss,"verify") and iss.verify(gk) is True, "verify() exists and works for the base gate")

print("== atomic burn under concurrency: same 1-time key fired in parallel ==")
r=iss.request_key(Area.CHORES, reason="race")
_,_,rk=iss.grant(r.request_id, admin="justin", one_time=True)
results=[]
def fire():
    results.append(g.check_action(rk, ActionRequest(Area.CHORES)).state)
threads=[threading.Thread(target=fire) for _ in range(20)]
for t in threads: t.start()
for t in threads: t.join()
cleared_count=sum(1 for s in results if s is GateState.CLEARED)
ok(cleared_count==1, f"exactly 1 of 20 parallel uses cleared (got {cleared_count})")

print("== revocation: admin kills a standing key ==")
r=iss.request_key(Area.CHORES, reason="standing")
_,_,sk=iss.grant(r.request_id, admin="justin", one_time=False, valid_for_seconds=3600)
ok(g.check_action(sk, ActionRequest(Area.CHORES)).state is GateState.CLEARED, "standing key works")
iss.revoke(sk.token, admin="justin")
ok(g.check_action(sk, ActionRequest(Area.CHORES)).state is GateState.BLOCKED, "revoked key is dead")

print(f"\nALL {p} CHECKS PASSED")
