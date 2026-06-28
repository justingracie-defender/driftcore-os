"""
test_recovery.py
================
Proves the recovery ("digital save state") layer:

  - The agent-facing store can create/read but has NO delete/modify method.
  - Restore and prune require a HUMAN authoriser (agent/system rejected).
  - The ledger is tamper-evident (altering/removing an event is detected).
  - A monitor halt freezes new actions and preserves save-states.
  - Restore is refused if the ledger is compromised.
  - Full round-trip: snapshot -> mutate -> halt -> human restore -> data back.

Run:  python test_recovery.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from driftcore.recovery import (
    CheckpointStore, RestoreAuthority, RecoveryManager,
    InMemorySnapshotter, CheckpointStatus,
)

PASS, FAIL = "PASS", "FAIL"
_results = []


def check(name, cond):
    _results.append(bool(cond))
    print(f"  [{PASS if cond else FAIL}] {name}")


# ── Agent-facing store is create/read only ─────────────────────────
print("\nAgent-facing store has no delete/modify")

store = CheckpointStore()
api = dir(store)
check("no delete method on store",
      not any(m in api for m in ("delete", "remove", "modify", "edit", "update")))
check("has create/get/list/verify",
      all(m in api for m in ("create", "get", "list", "verify_integrity")))


# ── Create + integrity ─────────────────────────────────────────────
print("\nCreate + ledger integrity")

snap = InMemorySnapshotter({"db:row1": "original", "db:row2": "keep"})
mgr = RecoveryManager(store, snap)

ok, cid = mgr.before_action("update row1", ["db:row1"], triggered_by="agent")
check("checkpoint created before action", ok and isinstance(cid, str))
intact, _ = store.verify_integrity()
check("ledger verifies intact after create", intact is True)


# ── Restore requires a human ───────────────────────────────────────
print("\nRestore is human-only")

# agent mutates the data
snap.state["db:row1"] = "AGENT CHANGED THIS"

ok_sys, _ = mgr.restore(cid, authorised_by="system")
check("restore by 'system' rejected", ok_sys is False)
ok_agent, _ = mgr.restore(cid, authorised_by="agent")
check("restore by 'agent' rejected", ok_agent is False)
check("data still changed after rejected restores",
      snap.state["db:row1"] == "AGENT CHANGED THIS")

ok_human, _ = mgr.restore(cid, authorised_by="justin")
check("restore by human succeeds", ok_human is True)
check("data rolled back to pre-action state",
      snap.state["db:row1"] == "original")
check("untouched resource unaffected", snap.state["db:row2"] == "keep")


# ── Tamper evidence ────────────────────────────────────────────────
print("\nLedger is tamper-evident")

store2 = CheckpointStore()
mgr2 = RecoveryManager(store2, InMemorySnapshotter({"x": "1"}))
mgr2.before_action("a1", ["x"])
mgr2.before_action("a2", ["x"])
intact_before, _ = store2.verify_integrity()
check("two-checkpoint ledger intact", intact_before is True)

# tamper: drop the first event (simulate a deleted save-state record)
del store2._events[0]
intact_after, reason = store2.verify_integrity()
check("removing a ledger event is detected", intact_after is False)

# restore refuses on a compromised ledger
store3 = CheckpointStore()
snap3 = InMemorySnapshotter({"y": "ok"})
mgr3 = RecoveryManager(store3, snap3)
_, cid3 = mgr3.before_action("a", ["y"])
store3._events[-1] = store3._events[-1].__class__(
    **{**store3._events[-1].__dict__, "detail": "tampered"})
ok_t, msg_t = mgr3.restore(cid3, authorised_by="justin")
check("restore refused when ledger compromised", ok_t is False)


# ── Halt / freeze ──────────────────────────────────────────────────
print("\nMonitor halt freezes mutation, preserves save-states")

store4 = CheckpointStore()
snap4 = InMemorySnapshotter({"z": "v0"})
mgr4 = RecoveryManager(store4, snap4)
ok0, cid4 = mgr4.before_action("safe action", ["z"])
check("action allowed before halt", ok0 is True)

result = mgr4.trigger_halt("mass-delete pattern detected", severity="critical")
check("halt sets frozen state", mgr4.frozen is True)
check("halt reports checkpoints available", result["checkpoints_available"] >= 1)

ok_frozen, _ = mgr4.before_action("another action", ["z"])
check("new actions refused while frozen", ok_frozen is False)

# restore still works while frozen (rolling back is what you do during a halt)
snap4.state["z"] = "corrupted"
ok_r, _ = mgr4.restore(cid4, authorised_by="justin")
check("human restore works while frozen", ok_r and snap4.state["z"] == "v0")

# unfreeze is human-only
ok_uf_sys, _ = mgr4.unfreeze("system")
check("unfreeze by 'system' rejected", ok_uf_sys is False)
ok_uf, _ = mgr4.unfreeze("justin")
check("unfreeze by human succeeds", ok_uf and mgr4.frozen is False)


# ── Prune keeps the record, drops the bytes ────────────────────────
print("\nPrune is human-only and keeps the ledger record")

auth = RestoreAuthority(store4, snap4)
ok_p_sys, _ = auth.prune(cid4, authorised_by="system")
check("prune by 'system' rejected", ok_p_sys is False)
ok_p, _ = auth.prune(cid4, authorised_by="justin")
check("prune by human succeeds", ok_p is True)
check("pruned checkpoint marked PRUNED, record remains",
      store4.get(cid4).status is CheckpointStatus.PRUNED)
intact_final, _ = store4.verify_integrity()
check("ledger still intact after prune", intact_final is True)


# ── Hardening: empty resources + concurrency ───────────────────────
print("\nHardening")

store5 = CheckpointStore()
mgr5 = RecoveryManager(store5, InMemorySnapshotter({"a": 1}))
ok_empty, _ = mgr5.before_action("noop", [])
check("before_action rejects empty resource_ids", ok_empty is False)

raised = False
try:
    store5.create("noop", [], b"x")
except ValueError:
    raised = True
check("store.create raises on empty resource_ids", raised is True)

# concurrent creates must not corrupt the hash-linked ledger
import threading
store6 = CheckpointStore()
snap6 = InMemorySnapshotter({f"r{i}": i for i in range(50)})
mgr6 = RecoveryManager(store6, snap6)

def worker(n):
    for i in range(20):
        mgr6.before_action(f"act-{n}-{i}", [f"r{(n + i) % 50}"])

threads = [threading.Thread(target=worker, args=(n,)) for n in range(5)]
for t in threads: t.start()
for t in threads: t.join()

intact_conc, reason_conc = store6.verify_integrity()
check("ledger intact after 100 concurrent creates", intact_conc is True)
check("all 100 concurrent checkpoints recorded", len(store6.list()) == 100)


# ── Checkpoint context metadata (decision-path traceability) ───────
print("\nContext metadata: trace an incident to the decision path")

from driftcore.recovery import CheckpointContext

store7 = CheckpointStore()
snap7 = InMemorySnapshotter({"lesson:1": "v0"})
mgr7 = RecoveryManager(store7, snap7)

ctx = CheckpointContext(domain="childcare", skill="TutoringSkill",
                        skill_version="v4.2", profile="CaregiverProfile",
                        mode="TRUTH")
ok7, cid7 = mgr7.before_action("update tutoring record", ["lesson:1"],
                               triggered_by="agent", context=ctx)
cp = store7.get(cid7)
check("checkpoint carries the domain", cp.context.domain == "childcare")
check("checkpoint carries the skill version", cp.context.skill_version == "v4.2")
check("incident review can answer which profile was active",
      cp.context.profile == "CaregiverProfile")

intact_ctx, _ = store7.verify_integrity()
check("context-bearing ledger verifies intact", intact_ctx is True)
create_evt = [e for e in store7.events() if e.checkpoint_id == cid7][0]
check("context is folded into the hashed event record",
      "childcare" in create_evt.detail and "v4.2" in create_evt.detail)

ok_nc, cid_nc = mgr7.before_action("plain action", ["lesson:1"])
check("checkpoints without context still work",
      ok_nc and store7.get(cid_nc).context.summary() == "no-context")


print("\n" + "=" * 56)
passed, total = sum(_results), len(_results)
print(f"{passed}/{total} checks passed")
print("=" * 56)
if passed < total:
    sys.exit(1)
