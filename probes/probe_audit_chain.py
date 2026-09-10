"""Attack the audit chain. It claims: altered, deleted, or inserted records
break the chain and the system shuts down.

Three verbs, three attacks, plus the one nobody states: TRUNCATION. A hash chain
links each entry to the one before it, which makes it tamper-evident against
edits in the middle — and says nothing about lopping off the end, because a
shorter chain is still internally consistent.

Run from the repo root: python3 probes/probe_audit_chain.py
"""
import json
import os
import shutil
import sys
import tempfile

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if not os.path.isdir(os.path.join(_root, "driftcore")):
    raise SystemExit(f"REFUSING TO RUN: no driftcore package at {_root!r}.")
sys.path.insert(0, _root)

# (2026-09-09) An unconfigured process now REFUSES identity rather than accepting
# any name not on a six-word denylist. A probe is not a deployment and verifies
# nobody, so it declares that — otherwise its own CONTROLS fail and the failure
# reads as a finding. Caught exactly that way: this probe reported a "leak" that
# was its legitimate-release control being denied.
import driftcore.authority.human_identity as _identity_boot
_identity_boot.declare_label_only("probe: single process, no verifier installed")


RESULTS = []


def result(attack, detected, detail=""):
    RESULTS.append((attack, detected))
    print(f"  {'ok  ' if detected else 'LEAK'}  {attack:38s} "
          f"{'detected' if detected else 'NOT DETECTED'}")
    if detail:
        print(f"         {detail}")


def fresh_chain(n=4):
    """A real chain in a scratch cwd, so nothing touches the repo's own log."""
    d = tempfile.mkdtemp()
    os.chdir(d)
    import importlib
    import driftcore.audit as audit
    importlib.reload(audit)
    for i in range(n):
        audit.record(action=f"EVENT_{i}", memory_text=f"entry {i}",
                     authorised_by="operator_jane")
    return d, audit


def verify(audit=None):
    """Verify in a FRESH INTERPRETER, reading only the file.

    An earlier version of this probe called verify_chain() in-process. `_last_hash`
    and `_sequence` are module globals, so truncation was 'detected' by memory
    state that a restart destroys — the check passed for a reason the threat model
    does not have. The realistic attacker edits the log while the system is down.
    """
    import subprocess
    code = ("import sys; sys.path.insert(0, %r)\n"
            "import driftcore.audit as a\n"
            "try: print('OK' if a.verify_chain() else 'BAD')\n"
            "except SystemExit: print('BAD')\n"
            "except Exception: print('BAD')\n") % _root
    out = subprocess.run([sys.executable, "-c", code], cwd=os.getcwd(),
                         capture_output=True, text=True, timeout=60)
    return "OK" in out.stdout


def path_of(d):
    for c in ("logs/audit_chain.jsonl", "audit_chain.jsonl"):
        p = os.path.join(d, c)
        if os.path.exists(p):
            return p
    raise SystemExit("chain file not found — probe cannot run, NOT a clearance")


print("\n[control] an untampered chain must VERIFY")
d, audit = fresh_chain()
p = path_of(d)
_clean = verify()
print(f"  {'ok  ' if _clean else 'BROKEN'}  clean chain verifies: {_clean}")
if not _clean:
    raise SystemExit("  control failed — every result below would be meaningless")
_backup = open(p).read()
_head_backup = open(os.path.join(os.path.dirname(p) or ".", "audit_head.json")).read()


def restore():
    open(p, "w").write(_backup)


print("\n[1] ALTER a record in the middle")
lines = _backup.splitlines()
e = json.loads(lines[1]); e["memory_text"] = "ALTERED"
lines[1] = json.dumps(e)
open(p, "w").write("\n".join(lines) + "\n")
result("alter a middle record", not verify())
restore()

print("\n[2] DELETE a record from the middle")
lines = _backup.splitlines()
del lines[1]
open(p, "w").write("\n".join(lines) + "\n")
result("delete a middle record", not verify())
restore()

print("\n[3] INSERT a forged record")
lines = _backup.splitlines()
e = json.loads(lines[1]); e["action"] = "FORGED_APPROVAL"
lines.insert(2, json.dumps(e))
open(p, "w").write("\n".join(lines) + "\n")
result("insert a forged record", not verify())
restore()

print("\n[4] TRUNCATE the tail — the verb the guarantee does not name")
lines = _backup.splitlines()
open(p, "w").write("\n".join(lines[:-1]) + "\n")
_trunc_detected = not verify()
result("truncate the last record", _trunc_detected,
       "A hash chain links each entry BACKWARDS. Removing the newest leaves a "
       "shorter chain that is still internally consistent, so links alone cannot "
       "see it. Detecting this needs a length or head-pointer kept somewhere the "
       "attacker does not control.")
restore()

print("\n[5] TRUNCATE everything — reset to an empty chain")
open(p, "w").write("")
_empty_detected = not verify()
result("truncate the entire chain", _empty_detected,
       "An empty chain has no broken link either. If this passes, deleting the "
       "log is quieter than editing it.")
restore()

print("\n[5b] DELETE the chain file entirely — not the same as emptying it")
os.remove(p_chain := p)
_del_detected = not verify()
result("delete the chain file", _del_detected,
       "Truncating to zero bytes and deleting the file are two spellings of "
       "'no entries'. The v113 anchor caught one and returned True before "
       "consulting itself on the other.")
restore()

print("\n[5c] THE FULL GRID — {empty, deleted} x {intact, corrupt, deleted}")
# Enumerated as a grid rather than as remembered cases. Three separate passes at
# this fix each closed a subset and each reported success; the cell that survived
# longest (delete chain + corrupt head) was found by a reviewer who wrote the grid
# out instead of listing the attacks they happened to think of.
_CORRUPT = '{"sequence":9,"entry_hash":"x","mac":"wrong"}'
_head = os.path.join(os.path.dirname(p) or ".", "audit_head.json")
for _chain_state in ("empty", "deleted"):
    for _head_state in ("intact", "corrupt", "deleted"):
        restore()
        if _chain_state == "empty":
            open(p, "w").write("")
        else:
            os.remove(p)
        if _head_state == "corrupt":
            open(_head, "w").write(_CORRUPT)
        elif _head_state == "deleted":
            try:
                os.remove(_head)
            except FileNotFoundError:
                pass
        # Both files gone is indistinguishable from a fresh install using only
        # what is inside the box. It is expected to pass and is not a clearance.
        _both_gone = _chain_state == "deleted" and _head_state == "deleted"
        _det = not verify()
        result(f"chain {_chain_state} + head {_head_state}",
               _det or _both_gone,
               "expected to pass — needs an anchor outside the box"
               if _both_gone else "")
        if _head_state != "intact":
            open(_head, "w").write(_head_backup)
restore()
open(_head, "w").write(_head_backup)

print("\n[6] REWRITE the whole chain consistently")
# The strongest attack: an attacker who has the hashing code can rebuild a
# self-consistent chain from scratch. Nothing anchors this file to the outside.
try:
    import importlib
    a2 = importlib.reload(audit)
    os.remove(p)
    a2.record(action="REWRITTEN", memory_text="a chain of my own",
              authorised_by="mallory")
    _rewrite_detected = not verify()
except Exception as ex:
    _rewrite_detected = True
result("rebuild a self-consistent chain", _rewrite_detected,
       "Tamper-EVIDENCE requires an anchor the attacker cannot recompute — a "
       "signature over the head, or a copy off-box. A pure hash chain in a file "
       "the attacker can write proves ordering, not authenticity.")
restore()

print("\n" + "=" * 70)
leaks = [a for a, d in RESULTS if not d]
print(f"  attacks run : {len(RESULTS)}")
print(f"  detected    : {len(RESULTS) - len(leaks)}")
print(f"  NOT detected: {len(leaks)}")
for a in leaks:
    print(f"      {a}")
print()
print("  The claim under test was: 'If any record is altered, deleted, or")
print("  inserted, the chain breaks.' Those three verbs are the ones a hash")
print("  chain covers. Whether the sentence should also name truncation and")
print("  wholesale replacement is what these results decide.")
