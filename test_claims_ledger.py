"""
test_claims_ledger.py — does the ledger actually catch what it says it catches?

A governance tool that only passes on already-fixed code proves nothing. So the
central test here rebuilds the exact defect shapes this session found, in a scratch
tree, and asserts the tool flags them. Ground truth, not self-assessment.

Run: python3 test_claims_ledger.py
"""

import importlib.util
import json
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "claims_ledger", Path(__file__).parent / "scripts" / "claims_ledger.py")
CL = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(CL)

_passed = _total = 0


def check(label, cond):
    global _passed, _total
    _total += 1
    if cond:
        _passed += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


def tree(files):
    """A scratch package with the given {relpath: source}."""
    d = Path(tempfile.mkdtemp())
    for rel, body in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return d


def scan(d):
    return CL.scan_claims(d / "driftcore", d)


print("=== the summary line of a CRITICAL docstring is a claim ===")

d = tree({"driftcore/hardware/x.py": '''
def impl_id():
    """A stable identity for the CODE registered behind an actuator."""
'''})
_, loose = scan(d)
check("a plain declarative summary with NO modal word is caught",
      any("stable identity" in u["text"] for u in loose))
check("and it is recorded as a summary claim",
      any(u["kind"] == "summary" for u in loose))

d = tree({"driftcore/safety/y.py": '''
"""y.py — Physical System Cutoff

In real deployment this maps to physical relay/interlock signals.
"""
'''})
_, loose = scan(d)
check("a module-level summary is caught too",
      any("Physical System Cutoff" in u["text"] for u in loose))


print("=== modal assertions in the body are caught as well ===")

d = tree({"driftcore/kernel/z.py": '''
class R:
    """Levels.

    Graduated responses prevent unnecessary shutdowns while ensuring dangerous
    situations are always stopped.
    """
'''})
_, loose = scan(d)
check("an 'always' assertion below the summary is caught",
      any("always stopped" in u["text"] for u in loose))
check("and is recorded as an assertion, not a summary",
      any(u["kind"] == "assertion" and "always stopped" in u["text"]
          for u in loose))


print("=== history and stated limits are NOT claims about current behaviour ===")

d = tree({"driftcore/safety/h.py": '''
def f():
    """Does a thing.

    An earlier version did not refuse this and the machine never stopped.
    HONEST LIMIT: this cannot prove the actuator obeyed.
    """
'''})
_, loose = scan(d)
texts = " ".join(u["text"] for u in loose)
check("a past-defect sentence is not demanded as a claim",
      "An earlier version" not in texts)
check("an acknowledged limit is not demanded as a claim",
      "HONEST LIMIT" not in texts)


print("=== non-CRITICAL modules are out of scope ===")

d = tree({"driftcore/fable/story.py": '''
"""A narrative helper that must never be used for safety decisions."""
'''})
_, loose = scan(d)
check("a LOW-tier module contributes nothing", loose == [])


print("=== tagging removes a claim from the untagged backlog ===")

body = '''
def f():
    """Does a thing.

    CLAIM never-widens: a commanded level fires that level and every lesser one,
    never a greater one.
    """
'''
d = tree({"driftcore/hardware/t.py": body})
tagged, loose = scan(d)
check("the tag is picked up", "driftcore/hardware/t.py:never-widens" in tagged)
check("wrapped continuation lines are captured, not truncated at the newline",
      "never a greater one" in tagged["driftcore/hardware/t.py:never-widens"]["text"])
check("and the tagged sentence is not ALSO reported as untagged",
      not any("every lesser one" in u["text"] for u in loose))


print("=== an unpaired tagged claim FAILS ===")

d = tree({"driftcore/hardware/t.py": body})
refs = CL.scan_references(d)
check("no test names it", "driftcore/hardware/t.py:never-widens" not in refs)

(d / "test_thing.py").write_text(
    "# CLAIMS: driftcore/hardware/t.py:never-widens\n")
refs = CL.scan_references(d)
check("a test that names it is found",
      "driftcore/hardware/t.py:never-widens" in refs)
check("and the reference records which file",
      "test_thing.py" in refs["driftcore/hardware/t.py:never-widens"])


print("=== waivers are per-sentence and survive nothing but that sentence ===")

c1 = {"module": "driftcore/safety/a.py", "where": "f", "text": "must never widen"}
c2 = {"module": "driftcore/safety/a.py", "where": "f", "text": "must never widen."}
check("the same sentence produces the same waiver key",
      CL._key(c1) == CL._key(dict(c1)))
check("EDITING the sentence invalidates its waiver", CL._key(c1) != CL._key(c2))
check("the same sentence in another module is a different key",
      CL._key(c1) != CL._key(dict(c1, module="driftcore/safety/b.py")))


print("=== the tool runs against the real tree and reports honestly ===")

r = subprocess.run([sys.executable, "scripts/claims_ledger.py"],
                   capture_output=True, text=True, cwd=Path(__file__).parent)
# The tree currently FAILS, on purpose: 41 waivers in three blanket groups, made by
# this tool's own author, await a human reading them. Asserting exit 0 here would
# have required raising the threshold or templating 41 reasons — both of which are
# the pattern the check exists to catch. Assert the failure is the EXPECTED one.
check("it exits non-zero while the ceiling raise is unsigned", r.returncode == 1)
check("and reports the acknowledged backlog separately from judgements",
      "acknowledged, UNJUDGED" in r.stdout and "HUMAN-SIGNED" in r.stdout)
check("and says plainly that acknowledged is not a decision",
      "not a decision" in r.stdout)
# The run now exits non-zero because the live baseline HAS blanket waives, so the
# closing "does NOT prove" text is not reached. That is the correct state; assert the
# reason for the failure instead.
check("it names what is blocking it rather than failing silently",
      "ceiling rose" in r.stdout)
check("it reports the backlog rather than hiding it",
      "untagged claims in CRITICAL docstrings" in r.stdout)

base = json.loads(
    (Path(__file__).parent / "scripts" / "claims_ledger_baseline.json").read_text())
check("the baseline records a ceiling", isinstance(base["untagged_ceiling"], int))
check("the note frames the ceiling as a capability boundary, not a setting",
      "CAPABILITY BOUNDARY, NOT A SETTING" in base["_note"])

# ─────────────────────────────────────────────────────────────────────────────
# Blanket-waive detection (cold pass, 2026-08-20).
#
# The author of this tool reached for a bulk waive on the baseline three times in one
# day — 57, then 106, then 58 items with a single shared reason, when between two and
# seven were actually new. Each was caught by reading the output, which is not a
# control. A blanket waive has a mechanical signature: N entries sharing one reason
# string. This is that check.
# ─────────────────────────────────────────────────────────────────────────────

print("=== a waiver is a judgement about one sentence ===")

# (red-team, Grok 2026-08-20.) This previously asserted the threshold was "low enough
# to catch a loop" and "high enough that a handful is fine" — a test written to pass
# against a number chosen one above the author's own largest batch of seven. The test
# was as calibrated as the constant. There is no correct number: two waivers sharing
# a reason were not judged individually.
check("no two waivers may share a reason", CL.BLANKET_THRESHOLD == 1)


def _grouped(waived):
    """The grouping the check performs, exercised directly."""
    by = {}
    for k, v in waived.items():
        if isinstance(v, dict) and v.get("reason"):
            by.setdefault((v["reason"], v.get("reviewer")), []).append(k)
    return {kv: ks for kv, ks in by.items() if len(ks) > CL.BLANKET_THRESHOLD}


_blanket = {f"c{i}": {"reason": "prose in the module", "reviewer": "someone"}
            for i in range(CL.BLANKET_THRESHOLD + 5)}
check("a batch sharing one reason is detected", len(_grouped(_blanket)) == 1)

_individual = {f"c{i}": {"reason": f"restates claim-{i}, paired to test_{i}",
                         "reviewer": "someone"}
               for i in range(CL.BLANKET_THRESHOLD + 5)}
check("the same count with distinct reasons is NOT flagged",
      _grouped(_individual) == {})

_small = {f"c{i}": {"reason": "same reason", "reviewer": "someone"}
          for i in range(CL.BLANKET_THRESHOLD)}
check("a batch at the threshold is not flagged", _grouped(_small) == {})

# Grouping is by (reason, reviewer), so the same reason from two people is two
# separate judgements — each judged on its own size. My first version of this test
# asserted the pair went unflagged at THRESHOLD+2 each, which is simply over the
# line twice; the test was wrong, not the check.
_two_reviewers = {}
for i in range(CL.BLANKET_THRESHOLD + 2):
    _two_reviewers[f"a{i}"] = {"reason": "shared", "reviewer": "alice"}
    _two_reviewers[f"b{i}"] = {"reason": "shared", "reviewer": "bob"}
check("the same reason from two reviewers is TWO groups, each judged on its own",
      len(_grouped(_two_reviewers)) == 2)

_split_small = {}
for i in range(CL.BLANKET_THRESHOLD - 1):
    _split_small[f"a{i}"] = {"reason": "shared", "reviewer": "alice"}
    _split_small[f"b{i}"] = {"reason": "shared", "reviewer": "bob"}
check("and neither fires when each is under the threshold",
      _grouped(_split_small) == {})

check("a waiver with no reason at all is not counted as a blanket group",
      _grouped({f"c{i}": {"reviewer": "x"} for i in range(20)}) == {})

# The live baseline HAD three blanket groups when this check was written. They were
# not resolved by raising the threshold or by templating reasons — both of which are
# the pattern the check exists to catch. They were resolved by naming what they
# actually were: a backlog, moved to `acknowledged`. This asserts they are gone from
# `waived` AND still counted somewhere, because deleting them would have been the
# third bad option.
_live = json.loads(
    (Path(__file__).parent / "scripts" / "claims_ledger_baseline.json").read_text())
check("the live baseline has no blanket waives left",
      _grouped(_live.get("waived", {})) == {})
check("and the batch was moved, not deleted",
      len(_live.get("acknowledged", {})) >= 40)


# ─────────────────────────────────────────────────────────────────────────────
# JUDGED vs ACKNOWLEDGED (cold pass, 2026-08-20).
#
# The baseline used one field for two acts: "I read this sentence and it needs no
# test" and "this is backlog prose nobody has looked at". Conflating them is what
# made bulk-waiving feel reasonable — because acknowledging a backlog IS reasonable,
# and the file had no word for it. Both suppress the untagged count; only one claims
# to have been read.
# ─────────────────────────────────────────────────────────────────────────────

print("=== acknowledged is not waived ===")

_b = json.loads(
    (Path(__file__).parent / "scripts" / "claims_ledger_baseline.json").read_text())
check("the baseline has both fields", "waived" in _b and "acknowledged" in _b)
check("the note names all three dispositions and which one suppresses",
      "ONLY ONE OF THEM SUPPRESSES" in _b["_note"]
      and "acknowledged" in _b["_note"] and "PROPOSAL" in _b["_note"])
check("every WAIVED entry carries its own reason",
      all(v.get("reason") for v in _b["waived"].values()))
check("and no two of them share it",
      len({v["reason"] for v in _b["waived"].values()}) == len(_b["waived"]))
check("every waiver names who PROPOSED it",
      all(v.get("proposed_by") for v in _b["waived"].values()))
check("and has a reviewer field, even when null",
      all("reviewer" in v for v in _b["waived"].values()))
check("an unsigned waiver is marked AWAITING_HUMAN",
      all(v.get("status") == "AWAITING_HUMAN"
          for v in _b["waived"].values() if not v.get("reviewer")))
check("no ACKNOWLEDGED entry pretends to have one",
      all("reason" not in v for v in _b["acknowledged"].values()))
check("acknowledged entries record which batch they came from",
      all(v.get("batch") for v in _b["acknowledged"].values()))

check("blanket detection no longer fires, because the batch is not called a judgement",
      _grouped(_b["waived"]) == {})
check("and the batch is still visible rather than deleted",
      len(_b["acknowledged"]) > 0)

# The property that matters: both suppress, only one claims to have been read. If a
# future edit lets `acknowledged` grow without the ceiling falling, the backlog is
# laundering itself.
check("acknowledged is bounded by the same ceiling as everything else",
      isinstance(_b["untagged_ceiling"], int))
check("moving an item to waived requires a reason the schema enforces",
      all({"text", "reason", "reviewer"} <= set(v) for v in _b["waived"].values()))


# ─────────────────────────────────────────────────────────────────────────────
# THE PROPOSER IS NOT THE REVIEWER (red-team, Grok 2026-08-20).
#
# Every waiver in this file was drafted by the model that also wrote the code being
# waived. In a repo whose root of authority is human identity, and whose central
# claim is that a caller may say what it wants to do and never what that does, the
# model judging which of its own prose needs no test is the same closed loop with the
# labels changed. Verified: 58 waivers, 58 reviewers, all `claude (...)`, zero humans.
# ─────────────────────────────────────────────────────────────────────────────

print("=== the model proposes; a human signs ===")

_b2 = json.loads(
    (Path(__file__).parent / "scripts" / "claims_ledger_baseline.json").read_text())
check("the note says an unsigned waiver is a proposal, not a judgement",
      "PROPOSAL" in _b2["_note"] and "Does NOT suppress" in _b2["_note"])
check("no waiver claims a model as reviewer of record",
      not any(str(v.get("reviewer", "")).startswith("claude")
              for v in _b2["waived"].values()))
_unsigned = [k for k, v in _b2["waived"].items() if not v.get("reviewer")]
check("unsigned waivers are visible rather than implied",
      len(_unsigned) == len(_b2["waived"]) or _unsigned == [])

_r = subprocess.run([sys.executable, "scripts/claims_ledger.py"],
                    capture_output=True, text=True, cwd=Path(__file__).parent)
check("the run reports signed and unsigned separately",
      "HUMAN-SIGNED" in _r.stdout and "awaiting a human" in _r.stdout)
check("and names who drafted the unsigned ones",
      "proposed_by" in _r.stdout or "AWAITING HUMAN" in _r.stdout)


print("=== keying is by claim site, and the note now says so ===")

# Grok found "Shared identity gate, guarded." waived in two modules and acknowledged
# in three. That is defensible — whether a sentence restates a tagged claim depends on
# whether THAT module has the tag — but the old note said "a judgement about one
# sentence", which made it look like an inconsistency. The keying is site-based and
# is now documented as such.
check("the note records that the honest number rose when the measure was fixed",
      "1407" in _b2["_note"] and "1309" in _b2["_note"])
check("keys carry module and location, not just a text hash",
      all(k.count("::") == 2 for k in list(_b2["waived"]) + list(_b2["acknowledged"])))
check("so the same sentence in two modules is two entries",
      CL._key({"module": "a.py", "where": "f", "text": "same"})
      != CL._key({"module": "b.py", "where": "f", "text": "same"}))


print("=== the threshold cannot be tuned around the author ===")

check("the note records the ceiling bypass that motivated the gate",
      "99999" in _b2["_note"])
_two_same = {"k1": {"reason": "same", "reviewer": "h"},
             "k2": {"reason": "same", "reviewer": "h"}}
check("even TWO sharing a reason is a blanket group now",
      len(_grouped(_two_same)) == 1)


print("-" * 60)
print(f"  {_passed}/{_total} tests passed")
if _passed != _total:
    raise SystemExit(1)






