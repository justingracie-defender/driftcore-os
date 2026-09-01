"""
test_authority_sites.py — does the sweep catch what it was built from?

The tool exists because five modules had the same defect on the same day, and every
ratchet in the repo missed them — two were in subsystems (`media/`, `cognition/`) that
the tier list does not name. A governance tool validated only against fixed code
proves nothing, so these tests rebuild each real shape in a scratch tree.

Run: python3 test_authority_sites.py
"""

import importlib.util
import tempfile
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "authority_sites", Path(__file__).parent / "scripts" / "authority_sites.py")
AS = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(AS)

_p = _t = 0


def check(label, cond):
    global _p, _t
    _t += 1
    if cond:
        _p += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


def tree(rel, body):
    d = Path(tempfile.mkdtemp())
    f = d / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(body)
    return AS.scan(d)


print("=== the five real shapes, as they actually appeared ===")

s = tree("driftcore/safety/recovery.py", '''
def attempt_recovery(self, authorized_by: str = "human_operator"):
    if not authorized_by or authorized_by == "agent":
        return {"status": "DENIED"}
    return {"status": "APPROVED"}
''')
check("recovery.py's equality-against-'agent' is caught", len(s) == 1)
check("it is classified as a DENYLIST", s[0]["kind"] == "DENYLIST")
check("the human-looking DEFAULT is reported", s[0]["default"] == "human_operator")
check("and that the module never delegates",
      s[0]["delegates_to_is_human"] is False)

s = tree("driftcore/media/policy.py", '''
def change_policy(self, new_policy, authorised_by: str = "system"):
    human = authorised_by not in ("", "system", "auto", "auto-sign", None)
    return human
''')
check("media/policy.py's tuple denylist is caught", len(s) == 1)
check("every listed literal is reported",
      set(s[0]["literals"]) == {"", "system", "auto", "auto-sign"})

s = tree("driftcore/cognition/cognitive_mode.py", '''
def set_mode(self, new_mode, requested_by: str = "human_operator"):
    if requested_by == "agent":
        return {"status": "DENIED"}
''')
check("cognitive_mode.py is caught even though `cognition/` is NOT a CRITICAL tier",
      len(s) == 1)

s = tree("driftcore/verification/edge_loop.py", '''
def ratify(self, report, by: str = "human_operator"):
    if by == "agent":
        return {"status": "DENIED"}

def overturn(self, rid, by: str = "human_operator"):
    if by == "agent":
        return {"status": "DENIED"}
''')
check("both edge_loop sites are caught separately", len(s) == 2)
check("each names its own function",
      {x["function"] for x in s} == {"ratify", "overturn"})


print("=== a delegating site is clean ===")

s = tree("driftcore/safety/good.py", '''
from driftcore.authority.human_identity import is_human

def release(self, authorized_by: str):
    if not is_human(authorized_by, action="release"):
        return "DENIED"
    return "OK"
''')
check("delegating to is_human produces no finding", s == [])


print("=== precision: it does not flag ordinary code ===")

s = tree("driftcore/kernel/plain.py", '''
def render(self, by: str = "system"):
    """A comparison that decides FORMATTING, not authority."""
    label = "operator" if by == "system" else by
    return label
''')
check("a literal compare on an authorizer-named param IS still flagged",
      len(s) == 1)

s = tree("driftcore/kernel/other.py", '''
def compute(self, mode: str = "fast"):
    if mode == "slow":
        return 1
    return 2
''')
check("a param that is not an authorizer name is ignored", s == [])

s = tree("driftcore/kernel/var.py", '''
def release(self, authorized_by: str, owner: str):
    if authorized_by != owner:
        return "DENIED"
''')
check("comparing against a VARIABLE is not a denylist", s == [])


print("=== the primitive itself is exempt ===")

d = Path(tempfile.mkdtemp())
f = d / "driftcore/authority/human_identity.py"
f.parent.mkdir(parents=True, exist_ok=True)
f.write_text('''
def is_human(authorised_by):
    return authorised_by not in ("agent", "system", "")
''')
check("human_identity.py owns the legacy denylist by design and is skipped",
      AS.scan(d) == [])


print("=== keys are stable so a waiver survives a code move ===")

a = {"module": "m.py", "function": "f", "param": "by"}
check("the same site keys the same", AS.key(a) == AS.key(dict(a)))
check("a different function is a different key",
      AS.key(a) != AS.key(dict(a, function="g")))
check("a different param is a different key",
      AS.key(a) != AS.key(dict(a, param="authorized_by")))

# ─────────────────────────────────────────────────────────────────────────────
# CLAIMS: driftcore/safety/safe_halt.py:gate-never-raises
# CLAIMS: driftcore/verification/edge_loop.py:gate-never-raises
#
# The wrapper each patched module uses must never raise. `is_human` was written to be
# a boolean gate precisely so an exception cannot turn a refusal into a crash, and a
# wrapper that reintroduces one at the import boundary gives that back.
# ─────────────────────────────────────────────────────────────────────────────

from driftcore.safety.safe_halt import _is_human as _halt_gate, RELEASE_ACTION
from driftcore.verification.edge_loop import _is_human as _edge_gate, RATIFY_ACTION
from driftcore.media.policy import _is_human as _media_gate

print("=== every gate wrapper is total ===")

_HOSTILE = [None, 42, True, [], {}, set(), object(),
            type("X", (), {"__str__": lambda s: "justin"})(),
            type("Y", (), {"__eq__": lambda s, o: True})(),
            float("nan"), b"justin", ("justin",)]

for name, gate, action in (("safe_halt", _halt_gate, RELEASE_ACTION),
                           ("edge_loop", _edge_gate, RATIFY_ACTION),
                           ("media/policy", _media_gate, None)):
    bad = []
    for v in _HOSTILE:
        try:
            r = gate(v) if action is None else gate(v, action=action)
            if r is not False:
                bad.append((v, r))
        except Exception as e:
            bad.append((v, f"RAISED {type(e).__name__}"))
    check(f"{name}: every hostile value returns False, none raises", not bad)

print("-" * 60)
print(f"  {_p}/{_t} tests passed")
if _p != _t:
    raise SystemExit(1)
