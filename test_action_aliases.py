"""
test_action_aliases.py — the fourth ratchet, validated against constructed shapes.

The effect registry protects an action NAME. What executes is an IMPLEMENTATION. When
several names reach one implementation and only some carry the dangerous declaration,
the guard is intact and the operation is reachable around it.

Run: python3 test_action_aliases.py
"""

import importlib.util
import subprocess
import sys
from pathlib import Path

from driftcore.authority import human_identity as hi
from driftcore.verification.intent_ledger import IntentLedger, IntentError
from driftcore.verification.mediated_actuation import ActuationBroker
from driftcore.verification.signed_permission import PermissionVerifier
from driftcore.verification.invariant_guard import Effect

_spec = importlib.util.spec_from_file_location(
    "action_aliases", Path(__file__).parent / "scripts" / "action_aliases.py")
AA = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(AA)

_p = _t = 0


def check(label, cond):
    global _p, _t
    _t += 1
    if cond:
        _p += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


def kinds(f):
    return {x["kind"] for x in f}


def broker(name="B"):
    return ActuationBroker(f"/tmp/dc_aa_{name}.sock", PermissionVerifier(),
                           broker_id=name)


hi.reset_policy()
hi.register_human_principal("op")

print("=== one callable behind two names ===")

b = broker("shared")
shared = lambda **kw: "done"                                        # noqa: E731
b.register_actuator("arm_left", shared, required_scope=("arm_left:grip",),
                    effects=[Effect.PHYSICAL_FORCE], effect_declared_by="op")
b.register_actuator("arm_backup", shared, required_scope=("arm_backup:anything",),
                    effects=[Effect.NONE], effect_declared_by="op")
f = AA.audit(broker=b)
check("two ids running the same code with different declarations is caught",
      "SHARED_IMPLEMENTATION" in kinds(f))
check("the finding names both ids",
      any("arm_backup" in x["detail"] and "arm_left" in x["detail"] for x in f))

b2 = broker("agree")
same = lambda **kw: "done"                                          # noqa: E731
b2.register_actuator("arm_a", same, required_scope=("arm:grip",),
                     effects=[Effect.PHYSICAL_FORCE], effect_declared_by="op")
b2.register_actuator("arm_b", same, required_scope=("arm:grip",),
                     effects=[Effect.PHYSICAL_FORCE], effect_declared_by="op")
check("two ids that AGREE on scope and effects are not flagged",
      "SHARED_IMPLEMENTATION" not in kinds(AA.audit(broker=b2)))

b3 = broker("distinct")
b3.register_actuator("arm_x", lambda **kw: "x", required_scope=("arm_x:go",),
                     effects=[Effect.PHYSICAL_FORCE], effect_declared_by="op")
b3.register_actuator("arm_y", lambda **kw: "y", required_scope=("arm_y:go",),
                     effects=[Effect.NONE], effect_declared_by="op")
check("genuinely different callables are not aliases",
      "SHARED_IMPLEMENTATION" not in kinds(AA.audit(broker=b3)))


print("=== surface with no declaration, and declarations with no surface ===")

led = IntentLedger()
led.register_action("arm_x:go", declared_by="op")
f = AA.audit(ledger=led, broker=b3)
check("an actuator with no ledger declaration is caught",
      any(x["kind"] == "UNGOVERNED_SURFACE" and x["subject"] == "arm_y" for x in f))
check("the declared one is not", not any(
    x["kind"] == "UNGOVERNED_SURFACE" and x["subject"] == "arm_x" for x in f))

led2 = IntentLedger()
led2.register_action("ghost_arm:go", declared_by="op")
f = AA.audit(ledger=led2, broker=b3)
check("a declaration naming an actuator the broker lacks is caught",
      "DANGLING_DECLARATION" in kinds(f))
check("and it says the declaration guards nothing here",
      any("guards nothing" in x["detail"] for x in f))


print("=== a clean deployment reports clean ===")

b4 = broker("clean")
b4.register_actuator("arm_left", lambda **kw: "x",
                     required_scope=("arm_left:grip",),
                     effects=[Effect.PHYSICAL_FORCE], effect_declared_by="op")
led3 = IntentLedger()
led3.register_action("arm_left:grip", declared_by="op")
check("no findings on a matched ledger and broker",
      AA.audit(ledger=led3, broker=b4) == [])
# This used to assert `AA.audit() == []` — "auditing nothing at all is clean". That
# enshrined the exact defect the totality rule exists to prevent, one layer up: an
# empty SCOPE is not a clean deployment.
check("auditing nothing at all is NOT clean",
      "SCOPE_UNSPECIFIED" in kinds(AA.audit()))


print("=== a check that cannot fire is not a check ===")

# (red-team, Meta 2026-08-15 — CONFIRMED.) The original ALIAS_COLLISION check grouped
# specs by a key that IS the canonical form, so every bucket held exactly one member
# and it could never fire. The test asserting "the registry cannot hold an
# ALIAS_COLLISION" passed VACUOUSLY. Replaced with NON_CANONICAL_KEY, which is
# reachable by anything that writes _actions directly — a legacy snapshot, a restore.

led5 = IntentLedger()
led5.register_action("remove the founder", declared_by="op")
check("a clean registry has no key findings",
      "NON_CANONICAL_KEY" not in kinds(AA.audit(ledger=led5)))
led5._actions["Remove The Founder"] = led5._actions["remove the founder"]
f = AA.audit(ledger=led5)
check("a key stored in non-canonical form IS caught",
      "NON_CANONICAL_KEY" in kinds(f))
check("and it is marked critical",
      any(x.get("severity") == "CRITICAL" for x in f
          if x["kind"] == "NON_CANONICAL_KEY"))
check("the finding explains that lookup will never reach it",
      any("guards nothing" in x["detail"] for x in f))


print("=== a check that cannot RUN must not report a pass ===")

b6 = broker("broken")
for _n in ("a1", "a2"):
    b6.register_actuator(_n, lambda **kw: "x", required_scope=(f"{_n}:go",),
                         effects=[Effect.PHYSICAL_FORCE], effect_declared_by="op")
check("a healthy broker is clean",
      "IDENTITY_UNAVAILABLE" not in kinds(AA.audit(broker=b6)))
b6._implementation_id = lambda aid: (_ for _ in ()).throw(RuntimeError("boom"))
f = AA.audit(broker=b6)
check("a broken identity function produces a finding per actuator",
      sum(1 for x in f if x["kind"] == "IDENTITY_UNAVAILABLE") == 2)
check("rather than collapsing them into one bucket and skipping",
      "SHARED_IMPLEMENTATION" not in kinds(f))


print("=== findings say HOW declarations differ, not merely that they do ===")

b7 = broker("diff")
shared2 = lambda **kw: "done"                                       # noqa: E731
b7.register_actuator("arm_left", shared2, required_scope=("arm_left:grip",),
                     effects=[Effect.PHYSICAL_FORCE], effect_declared_by="op")
b7.register_actuator("arm_backup", shared2, required_scope=("arm_backup:anything",),
                     effects=[Effect.NONE], effect_declared_by="op")
f = [x for x in AA.audit(broker=b7) if x["kind"] == "SHARED_IMPLEMENTATION"]
check("the scope of each id appears in the detail",
      f and "arm_left:grip" in f[0]["detail"]
      and "arm_backup:anything" in f[0]["detail"])
check("and it is marked critical", f and f[0].get("severity") == "CRITICAL")


print("=== homoglyphs and unicode ===")

from driftcore.verification.intent_ledger import canonical_action as _c
check("a Cyrillic lookalike is NOT folded into the latin name",
      _c("\u0430rm_left:grip") != _c("arm_left:grip"))
check("NFKC compatibility forms ARE folded",
      _c("\ufb01le") == _c("file") and _c("\uff41rm") == _c("arm"))

led6 = IntentLedger()
led6.declare_authority("cc", "op", declared_by="op")
led6.register_action("remove the founder", declared_by="op",
                     changes_authority_of="cc")
_homo = False
try:
    led6.register_action("\u0430rm_left:grip", declared_by="op")   # Cyrillic 'а'
    _homo = True
except IntentError:
    pass
check("a homoglyph is a DIFFERENT action, registered separately (not silently merged)",
      _homo)
check("both are in the registry", len(led6._actions) == 2)

# (red-team, Grok 2026-08-15 — CONFIRMED.) The previous version of this block asserted
# len(_actions) == 2 and claimed in a comment that "the surface audit can then flag it
# as undeclared" — and never called audit(). A claim in a test comment that the test
# does not exercise is the same defect as a claim in a docstring no test can falsify.
b_homo = broker("homoglyph")
b_homo.register_actuator("arm_left", lambda **kw: "x",
                         required_scope=("arm_left:grip",),
                         effects=[Effect.PHYSICAL_FORCE], effect_declared_by="op")
_f = AA.audit(ledger=led6, broker=b_homo)
check("the audit ACTUALLY flags the homoglyph declaration as dangling",
      any(x["kind"] == "DANGLING_DECLARATION" and "\u0430rm_left" in x["subject"]
          for x in _f))
check("while the genuine latin declaration is not flagged",
      not any(x["kind"] == "DANGLING_DECLARATION" and x["subject"] == "arm_left:grip"
              for x in _f))


print("=== totality over the objects it is given ===")

b_empty = broker("empty")
led_names = IntentLedger()
led_names.register_action("remove the founder", declared_by="op")
led_names.register_action("buy advertising", declared_by="op")
check("a broker with no actuators and a ledger of bare names is clean",
      AA.audit(ledger=led_names, broker=b_empty) == [])
check("a ledger with nothing in it is clean",
      AA.audit(ledger=IntentLedger(), broker=b_empty) == [])
check("but only when BOTH sides were supplied",
      "PARTIAL_AUDIT" in kinds(AA.audit(ledger=led_names)))
check("every finding kind the tool can emit carries a severity",
      all("severity" in x for x in
          AA.audit(ledger=IntentLedger(), broker=b_empty)) is True)

b_bad = broker("badrec")
b_bad.register_actuator("arm_a", lambda **kw: "x", required_scope=("arm_a:go",),
                        effects=[Effect.PHYSICAL_FORCE], effect_declared_by="op")
b_bad._actuators["arm_a"] = {"fn": lambda **kw: "x"}      # not the (fn, scope) shape
_f = AA.audit(broker=b_bad)
check("an unreadable actuator record is a finding, not a silent empty scope",
      "UNREADABLE_RECORD" in kinds(_f) or "IDENTITY_UNAVAILABLE" in kinds(_f))


print("=== every finding carries a severity ===")

b_sev = broker("sev")
b_sev.register_actuator("orphan_arm", lambda **kw: "x",
                        required_scope=("orphan_arm:go",),
                        effects=[Effect.PHYSICAL_FORCE], effect_declared_by="op")
led_sev = IntentLedger()
led_sev.register_action("ghost:go", declared_by="op")
_f = AA.audit(ledger=led_sev, broker=b_sev)
check("UNGOVERNED_SURFACE and DANGLING_DECLARATION are both present", len(_f) == 2)
check("and neither is missing severity — a downstream filter would have dropped them",
      all("severity" in x for x in _f))


print("=== the documented limit, demonstrated ===")

b8 = broker("router")
b8.register_actuator("arm_left", lambda **kw: "moved",
                     required_scope=("arm_left:grip",),
                     effects=[Effect.PHYSICAL_FORCE], effect_declared_by="op")
led7 = IntentLedger()
led7.register_action("arm_left:grip", declared_by="op")
ROUTER = {"grip the cup": "arm_left", "reorganise governance": "arm_left"}
check("two names routed to one actuator OUTSIDE DriftCore is a real alias",
      len(ROUTER) == 2 and len(set(ROUTER.values())) == 1)
check("and the audit is clean — the blind spot is real, not rhetorical",
      AA.audit(ledger=led7, broker=b8) == [])


print("=== the ledger refuses the collision this cannot otherwise see ===")

led4 = IntentLedger()
led4.declare_authority("cc", "op", declared_by="op")
led4.register_action("remove the founder", declared_by="op",
                     changes_authority_of="cc")
_refused = False
try:
    led4.register_action("Remove The Founder", declared_by="op")
except IntentError:
    _refused = True
check("an alias dropping the declaration is refused at registration", _refused)
# NOT "no ALIAS_COLLISION" — that assertion could never have failed, which is what
# Meta caught. Assert the property that CAN: the registry holds exactly one spec, and
# it is the guarded one.
check("the registry holds exactly one spec for the operation",
      len([k for k in led4._actions if "founder" in k]) == 1)
check("and it is the GUARDED one",
      led4._actions[_c("remove the founder")].changes_authority_of == "cc")


print("=== the tool's own self-test is wired and passes ===")

r = subprocess.run([sys.executable, "scripts/action_aliases.py", "--self-test"],
                   capture_output=True, text=True, cwd=Path(__file__).parent)
check("scripts/action_aliases.py --self-test exits 0", r.returncode == 0)
check("and states what it cannot see", "dispatcher" in AA.__doc__)

hi.reset_policy()



# ─────────────────────────────────────────────────────────────────────────────
# AUDIT TOTALITY (red-team, ChatGPT 2026-08-15).
#
# `audit()` conflated "no findings" with "I successfully inspected the objects I was
# given". Three fail-opens fell out of that, and two of them misattributed — an
# unreadable broker blamed the ledger, an unreadable ledger blamed the broker. A
# wrong finding costs more than a missing one, because someone acts on it.
# ─────────────────────────────────────────────────────────────────────────────

print("=== nothing unreadable may report clean ===")


class _Opaque:
    """An object with no registry at all — a refactor, a mock, a wrong argument."""


b_ok = broker("total")
b_ok.register_actuator("arm", lambda **kw: "x", required_scope=("arm:go",),
                       effects=[Effect.PHYSICAL_FORCE], effect_declared_by="op")
led_ok = IntentLedger()
led_ok.register_action("arm:go", declared_by="op")
check("the control pair is clean", AA.audit(ledger=led_ok, broker=b_ok) == [])

f = AA.audit(ledger=led_ok, broker=_Opaque())
check("an unreadable BROKER is a finding", "BROKER_UNREADABLE" in kinds(f))
check("and it does not also blame the ledger",
      "DANGLING_DECLARATION" not in kinds(f))

f = AA.audit(ledger=_Opaque(), broker=b_ok)
check("an unreadable LEDGER is a finding", "LEDGER_UNREADABLE" in kinds(f))
check("and it does not also blame the broker",
      "UNGOVERNED_SURFACE" not in kinds(f))

b_decl = broker("decl")
b_decl.register_actuator("arm", lambda **kw: "x", required_scope=("arm:go",),
                         effects=[Effect.PHYSICAL_FORCE], effect_declared_by="op")
b_decl.declaration_hash = lambda aid: (_ for _ in ()).throw(RuntimeError("boom"))
f = AA.audit(broker=b_decl)
check("declaration_hash raising on a SINGLE actuator is a finding",
      "DECLARATION_UNAVAILABLE" in kinds(f))
check("the exception type survives into the detail",
      any("RuntimeError" in x["detail"] for x in f))


print("=== two registrations, one logical name ===")

b_col = broker("collide")
b_col.register_actuator("arm_left", lambda **kw: "a",
                        required_scope=("arm_left:go",),
                        effects=[Effect.PHYSICAL_FORCE], effect_declared_by="op")
b_col._actuators["ARM_LEFT"] = (lambda **kw: "b", ("ARM_LEFT:go",))
f = AA.audit(broker=b_col)
check("actuator ids that casefold together are caught",
      "CANONICAL_ACTUATOR_COLLISION" in kinds(f))
check("and it is critical",
      any(x.get("severity") == "CRITICAL" for x in f
          if x["kind"] == "CANONICAL_ACTUATOR_COLLISION"))
check("distinct ids are not flagged",
      "CANONICAL_ACTUATOR_COLLISION" not in kinds(AA.audit(broker=b_ok)))


print("=== every check must be un-silenceable ===")


def _blinded(mutate):
    bb = broker(f"blind{id(mutate)}")
    bb.register_actuator("arm", lambda **kw: "x", required_scope=("arm:go",),
                         effects=[Effect.PHYSICAL_FORCE], effect_declared_by="op")
    ll = IntentLedger()
    ll.register_action("arm:go", declared_by="op")
    mutate(ll, bb)
    return AA.audit(ledger=ll, broker=bb)


for _label, _mut in [
    ("declaration_hash",
     lambda l, b: setattr(b, "declaration_hash",
                          lambda aid: (_ for _ in ()).throw(RuntimeError("x")))),
    ("_implementation_id",
     lambda l, b: setattr(b, "_implementation_id",
                          lambda aid: (_ for _ in ()).throw(RuntimeError("x")))),
    ("the actuator record shape",
     lambda l, b: b._actuators.__setitem__("arm", {"fn": None})),
]:
    _f = _blinded(_mut)
    check(f"blinding {_label} never reports clean", _f != [])
    check(f"and every finding from it carries severity",
          all("severity" in x for x in _f))

check("a finding schema violation would be visible: all four keys present",
      all({"kind", "subject", "severity", "detail"} <= set(x)
          for x in _blinded(lambda l, b: b._actuators.__setitem__("arm", None))))

hi.reset_policy()




# ─────────────────────────────────────────────────────────────────────────────
# COLD PASS on the auditor itself (2026-08-15). The totality rule had been applied
# to the registries and never to the auditor's own inputs, its own side effects, or
# its own reporting layer.
# ─────────────────────────────────────────────────────────────────────────────

print("=== an empty scope is not a clean deployment ===")

check("no arguments at all is SCOPE_UNSPECIFIED, not clean",
      kinds(AA.audit()) == {"SCOPE_UNSPECIFIED"})
check("and it is critical",
      all(x["severity"] == "CRITICAL" for x in AA.audit()))

b_only = broker("solo")
b_only.register_actuator("arm", lambda **kw: "x", required_scope=("arm:go",),
                         effects=[Effect.PHYSICAL_FORCE], effect_declared_by="op")
f = AA.audit(broker=b_only)
check("a broker with no ledger is PARTIAL, not clean",
      "PARTIAL_AUDIT" in kinds(f))
check("and the finding names which checks did not run",
      any("UNGOVERNED_SURFACE" in x["detail"] for x in f
          if x["kind"] == "PARTIAL_AUDIT"))

led_only = IntentLedger()
led_only.register_action("arm:go", declared_by="op")
f = AA.audit(ledger=led_only)
check("a ledger with no broker is PARTIAL too", "PARTIAL_AUDIT" in kinds(f))
check("naming the other side", any(x["subject"] == "broker" for x in f
                                   if x["kind"] == "PARTIAL_AUDIT"))
check("supplying BOTH is the only way to reach clean",
      AA.audit(ledger=led_only, broker=b_only) == [])


print("=== the auditor does not write to what it audits ===")

b_obs = broker("observe")
b_obs.register_actuator("arm", lambda **kw: "x", required_scope=("arm:go",),
                        effects=[Effect.PHYSICAL_FORCE], effect_declared_by="op")
led_obs = IntentLedger()
led_obs.register_action("arm:go", declared_by="op")
# A swapped callable is exactly the case where _implementation_id rewrites its cache.
b_obs._actuators["arm"] = (lambda **kw: "SWAPPED", b_obs._actuators["arm"][1])
_before = dict(b_obs._impl_ids)
_f1 = AA.audit(ledger=led_obs, broker=b_obs)
check("the broker's identity cache is unchanged after an audit",
      dict(b_obs._impl_ids) == _before)
_f2 = AA.audit(ledger=led_obs, broker=b_obs)
check("so two consecutive audits report the same thing",
      [x["kind"] for x in _f1] == [x["kind"] for x in _f2])


print("=== the reporting layer cannot lose the findings it was given ===")

_survived = True
try:
    AA.report([{"kind": "X"}], quiet=True)
except Exception:
    _survived = False
check("a malformed finding does not crash the reporter", _survived)
check("a malformed finding still returns a FAIL exit code",
      AA.report([{"kind": "X"}], quiet=True) == 1)
check("well-formed findings alongside it still report",
      AA.report([{"kind": "X"},
                 {"kind": "Y", "subject": "s", "severity": "HIGH",
                  "detail": "d"}], quiet=True) == 1)
check("and a genuinely empty list is still a pass", AA.report([], quiet=True) == 0)

hi.reset_policy()

print("-" * 60)
assert isinstance(_p, int) and isinstance(_t, int)
print(f"  {_p}/{_t} tests passed")
if _p != _t:
    raise SystemExit(1)
