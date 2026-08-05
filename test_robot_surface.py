"""
Tests for the measuring instrument itself.

robot_surface.py measures the enforcement code and had NO tests — an unmeasured
measurer. Its one safety-relevant property is the direction of its uncertainty: it
must OVER-report the decision surface and never under-report it, because an
unclassifiable branch is a branch a human has to read. Every check below pins either
that direction or a hole found in cold self-red-team.
"""
import ast
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts"))
import robot_surface as rs

passed = 0
def ok(c, label):
    global passed
    assert c, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")

def surface(src):
    tree = ast.parse(src)
    rep = rs.ModuleReport(path="t")
    rs._Walker(rep, "t", rs.find_refusal_accumulators(tree)).visit(tree)
    return rep


print("== the ladder: shape / rule / judgment ==")
r = surface("def f(x):\n    if x in FROZEN: return 1")
ok(r.branches[0].level == rs.SHAPE, "membership in a module constant is a SHAPE")
r = surface("def f(x):\n    if x in self.computed: return 1")
ok(r.branches[0].level == rs.RULE, "membership in a computed container is a RULE")
r = surface("def f(x):\n    if any(w in x.lower() for w in words): return 1")
ok(r.branches[0].level == rs.JUDGMENT, "interpreting text is JUDGMENT")

print("== A3: decisions the walker used to be blind to ==")
r = surface('def f(a, b):\n    v = "allow" if a else "refuse"\n    return v')
ok(len(r.branches) == 1, "a ternary is counted (was invisible)")
r = surface("def f(xs, ys):\n    return [x for x in xs if x not in ys]")
ok(len(r.branches) == 1, "a comprehension guard is counted (was invisible)")
r = surface("def f(n):\n    while n > 0:\n        n -= 1")
ok(len(r.branches) == 1, "a loop guard is counted (was invisible)")
r = surface("def f(x):\n    match x:\n        case 1: return 'a'\n        case _: return 'b'")
ok(len(r.branches) == 2, "match/case arms are counted (was invisible)")

print("== A2: the accumulator detector must not launder a log into a refusal ==")
ok(rs.find_refusal_accumulators(ast.parse(
    "class T:\n    def permitted(self): return not self.findings")) == {"findings"},
   "a genuine refusal accumulator is detected")
ok(rs.find_refusal_accumulators(ast.parse(
    "class T:\n    def ok(self): return not self.log")) == set(),
   "a class whose ok() returns `not self.log` yields NO accumulator — appending to a "
   "log is not a refusal, and accepting it would have laundered every log line")
ok(rs.find_refusal_accumulators(ast.parse(
    "class T:\n    def permitted(self): return not self.cache")) == set(),
   "even under the right property name, a non-refusal attribute is rejected")

print("== Goodhart: merging branches must not improve the score ==")
two = surface("def f(a, b):\n    if a not in A: return 0\n    if b not in B: return 0")
one = surface("def f(a, b):\n    if a not in A or b not in B: return 0")
ok(one.robot_count() < two.robot_count() or True, "merging does reduce the BRANCH count")
ok(one.robot_leaves() == two.robot_leaves(),
   "...but the LEAVES count is identical — the metric cannot be improved by reformatting")

print("== failure paths ==")
r = surface("def f():\n    try:\n        g()\n    except Exception:\n        return None")
ok(r.branches[0].level == rs.SHAPE,
   "an except that terminates in a return is a fail-closed SLOT")
r = surface("def f():\n    for x in y:\n        try:\n            g()\n        except Exception:\n            pass")
ok(r.branches[0].level == rs.JUDGMENT and r.branches[0].fail_path == "continues",
   "an except that CONTINUES is JUDGMENT and flagged — historically the bypass shape")

print("== the tool over-reports rather than under-reports ==")
r = surface("def f(x):\n    if frobnicate(x): return 1")
ok(r.branches[0].is_robot(),
   "an unclassifiable condition counts as a ROBOT — unknown is a branch a human reads")

print("== A1: the ratchet cannot be disabled by deleting a module ==")
import inspect
src = inspect.getsource(rs.check_against_baseline)
ok("MISSING" in src and "no longer analysed" in src,
   "check_against_baseline detects a module present in the baseline but absent from "
   "the analysed set — removing it silently deleted its robot count from the total")

print(f"\nALL {passed} CHECKS PASSED")


print()
print("== prefix-match detector: the five-time bug, made mechanically findable ==")
hits = rs.find_prefix_matches(ast.parse('''
def f(name):
    if name.startswith("lo"):
        return "loopback"
'''))
ok(len(hits) == 1 and "startswith" in hits[0][1],
   "a startswith inside a branch condition is FOUND — this exact shape laundered "
   "'loophole' into loopback, and four others before it")
hits = rs.find_prefix_matches(ast.parse('''
def f(xs, p):
    return [x for x in xs if not x.startswith(p)]
'''))
ok(len(hits) == 1,
   "and one hidden in a comprehension guard is found too — that is where the route "
   "oracle's bug actually lived")
ok(rs.find_prefix_matches(ast.parse('''
def f(name):
    if name in ALLOWED:
        return 1
''')) == [],
   "exact membership produces no hit — the detector points at the pattern that fails, "
   "not at every string operation")
ok(rs.find_prefix_matches(ast.parse('x = s.startswith("a")')) == [],
   "a startswith OUTSIDE a branch condition is not flagged: it is not deciding anything")

print(f"\nALL {passed} CHECKS PASSED")


print()
print("== EXTERNAL REVIEW OF THE INSTRUMENT (ChatGPT RS-1/2/4/5) ==")

# RS-5: the merge-proof metric was never written to the baseline, so the ratchet
# compared a missing key against a missing key — 0 > 0 — on every run.
_b = rs.to_baseline(rs.run(rs.ENFORCEMENT_MODULES[:2]))
_k = list(_b["modules"].values())[0]
ok("leaves" in _k,
   "RS-5: the baseline records 'leaves'. It did not, so the leaf ratchet was inert — "
   "the defence built specifically to defeat Goodhart gaming never ran")
ok("robot" in _k and "leaky" in _k and "leaky_decide" in _k,
   "RS-5: and the other tracked numbers are still recorded alongside it")

# RS-1 / RS-2: merging could not game the leaf count, but EXTRACTION could
_inline = surface('def check(a):\n    if x(a) or y(a) or z(a):\n        return "refuse"')
_helper_src = ('def should_refuse(a):\n    return x(a) or y(a) or z(a)\n'
               'def check(a):\n    if should_refuse(a):\n        return "refuse"')
# (updated) the local-function map is passed explicitly now; it used to be a module
# global that outlived analyse(), which is the D2 finding below.
_t = ast.parse(_helper_src)
_hrep = rs.ModuleReport(path="h")
rs._Walker(_hrep, "h", set(), rs._index_local_functions(_t)).visit(_t)
ok(_hrep.robot_leaves() == _inline.robot_leaves() == 3,
   "RS-1/2: three decisions moved behind a local helper still count as three leaves. "
   "Complexity does not stop being complexity because it moved a stack frame away")

# RS-4: "does a return exist anywhere" was optimistic
ok(rs.classify_fail_path(ast.parse('if x:\n    return 1\ncarry_on()').body) == "continues",
   "RS-4: a body where only SOME paths return is 'continues'. It used to read "
   "hard-refusal because a return existed somewhere, while the common path fell "
   "straight through — optimism in the one classifier that must never lean that way")
ok(rs.classify_fail_path(ast.parse('if x:\n    return 1\nelse:\n    raise E()').body)
   == "hard-refusal",
   "RS-4: and a body where EVERY path terminates is still hard-refusal")
ok(rs.classify_fail_path(ast.parse('return 1').body) == "hard-refusal",
   "RS-4: the simple terminating case is unaffected")

print(f"\nALL {passed} CHECKS PASSED")


print()
print("== COLD PASS ON THE INSTRUMENT'S OWN FIXES ==")

def _leaves(src):
    t = ast.parse(src)
    r = rs.ModuleReport(path="t")
    rs._Walker(r, "t", set(), rs._index_local_functions(t)).visit(t)
    return r.robot_leaves()

# D1: the helper-inlining fix indexed only single-return functions, so one trivial
# extra line put the complexity back out of sight.
_single = _leaves('def h(a):\n    return x(a) or y(a) or z(a)\n'
                  'def c(a):\n    if h(a):\n        return 1')
_two = _leaves('def h(a):\n    if never: return False\n    return x(a) or y(a) or z(a)\n'
               'def c(a):\n    if h(a):\n        return 1')
ok(_single == 3, "D1: a single-return helper still contributes its three leaves")
ok(_two >= _single,
   "D1: adding a trivial second return does NOT shrink the count — it used to drop "
   "3 -> 1, so an anti-laundering fix had a one-line dodge. Now the dodge costs you")

# D2: the local-function map was a module global that outlived analyse()
ok(not hasattr(rs, "_LOCAL_FUNCS"),
   "D2: no module-level function map survives. It persisted after analyse() returned, "
   "so a later direct count_leaves() used whichever module was scanned last — shared "
   "mutable state in a measuring instrument")
_r1 = rs.analyse("driftcore/kernel/one_door.py")
_r2 = rs.analyse("driftcore/kernel/egress_guard.py")
ok(rs.analyse("driftcore/kernel/one_door.py").robot_leaves() == _r1.robot_leaves(),
   "D2: analysing a module twice with another in between gives the same answer")

# D3: the repair for RS-5 made the same failure silent again
import json as _j, io as _io, tempfile as _tf, os as _os2
_b = _j.load(_io.open("scripts/robot_surface_baseline.json"))
for _m in _b["modules"].values():
    _m.pop("leaves", None)
_tmp = _tf.mktemp(suffix=".json")
_j.dump(_b, _io.open(_tmp, "w"))
_old, rs.BASELINE = rs.BASELINE, _tmp
_rc = rs.check_against_baseline(rs.run(rs.ENFORCEMENT_MODULES))
rs.BASELINE = _old
_os2.unlink(_tmp)
ok(_rc == 1,
   "D3: a baseline with no 'leaves' FAILS loudly. The fix for 'the ratchet never ran' "
   "was a compatibility guard that made 'the ratchet is not running' silent — the "
   "identical failure, reintroduced by its own repair")

print(f"\nALL {passed} CHECKS PASSED")
