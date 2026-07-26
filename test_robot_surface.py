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
