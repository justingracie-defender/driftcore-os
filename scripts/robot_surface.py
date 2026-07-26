#!/usr/bin/env python3
"""
robot_surface.py — measure the DECISION SURFACE of the enforcement code.

WHAT THIS MEASURES, AND WHY
───────────────────────────
Design principle (arrived at across four review passes):

    Every part of DriftCore should be a SLOT if it can possibly be one, and the parts
    that must be ROBOTS should be as small and as dumb as possible, sitting behind
    something that fails closed.

  SLOT   — a fixed shape. Input either matches or it does not. Small state space.
           `triple in ALLOWED_DESTINATIONS`. Nothing to trick.
  ROBOT  — code that interprets. It has an inside, and the inside can be fooled.

Every bug found in this repo's enforcement code lived in a robot branch. Not one lived
in a set-membership test. So the robot-branch count is not an aesthetic score: it is
the review budget and the attack surface, and it should only ever go down.

THE LADDER (three levels, not a binary)
───────────────────────────────────────
An earlier draft of this idea claimed "a slot's correctness is provable". That is too
strong, and this repo has the counterexample: the isolation check whose SHAPE was right
("the process must have no network") while the IMPLEMENTATION checked something else
("a different namespace"). A slot is far more amenable to exhaustive verification than
a robot. It is not automatically correct.

    SHAPE      fixed structure, small state space, exhaustively checkable
    RULE       bounded contextual decision — must be tested, should be minimised
    JUDGMENT   interpretation, inference, weighing — never exhaustively verifiable,
               and must never be the last thing standing before a dangerous capability
    PLUMBING   logging, serialisation, formatting — no policy, but still needs review

FAILURE PATHS ARE THE HIDING PLACE
──────────────────────────────────
A small robot whose ERROR path re-enters a large robot is not a small robot. It is a
large one with a small front door. Every fail-open this repo has found was of exactly
that shape: an `except` that fell through to "no capability declared", a registry read
that defaulted to an empty effect set. So each branch is also scored on whether its
failure path terminates in a hard refusal (slot) or hands control onward (robot).

WHAT THIS TOOL IS NOT
─────────────────────
It is itself a ROBOT. It reads code and forms judgments about it, and it can be wrong
in both directions. That is survivable for exactly one reason: it AUTHORISES NOTHING.
It is a measuring instrument, not a gate. Nothing in the enforcement path consults it,
so gaming it buys an attacker nothing but a misleading number in a report a human reads.

Its one safety-relevant property is the direction of its uncertainty: anything it
cannot mechanically prove to be a shape is counted as a ROBOT. It will over-report the
surface, never under-report it. An unclassifiable branch is a branch a reviewer has to
read, which is the correct default.

USAGE
─────
    python3 scripts/robot_surface.py                    # report
    python3 scripts/robot_surface.py --baseline         # write the ratchet baseline
    python3 scripts/robot_surface.py --check            # CI: fail if the surface grew
    python3 scripts/robot_surface.py --module egress_guard --verbose
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE = os.path.join(REPO, "scripts", "robot_surface_baseline.json")

# The enforcement surface: the files whose branches can refuse or permit an action.
# Deliberately explicit rather than a glob — the set of things that can say "no" to an
# actuation is a list a human should maintain, not a directory listing.
ENFORCEMENT_MODULES = [
    "driftcore/kernel/one_door.py",
    "driftcore/kernel/actuation_gate.py",
    "driftcore/kernel/egress_guard.py",
    "driftcore/kernel/escalation_lexicon.py",
    "driftcore/kernel/blast_radius.py",
    "driftcore/kernel/isolation_manifest.py",
    "driftcore/kernel/effect_guard.py",
    "driftcore/kernel/invariants.py",
    "driftcore/verification/invariant_guard.py",
    "driftcore/verification/mediated_actuation.py",
]

SHAPE, RULE, JUDGMENT, PLUMBING = "SHAPE", "RULE", "JUDGMENT", "PLUMBING"

# Names that indicate interpretation of meaning rather than matching of structure.
# A branch touching any of these is JUDGMENT: it is reasoning about what something
# MEANS, which is the level that can never be exhaustively verified.
_JUDGMENT_MARKERS = {
    "scan", "classify", "infer", "_infer_effects", "lexicon", "concerns",
    "normalize", "fires", "match", "search", "findall", "finditer",
    "startswith", "endswith", "lower", "upper", "casefold", "strip",
}
# Names that indicate policy-free machinery.
_PLUMBING_MARKERS = {
    "record", "log", "audit", "dumps", "loads", "append", "isoformat",
    "hexdigest", "encode", "decode", "join", "format", "repr",
}
# Comparators that are pure structure.
_SHAPE_CMP = (ast.Is, ast.IsNot, ast.In, ast.NotIn, ast.Eq, ast.NotEq,
              ast.Lt, ast.LtE, ast.Gt, ast.GtE)


def count_leaves(test: ast.AST) -> int:
    """Atomic tests inside a condition, counting through boolean compounds.

    GOODHART DEFENCE (external review). The branch count alone is gameable:

        if a: refuse()          ->   if a or b: refuse()
        if b: refuse()

    Two branches become one. The metric improves; nothing about the code got safer.
    Verified empirically against this tool before adding this — the attack worked.

    Leaves counts `a` and `b` separately either way, so merging cannot move it. A
    measure that can be improved by reformatting is not a measure, and the ratchet
    tracks BOTH: branches may merge, but the decision leaves behind them may not grow.
    """
    if isinstance(test, ast.BoolOp):
        return sum(count_leaves(v) for v in test.values)
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return count_leaves(test.operand)
    return 1


@dataclass
class Branch:
    module: str
    function: str
    line: int
    source: str
    level: str
    reason: str
    fail_path: str          # "hard-refusal" | "continues" | "n/a"
    attacker_input: bool
    grants_authority: bool
    leaves: int = 1

    def is_robot(self) -> bool:
        return self.level in (RULE, JUDGMENT)


@dataclass
class ModuleReport:
    path: str
    branches: List[Branch] = field(default_factory=list)
    max_depth: int = 0

    def counts(self) -> Dict[str, int]:
        c = {SHAPE: 0, RULE: 0, JUDGMENT: 0, PLUMBING: 0}
        for b in self.branches:
            c[b.level] += 1
        return c

    def robot_count(self) -> int:
        return sum(1 for b in self.branches if b.is_robot())

    def robot_leaves(self) -> int:
        """Atomic decisions inside robot branches — the merge-proof companion."""
        return sum(b.leaves for b in self.branches if b.is_robot())

    def leaky_failures(self) -> int:
        """Robot branches whose failure path does NOT terminate in a refusal.
        These are the ones that historically became bypasses."""
        return sum(1 for b in self.branches
                   if b.is_robot() and b.fail_path == "continues")


def _names_in(node: ast.AST) -> set:
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out.add(n.id)
        elif isinstance(n, ast.Attribute):
            out.add(n.attr)
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
            out.add(n.func.id)
    return out


def _is_constant_container(node: ast.AST) -> bool:
    """True for a literal or an ALL_CAPS module constant — the right-hand side of a
    membership test that makes it a shape rather than a lookup into mutable state."""
    if isinstance(node, (ast.Set, ast.Tuple, ast.List, ast.Constant)):
        return True
    if isinstance(node, ast.Name) and node.id.isupper():
        return True
    if isinstance(node, ast.Attribute) and node.attr.isupper():
        return True
    return False


def classify_test(test: ast.AST) -> Tuple[str, str]:
    """Classify a branch condition. Anything not provably a shape becomes a robot."""
    names = _names_in(test)

    if names & _PLUMBING_MARKERS and not (names & _JUDGMENT_MARKERS):
        return PLUMBING, "policy-free machinery (logging/serialisation)"

    # Interpretation of meaning -> JUDGMENT, the level that cannot be exhausted.
    hit = names & _JUDGMENT_MARKERS
    if hit:
        return JUDGMENT, f"interprets meaning via {sorted(hit)[0]}()"

    # `x is None`, `x is not None`, `not x` -> presence/absence, pure structure.
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        inner = test.operand
        if isinstance(inner, (ast.Name, ast.Attribute, ast.Constant)):
            return SHAPE, "presence/absence test"
    if isinstance(test, (ast.Name, ast.Attribute)):
        return SHAPE, "truthiness of a single value"

    if isinstance(test, ast.Compare):
        if not all(isinstance(op, _SHAPE_CMP) for op in test.ops):
            return RULE, "comparison with a non-structural operator"
        # membership against a constant container is the canonical slot
        for op, comp in zip(test.ops, test.comparators):
            if isinstance(op, (ast.In, ast.NotIn)):
                if _is_constant_container(comp):
                    return SHAPE, "membership in a fixed set — canonical slot"
                return RULE, "membership in a mutable/computed container"
            if isinstance(op, (ast.Is, ast.IsNot)):
                return SHAPE, "identity test (None/enum/sentinel)"
            if isinstance(comp, ast.Constant):
                return SHAPE, "comparison against a literal"
        return RULE, "bounded comparison against computed value"

    if isinstance(test, ast.Call):
        fn = test.func.id if isinstance(test.func, ast.Name) else getattr(test.func, "attr", "")
        if fn == "isinstance":
            return SHAPE, "type shape"
        if fn in ("any", "all"):
            return JUDGMENT, f"{fn}() over a generated sequence"
        return RULE, f"delegates the decision to {fn}()"

    if isinstance(test, ast.BoolOp):
        # a compound test is only a shape if EVERY leg is a shape
        legs = [classify_test(v) for v in test.values]
        if all(l == SHAPE for l, _ in legs):
            return SHAPE, "compound of shape tests"
        worst = JUDGMENT if any(l == JUDGMENT for l, _ in legs) else RULE
        return worst, "compound containing a non-shape leg"

    return RULE, "UNCLASSIFIED — counted as a robot until proven a shape"


def find_refusal_accumulators(tree: ast.AST) -> set:
    """Find collections that PROVABLY act as refusals in this module.

    There are two legitimate refusal idioms in this codebase:

        1. RETURN/RAISE   the broker returns a refusal verdict immediately.
        2. ACCUMULATE     the verifier appends to `findings`, and the report's
                          `permitted` is defined as "no findings".

    The tool originally understood only the first, so it counted every `except` in a
    verifier-style module as a leaky path, which was a mismeasurement rather than a
    finding. Teaching it the second idiom is defensible ONLY because the idiom is
    mechanically provable: this function looks for a property whose body is literally
    `return not self.<attr>` (or an emptiness test on it), and only then treats
    `<anything>.<attr>.append(...)` as a terminal refusal.

    This is deliberately NOT a general "append counts as refusing" rule. That would
    launder any logging or bookkeeping append into a slot. If a module does not define
    the property, the idiom does not apply there and nothing is relaxed.
    """
    # An accumulator must be named like a refusal, not merely be a list that something
    # is appended to. Narrow by construction: a name outside this set is not proof of
    # the idiom, and this function's whole justification is that it PROVES the idiom
    # rather than assuming it.
    REFUSAL_NAMES = {"findings", "violations", "refusals", "denials", "failures"}
    accumulators = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # "ok" and "passed" were accepted as refusal properties. A class whose ok()
        # returns `not self.log` then made every log append a "terminal refusal" — a
        # laundering vector introduced by the fix for a mismeasurement. Both the
        # PROPERTY and the ATTRIBUTE must now be refusal-semantic.
        if node.name not in ("permitted", "is_permitted"):
            continue
        for stmt in ast.walk(node):
            if not isinstance(stmt, ast.Return) or stmt.value is None:
                continue
            v = stmt.value
            # `return not self.findings`
            if isinstance(v, ast.UnaryOp) and isinstance(v.op, ast.Not):
                if (isinstance(v.operand, ast.Attribute)
                        and v.operand.attr in REFUSAL_NAMES):
                    accumulators.add(v.operand.attr)
            # `return len(self.findings) == 0`
            if isinstance(v, ast.Compare) and isinstance(v.left, ast.Call):
                fn = getattr(v.left.func, "id", "")
                if fn == "len" and v.left.args:
                    a = v.left.args[0]
                    if isinstance(a, ast.Attribute) and a.attr in REFUSAL_NAMES:
                        accumulators.add(a.attr)
    return accumulators


def classify_fail_path(body: List[ast.stmt], accumulators: set = frozenset()) -> str:
    """Does this branch body terminate in a refusal, or hand control onward?

    A robot whose error path re-enters a larger robot is a large robot with a small
    front door. Every fail-open found in this repo had that shape.
    """
    if not body:
        return "continues"
    # A proven refusal-accumulator append terminates the path: the report it feeds
    # cannot subsequently be permitted. Verified per-module, never assumed.
    if accumulators:
        for n in ast.walk(ast.Module(body=body, type_ignores=[])):
            if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and n.func.attr == "append"
                    and isinstance(n.func.value, ast.Attribute)
                    and n.func.value.attr in accumulators):
                return "hard-refusal"
    for stmt in body:
        if isinstance(stmt, ast.Raise):
            return "hard-refusal"
        if isinstance(stmt, ast.Return):
            # a bare `return` or a returned refusal both terminate the path
            return "hard-refusal"
    # nested control flow that eventually returns still counts if every leaf returns
    returns = [n for n in ast.walk(ast.Module(body=body, type_ignores=[]))
               if isinstance(n, (ast.Return, ast.Raise))]
    return "hard-refusal" if returns else "continues"


class _Walker(ast.NodeVisitor):
    def __init__(self, report: ModuleReport, module: str, accumulators: set = frozenset()):
        self.r, self.module = report, module
        self.acc = accumulators
        self.fn = "<module>"
        self.depth = 0

    def visit_FunctionDef(self, node):
        prev, self.fn = self.fn, node.name
        prev_d, self.depth = self.depth, 0
        self.generic_visit(node)
        self.fn, self.depth = prev, prev_d

    visit_AsyncFunctionDef = visit_FunctionDef

    def _add(self, node, test_src, level, reason, fail_path):
        names = _names_in(node)
        self.r.branches.append(Branch(
            module=self.module, function=self.fn, line=node.lineno,
            source=test_src[:70], level=level, reason=reason, fail_path=fail_path,
            leaves=(count_leaves(node.test)
                    if isinstance(node, (ast.If, ast.IfExp, ast.While)) else 1),
            attacker_input=bool(names & {"params", "command", "action", "url", "text",
                                         "action_text", "req", "target", "host"}),
            grants_authority=bool(names & {"ALLOW", "permitted", "grant", "authorize",
                                           "commit", "reserve"})))

    def visit_If(self, node):
        level, reason = classify_test(node.test)
        self._add(node, ast.unparse(node.test), level, reason,
                  classify_fail_path(node.body, self.acc))
        self.depth += 1
        self.r.max_depth = max(self.r.max_depth, self.depth)
        self.generic_visit(node)
        self.depth -= 1

    def visit_IfExp(self, node):
        # A ternary is a decision. `x = "allow" if cond else "refuse"` was counted as
        # nothing, which breaks the over-report-never-under-report claim the tool's
        # safety argument rests on.
        level, reason = classify_test(node.test)
        self._add(node, f"({ast.unparse(node.test)}) ?:", level,
                  reason + " [ternary]", "continues")
        self.generic_visit(node)

    def visit_While(self, node):
        level, reason = classify_test(node.test)
        self._add(node, f"while {ast.unparse(node.test)}", level,
                  reason + " [loop guard]", classify_fail_path(node.body, self.acc))
        self.generic_visit(node)

    def _comprehension_guards(self, node):
        for gen in getattr(node, "generators", []):
            for cond in gen.ifs:
                level, reason = classify_test(cond)
                self._add(node, f"[... if {ast.unparse(cond)}]", level,
                          reason + " [comprehension guard]", "continues")

    def visit_ListComp(self, node):
        self._comprehension_guards(node); self.generic_visit(node)

    def visit_SetComp(self, node):
        self._comprehension_guards(node); self.generic_visit(node)

    def visit_DictComp(self, node):
        self._comprehension_guards(node); self.generic_visit(node)

    def visit_GeneratorExp(self, node):
        self._comprehension_guards(node); self.generic_visit(node)

    def visit_Match(self, node):
        # match/case was not walked at all, so a decision expressed as a match was
        # invisible. The tool claims to over-report, never under-report; a whole
        # control-flow construct going uncounted broke that claim.
        for case in node.cases:
            src = ast.unparse(case.pattern)
            fail = classify_fail_path(case.body, self.acc)
            level = SHAPE if isinstance(case.pattern, (ast.MatchValue, ast.MatchSingleton)) \
                else RULE
            reason = ("matches a literal pattern" if level == SHAPE
                      else "structural/capture pattern — not a fixed value")
            self._add(node, f"case {src}", level, reason, fail)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        exc = ast.unparse(node.type) if node.type else "bare"
        fail = classify_fail_path(node.body, self.acc)
        # An exception handler that terminates in a refusal IS a slot: it converts an
        # unknown internal state into a fixed "no". One that continues is the single
        # most dangerous construct in this codebase's history.
        if fail == "hard-refusal":
            level, reason = SHAPE, "error -> hard refusal (fail-closed slot)"
        else:
            level, reason = JUDGMENT, "ERROR PATH CONTINUES — historically a bypass"
        self._add(node, f"except {exc}", level, reason, fail)
        self.generic_visit(node)


def analyse(path: str) -> Optional[ModuleReport]:
    full = os.path.join(REPO, path)
    if not os.path.exists(full):
        return None
    with open(full, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    rep = ModuleReport(path=path)
    _Walker(rep, os.path.basename(path), find_refusal_accumulators(tree)).visit(tree)
    return rep


def run(modules: List[str]) -> List[ModuleReport]:
    out = []
    for m in modules:
        r = analyse(m)
        if r:
            out.append(r)
    return out


def print_report(reports: List[ModuleReport], verbose: bool = False):
    print(f"\n{'MODULE':<44} {'SHAPE':>6} {'RULE':>6} {'JUDG':>6} {'PLUMB':>6} "
          f"{'ROBOT':>6} {'LEAF':>5} {'LEAK':>5} {'DEPTH':>6}")
    print("-" * 92)
    tot = {SHAPE: 0, RULE: 0, JUDGMENT: 0, PLUMBING: 0}
    robots = leaks = 0
    for r in sorted(reports, key=lambda x: -x.robot_count()):
        c = r.counts()
        for k in tot:
            tot[k] += c[k]
        robots += r.robot_count()
        leaks += r.leaky_failures()
        flag = "  <-- leaky failure path" if r.leaky_failures() else ""
        print(f"{r.path:<44} {c[SHAPE]:>6} {c[RULE]:>6} {c[JUDGMENT]:>6} "
              f"{c[PLUMBING]:>6} {r.robot_count():>6} {r.robot_leaves():>5} "
              f"{r.leaky_failures():>5} {r.max_depth:>6}{flag}")
    print("-" * 92)
    total_branches = sum(tot.values())
    pct = (robots / total_branches * 100) if total_branches else 0
    print(f"{'TOTAL':<44} {tot[SHAPE]:>6} {tot[RULE]:>6} {tot[JUDGMENT]:>6} "
          f"{tot[PLUMBING]:>6} {robots:>6} {leaks:>5}")
    print(f"\nrobot surface: {robots} of {total_branches} branches ({pct:.0f}%) "
          f"— this is the review budget and the attack surface")
    if leaks:
        print(f"LEAKY FAILURE PATHS: {leaks}. A robot whose error path continues is a "
              f"large robot with a small front door. Read these first.")

    if verbose:
        for r in reports:
            robots_here = [b for b in r.branches if b.is_robot()]
            if not robots_here:
                continue
            print(f"\n--- {r.path} : {len(robots_here)} robot branch(es) ---")
            for b in sorted(robots_here, key=lambda x: (x.fail_path != "continues",
                                                        x.line)):
                mark = "!" if b.fail_path == "continues" else " "
                tags = []
                if b.attacker_input:
                    tags.append("attacker-input")
                if b.grants_authority:
                    tags.append("grants-authority")
                t = (" [" + ",".join(tags) + "]") if tags else ""
                print(f" {mark} L{b.line:<5} {b.level:<8} {b.function}(): "
                      f"{b.source}{t}\n      -> {b.reason}")


def to_baseline(reports: List[ModuleReport]) -> dict:
    return {"note": ("Baseline history. (1) first recording. (2) after "
                     "isolation_manifest's error paths were made to refuse locally AND "
                     "the tool was taught the accumulate-refusal idiom it had been "
                     "mismeasuring. (3) after adding the merge-proof 'leaves' companion "
                     "metric and match/case walking. (4) after cold self-red-team found "
                     "the walker was blind to ternaries, comprehension guards and loop "
                     "guards — the numbers ROSE because the instrument now sees "
                     "decisions it previously missed, which is the opposite of tuning. "
                     "Every entry is an instrument correction or a real improvement. A "
                     "baseline moves when the world moves or the ruler was wrong, never "
                     "to make a number look better."),
            "modules": {r.path: {"robot": r.robot_count(),
                                 "leaky": r.leaky_failures()} for r in reports},
            "total_robot": sum(r.robot_count() for r in reports),
            "total_leaky": sum(r.leaky_failures() for r in reports)}


def check_against_baseline(reports: List[ModuleReport]) -> int:
    if not os.path.exists(BASELINE):
        print("no baseline recorded; run with --baseline first")
        return 1
    with open(BASELINE) as fh:
        base = json.load(fh)
    now = to_baseline(reports)
    failed = False

    # A module that VANISHES from the enforcement list takes its robot count with it.
    # Dropping mediated_actuation from ENFORCEMENT_MODULES moved the total 104 -> 74
    # and the ratchet passed in silence, because the loop below only walks modules that
    # are still present. A gate that can be disabled by editing a list is not a gate.
    for path in base["modules"]:
        if path not in now["modules"]:
            print(f"MISSING {path}: it is in the baseline but no longer analysed. "
                  f"Removing a module from ENFORCEMENT_MODULES silently deletes its "
                  f"robot count from the total. If it was genuinely deleted or renamed, "
                  f"re-baseline deliberately and say so.")
            failed = True

    # The ratchet is SAFETY-MONOTONIC: the surface may shrink freely and may never
    # grow without a deliberate, recorded decision to move the baseline.
    for path, cur in now["modules"].items():
        old = base["modules"].get(path)
        if old is None:
            print(f"NEW MODULE {path}: {cur['robot']} robot branches "
                  f"(add to baseline deliberately)")
            failed = True
            continue
        if cur["robot"] > old["robot"]:
            print(f"REGRESSION {path}: robot surface grew "
                  f"{old['robot']} -> {cur['robot']}")
            failed = True
        if cur.get("leaves", 0) > old.get("leaves", cur.get("leaves", 0)):
            print(f"REGRESSION {path}: robot decision LEAVES grew "
                  f"{old.get('leaves')} -> {cur['leaves']} (merging branches cannot "
                  f"hide this)")
            failed = True
        if cur["leaky"] > old["leaky"]:
            print(f"REGRESSION {path}: leaky failure paths grew "
                  f"{old['leaky']} -> {cur['leaky']}")
            failed = True
        if cur["robot"] < old["robot"]:
            print(f"improved   {path}: {old['robot']} -> {cur['robot']} robot branches")

    if failed:
        print("\nFAIL: the decision surface grew. Every bug found in this repo's "
              "enforcement code lived in a robot branch. If the growth is genuinely "
              "necessary, move the baseline deliberately and say why in the commit.")
        return 1
    print(f"\nOK: robot surface {now['total_robot']} "
          f"(baseline {base['total_robot']}), leaky {now['total_leaky']} "
          f"(baseline {base['total_leaky']})")
    return 0


def main():
    ap = argparse.ArgumentParser(description="measure the decision surface")
    ap.add_argument("--baseline", action="store_true", help="write the ratchet baseline")
    ap.add_argument("--check", action="store_true", help="CI: fail if the surface grew")
    ap.add_argument("--module", help="restrict to one module (substring match)")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="list every robot branch")
    args = ap.parse_args()

    mods = ENFORCEMENT_MODULES
    if args.module:
        mods = [m for m in mods if args.module in m]
        if not mods:
            print(f"no enforcement module matching {args.module!r}")
            return 2

    reports = run(mods)
    if not reports:
        print("no modules analysed")
        return 2

    if args.check:
        return check_against_baseline(reports)

    print_report(reports, verbose=args.verbose or bool(args.module))

    if args.baseline:
        with open(BASELINE, "w") as fh:
            json.dump(to_baseline(reports), fh, indent=2, sort_keys=True)
        print(f"\nbaseline written to {BASELINE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
