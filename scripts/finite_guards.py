#!/usr/bin/env python3
"""
finite_guards.py — a guard that never declares its behaviour for non-finite values
is not a guard, and a scanner that cannot establish it scanned anything is not a gate.

WHY THIS EXISTS
---------------
NaN is false against `<` and false against `>`. `+inf` is false against `> ttl`. So a
comparison deciding something safety-relevant takes whichever branch means ALLOW when
handed a non-finite value, and the configuration that produced it looks entirely
valid. THE SET IS {NaN, +inf, -inf}, not NaN alone:

    if retention_seconds <= 0:  raise      # +inf passes this
    if age > retention_seconds: expire     # finite > +inf is False, so never

Found by execution in `clarification_channel._require_fresh`, 2026-08-25:

    age = time.monotonic() - float("nan")   # nan
    age < 0                                 # False -> not a clock fault
    age > self._ttl                         # False -> never expires

The answer was immortal, and nothing broke only because a DIFFERENT layer killed it
first. That is INCIDENTAL CONTAINMENT (§0e of `000_AI_START_HERE.md`), not the
freshness guard being correct.

THE SCANNER'S OWN INVARIANTS
----------------------------
The first version of this file HAD the failure class it was built to detect. Empty
scan root -> no findings -> exit 0. Missing baseline -> the current state becomes its
own ceiling -> exit 0. Structurally identical to NaN -> comparison false -> ALLOW:

    AN UNVERIFIED STATE WAS CONVERTED INTO AN AFFIRMATIVE SAFETY RESULT.

(Consolidated red team: ChatGPT, Meta, Grok, GLM, 2026-08-25. GLM found the
inversion, Grok the polarity gap, Meta the implementation shortcuts.)

CLAIM scan-integrity: a PASS establishes that the intended source population was
found, parsed and examined. Zero files, a missing root, or ANY parse failure is a
failure result, never a clean one.
CLAIM baseline-integrity: a PASS requires a schema-valid baseline created
deliberately. A missing baseline, a missing field, or a mismatched root fails; the
current state can never become its own ceiling.
CLAIM finding-identity: the ratchet compares SETS keyed by module, qualified function
and a fingerprint of the comparison itself, never counts. Remove one finding and add
another and the count is unchanged and the run fails.
CLAIM proof-locality: a finiteness check proves the VALUE it was applied to, at the
point it was applied, and nothing else. `isfinite(other)` does not bless `ttl`, and a
reassignment after the check revokes it.
CLAIM rejecting-polarity: a range test is exempt only when the non-finite path
provably reaches a raise. `if not (0 < x <= 1): return ALLOW` is a finding — same
shape, inverted consequence.
CLAIM heuristics-rank-they-do-not-gate: every ordered comparison on a
boundary-crossing value is examined. Name hints affect reporting order only, because
a hint list used as a gate means `def f(x)` hides the identical bug — and a `count`
prefix was suppressing `countdown_seconds`.

WHAT A GREEN RUN MEANS, EXACTLY
-------------------------------
    "The scan was complete, the baseline was valid, and no newly detected violation
     occurred within this scanner's explicitly bounded coverage model."

IT DOES NOT MEAN the repository contains no non-finite safety bugs. That sentence is
the difference between an engineering instrument and a pseudo-proof, and it is why
this belongs beside runtime property tests: a static shape can be renamed, wrapped or
moved by an optimiser; `guard(float("nan")) is BLOCKED` cannot.

HONEST LIMITS
-------------
* IT IS AST-SHAPED, NOT DATAFLOW. Proof tracking is one hop and name-based. A value
  laundered through a helper this file cannot read, or reached through an alias, is
  invisible. Bounded deliberately — the alternative is writing a compiler to check a
  property a runtime test checks directly.
* IT IS A GOODHART SURFACE. An agent making CI green can rename a value, wrap a
  comparison in `operator.gt`, or route it through an unrecognised helper. Static
  detection must not be the only semantic defence in a repository operated by
  optimisers.
* REMEDIATION TEXT IS PART OF THE ATTACK SURFACE. Advice to "write a positive-range
  assertion" without stating the required polarity is instructions for building the
  vulnerability. Every message here names the polarity.
* UNJUDGED IS NOT WAIVED. Baseline entries carry `status: UNJUDGED` and
  `reviewer: null`. The tool does not currently enforce that distinction; it records
  it. Enforcement would need a per-site waiver protocol with a signature, which is
  the same shape as the claims ledger and is not built here.

Run: python3 scripts/finite_guards.py             # check
     python3 scripts/finite_guards.py --init      # create the baseline, deliberately
     python3 scripts/finite_guards.py --lock      # re-record after review
     python3 scripts/finite_guards.py --list
     python3 scripts/finite_guards.py --self-test
"""

from __future__ import annotations

import ast
import hashlib
import json
import pathlib
import re
import sys
from typing import Dict, List, Set, Tuple

SCHEMA = 1
SCAN_ROOT_NAME = "driftcore"

# Ranking only. NEVER a gate — see CLAIM heuristics-rank-they-do-not-gate.
NUMERIC_HINT = re.compile(
    r"ttl|age|deadline|timeout|expir|elapsed|_s$|_ms$|seconds|interval|"
    r"torque|velocity|speed|accel|force|angle|distance|margin|clearance|"
    r"threshold|limit|budget|score|ratio|confidence|rate|temp|voltage|current|"
    r"pressure|weight|load|latency|drift|delta|tolerance|bound|cap", re.I)

FINITE_NAMES = {"isfinite", "isnan", "isinf"}
MEASURING_CALLS = {"len", "count", "sum"}
ORDER_OPS = (ast.Lt, ast.Gt, ast.LtE, ast.GtE)

PASS = "PASS"
NEW_FINDINGS = "NEW_FINDINGS"
REGRESSION = "REGRESSION"
SCAN_INCOMPLETE = "SCAN_INCOMPLETE"
INVALID_BASELINE = "INVALID_BASELINE"


class ScanError(Exception):
    """Scan integrity could not be established. Never downgraded to a clean result."""


def _name(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return getattr(node.func, "attr", getattr(node.func, "id", "")) or ""
    return ""


def _names_in(node) -> Set[str]:
    """Every identifier in a subtree, so `ttl + 5 > limit` is not invisible."""
    return {got for n in ast.walk(node) if (got := _name(n))}


def _is_measuring(node) -> bool:
    """`len(items) > limit` is counting. A SIBLING named `index` is not a reason to
    suppress a comparison on `timeout_seconds` — and a name-prefix rule also
    suppressed `countdown_seconds`, which is a real safety value."""
    return isinstance(node, ast.Call) and _name(node) in MEASURING_CALLS


def _params(fn) -> Set[str]:
    args = fn.args
    return {a.arg for a in (list(getattr(args, "posonlyargs", []))
                            + args.args + args.kwonlyargs)}


def _fingerprint(node: ast.AST) -> str:
    """Structure, not text: survives reformatting and line moves, and distinguishes
    two different comparisons inside one function."""
    return hashlib.sha256(
        ast.dump(node, annotate_fields=False).encode("utf-8")).hexdigest()[:12]


def _finite_proving_params(tree: ast.AST) -> Dict[str, Set[int]]:
    """Module-local helpers that prove finiteness OF ONE OF THEIR OWN PARAMETERS.

    A helper calling `isfinite` on something unrelated proves nothing about its
    argument, and one whose docstring merely MENTIONS isfinite proves nothing at
    all — the check is an AST call, never a string match.
    """
    out: Dict[str, Set[int]] = {}
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        ordered = [a.arg for a in (list(getattr(fn.args, "posonlyargs", []))
                                   + fn.args.args + fn.args.kwonlyargs)]
        proven = {ordered.index(nm)
                  for call in ast.walk(fn)
                  if isinstance(call, ast.Call) and _name(call) in FINITE_NAMES
                  for arg in call.args
                  if (nm := _name(arg)) in ordered}
        if proven:
            out[fn.name] = proven
    return out


def _proof_events(fn, helpers: Dict[str, Set[int]]):
    """(proofs, kills) as {name: [lineno, ...]}.

    A proof is `isfinite(name)`, or `name = helper(name)` where the helper proves
    that positional argument. A kill is any other assignment to the name, because a
    finiteness fact is not permanent:

        if not math.isfinite(ttl): raise
        ttl = float("nan")          # <- the proof is dead from here
        if ttl > 5: ...
    """
    proofs: Dict[str, List[int]] = {}
    kills: Dict[str, List[int]] = {}
    for call in [n for n in ast.walk(fn) if isinstance(n, ast.Call)]:
        if _name(call) in FINITE_NAMES:
            for arg in call.args:
                if nm := _name(arg):
                    proofs.setdefault(nm, []).append(call.lineno)
    for node in ast.walk(fn):
        targets, value = [], None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            targets, value = [node.target], node.value
        for t in targets:
            nm = _name(t)
            if not nm:
                continue
            laundered = (
                isinstance(value, ast.Call) and _name(value) in helpers
                and any(_name(a) == nm and i in helpers[_name(value)]
                        for i, a in enumerate(value.args)))
            (proofs if laundered else kills).setdefault(nm, []).append(node.lineno)
    return proofs, kills


def _is_proven_at(nm: str, line: int, proofs, kills) -> bool:
    best = max([ln for ln in proofs.get(nm, []) if ln < line], default=None)
    if best is None:
        return False
    return not any(best < k < line for k in kills.get(nm, []))


def _ends_in_raise(body) -> bool:
    return bool(body) and any(isinstance(s, ast.Raise) for s in body)


def _is_rejecting_range(cmp_node: ast.Compare, parents: Dict[int, ast.AST]) -> bool:
    """Exempt ONLY a range test whose non-finite path provably reaches a raise.

        if not (0 < x <= 1): raise        -> NaN raises. SAFE.
        if not (0 < x <= 1): return OK    -> NaN returns OK. NOT SAFE, same shape.
        if not (0 < x <= 1 or ok): raise  -> the `or` decides it. OUTSIDE MODEL.
        if 0 < x <= 1: ... else: raise    -> NaN takes else. SAFE.

    Syntax is not the property. Reaching the rejection is the property.
    """
    if len(cmp_node.ops) < 2:
        return False
    parent = parents.get(id(cmp_node))
    if isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.Not):
        grand = parents.get(id(parent))
        return (isinstance(grand, ast.If) and grand.test is parent
                and _ends_in_raise(grand.body))
    if isinstance(parent, ast.If) and parent.test is cmp_node:
        return _ends_in_raise(parent.orelse)
    return False


def scan(root: pathlib.Path, rel_to: pathlib.Path) -> Tuple[List[dict], dict]:
    """Returns (findings, coverage). Raises ScanError if integrity cannot be shown."""
    if not root.exists() or not root.is_dir():
        raise ScanError(
            f"scan root {root} does not exist. A missing source population is not an "
            f"absence of findings, it is an absence of evidence, and this scanner "
            f"will not report the second as the first.")
    sources = sorted(root.rglob("*.py"))
    if not sources:
        raise ScanError(
            f"scan root {root} contains no Python files. Zero files scanned cannot "
            f"produce a clean result.")
    findings: List[dict] = []
    for path in sources:
        rel = str(path.relative_to(rel_to))
        try:
            src = path.read_text()
            tree = ast.parse(src)
        except (SyntaxError, UnicodeDecodeError) as exc:
            raise ScanError(
                f"{rel} could not be parsed ({type(exc).__name__}). An unparseable "
                f"file must not disappear from a safety scan — fix it, or exclude it "
                f"deliberately and say so.") from exc
        findings.extend(_scan_module(tree, src, rel))
    return findings, {"files_discovered": len(sources), "files_parsed": len(sources)}


def _scan_module(tree, src, rel) -> List[dict]:
    helpers = _finite_proving_params(tree)
    parents: Dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node

    from_param: Set[str] = set()
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = _params(fn) - {"self"}
        for node in ast.walk(fn):
            targets, value = [], None
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign):
                targets, value = [node.target], node.value
            for t in targets:
                if (isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name)
                        and t.value.id == "self" and value is not None
                        and (_names_in(value) & params)):
                    from_param.add(t.attr)

    out: List[dict] = []

    def examine(fn, stack):
        params = _params(fn) - {"self"}
        proofs, kills = _proof_events(fn, helpers)
        for cmp_node in [n for n in ast.walk(fn) if isinstance(n, ast.Compare)]:
            if not any(isinstance(o, ORDER_OPS) for o in cmp_node.ops):
                continue
            operands = [cmp_node.left] + list(cmp_node.comparators)
            if any(_is_measuring(o) for o in operands):
                continue
            crossing = sorted({n for o in operands for n in _names_in(o)}
                              & (params | from_param))
            if not crossing:
                continue
            unproven = [n for n in crossing
                        if not _is_proven_at(n, cmp_node.lineno, proofs, kills)]
            if not unproven or _is_rejecting_range(cmp_node, parents):
                continue
            out.append({
                "module": rel, "function": ".".join(stack) or "<module>",
                "fingerprint": _fingerprint(cmp_node), "values": unproven,
                "expr": " ".join(
                    (ast.get_source_segment(src, cmp_node) or "").split())[:80],
                "line": cmp_node.lineno,
                "ranked": any(NUMERIC_HINT.search(n) for n in crossing)})

    def walk(node, stack):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                examine(child, stack + [child.name])
                walk(child, stack + [child.name])
            elif isinstance(child, ast.ClassDef):
                walk(child, stack + [child.name])
            else:
                walk(child, stack)

    walk(tree, [])
    return out


def key(f: dict) -> str:
    return f"{f['module']}::{f['function']}::{f['fingerprint']}"


def load_baseline(path: pathlib.Path) -> dict:
    if not path.exists():
        raise ScanError(
            f"no baseline at {path.name}. A first run must not bless whatever it "
            f"happens to find — run --init to create one deliberately.")
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ScanError(f"baseline is not valid JSON: {exc}")
    for field in ("schema", "root", "files_scanned", "findings", "resolved"):
        if field not in data:
            raise ScanError(
                f"baseline is missing required field {field!r}. A baseline with "
                f"holes cannot establish anything: the previous version defaulted a "
                f"missing ceiling to the current count, which made the repository "
                f"its own standard.")
    if data["schema"] != SCHEMA:
        raise ScanError(f"baseline schema {data['schema']} != {SCHEMA}; "
                        f"migrate it deliberately")
    if data["root"] != SCAN_ROOT_NAME:
        raise ScanError(
            f"baseline was taken over root {data['root']!r} but this run scans "
            f"{SCAN_ROOT_NAME!r}. A baseline from another scope proves nothing here.")
    return data


def write_baseline(path: pathlib.Path, findings, coverage, resolved=None) -> None:
    path.write_text(json.dumps({
        "schema": SCHEMA,
        "root": SCAN_ROOT_NAME,
        "files_scanned": coverage["files_parsed"],
        "_note": ("Findings are an IDENTITY SET, not a count: swapping one finding "
                  "for another leaves the count unchanged and fails the run. These "
                  "are UNJUDGED - a backlog, not a decision. Each needs a human to "
                  "say 'this value cannot be non-finite here, and here is why' or "
                  "'guard it'. UNJUDGED IS NOT WAIVED."),
        "findings": {key(f): {"module": f["module"], "function": f["function"],
                              "expr": f["expr"], "values": f["values"],
                              "status": "UNJUDGED", "reviewer": None}
                     for f in findings},
        "resolved": resolved or {},
    }, indent=2) + "\n")


def check(repo: pathlib.Path, baseline_path: pathlib.Path, verbose=False):
    try:
        findings, coverage = scan(repo / SCAN_ROOT_NAME, repo)
    except ScanError as exc:
        return SCAN_INCOMPLETE, f"  {exc}", None
    try:
        baseline = load_baseline(baseline_path)
    except ScanError as exc:
        return INVALID_BASELINE, f"  {exc}", None
    known, resolved = set(baseline["findings"]), set(baseline["resolved"])
    current = {key(f): f for f in findings}
    new = sorted(set(current) - known - resolved)
    back = sorted(set(current) & resolved)
    gone = sorted(known - set(current))
    if coverage["files_parsed"] < baseline["files_scanned"]:
        return SCAN_INCOMPLETE, (
            f"  scanned {coverage['files_parsed']} files, baseline covered "
            f"{baseline['files_scanned']}. The scope shrank; a smaller scan is not "
            f"a cleaner repository."), None
    report = [f"  files parsed: {coverage['files_parsed']} "
              f"(baseline {baseline['files_scanned']})",
              f"  known: {len(known)}   current: {len(current)}   new: {len(new)}   "
              f"removed: {len(gone)}   resolved: {len(resolved)}"]
    if verbose:
        for k in sorted(current, key=lambda k: (not current[k]["ranked"], k)):
            f = current[k]
            report.append(f"  {'NEW ' if k in new else '    '}{f['module']}:"
                          f"{f['line']} {f['function']} -> {f['expr']}")
    if back:
        return REGRESSION, "\n".join(
            report + ["", "  a site recorded as FIXED is unguarded again:"]
            + [f"    {k}" for k in back]), current
    if new:
        return NEW_FINDINGS, "\n".join(
            report + ["", "  new unguarded non-finite boundaries:"]
            + [f"    {k}\n      {current[k]['expr']}" for k in new]
            + ["", "  Check the compared VALUE for finiteness, or write the "
               "validation so the non-finite path REACHES A RAISE:",
               "      if not (0.0 < x <= 1.0): raise    # NaN and +/-inf raise here",
               "      if not (0.0 < x <= 1.0): return   # NOT safe: same shape, "
               "inverted consequence"]), current
    return PASS, "\n".join(report), current


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    here = pathlib.Path(__file__).resolve().parent
    repo, baseline_path = here.parent, here / "finite_guards_baseline.json"
    if "--self-test" in argv:
        return self_test()
    if "--init" in argv or "--lock" in argv:
        try:
            findings, coverage = scan(repo / SCAN_ROOT_NAME, repo)
        except ScanError as exc:
            print(f"  {SCAN_INCOMPLETE}: {exc}")
            return 1
        resolved = {}
        if baseline_path.exists():
            try:
                resolved = load_baseline(baseline_path)["resolved"]
            except ScanError:
                resolved = {}
        write_baseline(baseline_path, findings, coverage, resolved)
        print(f"  baseline written: {len(findings)} findings over "
              f"{coverage['files_parsed']} files, all UNJUDGED.")
        return 0
    result, detail, _ = check(repo, baseline_path, verbose="--list" in argv)
    print(detail)
    print(f"\n  RESULT: {result}")
    if result == PASS:
        print("  (means: the scan was complete, the baseline was valid, and no newly "
              "detected violation occurred within this scanner's bounded coverage "
              "model. NOT: the repository has no non-finite bugs.)")
    return 0 if result == PASS else 1


def self_test() -> int:
    """Adversarial, and it must catch the incident that created it."""
    import shutil
    import subprocess
    import tempfile

    made: List[pathlib.Path] = []

    def fixture(files, baseline=None):
        d = pathlib.Path(tempfile.mkdtemp())
        made.append(d)
        (d / "scripts").mkdir()
        (d / SCAN_ROOT_NAME).mkdir()
        shutil.copy(__file__, d / "scripts" / "finite_guards.py")
        for name, text in files.items():
            (d / SCAN_ROOT_NAME / name).write_text(text)
        if baseline is not None:
            (d / "scripts" / "finite_guards_baseline.json").write_text(
                json.dumps(baseline))
        return d

    EMPTY = {"schema": SCHEMA, "root": SCAN_ROOT_NAME, "files_scanned": 0,
             "findings": {}, "resolved": {}}
    BAD = "def f(ttl_seconds):\n    if ttl_seconds <= 0:\n        raise ValueError\n"

    def n_findings(src):
        d = fixture({"m.py": src})
        return len(scan(d / SCAN_ROOT_NAME, d)[0])

    def cli(d, args=()):
        script = d / "scripts" / "finite_guards.py"
        # The harness must run THE COPY. A previous probe ran the original by
        # absolute path, so every fixture silently scanned the real repository and
        # eight findings were reported from a broken harness.
        assert script.exists() and script.parent.parent == d, "harness must use the copy"
        r = subprocess.run([sys.executable, str(script), *args], cwd=d,
                           capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr

    passed = failed = 0

    def case(label, got, want):
        nonlocal passed, failed
        if got == want:
            passed += 1
            print(f"  ok   {label}")
        else:
            failed += 1
            print(f"  FAIL {label}: expected {want}, got {got}")

    try:
        print("-- detection --")
        INCIDENT = ("import time\nclass C:\n"
                    "    def __init__(self, ttl):\n        self._ttl = ttl\n"
                    "    def _require_fresh(self, exchange):\n"
                    "        age = time.monotonic() - float(exchange.asked_mono)\n"
                    "        if age < 0:\n            raise ValueError\n"
                    "        if age > self._ttl:\n            raise ValueError\n")
        case("THE MOTIVATING INCIDENT is detected", n_findings(INCIDENT) >= 1, True)
        case("a plain negative test", n_findings(BAD), 1)
        case("a value with no hint in its name is still examined",
             n_findings("def f(x):\n    if x <= 0:\n        raise ValueError\n"), 1)
        case("countdown_seconds is not suppressed as counting", n_findings(
            "def f(countdown_seconds):\n    if countdown_seconds <= 0:\n"
            "        raise ValueError\n"), 1)
        case("len() genuinely is counting", n_findings(
            "def f(items, limit):\n    if len(items) > limit:\n"
            "        raise ValueError\n"), 0)
        case("arithmetic on a parameter stays visible", n_findings(
            "def f(ttl, limit):\n    if ttl + 5 > limit:\n        raise ValueError\n"), 1)
        case("positional-only parameters are examined", n_findings(
            "def f(ttl, /):\n    if ttl <= 0:\n        raise ValueError\n"), 1)
        case("annotated attribute assignment traces provenance", n_findings(
            "class C:\n    def __init__(self, ttl):\n        self._ttl: float = ttl\n"
            "    def g(self, x):\n        return x > self._ttl\n"), 1)
        case("async functions are examined", n_findings(
            "async def f(ttl_seconds):\n    if ttl_seconds <= 0:\n"
            "        raise ValueError\n"), 1)

        print("-- polarity --")
        case("a rejecting range is exempt", n_findings(
            "def f(x):\n    if not (0.0 < x <= 1.0):\n        raise ValueError\n"), 0)
        case("if/else where else raises is exempt", n_findings(
            "def f(x):\n    if 0.0 < x <= 1.0:\n        pass\n    else:\n"
            "        raise ValueError\n"), 0)
        case("INVERTED polarity is a finding", n_findings(
            "ALLOW = 'a'\ndef f(x):\n    if not (0.0 < x <= 1.0):\n"
            "        return ALLOW\n"), 1)
        case("an `or` in the test puts it outside the model", n_findings(
            "def f(x, ok):\n    if not (0.0 < x <= 1.0 or ok):\n"
            "        raise ValueError\n"), 1)

        print("-- proof locality --")
        case("isfinite on the value guards it", n_findings(
            "import math\ndef f(ttl):\n    if not math.isfinite(ttl):\n"
            "        raise ValueError\n    if ttl > 5:\n        raise ValueError\n"), 0)
        case("isfinite on ANOTHER value does not", n_findings(
            "import math\ndef f(ttl, force):\n    if not math.isfinite(force):\n"
            "        raise ValueError\n    if ttl > 5:\n        raise ValueError\n"), 1)
        case("reassignment after the check revokes it", n_findings(
            "import math\ndef f(ttl):\n    if not math.isfinite(ttl):\n"
            "        raise ValueError\n    ttl = float('nan')\n"
            "    if ttl > 5:\n        raise ValueError\n"), 1)
        case("a helper that PROVES its argument counts", n_findings(
            "import math\ndef _req(x):\n    if not math.isfinite(x):\n"
            "        raise ValueError\n    return x\n"
            "def f(ttl):\n    ttl = _req(ttl)\n    if ttl > 5:\n"
            "        raise ValueError\n"), 0)
        case("a helper that only MENTIONS the check does not", n_findings(
            "def _req(x):\n    # we used to call math.isfinite here, but it was slow\n"
            "    return float(x)\ndef f(ttl):\n    ttl = _req(ttl)\n"
            "    if ttl > 5:\n        raise ValueError\n"), 1)
        case("a helper proving a DIFFERENT argument does not bless this one",
             n_findings(
                 "import math\ndef _req(a, b):\n    if not math.isfinite(b):\n"
                 "        raise ValueError\n    return a\n"
                 "def f(ttl, other):\n    ttl = _req(ttl, other)\n"
                 "    if ttl > 5:\n        raise ValueError\n"), 1)

        print("-- scan integrity (subprocess, against the copy) --")
        case("an empty scan root fails closed", cli(fixture({}, EMPTY))[0], 1)
        d = fixture({"m.py": "x = 1\n"}, EMPTY)
        shutil.rmtree(d / SCAN_ROOT_NAME)
        case("a missing scan root fails closed", cli(d)[0], 1)
        rc, out = cli(fixture({"broken.py": "def f(ttl:\n  if ttl <= 0\n"}, EMPTY))
        case("an unparseable file fails closed", rc, 1)
        case("and the failure names the file", "broken.py" in out, True)

        print("-- baseline integrity --")
        case("no baseline fails closed", cli(fixture({"m.py": BAD}))[0], 1)
        case("a baseline missing a field fails closed", cli(fixture(
            {"m.py": BAD}, {"schema": SCHEMA, "root": SCAN_ROOT_NAME,
                            "findings": {}, "resolved": {}}))[0], 1)
        case("a wrong schema fails closed",
             cli(fixture({"m.py": BAD}, dict(EMPTY, schema=99)))[0], 1)
        case("a baseline from another root fails closed",
             cli(fixture({"m.py": BAD}, dict(EMPTY, root="elsewhere")))[0], 1)
        case("a real finding against an empty baseline fails",
             cli(fixture({"m.py": BAD}, EMPTY))[0], 1)
        d = fixture({"m.py": BAD})
        case("--init creates the baseline deliberately", cli(d, ["--init"])[0], 0)
        case("and the same tree then passes", cli(d)[0], 0)

        print("-- ratchet identity --")
        d = fixture({"m.py": BAD})
        cli(d, ["--init"])
        (d / SCAN_ROOT_NAME / "m.py").write_text(
            "def g(timeout_seconds):\n    if timeout_seconds <= 0:\n"
            "        raise ValueError\n")
        case("SWAPPING one finding for another fails (count unchanged)",
             cli(d)[0], 1)
        d = fixture({"m.py": BAD})
        cli(d, ["--init"])
        (d / SCAN_ROOT_NAME / "m.py").write_text(
            "import math\ndef f(ttl_seconds):\n"
            "    if not math.isfinite(ttl_seconds):\n        raise ValueError\n"
            "    if ttl_seconds <= 0:\n        raise ValueError\n")
        case("fixing a finding passes", cli(d)[0], 0)
        d = fixture({"m.py": BAD})
        cli(d, ["--init"])
        (d / SCAN_ROOT_NAME / "n.py").write_text(
            "def h(margin_seconds):\n    if margin_seconds <= 0:\n"
            "        raise ValueError\n")
        case("adding a NEW finding fails", cli(d)[0], 1)
    finally:
        for d in made:
            shutil.rmtree(d, ignore_errors=True)

    print("-" * 60)
    print(f"  {passed}/{passed + failed} scanner self-tests passed")
    print("  SELF-TEST: " + ("PASS" if not failed else "FAIL"))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
