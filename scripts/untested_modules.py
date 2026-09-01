#!/usr/bin/env python3
"""
untested_modules.py — make the unmapped territory visible.

WHY THIS EXISTS
───────────────
A module with zero tests is not examined and found fine. It is ABSENT FROM THE
EVIDENCE STREAM. It produces no output, so it appears in no review.

This was found the expensive way. `driftcore/hardware/hardware_safety.py` — 413 lines,
live (main.py constructs it, sensor_interfaces routes real sensor readings into it),
and described in its own docstring as what actually stops the machine — had no tests at
all. It reported `power_cut: True` when the relay had raised and when no relay was wired
at all. Four independent AI reviewers read this repo and none of them saw it, because
every one of them read TEST RESULTS as the map of the system. Unmapped territory
generates no output to read.

The passing count makes it worse, not better. "3023 passing across 91 files" produces
exactly the confidence that stops anyone asking *what is not in the 91?* The larger the
suite, the more convincing the illusion of coverage.

This repo already contains the detector for this exact failure — `coverage_gap.py`,
whose thesis is that **the lie exists only in the shape of what was never said**. It was
pointed at agents. The test suite had the identical shape: nothing false was ever
claimed, every green number was true, and the untested modules were simply never
mentioned. Nothing contradicted anything.

So: the same treatment as the robot-surface ratchet. Not a coverage percentage — a
committed list of what is knowingly unmapped, which may shrink freely and may only grow
by a deliberate, recorded decision.

THE BASELINE IS GOVERNANCE DATA, NOT BUILD OUTPUT
──────────────────────────────────────────────────
(red-team) Anyone who can edit the baseline can convert NEW UNTESTED MODULE into KNOWN
UNTESTED MODULE and satisfy this tool. The program cannot prevent that — a waiver list
is only as good as the review of edits to it. So treat `untested_modules_baseline.json`
as policy requiring independent review, and flag baseline growth separately from ordinary
code changes in CI. Otherwise the ratchet reduces to "trust whoever edits the exception
list", which is exactly the hidden trust seam this project hunts everywhere else.

WHAT THIS IS NOT
────────────────
This does not measure test QUALITY. A module can be referenced by a test that asserts
nothing useful. It answers one narrow question honestly: does any test source IMPORT this
module? That is weaker than "a test exercises it" — `ast` proves an import statement
exists, not that it executes or that anything asserts on it (an import under `if False:`
counts). It is the floor, not the ceiling; dynamic coverage evidence is the next rung.

Usage:
    python3 scripts/untested_modules.py              # check against the baseline
    python3 scripts/untested_modules.py --list       # show the current gap
    python3 scripts/untested_modules.py --baseline   # re-baseline deliberately
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import pathlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "driftcore"
BASELINE = Path(__file__).resolve().parent / "untested_modules_baseline.json"

def module_names(path: Path):
    """(dotted, stem) for a source file. Package __init__ files carry the package name,
    because `driftcore/enforcement/__init__.py` IS the enforcement module."""
    rel = path.relative_to(ROOT)
    parts = list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts), parts[-1]


SKIP_DIRS = {"__pycache__", ".git", "venv", ".venv", "env", "node_modules",
             "build", "dist", ".pytest_cache", ".eggs"}


def test_sources():
    """Every file whose imports count as 'a test source references this'.

    (red-team) Two earlier defects: only `test_*.py` was collected, so `conftest.py`
    and fixture helpers were missed; and root was searched non-recursively while
    `tests/` was recursive, so `integration/test_safety.py` was invisible. Both failed
    toward FALSE GAPS rather than false assurance — the safe direction — but noise in a
    ratchet trains people to re-baseline without reading, which is how a ratchet quietly
    stops being one."""
    out = []
    for p in ROOT.rglob("*.py"):
        if SKIP_DIRS & set(p.parts):
            continue
        name = p.name
        if name.startswith("test_") or name == "conftest.py" or "tests" in p.parts:
            out.append(p)
    return out


def imported_by_tests(blobs):
    """The set of dotted module names ACTUALLY imported by the test corpus.

    (red-team) The first version's very first check was `if dotted in text: return True`
    — an unrestricted substring search. Any test file that merely MENTIONED a module's
    dotted name, in a comment or a docstring or a log string, marked it as covered.
    Verified: a file importing nothing, carrying only the comment "mentions
    driftcore.safety.safe_halt", removed safe_halt from the unmapped list. The tool
    re-opened the exact lie it exists to close, in the line right under a docstring
    promising it would not. Parsing the imports with `ast` removes the whole class:
    a comment is not an import node, so it cannot be mistaken for one.

    KNOWN LIMIT, stated rather than hidden: imports that exist only inside a string
    executed in a subprocess are invisible to `ast`. Such a module is reported as
    unmapped even though a test drives it. That direction is the safe one — it
    over-reports the gap rather than hiding it."""
    names = set()
    for path, text in blobs:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            print(f"  warning: could not parse {path.name}; its imports are not counted "
                  f"(the gap is over-reported, never under-reported)")
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    names.add(a.name)
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if node.level:
                    # (red-team) These used to be DROPPED, so `from .hardware_safety
                    # import EmergencyStop` inside a package test counted as no import
                    # at all and the module was reported unmapped though it was used
                    # everywhere. False alarms are the safe direction, but a tool that
                    # cries wolf gets ignored, which costs more than it saves. Resolve
                    # the level against the importing file's own package instead.
                    try:
                        pkg = path.resolve().relative_to(ROOT).parts[:-1]
                    except ValueError:
                        pkg = ()
                    base = pkg[:len(pkg) - (node.level - 1)] if node.level > 1 else pkg
                    mod = ".".join(list(base) + ([mod] if mod else []))
                names.add(mod)
                for a in node.names:
                    names.add(f"{mod}.{a.name}" if mod else a.name)
    return names


# Review priority by SUBSYSTEM. This is not a risk score and does not pretend to be —
# line counts do not measure danger. It exists because 5,000 undifferentiated lines
# prioritise nothing, and the goal is to make unexamined DECISION SURFACE visible.
# (red-team) Substring matching mis-tiered: "kernel/" matched
# `driftcore/some_kernel/x.py`. Compare PATH COMPONENTS so a directory named
# `hardware_emulator` or `some_kernel` is not mistaken for `hardware` or `kernel`.
_CRITICAL = {"safety", "hardware", "kernel", "governance", "verification",
             "network", "recovery", "memory"}
_HIGH = {"drift", "cognition", "objectives", "agents", "uncertainty", "authority"}


def _tier(module: str) -> str:
    parts = set(pathlib.PurePosixPath(module).parts)
    if parts & _CRITICAL:
        return "CRITICAL"
    if parts & _HIGH:
        return "HIGH"
    return "LOW"


def _api_digest(body: str) -> str:
    """A digest of the callable surface: every def/class and its parameter names.
    Stable under comment and docstring edits; changes when behaviour surface does."""
    try:
        tree = ast.parse(body)
    except SyntaxError:
        return "unparseable"
    sig = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = [a.arg for a in n.args.args + n.args.kwonlyargs]
            sig.append(f"def {n.name}({','.join(args)})")
        elif isinstance(n, ast.ClassDef):
            sig.append(f"class {n.name}")
    return hashlib.sha256("\n".join(sorted(sig)).encode()).hexdigest()


def scan():
    blobs = []
    for f in test_sources():
        try:
            blobs.append((f, f.read_text(errors="ignore")))
        except OSError:
            pass
    imported = imported_by_tests(blobs)
    gaps = {}
    for src in sorted(PKG.rglob("*.py")):
        if "__pycache__" in src.parts:
            continue
        dotted, stem = module_names(src)
        if not stem:
            continue
        body = src.read_text(errors="ignore")
        if not body.strip():
            continue        # an empty file has nothing to test; reporting it is noise
        if dotted not in imported:
            rel = str(src.relative_to(ROOT))
            gaps[rel] = {
                # (red-team) The byte hash fires on ANY edit, so a reviewer seeing only
                # "55 -> 600 lines" may rubber-stamp a change that swapped comments for
                # code. `api_sha256` covers only the callable surface (def/class names
                # and their parameters), so a comment-or-docstring-only edit leaves it
                # UNCHANGED while any change to what the module can do alters it. The
                # waiver is then on the behaviour, not merely on the bytes.
                "api_sha256": _api_digest(body),
                # (red-team) A PATH IS NOT AN IDENTITY FOR SAFETY REVIEW. Without a
                # content hash, a waived file can go from 55 lines to 600 with entirely
                # new emergency behaviour and the tool still says "already in the
                # baseline". The hash makes the waiver apply to specific reviewed code.
                "sha256": hashlib.sha256(body.encode("utf-8", "replace")).hexdigest(),
                "lines": len(body.splitlines()),
                "tier": _tier(rel),
            }
    return gaps


def render(gaps):
    if not gaps:
        return "  no unmapped modules"
    order = {"CRITICAL": 0, "HIGH": 1, "LOW": 2}
    rows = sorted(gaps.items(), key=lambda kv: (order[kv[1]["tier"]], -kv[1]["lines"]))
    out = [f"  {info['tier']:8} {info['lines']:5d}  {mod}" for mod, info in rows]
    total = sum(i["lines"] for i in gaps.values())
    crit = sum(i["lines"] for i in gaps.values() if i["tier"] == "CRITICAL")
    out.append("  " + "-" * 56)
    out.append(f"  {len(gaps)} module(s), {total} lines with no test-source import "
               f"({crit} of them CRITICAL-tier)")
    return "\n".join(out)


def load_baseline():
    data = json.loads(BASELINE.read_text())
    waived = data.get("waived")
    if waived is None:
        raise SystemExit(
            f"  {BASELINE.name} is in the OLD format (a bare path list with no content\n"
            f"  hashes). That format could not detect a waived file being rewritten, so\n"
            f"  it is refused rather than silently accepted. Re-baseline deliberately:\n"
            f"      python3 scripts/untested_modules.py --baseline")
    return waived


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", action="store_true",
                    help="write the ratchet baseline (a governance act, see the header)")
    ap.add_argument("--list", action="store_true", help="show the current gap")
    ap.add_argument("--max-age-days", type=int, default=0,
                    help="fail waivers older than N days (needs a `date` field); a "
                         "ratchet must tighten in both directions or 'waived' becomes "
                         "'permanent'")
    args = ap.parse_args()

    now = scan()

    if args.baseline:
        # Carry forward the human fields. A re-baseline must never silently erase why a
        # waiver was granted or who granted it.
        if BASELINE.is_file():
            try:
                prev = json.loads(BASELINE.read_text()).get("waived", {})
            except Exception:
                prev = {}
            for mod, info in now.items():
                old = prev.get(mod, {})
                for field in ("reason", "reviewer", "date"):
                    if old.get(field):
                        info[field] = old[field]
        # No `count` field: it is derivable from the list, it was never validated
        # against it, and a second source of truth that nothing checks is just one more
        # piece of repository state that can lie.
        BASELINE.write_text(json.dumps({"waived": now}, indent=2, sort_keys=True) + "\n")
        print(render(now))
        print(f"\nbaseline written to {BASELINE.relative_to(ROOT)}")
        return 0

    if args.list:
        print(render(now))
        return 0

    if not BASELINE.is_file():
        print(render(now))
        print("\nNo baseline yet. Run with --baseline to record the known gap.")
        return 1

    waived = load_baseline()
    new = sorted(m for m in now if m not in waived)
    closed = sorted(m for m in waived if m not in now)
    changed = sorted(m for m in now
                     if m in waived and now[m]["sha256"] != waived[m].get("sha256"))

    print(render(now))
    problems = False

    if new:
        problems = True
        print(f"\n  FAIL - {len(new)} module(s) added with no test-source import:")
        for m in new:
            print(f"    {now[m]['tier']:8} {m}")
        print("  Untested code is invisible to review: it produces no output, so it\n"
              "  appears in no report. Add a test, or waive it deliberately.")

    if changed:
        problems = True
        print(f"\n  FAIL - {len(changed)} waived module(s) CHANGED since review:")
        for m in changed:
            api_moved = now[m]["api_sha256"] != waived[m].get("api_sha256")
            kind = ("BEHAVIOUR SURFACE CHANGED" if api_moved
                    else "bytes changed, callable surface identical")
            print(f"    {now[m]['tier']:8} {m}  "
                  f"({waived[m].get('lines','?')} -> {now[m]['lines']} lines) — {kind}")
        print("  A waiver applies to the code that was reviewed, not to the filename.\n"
              "  A line-count delta alone can hide a swap of comments for code, so the\n"
              "  callable surface is tracked separately. Re-review, then re-baseline.")

    if closed:
        problems = True
        print(f"\n  FAIL - {len(closed)} gap(s) are now CLOSED but still waived:")
        for m in closed:
            print(f"    {m}")
        print("  Remove them from the baseline. While a closed gap stays on the waiver\n"
              "  list, losing its tests again is invisible - the module is already\n"
              "  'known', so the regression never reads as new. That is the hole this\n"
              "  check exists to shut.")

    missing_reason = sorted(m for m in waived if not waived[m].get("reason"))
    if missing_reason:
        print(f"\n  NOTE: {len(missing_reason)} waiver(s) carry no `reason`. A waiver "
              f"without a stated\n  reason is indistinguishable from an oversight; add "
              f'"reason"/"reviewer"/"date"\n  to the baseline entry so the next person '
              f"knows it was a decision.")

    if args.max_age_days:
        import datetime as _dt
        today = _dt.date.today()
        stale = []
        for m, info in waived.items():
            d = info.get("date")
            if not d:
                continue
            try:
                age = (today - _dt.date.fromisoformat(d)).days
            except ValueError:
                continue
            if age > args.max_age_days:
                stale.append((m, age))
        if stale:
            problems = True
            print(f"\n  FAIL - {len(stale)} waiver(s) older than "
                  f"{args.max_age_days} days:")
            for m, age in sorted(stale, key=lambda x: -x[1]):
                print(f"    {m}  ({age} days)")
            print("  Re-review the waiver or add a test. A waiver that never expires is\n"
                  "  a permanent exception wearing a ratchet's clothes.")

    if problems:
        # (red-team) Baseline GROWTH is a governance act, not an ordinary test failure:
        # anyone who can edit the waiver list converts NEW into KNOWN. A distinct exit
        # code lets CI route it to human review instead of burying it among red builds.
        return 2 if new else 1
    print(f"\n  OK: {len(waived)} waived gap(s), all unchanged; nothing new, nothing "
          f"regressed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
