#!/usr/bin/env python3
"""
authority_sites.py — find authorization decided by comparing a name to a literal.

WHY THIS EXISTS
---------------
On 2026-08-15 the same defect was found in five modules on the same day:

    recovery.py        if not authorized_by or authorized_by == "agent"
    media/policy.py    authorised_by not in ("", "system", "auto", "auto-sign", None)
    edge_loop.py       if by == "agent"                    (x2, default "human_operator")
    cognitive_mode.py  if requested_by == "agent"          (default "human_operator")
    safe_halt.py       if not authorized_by or authorized_by == "agent"

Every one decides whether a caller is HUMAN by comparing a name against string
literals. A denylist on an authorization boundary fails by construction: an agent
choosing its own authorizer string has to pick exactly the forbidden value to be
stopped. "Agent", "agent2", "the_model", "system2" and "not_a_human" all pass.
Three of the five defaulted the parameter to "human_operator", so the NO-ARGUMENT
call authorised itself.

The repo already had the right primitive — `human_identity.is_human`, which
escalates ATTESTED → REGISTERED → LABEL_ONLY. Modules that never call it are frozen
at the weakest mode forever: a deployment can configure attested identity everywhere
and these sites still consult a five-word list.

THE ROOT CAUSE, which is the reason this is a tool and not a note
-----------------------------------------------------------------
`untested_modules.py` and `claims_ledger.py` both tier by SUBSYSTEM NAME — safety,
hardware, kernel, governance, verification, network, recovery, memory. `media/` and
`cognition/` are not on that list, so two of the five sites were invisible to every
ratchet in the repo. A module that decides whether a privacy invariant may be
loosened is doing governance work regardless of which directory it sits in.

Tier by what a module DECIDES, not by where it lives. That sentence in a markdown
file would be doctrine. This file is the enforcement.

WHAT IT CANNOT DO
-----------------
* It finds comparisons against LITERALS. An authorization decided by comparing
  against a module-level list, or by a helper called `_check()`, is invisible here.
  Precision was chosen over recall: a noisy check gets switched off.
* It cannot tell a real authorization gate from a variable that merely happens to be
  named `by`. False positives are waivable with a reason.
* Calling `is_human` proves the site DELEGATES, not that it delegates correctly.
  `media/policy.py` was patched to delegate and still had a hole, because it bound no
  action and any valid attestation for any purpose passed. That class of defect is
  invisible to this tool and needs a human reading the call.

Usage:
    python3 scripts/authority_sites.py            # check against the baseline
    python3 scripts/authority_sites.py --list     # every site found
    python3 scripts/authority_sites.py --root DIR
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = Path(__file__).resolve().parent / "authority_sites_baseline.json"

# Parameter names that mean "who is asking". Drawn from the five real sites rather
# than invented, so the list is evidence rather than imagination.
AUTHORIZER = {
    "authorized_by", "authorised_by", "requested_by", "released_by", "approved_by",
    "registered_by", "authorizer", "authoriser", "principal", "by", "actor",
    "changed_by", "issued_by", "operator",
}

# Values that make a comparison a DENYLIST rather than an allow-list: the code is
# naming who is NOT human, which means everyone else is.
_NEGATIVE_HINT = {"agent", "system", "auto", "auto-sign", "", "ai", "model",
                  "assistant", "bot", "automation"}


def _literals(node) -> list:
    """String constants on the right-hand side of a comparison, if any."""
    out = []
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        out.append(node.value)
    elif isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        for e in node.elts:
            if isinstance(e, ast.Constant) and isinstance(e.value, str):
                out.append(e.value)
    return out


def scan_file(path: Path, rel: str):
    """Authorization sites in one file."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return [], False
    delegates = any(
        isinstance(n, ast.Name) and n.id == "is_human" for n in ast.walk(tree)
    ) or "is_human" in path.read_text(encoding="utf-8", errors="replace")

    sites = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        args = fn.args
        params = {a.arg for a in list(args.args) + list(args.kwonlyargs)}
        auth_params = params & AUTHORIZER
        if not auth_params:
            continue

        # A default that reads as a human is its own finding: the no-argument call
        # authorises itself. Three of the five real sites did this.
        defaults = {}
        pos = list(args.args)[len(args.args) - len(args.defaults):]
        for p, d in zip(pos, args.defaults):
            if p.arg in auth_params and isinstance(d, ast.Constant):
                defaults[p.arg] = d.value
        for p, d in zip(args.kwonlyargs, args.kw_defaults):
            if p.arg in auth_params and isinstance(d, ast.Constant):
                defaults[p.arg] = d.value

        for cmp_node in ast.walk(fn):
            if not isinstance(cmp_node, ast.Compare):
                continue
            left = cmp_node.left
            if not (isinstance(left, ast.Name) and left.id in auth_params):
                continue
            for op, comp in zip(cmp_node.ops, cmp_node.comparators):
                lits = _literals(comp)
                if not lits:
                    continue
                kind = ("DENYLIST" if isinstance(op, (ast.NotEq, ast.NotIn))
                        or any(l.lower() in _NEGATIVE_HINT for l in lits)
                        else "LITERAL_COMPARE")
                sites.append({
                    "module": rel, "function": fn.name, "line": cmp_node.lineno,
                    "param": left.id, "kind": kind, "literals": lits,
                    "default": defaults.get(left.id),
                    "delegates_to_is_human": delegates,
                })
    return sites, delegates


def scan(root: Path):
    pkg = root / "driftcore"
    out = []
    for src in sorted(pkg.rglob("*.py")):
        if src.name == "__init__.py":
            continue
        rel = src.relative_to(root).as_posix()
        if rel.endswith("authority/human_identity.py"):
            continue        # the primitive itself owns the legacy denylist, by design
        sites, _ = scan_file(src, rel)
        out.extend(sites)
    return out


def key(s) -> str:
    return f"{s['module']}::{s['function']}::{s['param']}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--root", default=str(ROOT))
    args = ap.parse_args()

    root = Path(args.root).resolve()
    sites = scan(root)
    try:
        waived = json.loads(BASELINE.read_text()).get("waived", {})
    except (OSError, ValueError):
        waived = {}

    live = [s for s in sites if key(s) not in waived]

    print()
    print("  AUTHORITY SITES — is 'are you human?' decided by a word list?")
    print("  " + "-" * 66)

    if args.list:
        for s in sites:
            mark = "waived" if key(s) in waived else "LIVE"
            print(f"  [{mark:6}] {s['module']}:{s['line']} {s['function']}() "
                  f"{s['param']} {s['kind']} {s['literals']}")
        print()

    print(f"  sites found: {len(sites)}    waived: {len(sites) - len(live)}    "
          f"LIVE: {len(live)}")
    print()

    if not live:
        print("  RESULT: OK — no authorization decided by comparing a name to a")
        print("  literal. NOTE: delegating to is_human proves the site DELEGATES,")
        print("  not that it binds an action. media/policy.py delegated and still")
        print("  accepted an attestation issued for something else.")
        return 0

    for s in live:
        print(f"  {s['kind']}  {s['module']}:{s['line']}  {s['function']}()")
        print(f"      {s['param']} compared against {s['literals']}")
        if s["default"] is not None:
            print(f"      DEFAULT is {s['default']!r} — the no-argument call "
                  f"authorises itself")
        if not s["delegates_to_is_human"]:
            print(f"      this module never calls is_human, so it is frozen at the "
                  f"weakest identity mode")
        print()
    print("  RESULT: FAIL — an agent picking its own authorizer string only has to")
    print("  avoid the listed words. Delegate to human_identity.is_human with a")
    print("  BOUND action, or waive with a reason in authority_sites_baseline.json.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
