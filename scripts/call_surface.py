#!/usr/bin/env python3
"""
call_surface.py — "you changed X; here are all its callers" — and a ratchet.

WHY THIS EXISTS
---------------
§0f says enumerate the set before you act on it. It has now been violated twice in
this repository with the SAME trigger, and both times the shape was identical:

  1. `register_key` gained a mandatory keyword. The migration globbed `test_*.py`
     plus one known production file. `eval_harness.py` and `scripts/decision_lens.py`
     were neither and were missed. §0f records that the suite caught it and calls
     that "luck, not method."

  2. `_is_human` gained a mandatory keyword. The migration enumerated callers only
     inside the two files already being edited. Eleven test files broke. The suite
     caught it again.

A rule that has been read, written about, and violated by the same author in the
same session is not a rule problem. §0f is prose; prose does not enumerate.

WHAT IT DOES
------------
    python3 scripts/call_surface.py --symbol _is_human
        Every call site of that name, anywhere in the tree, INCLUDING through
        aliased imports (`from x import GrantAuthority as _GA` then `_GA(...)`).
        Run this BEFORE changing a signature, not after.

    python3 scripts/call_surface.py
        Ratchet. For every function defined in this repo that has a keyword-only
        parameter with NO default, find calls that omit it. Any hit is a FAIL.

The ratchet is a check on STATE, not on a diff. It needs no git and no knowledge of
what changed, and it flags a broken call site whether it was broken five minutes ago
or five months ago. That matters because both recorded incidents were caught by the
suite only where the broken line happened to execute; a call site the suite never
reaches raises `TypeError` in production instead.

Parsing is `ast`, not grep, deliberately. §0f's own closing warning is that a
line-oriented grep lies about wrapped calls — a survivor whose arguments continue on
the following line reads as clean.

WHAT IT CANNOT DO — read before trusting a green run
-----------------------------------------------------
* It resolves calls by NAME plus alias, not by type. Two unrelated functions sharing
  a name are conflated, and a call through a variable (`fn = obj.method; fn(...)`)
  or `getattr` is invisible. It is a net, not a proof.
* It only knows about required keyword-only parameters. A positional parameter added
  in the middle of a signature is a worse migration hazard and is NOT covered.
* `**kwargs` at a call site is treated as possibly supplying the argument, so a
  caller that forwards a dict is not flagged. That is deliberate — flagging it would
  produce noise nobody reads — and it is a hole.
* A green run says no call site omits a required keyword. It says nothing about
  whether the callers pass the RIGHT value.
"""

import argparse
import ast
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKIP = {"__pycache__", ".git", "node_modules", "_config"}


def _files():
    for p in sorted(ROOT.rglob("*.py")):
        if SKIP & set(p.parts):
            continue
        yield p


def _parse(p):
    try:
        return ast.parse(p.read_text(encoding="utf-8", errors="ignore"), str(p))
    except SyntaxError:
        return None


def definitions():
    """{name: {frozenset(required kwonly params), ...}} for every def in the repo.

    Keyed by NAME, and the value is a SET of distinct signatures. A name defined
    more than once with different requirements cannot be resolved by this tool —
    it matches calls by name, not by type — and must be reported as ambiguous
    rather than flagged.

    (Found on this tool's first run.) The first version keyed by name and unioned
    the requirements, so five different `restore` methods became one imaginary
    function requiring `restored_by` and `reason`. It flagged
    `recovery/manager.py`'s `restore(checkpoint_id, authorised_by)` — which has no
    keyword-only parameters at all — as a violation. A ratchet whose first output
    is wrong is a ratchet nobody reads.
    """
    out = {}
    for p in _files():
        tree = _parse(p)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = node.args
                req = frozenset(k.arg for k, d in zip(a.kwonlyargs, a.kw_defaults)
                                if d is None)
                out.setdefault(node.name, set()).add(req)
    return out


def module_level_defs():
    """Module-level functions only, with file and full signature.

    (2026-09-04) The AMBIGUOUS bucket exists because two methods can share a name
    on unrelated classes — `HumanIdentityVerifier.verify` vs
    `PermissionVerifier.verify` — and the AST cannot tell them apart. That is a
    real limit and it is why divergence is not gated in general.

    It does NOT apply to module-level functions. `_is_human` is defined at module
    scope in three modules that `test_human_identity.py` asserts share ONE
    implementation. Divergence there is not ambiguity; it is a migration that
    landed on some copies and not others, which is the exact mistake this file
    was written about and then failed to stop — it printed
    `_is_human() defined with differing signatures` and exited PASS. A sensor
    that notices and does not gate is the thing this project calls a counted
    sensor rather than an interlock.
    """
    out = {}
    for p in _files():
        tree = _parse(p)
        if tree is None:
            continue
        rel = str(p.relative_to(ROOT))
        for node in tree.body:                 # top level only, not ast.walk
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = node.args
                names = [x.arg for x in a.posonlyargs + a.args]
                kw = [k.arg + ("" if d is None else "=")
                      for k, d in zip(a.kwonlyargs, a.kw_defaults)]
                sig = f"({', '.join(names)}" + (f"; *, {', '.join(kw)}" if kw else "") + ")"
                out.setdefault(node.name, []).append((rel, node.lineno, sig))
    return out


def aliases_for(symbol):
    """Names `symbol` is called by, per file, following `import X as Y`."""
    per_file = {}
    for p in _files():
        tree = _parse(p)
        if tree is None:
            continue
        names = {symbol}
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for al in node.names:
                    if al.name.split(".")[-1] == symbol and al.asname:
                        names.add(al.asname)
        per_file[p] = names
    return per_file


def calls(symbol):
    """Every call site of `symbol`, following aliases. (path, line, has_kwargs, kws)"""
    found = []
    for p, names in aliases_for(symbol).items():
        tree = _parse(p)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            # A bare call `foo(...)` names the function. A method call
            # `obj.foo(...)` does NOT: the receiver's type is unknowable from the
            # AST, so the name alone cannot pick a definition.
            #
            # (2026-09-04) The ratchet flagged
            # `self._verifier.verify(att, action=...)` as missing
            # ['actuator_id','command'] — matching HumanIdentityVerifier.verify
            # against PermissionVerifier.verify by name. Two unrelated methods,
            # one name. Worse, it listed `verify` in the AMBIGUOUS bucket as
            # "UNCHECKED, not cleared" AND failed on it, which cannot both hold.
            # A method call is now marked so it can only be flagged when the name
            # has exactly one definition repo-wide.
            is_method = isinstance(f, ast.Attribute)
            name = (f.id if isinstance(f, ast.Name)
                    else f.attr if is_method else None)
            if name in names:
                kws = {k.arg for k in node.keywords if k.arg}
                star = any(k.arg is None for k in node.keywords)   # **kwargs
                found.append((p.relative_to(ROOT), node.lineno, star, kws,
                              is_method))
    return found


def _per_file_context():
    """(definitions in each file, and where each file imports a name from)."""
    local, defined_in = {}, {}
    for p in _files():
        tree = _parse(p)
        if tree is None:
            continue
        f = str(p.relative_to(ROOT))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = node.args
                req = frozenset(k.arg for k, d in zip(a.kwonlyargs, a.kw_defaults)
                                if d is None)
                local.setdefault(f, {})[node.name] = req
                defined_in.setdefault(node.name, {})[
                    f.replace("/", ".").removesuffix(".py")] = req

    src = {}
    for p in _files():
        tree = _parse(p)
        if tree is None:
            continue
        f = str(p.relative_to(ROOT))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                for al in node.names:
                    mods = defined_in.get(al.name, {})
                    if node.module in mods:
                        src[(f, al.asname or al.name)] = mods[node.module]
    return local, src


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--symbol", help="enumerate every call site of this name")
    args = ap.parse_args()

    if args.symbol:
        sites = calls(args.symbol)
        print(f"\n  CALL SURFACE of {args.symbol!r}")
        print("  " + "-" * 66)
        by_file = {}
        for path, line, _, kws, _m in sites:
            by_file.setdefault(str(path), []).append((line, sorted(kws)))
        for f in sorted(by_file):
            print(f"    {f}")
            for line, kws in sorted(by_file[f]):
                print(f"      :{line:<5} kwargs={kws or '-'}")
        print(f"\n  {len(sites)} call site(s) across {len(by_file)} file(s).")
        print("  Aliased imports followed. Calls through a variable or getattr are")
        print("  NOT followed — read the list, do not count it (§0f).")
        return 0

    # Resolve PER FILE, not globally. A global name→signature map made `_is_human`
    # ambiguous (five definitions), and the ambiguity rule then skipped it — so the
    # first version of this ratchet did not catch the very mistake it was built for.
    # Fixing the false positive had produced a false negative on the motivating
    # case. Resolution order for a call in file F:
    #   1. a definition of that name in F itself
    #   2. the definition in whichever repo module F imports it from
    #   3. otherwise ambiguous, and reported rather than flagged
    local_defs, import_src = _per_file_context()
    global_defs = definitions()
    violations, ambiguous = [], set()

    for sym, sigs in global_defs.items():
        if not any(sigs):
            continue
        for path, line, star, kws, is_method in calls(sym):
            f = str(path)
            needed = None
            if sym in local_defs.get(f, {}):
                needed = local_defs[f][sym]
            elif (f, sym) in import_src:
                needed = import_src[(f, sym)]
            elif len(sigs) == 1:
                needed = next(iter(sigs))
            # A method call resolves by name only when the name is unique in the
            # whole repo. Otherwise the receiver's type decides, and the AST does
            # not know it. Reporting such a call as a violation is the
            # false-positive that made this ratchet contradict its own AMBIGUOUS
            # bucket.
            if is_method and len(sigs) > 1:
                needed = None
            if needed is None:
                ambiguous.add((sym, tuple(tuple(sorted(x)) for x in sorted(sigs, key=sorted))))
                continue
            if star:
                continue                       # **kwargs may supply it
            missing = [n for n in sorted(needed) if n not in kws]
            if missing:
                violations.append((f, line, sym, missing))
    ambiguous = sorted((s, [list(x) for x in sg]) for s, sg in ambiguous)

    print("\n  CALL SURFACE — required keyword-only arguments are supplied")
    print("  " + "-" * 66)
    checkable = sum(1 for v in global_defs.values() if any(v))
    print(f"  functions with required keyword-only params : {checkable} checkable")
    print(f"  call sites omitting one                     : {len(violations)}")
    print(f"  AMBIGUOUS, not checked                      : {len(ambiguous)}")
    for sym, sigs in sorted(ambiguous):
        print(f"      {sym}() defined with differing signatures: {sigs}")
    if ambiguous:
        print("      ^ resolved by name, so these are UNCHECKED, not cleared.")

    # ── module-level divergence: GATED, not merely reported ──────────────────
    ACCEPTED_DIVERGENCE = {
        # name: a reason unique to that name. A shared reason names nothing and
        # is how a waiver list becomes a rubber stamp.
    }
    # Only PRODUCTION copies. Two test files each defining a local `_mk` helper
    # is normal and expected; gating on that produced 36 hits of which one was
    # real, which is how a checker teaches people to ignore it. The case that
    # matters is a helper duplicated across `driftcore/` modules that are meant
    # to share one implementation — which is exactly `_is_human`, and exactly
    # what `test_human_identity.py` asserts when it says the fix "cannot be
    # applied to two of three again".
    diverged = []
    for name, entries in sorted(module_level_defs().items()):
        prod = [e for e in entries if e[0].startswith("driftcore/")]
        if len(prod) < 2:
            continue
        if len({sg for _, _, sg in prod}) > 1 and name not in ACCEPTED_DIVERGENCE:
            diverged.append((name, prod))

    print(f"  module-level fns defined >1x with DIFFERING signatures : "
          f"{len(diverged)}")
    if diverged:
        print()
        for name, entries in diverged:
            print(f"    {name}() — a change landed on some copies and not others:")
            for rel, ln, sg in entries:
                print(f"      {rel}:{ln}  {name}{sg}")
        print()
        print("    Module-level scope, so the name resolves unambiguously — this is")
        print("    not the AMBIGUOUS case above. Migrate the rest, or add the name to")
        print("    ACCEPTED_DIVERGENCE with a reason unique to it.")
    if violations:
        print()
        for path, line, sym, missing in sorted(violations):
            print(f"    {path}:{line}  {sym}() missing {missing}")
        print()
        print("    Each of these raises TypeError when the line executes. If the")
        print("    suite does not reach it, it raises in production instead. Both")
        print("    §0f incidents were caught only where the broken line happened")
        print("    to run.")
    print()
    # (2026-09-04) This read `if violations` while the exit status read
    # `violations or diverged`, so a run could print PASS and exit 1. This file
    # already records fixing that same contradiction once, for the AMBIGUOUS
    # bucket. A printed verdict that disagrees with the exit code is worse than
    # either alone: a human reads PASS, CI reads 1, and they act differently on
    # one run.
    print(f"  RESULT: {'FAIL' if (violations or diverged) else 'PASS'}")
    return 1 if (violations or diverged) else 0


if __name__ == "__main__":
    sys.exit(main())
