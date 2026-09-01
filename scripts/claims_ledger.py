#!/usr/bin/env python3
"""
claims_ledger.py — every safety claim in a CRITICAL docstring needs a test that
could have falsified it.

WHY THIS EXISTS
---------------
`untested_modules.py` finds modules no test imports. The gap it cannot see is a
module WITH tests whose tests never touch the thing the module claims to do. That
gap is not hypothetical; it is where most of this repo's real defects have lived:

  * `test_hardware_safety.py` had 27 passing tests. Every one fired a FIRE event —
    the TOP of the response ladder, where graduation cannot be observed because
    there is nothing above it to wrongly trigger. Meanwhile `ResponseLevel`'s own
    docstring said graduated responses exist to PREVENT unnecessary shutdowns, and a
    THERMAL throttle was firing POWER_CUT and ISOLATE. 27 green tests, headline
    claim never examined.
  * `_implementation_id` opened with "A stable identity for the CODE". It was not
    stable: an actuator writing to its own closed-over log rewrote its identity on
    first use.
  * `_stable_value` said "anything else is rendered by TYPE" while rendering
    containers by content.
  * `hardware_isolation` said it "maps to physical relay/interlock signals". There
    was no relay, and `full_isolation()` returned FULLY_ISOLATED on a live machine.
  * `trust_model`'s constants encoded "one safety violation quarantines" exactly
    (0.5 - 0.30 == 0.20) and the comparison was strict, so the one case the
    constants were tuned for was the one case that failed.

In nearly every one, THE DOCSTRING ALREADY CONTAINED THE SPECIFICATION THE CODE
VIOLATED. The prose was right. The code disagreed with it. Nothing compared the two.

So this tool compares the two. It does not read code and it does not judge whether a
test is good — neither is mechanisable. It does something narrower and checkable:
it finds sentences that ASSERT A SAFETY PROPERTY, and requires each to be either
paired with a test that names it, or waived on the record with a reason.

HOW TO USE IT
-------------
Tag a claim in the docstring:

    CLAIM ladder-descends: a commanded level implies every LESSER action and never
    a greater one.

Name it from the test that could falsify it:

    # CLAIMS: driftcore/hardware/hardware_safety.py:ladder-descends

Anything the detector flags that is NOT tagged appears as UNPAIRED and fails.
Waive with a reason in claims_ledger_baseline.json when a sentence is prose rather
than a property.

WHAT THIS CANNOT DO — read before trusting a green run
------------------------------------------------------
* It cannot tell whether the paired test is any good. A test named against a claim
  that asserts nothing passes this check. This finds claims with NO test; it does
  not find claims with a WEAK test. `test_hardware_safety.py` at 27 green tests
  would have passed this tool if someone had tagged it, and it was still blind.
* The detector is a keyword heuristic over English. It misses claims phrased without
  modal words, and flags emphatic prose that asserts nothing. Its false positives
  are the price of its false negatives being visible at all.
* A claim the author never wrote down is invisible here, exactly as it is to a
  reader. This raises the floor for stated claims; it cannot find unstated ones.

Usage:
    python3 scripts/claims_ledger.py              # check against the baseline
    python3 scripts/claims_ledger.py --list       # every detected claim
    python3 scripts/claims_ledger.py --unpaired   # only what needs attention
    python3 scripts/claims_ledger.py --root DIR   # check a different tree
"""

from __future__ import annotations

import argparse
import ast
import json
import pathlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = Path(__file__).resolve().parent / "claims_ledger_baseline.json"

# (red-team, Grok 2026-08-20 — CONFIRMED, and the sharpest finding against this
# tool.) This was 8, with the comment "deliberately low: a genuine batch of
# near-identical prose in one module is plausible up to a handful". The author's own
# largest reason-group was SEVEN. The threshold had been set one above his own
# behaviour and given a principled-sounding justification — a detector calibrated to
# exempt its author.
#
# There is no correct number. Two waivers sharing a reason were not judged
# individually; that is what the words mean. The threshold is 1 and the field for
# batches is `acknowledged`, which does not claim anyone read them.
BLANKET_THRESHOLD = 1

# Same subsystem tiering as untested_modules.py. Duplicated deliberately rather than
# imported: these two scripts must stay runnable independently of each other, and the
# list is short enough that divergence is visible. If it grows, share it.
_CRITICAL = {"safety", "hardware", "kernel", "governance", "verification",
             "network", "recovery", "memory"}


def _is_critical(rel: str) -> bool:
    return bool(set(pathlib.PurePosixPath(rel).parts) & _CRITICAL)


# ── what counts as a claim ────────────────────────────────────────────────────
# Words that turn a sentence from description into an assertion about behaviour.
# Tuned against the six real defects above: each of their docstrings matches.
_ASSERTS = re.compile(
    r"\b(must not|must|never|cannot|can not|always|refuses?|refused|rejects?|"
    r"guarantees?|ensures?|is not permitted|not allowed|fails closed|fail closed|"
    r"only ever|only if|only when|shall|will not|does not|is forbidden)\b",
    re.IGNORECASE)

# Sentences that TALK ABOUT a past defect or an acknowledged limit are not claims
# about current behaviour. Without this the tool drowns in its own repo's history —
# every "an earlier version did not" would demand a test.
_NOT_A_CLAIM = re.compile(
    r"\b(used to|previously|an earlier version|earlier version|the first version|"
    r"reproduced|red-team|honest limit|this cannot|cannot be claimed|"
    r"must not be claimed|not claimed|deliberately not|does not pretend|"
    r"what this does not do|out of scope|verified:|e\.g\.|for example)\b",
    re.IGNORECASE)

# Wrapped text is the norm in this repo's docstrings, so a claim continues across
# lines until a blank line or the next CLAIM. An earlier version anchored on `$` and
# silently truncated every claim at its first line break — a ledger that records half
# a specification is worse than one that records none, because it reads as complete.
_CLAIM_TAG = re.compile(
    r"^[ \t]*CLAIM[ \t]+([a-z0-9][a-z0-9\-]*)[ \t]*:[ \t]*"
    r"((?:.+)(?:\n(?![ \t]*(?:CLAIM[ \t]|\s*$)).+)*)",
    re.IGNORECASE | re.MULTILINE)
_CLAIMS_REF = re.compile(r"CLAIMS:\s*([^\s#]+)")


def _sentences(text: str):
    """Split a docstring into candidate sentences, keeping it dumb on purpose."""
    flat = re.sub(r"\s+", " ", text).strip()
    for raw in re.split(r"(?<=[.!?])\s+", flat):
        s = raw.strip()
        if 20 <= len(s) <= 400:
            yield s


def _docstrings(path: Path):
    """(qualname, docstring) for module, classes and functions."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return
    mod = ast.get_docstring(tree)
    if mod:
        yield "<module>", mod
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            doc = ast.get_docstring(node)
            if doc:
                yield node.name, doc


# Sections that are, by construction, NOT claims about current behaviour: a record of
# what a defect WAS, or a statement of what the module does not do. Keyword matching
# could not keep up with the phrasings ("The docstring said X; the constructor was
# the weakening mechanism", "It does not authenticate senders"), and every miss
# demanded a test for a sentence describing a bug that no longer exists. The section
# is the right unit — an author writing under a DEFECTS FOUND header is narrating,
# not specifying. (Found by running this tool against its own repo: the five cluster
# rewrites raised the backlog by 24, and most of the 24 were history.)
_NARRATIVE_HEADER = re.compile(
    r"^\s*(DEFECTS? FOUND|HONEST LIMITS?|WHAT THIS DOES NOT DO|"
    r"WHAT IS STILL NOT CLOSED|WHAT THIS CANNOT DO|NOT CLOSED|WHY THIS EXISTS|"
    r"HOW TO USE IT|USAGE|EARLIER CONTEXT|HISTORY|"
    # Sections that describe the FAILURE being closed, or why OTHER modules miss
    # it, are history about defects — not assertions about this module's behaviour.
    r"THE FAILURE THIS CLOSES|WHY THE EXISTING MODULES MISS)\b", re.IGNORECASE)
# A new ALL-CAPS-ish header ends a narrative section.
_ANY_HEADER = re.compile(r"^\s*[A-Z][A-Z ,/&'\-]{7,}\s*$")


def _claim_region(doc: str) -> str:
    """The part of a docstring that specifies, with narrative sections removed."""
    kept, narrating = [], False
    for line in doc.splitlines():
        if _NARRATIVE_HEADER.match(line):
            narrating = True
            continue
        if narrating:
            if _ANY_HEADER.match(line) and not _NARRATIVE_HEADER.match(line):
                narrating = False
            else:
                continue
        kept.append(line)
    return "\n".join(kept)


def _summary(doc: str) -> str:
    """The first sentence of a docstring — the specification, by convention.

    This is a RULE rather than a heuristic, and it is the tool's primary signal.
    Measured against five known real defects, the keyword detector below caught two.
    All three misses were summary lines phrased as plain declaratives with no modal
    word to match on:

        "A stable identity for the CODE registered behind an actuator."
        "A representation that is identical across processes."
        "In real deployment: maps to physical relay/interlock signals."

    Every one of those was false about the running code. A summary line is where an
    author states what a thing IS, so it is where the strongest claims live and where
    keyword matching is least likely to find them.
    """
    flat = re.sub(r"\s+", " ", doc).strip()
    first = re.split(r"(?<=[.!?])\s+", flat)[0].strip()
    return first if 15 <= len(first) <= 300 else ""


def scan_claims(pkg: Path, root: Path):
    """Every tagged claim, plus untagged claims by summary line and by assertion."""
    tagged, untagged = {}, []
    for src in sorted(pkg.rglob("*.py")):
        rel = src.relative_to(root).as_posix()
        if not _is_critical(rel) or src.name == "__init__.py":
            continue
        for qual, doc in _docstrings(src):
            for slug, text in _CLAIM_TAG.findall(doc):
                tagged[f"{rel}:{slug.lower()}"] = {
                    "module": rel, "slug": slug.lower(), "where": qual,
                    "text": re.sub(r"\s+", " ", text).strip()}
            # Remove tagged lines before hunting untagged claims, so a tagged claim
            # is not also reported as untagged.
            stripped = _claim_region(_CLAIM_TAG.sub("", doc)).strip()
            seen = set()
            summary = _summary(stripped)
            if summary and not _NOT_A_CLAIM.search(summary):
                seen.add(summary)
                untagged.append({"module": rel, "where": qual, "text": summary,
                                 "kind": "summary"})
            for sent in _sentences(stripped):
                if sent in seen:
                    continue
                if _ASSERTS.search(sent) and not _NOT_A_CLAIM.search(sent):
                    untagged.append({"module": rel, "where": qual, "text": sent,
                                     "kind": "assertion"})
    return tagged, untagged


def scan_references(root: Path):
    """Claim ids named by test files."""
    refs = {}
    for p in sorted(root.rglob("test_*.py")):
        try:
            body = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for cid in _CLAIMS_REF.findall(body):
            refs.setdefault(cid.lower().rstrip(",;"), set()).add(
                p.relative_to(root).as_posix())
    return refs


def _key(claim: dict) -> str:
    """A stable waiver key: module, location, and a digest of the text.

    Hashing the text rather than storing it means EDITING a waived claim un-waives
    it. That is the point — a waiver is a judgement about one specific sentence, and
    rewriting the sentence invalidates the judgement.
    """
    import hashlib
    h = hashlib.sha256(claim["text"].encode("utf-8")).hexdigest()[:12]
    return f"{claim['module']}::{claim['where']}::{h}"


CEILING_ACTION = "claims_ledger_raise_ceiling"
WAIVER_ACTION = "claims_ledger_sign_waiver"


def _signed_by_human(record, *, action: str) -> str:
    """The principal behind a signed record, or "" if there isn't one.

    (red-team 2026-08-23.) `reviewer` was a free string: writing
    `"reviewer": "justin"` made a waiver count as HUMAN-SIGNED. That is the
    word-list authorisation this repo has now found in six modules, sitting in the
    file that governs the module which fixed it. A signature is an attestation
    verified against a registered principal, or it is a claim about a signature.
    """
    if not isinstance(record, dict):
        return ""
    att = record.get("attestation")
    if not isinstance(att, dict):
        return ""
    try:
        from driftcore.authority.human_identity import (
            HumanAttestation, is_human)
        a = HumanAttestation(
            principal=str(att["principal"]), action=str(att["action"]),
            issued_at=float(att["issued_at"]), expires_at=float(att["expires_at"]),
            nonce=str(att["nonce"]), sig=str(att["sig"]))
    except Exception:
        return ""
    # KNOWN DEFECT, and the gate is fail-closed because of it. (2026-08-23.)
    # `is_human` on an attestation BURNS its single-use nonce — correct for
    # authorising an action, wrong for verifying a standing authorisation held in a
    # file. Verified: the first check on a stored attestation returns the principal,
    # every check after it returns "" because the nonce is spent. So a signature
    # written into this baseline would authorise exactly one run of the tool and then
    # start failing, which is worse than not accepting signatures at all.
    #
    # A stored attestation is a CERTIFICATE, not a token: it needs repeatable
    # verification plus expiry and revocation, and `human_identity` has no
    # non-consuming verify path. Adding one touches a primitive 19 modules depend on,
    # and is not a change to make at the end of a long session.
    #
    # Until that exists this returns "" always, so NOTHING is treated as signed and
    # no ceiling raise is authorised. That is the safe direction and it is a real
    # limitation, not a placeholder that happens to work.
    return ""


def load_baseline():
    if not BASELINE.exists():
        return {"waived": {}}
    try:
        return json.loads(BASELINE.read_text())
    except (OSError, ValueError):
        # A damaged governance file must not read as "nothing was waived", because
        # that direction silently PASSES things. Fail loudly instead.
        print("  claims_ledger: baseline is unreadable — refusing to guess.")
        raise SystemExit(2)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--unpaired", action="store_true")
    ap.add_argument("--root", default=str(ROOT))
    ap.add_argument("--require-human-reviewer", action="store_true",
                    help="fail when any waiver's reviewer of record is the model")
    args = ap.parse_args()
    require_human_reviewer = args.require_human_reviewer

    root = Path(args.root).resolve()
    pkg = root / "driftcore"
    if not pkg.is_dir():
        print(f"  no driftcore package under {root}")
        return 2

    tagged, untagged = scan_claims(pkg, root)
    refs = scan_references(root)
    _base = load_baseline()
    waived = _base.get("waived", {})
    # ACKNOWLEDGED is not WAIVED. (cold pass 2026-08-20.) The baseline used one field
    # for two different acts: "I read this and it needs no test" (a judgement) and
    # "this is backlog prose nobody has looked at" (a count). Conflating them is what
    # made a bulk operation feel acceptable — the author was not judging 41 things, he
    # was acknowledging 41 things, and the file had no word for it.
    #
    # Both suppress the untagged count. Only `waived` claims to have been read, and
    # only `waived` is subject to blanket detection. `acknowledged` is honest about
    # being unjudged and is bounded by the ceiling, which only moves down.
    acknowledged = _base.get("acknowledged", {})
    # (red-team 2026-08-23.) `acknowledged` used to suppress the untagged count
    # exactly as `waived` did — so bulk-acknowledging was bulk-waiving with a nicer
    # word, which is precisely what happened to 41 claims on 2026-08-20. If a bucket
    # discharges the debt it is a permission, whatever it is called.
    #
    # Acknowledged is now COUNTED. The ceiling measures unreviewed governance
    # material, and unjudged prose is unreviewed governance material by definition.
    # Only a HUMAN-SIGNED waiver suppresses.
    signed_waivers = {k: v for k, v in waived.items()
                      if _signed_by_human(v, action=WAIVER_ACTION)}
    suppressed = dict(signed_waivers)

    unpaired = {cid: c for cid, c in tagged.items() if cid not in refs}
    loose = [u for u in untagged if _key(u) not in suppressed]
    base = load_baseline()
    ceiling = base.get("untagged_ceiling")

    print()
    print("  CLAIMS LEDGER — stated safety properties vs tests that could break them")
    print("  " + "-" * 68)

    if args.list:
        for cid, c in sorted(tagged.items()):
            who = ", ".join(sorted(refs.get(cid, []))) or "— UNPAIRED —"
            print(f"  {cid}\n      {c['text'][:100]}\n      tested by: {who}")
        print()

    paired = len(tagged) - len(unpaired)
    print(f"  tagged claims:      {len(tagged)}")
    print(f"  paired with a test: {paired}")
    print(f"  UNPAIRED:           {len(unpaired)}")
    print(f"  untagged claims in CRITICAL docstrings: {len(loose)}"
          f"  (ceiling {ceiling if ceiling is not None else 'unset'})")
    _signed = sum(1 for v in waived.values()
                  if isinstance(v, dict) and v.get("reviewer"))
    print(f"  waived, HUMAN-SIGNED: {_signed}")
    print(f"  waived, awaiting a human: {len(waived) - _signed}")
    print(f"  acknowledged, UNJUDGED: {len(acknowledged)}"
          f"   <- a backlog, not a decision")
    print()

    failed = False

    # FAILURE 1 — a promise nothing keeps. Someone wrote CLAIM and no test named it.
    if unpaired:
        failed = True
        print("  FAIL - tagged claims that no test names:")
        for cid, c in sorted(unpaired.items()):
            print(f"    {cid}  ({c['where']})")
            print(f"        {c['text'][:96]}")
        print("    A claim in a docstring is a specification. Unpaired, it is a")
        print("    specification nothing checks — which is how a module ends up")
        print("    green while contradicting its own first paragraph.")
        print()

    # FAILURE 2 — the backlog GREW. The standing backlog is deliberately not a
    # failure: 1310 claims cannot be paired in one sitting, and a check that can only
    # fail is a check that gets switched off (the same reasoning that made the
    # preflight human-gate check policy-driven rather than absolute). What must never
    # happen quietly is ADDING a new unchecked safety claim, so the ceiling ratchets.
    if ceiling is not None and len(loose) > ceiling:
        failed = True
        print(f"  FAIL - untagged claims rose from {ceiling} to {len(loose)}.")
        print("    New safety prose was written that no test names. Either tag and")
        print("    pair it, or waive it with a reason. The ceiling only moves down.")
        print()
    # Raising the ceiling is not configuration. It increases the amount of unjudged
    # material the system tolerates, which is an authority-expanding operation and the
    # one edit that defeats every other check here. Verified: 1309 -> 99999 was
    # accepted in silence.
    _prev = _base.get("previous_ceiling")
    if ceiling is not None and isinstance(_prev, int) and ceiling > _prev:
        who = _signed_by_human(_base.get("ceiling_raise"), action=CEILING_ACTION)
        if not who:
            failed = True
            print(f"  FAIL - the ceiling rose from {_prev} to {ceiling} with no "
                  f"signed authorisation.")
            print("    Raising it increases the unjudged surface the system will")
            print("    tolerate. That is an authority-expanding operation and needs")
            print("    a `ceiling_raise` attestation from a registered human — the")
            print("    reason does not matter, the direction does.")
            print("    NOTE: signature verification is currently fail-closed. See")
            print("    _signed_by_human — a stored attestation cannot yet be checked")
            print("    without consuming it, so no raise can be authorised at all.")
            print()
        else:
            print(f"  ceiling raised {_prev} -> {ceiling}, authorised by {who!r}")
            print()
    elif ceiling is not None and len(loose) < ceiling:
        print(f"  Backlog fell {ceiling} -> {len(loose)}. Lower the ceiling in")
        print("  claims_ledger_baseline.json so the gain cannot be given back.")
        print()

    # ── blanket-waive detection ───────────────────────────────────────────────
    # (cold pass 2026-08-20.) A bulk waive leaves a signature: N entries sharing one
    # reason string, added by one reviewer. The author of this tool did it three
    # times in a day — 57, then 106, then 58 items, when between two and seven were
    # actually new — always while moving fast toward a deliverable. Each was caught
    # by reading the output, which is not a control. This is.
    #
    # Waiving is a judgement about ONE sentence. Identical reasoning across dozens of
    # them means the judgement was made about the batch, and a batch judgement on a
    # governance file is how a waiver list stops meaning anything.
    by_reason = {}
    for k, v in waived.items():
        if isinstance(v, dict) and v.get("reason"):
            by_reason.setdefault((v.get("reason"), v.get("reviewer")), []).append(k)
    blanket = {kv: ks for kv, ks in by_reason.items()
               if len(ks) > BLANKET_THRESHOLD}
    # A waiver nobody with authority has signed is a proposal, not a judgement.
    unsigned = {k: v for k, v in waived.items()
                if isinstance(v, dict) and not v.get("reviewer")}
    if blanket:
        failed = True
        print(f"  FAIL - {len(blanket)} reason(s) reused across multiple claims.")
        for (reason, reviewer), keys in sorted(blanket.items(),
                                               key=lambda x: -len(x[1])):
            print(f"    {len(keys)} claims, reviewer {reviewer!r}")
            print(f"        \"{(reason or '')[:100]}\"")
        print("    A waiver is a judgement about one sentence. If the same reason")
        print("    fits two claims, it is naming neither of them. There is no")
        print("    threshold here on purpose — the previous one was set to 8 while")
        print("    every real group was 5 to 7, which is what a number invites.")
        print()
        print("    RESOLVING THIS IS A HUMAN TASK, and deliberately not an easy one.")
        print("    Raising BLANKET_THRESHOLD is laundering. Generating individual")
        print("    reasons from a template is a blanket waive with extra steps. The")
        print("    only real fix is a person reading each claim and writing why it")
        print("    needs no test — or tagging and pairing it instead.")
        print()

    if unsigned:
        print(f"  {len(unsigned)} waiver(s) AWAITING HUMAN. Drafted by the model that")
        print("  wrote the code being waived; no human has signed them. They suppress")
        print("  the untagged count and they do not claim to have been judged.")
        for k, v in sorted(unsigned.items())[:6]:
            print(f"    {k.split('::')[0]}  (proposed_by {v.get('proposed_by','?')})")
        if len(unsigned) > 6:
            print(f"    ... and {len(unsigned) - 6} more")
        print()

    # ── reviewer of record ────────────────────────────────────────────────────
    # (red-team, Grok 2026-08-20.) Every waiver in this repo's baseline was reviewed
    # by the model whose prose it exempts. That is the intent ledger's own failure —
    # the caller declaring what its action does — one layer up, in the file that
    # governs the ledger. The model may PROPOSE a waiver. It should not be the
    # reviewer of record for the modules implementing the human gate.
    #
    # Printed unconditionally, and fails only when a deployment says it requires
    # human review — the same policy shape as the preflight checks, for the same
    # reason: a check that fails every development tree gets switched off.
    self_reviewed = [k for k, v in waived.items()
                     if str((v or {}).get("reviewer", "")).lower().startswith("claude")]
    if waived:
        print(f"  reviewer of record: {len(waived) - len(self_reviewed)} human, "
              f"{len(self_reviewed)} self-reviewed by the model")
        if self_reviewed and require_human_reviewer:
            failed = True
            print(f"  FAIL - {len(self_reviewed)} waiver(s) reviewed by the model "
                  f"whose prose they exempt.")
            print("    A model proposing a waiver is fine. A model being the final")
            print("    judge of which of its own sentences need no test is the")
            print("    caller declaring its own effects, in the governance file.")
        elif self_reviewed:
            print("    (not failing: no human-review policy declared. Pass")
            print("     --require-human-reviewer once a person has signed these off.)")
        print()

    # ── the same sentence, judged two ways ────────────────────────────────────
    # Keys are module::where::hash, so a sentence appearing in five modules is five
    # judgements. That is deliberate — prose can be load-bearing in one module and
    # incidental in another — but it means an identical sentence can be waived here
    # and unjudged there, and nobody notices. Reported rather than resolved.
    _by_text = {}
    for k, v in waived.items():
        _by_text.setdefault((v or {}).get("text", "")[:80], {"w": [], "a": []})["w"].append(k)
    for k, v in acknowledged.items():
        _by_text.setdefault((v or {}).get("text", "")[:80], {"w": [], "a": []})["a"].append(k)
    split = {t: g for t, g in _by_text.items() if g["w"] and g["a"]}
    if split:
        print(f"  {len(split)} sentence(s) waived in one module and unjudged in "
              f"another:")
        for t, g in list(split.items())[:5]:
            print(f'    "{t[:66]}"')
            print(f"        judged in {len(g['w'])}, still backlog in {len(g['a'])}")
        print("    Judgement is keyed by SITE, not by text — the same words can be")
        print("    load-bearing in one module and incidental in another. But if you")
        print("    judged the sentence rather than the site, these should agree.")
        print()

    if args.unpaired:
        for u in loose:
            print(f"    [{u['kind']:9}] {u['module']} ({u['where']})")
            print(f"        {u['text'][:96]}")
        print()

    if failed:
        print("  RESULT: FAIL")
        return 1
    print("  RESULT: OK — every tagged claim is named by a test, and no new")
    print("  unchecked claim was added.")
    if acknowledged:
        print(f"  {len(acknowledged)} claim(s) are ACKNOWLEDGED, not judged. Nobody has")
        print("  read them and decided they need no test. That is a standing debt,")
        print("  visible on purpose — moving one to `waived` requires reading it.")
    print("  What this does NOT prove: that those tests are any good. A claim")
    print("  paired to a weak test passes here. test_hardware_safety.py was green")
    print("  at 27 tests while blind to the ladder it was written to cover.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
