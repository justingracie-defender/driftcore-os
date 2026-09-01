#!/usr/bin/env python3
"""
doc_counts.py — no document quotes a bare test count.

WHY THIS EXISTS
---------------
`count_tests.sh` is the single source of truth for the test count. Nothing stopped a
document from quoting a number that disagreed with it, and four of them did: 2,228
in LAWZERO_BRIEF.md, 1400+ in DRIFTCORE_X_LAWZERO.md, "Current: 343 tests across 9
modules" in CONTRIBUTING.md, 2080 in REVIEWER_GUIDE.md — when the real figure was
4619. Each was correct when written. None carried the date it was written, so a
reader had no way to tell a current claim from a stale one.

The same session produced the other half of the failure: an instance wrote its OWN
counting command, got 3310, and told the human that the 3939 in his notes was not
reproducible. It was. The grep matched one of three summary formats the suite uses.
See §0g of `000_AI_START_HERE.md`.

WHAT THIS CHECKS, AND WHY THAT AND NOT MORE
--------------------------------------------
It does NOT verify the number. Verifying would mean running the suite on every doc
check — minutes of work to catch a class of error that citing the command prevents
outright. It checks the cheaper and more durable property:

  A markdown file that states a test count must cite `count_tests.sh` near it, or be
  listed as a historical record in the baseline below.

A cited command is re-derivable by the reader. A bare number is a claim about a
moment nobody wrote down.

WHAT THIS CANNOT DO — read before trusting a green run
-------------------------------------------------------
* It cannot tell whether a cited number is CURRENT, only whether the document points
  at the thing that would settle it. A doc citing the command and quoting 4619 will
  still say 4619 next year and still pass. That is a deliberate trade: the citation
  is what makes the staleness discoverable in one command.
* It is a regex over English. It will miss a count spelled out in words, and it will
  flag a version number that happens to sit next to the word "tests".
* It does NOT check per-module counts. "`test_preflight.py` (55 checks)" is a claim
  about one file and `count_tests.sh` cannot settle it. Those are reported as MODULE
  and left unchecked — an unjudged backlog, not an approval. Running each named file
  and comparing is the fix and nobody has done it.
* HISTORICAL is an exemption granted by path, not by reading. A file on that list can
  still carry a wrong current claim; nobody is checking those sentences.

Usage:
    python3 scripts/doc_counts.py           # check
    python3 scripts/doc_counts.py --list    # every count claim found, with verdict
"""

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CANONICAL = "count_tests.sh"

# A count claim: a number immediately qualified as tests/checks/test files.
CLAIM = re.compile(
    r"\b(\d[\d,]{1,7})\s*\+?\s*(tests?|checks?|test files?)\b", re.IGNORECASE)

# How far from the claim the citation may sit. A citation in a different section is
# not a citation of this sentence.
NEAR_LINES = 6

# A citation this early in a file reads as a disclaimer over the whole document.
HEADER_LINES = 12

# (self red-team, first run) The first version of this tool flagged 14 claims and was
# wrong about every one. They were PER-MODULE counts — "`test_preflight.py` (55
# checks)" — and the fix it demanded, "cite count_tests.sh", is wrong advice: that
# command reports the SUITE TOTAL and says nothing about one file. Two different
# claims about two different populations, and a detector that cannot tell them apart
# produces confident bad instructions.
#
# The tempting repair was to add all 14 files to HISTORICAL. That is the bulk-waive
# pattern this repo has documented as a recurring failure: it would have turned a
# detector defect into a permanent exemption and left the tool looking green.
#
# A claim is MODULE-SCOPED when a specific test file or module path sits next to it.
# Structural, not magnitude — "4619 tests" and "55 checks" differ in what they COUNT,
# not in how big they are.
#
# (second revision, same run) The first SCOPED pattern matched only `test_*.py` and
# `driftcore/...py` paths, and still mis-flagged six claims that name a BARE module
# filename — "(`breach_response.py`, 18 tests)". Same defect, narrower: a detector
# that recognises two spellings of "this is about one file" and not the third.
SCOPED = re.compile(r"[A-Za-z0-9_]+\.py")

# (third revision, found by mutation — not by reading it back) The module-scope
# exemption was silenced by ANY .py filename on the line. "~2,400 lines of code in
# main.py with 2,228 tests across the suite" passed: a stale suite-wide count in a
# document sent to an external reader, exempted because the sentence happened to
# mention a file. Evadable on purpose, and triggerable by accident, which is worse.
#
# Suite language OVERRIDES module scoping. A claim that says "across the suite" is
# about the suite no matter what else the sentence names.
SUITE_WORDS = re.compile(
    r"\b(suite|across|total|overall|repositor|repo|whole|entire)\w*\b", re.IGNORECASE)

# Files that RECORD what a past state was. Their numbers are supposed to be frozen;
# a changelog that updated itself would be lying about history. Exempt by path, and
# every entry needs its own reason — a shared reason names neither.
HISTORICAL = {
    "CHANGELOG.md":
        "a dated record of past releases; its figures describe those releases",
    "CHANGELOG_v3.5.md":
        "same, pinned to one version",
    "MANUS_HANDOFF.md":
        "a log of what was handed over when, including counts at handover time",
    "REVIEW_PHASE_B.md":
        "the report of one review phase; its counts are that phase's findings",
    "REVIEWER_GUIDE.md":
        "quotes a pre-merge local figure and says in the same sentence that it "
        "proves nothing about the merged repository — the staleness is the point",
}

SKIP_DIRS = {".git", "__pycache__", "node_modules", "_config"}


def docs():
    for p in sorted(ROOT.rglob("*.md")):
        if SKIP_DIRS & set(p.parts):
            continue
        yield p


def scan():
    findings = []
    for p in docs():
        rel = str(p.relative_to(ROOT))
        try:
            lines = p.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            # An unreadable doc is not "no claims found". Report it rather than
            # letting a decoding failure read as a pass.
            findings.append((rel, 0, "<unreadable>", "UNREADABLE"))
            continue
        for i, line in enumerate(lines):
            for m in CLAIM.finditer(line):
                lo = max(0, i - NEAR_LINES)
                hi = min(len(lines), i + NEAR_LINES + 1)
                # A file-level disclaimer is STRONGER than a per-line citation: it
                # covers every claim in the file, including ones added after it was
                # written. UPDATE_NOTES.md opens by saying it is a dated log and
                # naming the canonical command, then states a count 12 lines later —
                # correctly handled, and flagged anyway by the first version of this
                # check. Honouring the header is the fix. Growing HISTORICAL instead
                # would have been an exemption bought with a detector bug.
                header = any(CANONICAL in l for l in lines[:HEADER_LINES])
                cited = header or any(CANONICAL in l for l in lines[lo:hi])
                suite_lang = bool(SUITE_WORDS.search(line))
                scoped = (not suite_lang) and (
                    bool(SCOPED.search(line))
                    or (i and bool(SCOPED.search(lines[i - 1]))))
                if rel in HISTORICAL:
                    verdict = "HISTORICAL"
                elif scoped:
                    verdict = "MODULE"
                elif cited:
                    verdict = "CITED"
                else:
                    verdict = "BARE"
                findings.append((rel, i + 1, m.group(0), verdict))
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true",
                    help="show every count claim found, with its verdict")
    args = ap.parse_args()

    findings = scan()
    bare = [f for f in findings if f[3] == "BARE"]
    broken = [f for f in findings if f[3] == "UNREADABLE"]

    print()
    print("  DOC COUNTS — every stated test count cites the canonical command")
    print("  " + "-" * 68)

    if args.list:
        for rel, ln, text, verdict in findings:
            print(f"    [{verdict:10s}] {rel}:{ln}  {text}")
        print()

    counts = {v: sum(1 for f in findings if f[3] == v)
              for v in ("CITED", "HISTORICAL", "MODULE", "BARE", "UNREADABLE")}
    print(f"  cites {CANONICAL}: {counts['CITED']}")
    print(f"  historical record:   {counts['HISTORICAL']}   <- frozen on purpose")
    print(f"  module-scoped:       {counts['MODULE']}   <- NOT CHECKED, see below")
    print(f"  bare suite claims:   {counts['BARE']}")

    if broken:
        print()
        for rel, _, _, _ in broken:
            print(f"  UNREADABLE: {rel} — refusing to report it as having no claims.")

    if bare:
        print()
        print(f"  FAIL - {len(bare)} count claim(s) quote a number with no way to")
        print(f"    re-derive it. Each was true when written and none carries the")
        print(f"    date it was written. Cite `bash scripts/{CANONICAL}` within")
        print(f"    {NEAR_LINES} lines, or add the file to HISTORICAL with its own reason.")
        for rel, ln, text, _ in bare:
            print(f"      {rel}:{ln}  {text}")

    if counts["MODULE"]:
        print()
        print(f"  {counts['MODULE']} per-module count(s) are UNCHECKED, not approved.")
        print("    A claim like \"`test_preflight.py` (55 checks)\" is about one file, so")
        print(f"    `{CANONICAL}` cannot settle it — running that file can. Nobody is")
        print("    doing that yet. Named here so the gap is visible rather than absent.")

    print()
    print(f"  RESULT: {'FAIL' if (bare or broken) else 'PASS'}")
    return 1 if (bare or broken) else 0


if __name__ == "__main__":
    sys.exit(main())
