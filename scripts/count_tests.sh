#!/usr/bin/env bash
#
# count_tests.sh — single source of truth for the DriftCore test count.
#
# Runs every test_*.py file, reads the pass-summary line each one prints,
# and reports the totals. Use this before quoting a test count in any doc —
# the number in the README should match what this prints, nothing else.
#
# Two summary formats are accepted (the suite uses both, historically):
#   * "<passed>/<total> tests passed"  /  "<passed>/<total> checks passed"
#   * "ALL <n> CHECKS PASSED"          (no total; passed == total == n)
# A file that reports neither, or reports passed < total, counts as failing.
#
# Usage:
#   bash scripts/count_tests.sh
#
set -euo pipefail
cd "$(dirname "$0")/.."

total=0
files=0
fail=0

for f in test_*.py; do
    [ -e "$f" ] || continue
    files=$((files + 1))
    # (red-team) The exit code used to be discarded: python3 was piped straight into
    # grep, so a file that printed "ALL 50 CHECKS PASSED", then hit an assertion and
    # died, was counted as 50 passing and reported nothing. A crashed test file was
    # silently indistinguishable from a passing one — in the gate every claim about
    # this repository rests on. Capture the output and the status separately.
    # `set -euo pipefail` is active, so a plain assignment from a failing
    # command aborts the whole script. The || branch keeps the loop alive
    # so the crash can be REPORTED rather than silently ending the run.
    # (red-team, ChatGPT) A test file that HANGS used to stall the gate forever, so
    # "the suite has not finished" was indistinguishable from "the suite is still
    # working". A bounded timeout makes a hang a FAILURE (timeout exits 124, which the
    # non-zero branch below reports as CRASHED) instead of an indefinite wait.
    out="$(timeout "${PER_TEST_TIMEOUT:-180}" python3 "$f" 2>&1)" && rc=0 || rc=$?
    line="$(printf '%s\n' "$out" | grep -iE '[0-9]+/[0-9]+ (tests?|checks?) passed|ALL [0-9]+ CHECKS? PASSED' | tail -1 || true)"
    if [ "$rc" -ne 0 ]; then
        if [ "$rc" -eq 124 ]; then
            printf '  %-28s TIMED OUT (>%ss) after: %s\n' "$f" "${PER_TEST_TIMEOUT:-180}" "${line:-no summary}"
        else
            printf '  %-28s CRASHED (exit %s) after: %s\n' "$f" "$rc" "${line:-no summary}"
        fi
        printf '      %s\n' "$(printf '%s\n' "$out" | tail -1)"
        fail=$((fail + 1))
        continue
    fi
    nums="$(echo "$line" | grep -oE '[0-9]+/[0-9]+' | head -1 || true)"
    if [ -n "$nums" ]; then
        passed="${nums%%/*}"
        want="${nums##*/}"
    else
        n="$(echo "$line" | grep -oE '[0-9]+' | head -1 || true)"
        passed="$n"; want="$n"
    fi
    passed="${passed:-0}"; want="${want:-0}"
    printf '  %-28s %s\n' "$f" "${line:-NO SUMMARY LINE}"
    total=$((total + passed))
    if [ "$passed" != "$want" ] || [ -z "$line" ]; then
        fail=$((fail + 1))
    fi
done

echo "------------------------------------------------------------"
echo "  ${total} tests passing across ${files} test files"
if [ "$fail" -ne 0 ]; then
    echo "  WARNING: ${fail} file(s) did not report all-passing"
    exit 1
fi
