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
    line="$(python3 "$f" 2>&1 | grep -iE '[0-9]+/[0-9]+ (tests?|checks?) passed|ALL [0-9]+ CHECKS? PASSED' | tail -1 || true)"
    nums="$(echo "$line" | grep -oE '[0-9]+/[0-9]+' | head -1 || true)"
    if [ -n "$nums" ]; then
        passed="${nums%%/*}"
        want="${nums##*/}"
    else
        # "ALL <n> CHECKS PASSED" form: no total reported, so passed == total == n
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
