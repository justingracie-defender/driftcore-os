#!/usr/bin/env bash
#
# count_tests.sh — single source of truth for the DriftCore test count.
#
# Runs every test_*.py file, reads the "<passed>/<total> tests passed"
# line each one prints, and reports the totals. Use this before quoting
# a test count in any doc — the number in the README should match what
# this prints, nothing else.
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
    line="$(python3 "$f" 2>&1 | grep -iE '[0-9]+/[0-9]+ tests? passed' | tail -1 || true)"
    nums="$(echo "$line" | grep -oE '[0-9]+/[0-9]+' | head -1 || true)"
    passed="${nums%%/*}"; passed="${passed:-0}"
    want="${nums##*/}";   want="${want:-0}"
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
