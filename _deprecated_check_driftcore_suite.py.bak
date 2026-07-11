"""
check_driftcore_suite.py — pytest entry point for DriftCore
===========================================================

Why this file exists
--------------------
DriftCore's test files (test_*.py) are standalone scripts. Each one runs
its checks at import time and is meant to be run in its own process:

    python test_memory_core.py

Several of them intentionally trip the global enforcement shutdown
(enforcement._SHUTDOWN_TRIGGERED). That flag is process-wide and sticky
BY DESIGN — a real tamper shutdown must not silently reset itself. The
problem only appears under `pytest`, which imports every test_*.py into a
single process during collection: the shutdown state set by one file then
leaks into the next, producing confusing errors like

    RuntimeError: System is in shutdown state. Cannot store memory.

that look like memory bugs but are really test-order bugs.

The fix
-------
We don't make pytest import the script files at all (see pytest.ini:
`python_files = check_*.py`). Instead, this runner launches each test_*.py
in its OWN subprocess — a fresh interpreter, exactly the isolation the
suite was built for. A suite passes if its process exits 0.

Result:
  * `python test_x.py`  still works, unchanged.
  * `pytest`            works, with each suite isolated.
  * No test file is modified, so nothing can be corrupted by reformatting.

Run either way:
    pytest
    python check_driftcore_suite.py
"""

import os
import sys
import glob
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
TIMEOUT_SECONDS = 600

# This runner and any other check_*.py are not themselves suites to run.
_SELF = os.path.basename(__file__)


def discover_suites():
    """All standalone test_*.py scripts in this directory, sorted."""
    files = sorted(
        os.path.basename(p)
        for p in glob.glob(os.path.join(HERE, "test_*.py"))
    )
    return files


def run_suite(test_file):
    """
    Run one test_*.py in a fresh subprocess.
    Returns (returncode, combined_output).
    """
    proc = subprocess.run(
        [sys.executable, test_file],
        cwd=HERE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=TIMEOUT_SECONDS,
    )
    return proc.returncode, proc.stdout


# ── pytest entry point ────────────────────────────────────────────
# Parametrized so each suite shows up as its own line in pytest output:
#   check_driftcore_suite.py::test_suite[test_memory_core.py] PASSED

try:
    import pytest

    @pytest.mark.parametrize("test_file", discover_suites())
    def test_suite(test_file):
        rc, output = run_suite(test_file)
        # On failure, surface the script's own ✅/❌ lines in the report.
        assert rc == 0, (
            f"\n{test_file} exited with code {rc} (ran in isolation).\n"
            f"--- captured output (tail) ---\n"
            + "\n".join(output.splitlines()[-25:])
        )
except ImportError:
    # pytest not installed — direct execution still works (see __main__).
    pass


# ── direct execution (no pytest needed) ───────────────────────────

def main():
    suites = discover_suites()
    if not suites:
        print("No test_*.py suites found.")
        return 1

    print(f"Running {len(suites)} DriftCore suites, each in its own process\n")
    failed = []
    for f in suites:
        try:
            rc, _ = run_suite(f)
        except subprocess.TimeoutExpired:
            rc = -1
            print(f"  TIMEOUT  {f}")
            failed.append(f)
            continue
        mark = "PASS" if rc == 0 else f"FAIL ({rc})"
        print(f"  {mark:<10} {f}")
        if rc != 0:
            failed.append(f)

    print("\n" + "=" * 60)
    print(f"{len(suites) - len(failed)}/{len(suites)} suites passed")
    if failed:
        print("Failed:")
        for f in failed:
            print(f"  • {f}")
    print("=" * 60)
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
