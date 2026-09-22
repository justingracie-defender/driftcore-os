# SPDX-License-Identifier: Apache-2.0
"""Remove each new nonce protection in a disposable copy and require detection."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    ("append_cleanup_clock", "driftcore/verification/nonce_store.py",
     "        if now is None:\n            now = self._check_clock()",
     "        if now is None:\n            now = self._time()",
     "test_nonce_clock_paths.AppendLogClockTests.test_len_cleanup_blocks_signed_grant_replay"),
    ("sqlite_cleanup_clock", "driftcore/verification/nonce_store_sqlite.py",
     '        self._db.execute("BEGIN IMMEDIATE")\n        try:\n            now = self._check_clock()',
     '        self._db.execute("BEGIN IMMEDIATE")\n        try:\n            now = self._time()',
     "test_nonce_clock_paths.SqliteClockTests.test_stats_cleanup_blocks_signed_grant_replay"),
    ("finite_clock", "driftcore/verification/nonce_store.py",
     "    if not math.isfinite(value):", "    if False:",
     "test_nonce_clock_sequences.SqliteFreshTests.test_infinite_clock_cannot_delete_spent_records"),
    ("finite_window", "driftcore/verification/nonce_store.py",
     '    retention_seconds = _finite_number(retention_seconds, "retention_seconds")',
     '    retention_seconds = retention_seconds',
     "test_nonce_clock_sequences.SqliteFreshTests.test_nan_retention_is_refused"),
    ("checked_membership_sample", "driftcore/verification/nonce_store_sqlite.py",
     '                cutoff = now - self.retention_seconds\n                row = self._db.execute(',
     '                cutoff = self._time() - self.retention_seconds\n                row = self._db.execute(',
     "test_nonce_clock_paths.SqliteClockTests.test_membership_uses_the_checked_clock_sample"),
]


def main():
    out = Path(sys.argv[1]).resolve()
    out.mkdir(parents=True, exist_ok=False)
    results = []
    for name, relative, before, after, test in CASES:
        with tempfile.TemporaryDirectory(prefix="nonce-clock-control-") as temporary:
            tree = Path(temporary) / "source"
            def ignored(directory, names):
                blocked = set(shutil.ignore_patterns("__pycache__", "*.pyc", "logs", "*.zip", ".git")(directory, names))
                if Path(directory) == ROOT:
                    blocked.add("verification")
                return blocked
            shutil.copytree(ROOT, tree, ignore=ignored)
            target = tree / relative
            original = target.read_text()
            if original.count(before) != 1:
                raise RuntimeError(f"{name}: mutation anchor must match exactly once")
            statuses = {}
            for state in ("healthy", "broken", "restored"):
                target.write_text(original.replace(before, after, 1) if state == "broken" else original)
                result = subprocess.run([sys.executable, "-m", "unittest", test], cwd=tree,
                    capture_output=True, text=True, timeout=30,
                    env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
                output = result.stdout + result.stderr
                (out / f"{name}-{state}.log").write_text(output)
                statuses[state] = result.returncode
                if state == "broken":
                    if result.returncode == 0 or "AssertionError" not in output or "ERROR:" in output:
                        raise RuntimeError(f"{name}: removal did not produce an assertion failure")
                elif result.returncode != 0:
                    raise RuntimeError(f"{name}: {state} test failed")
            results.append({"control": name, "test": test, "exits": statuses})
            print(f"{name}: detected; restoration passed", flush=True)
    (out / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)}/{len(CASES)} nonce-clock removal controls detected")


if __name__ == "__main__":
    main()
