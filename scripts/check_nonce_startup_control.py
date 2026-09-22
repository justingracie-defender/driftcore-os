# SPDX-License-Identifier: Apache-2.0
"""Require the startup-lock regression to detect removal of the bounded retry."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TEST = "test_nonce_store_startup.NonceStartupTests.test_transient_startup_lock_retries_and_preserves_single_use"


def main():
    out = Path(sys.argv[1]).resolve()
    out.mkdir(parents=True, exist_ok=False)
    results = {}
    with tempfile.TemporaryDirectory(prefix="nonce-startup-control-") as temporary:
        tree = Path(temporary) / "source"
        def ignored(directory, names):
            blocked = set(shutil.ignore_patterns("__pycache__", "logs", "*.zip", ".git")(directory, names))
            if Path(directory) == ROOT:
                blocked.add("verification")
            return blocked
        shutil.copytree(ROOT, tree, ignore=ignored)
        path = tree / "driftcore/verification/nonce_store_sqlite.py"
        original = path.read_text()
        anchor = "            except sqlite3.OperationalError as error:\n"
        assert original.count(anchor) == 1
        for state in ("healthy", "broken", "restored"):
            path.write_text(original.replace(anchor, anchor + "                raise\n", 1)
                            if state == "broken" else original)
            p = subprocess.run([sys.executable, "-m", "unittest", TEST], cwd=tree,
                capture_output=True, text=True, timeout=30,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            output = p.stdout + p.stderr
            (out / (state + ".log")).write_text(output)
            results[state] = p.returncode
            if state == "broken":
                assert p.returncode != 0 and "AssertionError" in output and "ERROR:" not in output, output
            else:
                assert p.returncode == 0, output
    (out / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
    print("1/1 startup-retry removal control detected; healthy and restored controls passed")


if __name__ == "__main__":
    main()
