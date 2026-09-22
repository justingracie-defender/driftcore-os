# SPDX-License-Identifier: Apache-2.0
"""Check interrupted fixture isolation and retain the real-source refusal control."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile


def check(source):
    source = Path(source).resolve()
    results = {}
    for scenario in ("healthy", "interrupted", "real_bypass"):
        with tempfile.TemporaryDirectory(prefix="audit-isolation-control-") as temporary:
            root = Path(temporary)
            tree = root / "project"
            shutil.copytree(source, tree, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.zip"))
            scratch = root / "temporary-fixtures"
            scratch.mkdir()
            env = {**os.environ, "TMPDIR": str(scratch), "PYTHONDONTWRITEBYTECODE": "1"}
            if scenario == "real_bypass":
                (tree / "driftcore/unauthorized_test_fixture.py").write_text(
                    "import urllib.request\ndef bad():\n    return urllib.request.urlopen('https://invalid.example')\n")
            code = r'''
import os, runpy, sys
import driftcore.kernel.one_door_client as module
original = module.audit_bypasses
calls = 0
def audit(root):
    global calls
    calls += 1
    if sys.argv[1] == 'interrupted' and calls == 2:
        os._exit(23)
    return original(root)
module.audit_bypasses = audit
runpy.run_path('test_no_egress_bypass.py', run_name='__main__')
'''
            result = subprocess.run([sys.executable, "-c", code, scenario], cwd=tree,
                                    env=env, capture_output=True, text=True, timeout=20)
            expected = {"healthy": 0, "interrupted": 23, "real_bypass": 1}[scenario]
            if result.returncode != expected:
                raise RuntimeError(result.stdout + result.stderr)
            if scenario == "real_bypass" and "no unmediated network calls" not in result.stderr:
                raise RuntimeError("real source bypass did not trigger the intended assertion")
            results[scenario] = {"exit_code": result.returncode,
                "probe_left_inside_package": (tree / "driftcore/_audit_selftest_tmp.py").exists()}
    return results


if __name__ == "__main__":
    print(json.dumps({str(Path(p).resolve()): check(p) for p in sys.argv[1:]}, indent=2))
