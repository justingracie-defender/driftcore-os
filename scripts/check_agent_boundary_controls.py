# SPDX-License-Identifier: Apache-2.0
"""Removal controls for the agent response boundary; no OS socket required.

Usage: python3 scripts/check_agent_boundary_controls.py NEW_OUTPUT_DIRECTORY
Each selected test must pass, fail by assertion after removal, and pass restored.
"""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    ("dispatch_filter_disconnected", "driftcore/verification/mediated_actuation.py",
     "                        _send_agent_response(conn, self._handle(req))",
     "                        _send(conn, self._handle(req))",
     "test_real_dispatch_hides_key_registry_detail_but_operator_keeps_it"),
    ("private_detail_echoed", "driftcore/verification/agent_responses.py",
     '            "detail": message, "effect_status": status, "retry_safe": False}',
     '            "detail": response.get("detail", message), "effect_status": status, "retry_safe": False}',
     "test_real_dispatch_hides_callback_refusal_detail"),
    ("uncertain_effect_reported_clean", "driftcore/verification/agent_responses.py",
     '    message, status = _REFUSALS[code]',
     '    message, status = _REFUSALS[code]\n    status = "NOT_STARTED"',
     "test_actuator_exception_preserves_uncertainty_after_real_effect"),
    ("untrusted_success_truthiness", "driftcore/verification/agent_responses.py",
     '    if response.get("ok") is True:',
     '    if response.get("ok"):',
     "test_unknown_codes_and_invalid_responses_fail_conservatively"),
]


def run(tree, test, path):
    with tempfile.TemporaryDirectory() as logs:
        result = subprocess.run([sys.executable, "-m", "unittest",
            "test_agent_boundary.AgentBoundaryTests." + test], cwd=tree,
            env={**os.environ, "DRIFTCORE_LOG_DIR": logs, "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True, text=True, timeout=30)
    output = result.stdout + result.stderr
    path.write_text(output)
    return result.returncode, output


def main():
    out = Path(sys.argv[1]).resolve()
    out.mkdir(parents=True, exist_ok=False)
    rows = []
    for name, relative, before, after, test in CASES:
        with tempfile.TemporaryDirectory(prefix="agent-boundary-control-") as tmp:
            tree = Path(tmp)/"source"
            def ignored(directory, names):
                excluded = set(shutil.ignore_patterns("__pycache__", "logs", ".git", "*.zip")(directory, names))
                if Path(directory) == ROOT:
                    excluded.add("verification")
                return excluded
            shutil.copytree(ROOT, tree, ignore=ignored)
            target = tree/relative
            original = target.read_text()
            if original.count(before) != 1:
                raise RuntimeError(f"{name}: mutation anchor is not unique")
            healthy, _ = run(tree, test, out/(name + "-healthy.log"))
            if healthy:
                raise RuntimeError(f"{name}: healthy test failed")
            target.write_text(original.replace(before, after, 1))
            removed, output = run(tree, test, out/(name + "-removed.log"))
            if not removed or "AssertionError" not in output or "ERROR:" in output:
                raise RuntimeError(f"{name}: no qualifying assertion failure")
            target.write_text(original)
            restored, _ = run(tree, test, out/(name + "-restored.log"))
            if restored:
                raise RuntimeError(f"{name}: restored test failed")
            rows.append(dict(control=name, regression=test, healthy_exit=healthy,
                             removed_exit=removed, restored_exit=restored))
            print(f"{name}: detected; restored test passed", flush=True)
    (out/"summary.json").write_text(json.dumps(rows, indent=2)+"\n")
    print(f"{len(rows)}/{len(CASES)} mutation controls detected")


if __name__ == "__main__":
    main()
