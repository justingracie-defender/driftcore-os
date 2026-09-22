# SPDX-License-Identifier: Apache-2.0
"""Remove each policy protection in a disposable copy; require assertion failures.

Usage: python3 scripts/check_policy_binding_controls.py NEW_OUTPUT_DIRECTORY
Crashes, import errors, or a broken positive control do not establish detection.
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
    ("policy_equality_removed", "driftcore/verification/signed_permission.py",
     "            if not hmac.compare_digest(grant.policy_hash, expected_policy_hash):",
     "            if False:", "test_validly_signed_wrong_policy_rejected"),
    ("hash_not_signed", "driftcore/verification/signed_permission.py",
     '            payload["policy_hash"] = self.policy_hash',
     '            pass', "test_signature_binds_policy_independently_of_matching_check"),
    ("request_selects_policy", "driftcore/verification/mediated_actuation.py",
     "                                   expected_policy_hash=self.policy_hash,",
     "                                   expected_policy_hash=grant.policy_hash,",
     "test_new_policy_blocks_old_grant_before_effect_and_allows_new"),
    ("production_policy_optional", "driftcore/verification/mediated_actuation.py",
     '        if kwargs.get("policy_snapshot") is None:',
     '        if False:', "test_production_requires_snapshot_and_rejects_duck_types"),
]


def run(root, test, log):
    with tempfile.TemporaryDirectory() as logs:
        result = subprocess.run([sys.executable, "-m", "unittest",
            "test_policy_binding.PolicyBindingTests." + test], cwd=root,
            env={**os.environ, "DRIFTCORE_LOG_DIR": logs, "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True, text=True, timeout=30)
    output = result.stdout + result.stderr
    log.write_text(output)
    return result.returncode, output


def main():
    out = Path(sys.argv[1]).resolve()
    out.mkdir(parents=True, exist_ok=False)
    rows = []
    for name, path, before, after, test in CASES:
        with tempfile.TemporaryDirectory(prefix="policy-control-") as temporary:
            tree = Path(temporary)/"source"
            def ignored(directory, names):
                excluded = set(shutil.ignore_patterns("__pycache__", "logs", ".git", "*.zip")(directory, names))
                if Path(directory) == ROOT:
                    excluded.add("verification")
                return excluded
            shutil.copytree(ROOT, tree, ignore=ignored)
            target = tree/path
            original = target.read_text()
            if original.count(before) != 1:
                raise RuntimeError(f"{name}: mutation anchor is not unique")
            healthy, _ = run(tree, test, out/(name + "-healthy.log"))
            if healthy:
                raise RuntimeError(f"{name}: healthy test failed")
            target.write_text(original.replace(before, after, 1))
            broken, output = run(tree, test, out/(name + "-broken.log"))
            if not broken or "AssertionError" not in output or "ERROR:" in output:
                raise RuntimeError(f"{name}: expected assertion failure was absent")
            target.write_text(original)
            restored, _ = run(tree, test, out/(name + "-restored.log"))
            if restored:
                raise RuntimeError(f"{name}: restored test failed")
            rows.append(dict(control=name, regression=test, healthy_exit=healthy,
                             removed_exit=broken, restored_exit=restored))
            print(f"{name}: detected; restored test passed", flush=True)
    (out/"summary.json").write_text(json.dumps(rows, indent=2) + "\n")
    print(f"{len(rows)}/{len(CASES)} mutation controls detected")


if __name__ == "__main__":
    main()
