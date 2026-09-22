# SPDX-License-Identifier: Apache-2.0
"""Load-bearing mutation controls for the R2/R3 repair; local, no model calls.

Each selected regression passes on a restored copy and fails by assertion with
one protection removed. Import errors/crashes are not successful detections.
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
    ("caller_flags_trusted", "driftcore/verification/invariant_guard.py",
     '    return req.egress_authorized is not True',
     '    return not (req.context.owner_authorized and req.context.target_authorized)',
     "test_legacy_booleans_never_authorize"),
    ("global_verifier_used", "driftcore/authority/egress_authorization.py",
     '            self._verifier.verify(request.context.authorised_by, action=expected)',
     '            from driftcore.authority import human_identity\n'
     '            human_identity._verifier.verify(request.context.authorised_by, action=expected)',
     "test_global_verifier_replacement_does_not_change_pinned_guard"),
    ("principal_seal_removed", "driftcore/authority/human_identity.py",
     '            if self._sealed:', '            if False:',
     "test_pinned_principal_registry_cannot_be_changed"),
    ("broker_global_trust_root", "driftcore/verification/human_authorization.py",
     '            return self._verifier.verify(att, action=expected, now=now)',
     '            from driftcore.authority import human_identity\n'
     '            return human_identity._verifier.verify(att, action=expected, now=now)',
     "test_broker_global_replacement_has_no_authority"),
    ("destination_check_removed", "driftcore/verification/mediated_actuation.py",
     '                        if not dec.permitted:', '                        if False:',
     "test_broker_wrong_destination_despite_valid_signatures"),
]


def run(root, test, log):
    with tempfile.TemporaryDirectory() as tmp:
        p = subprocess.run([sys.executable, "-m", "unittest",
            "test_authority_boundary.AuthorityBoundaryTests." + test], cwd=root,
            env={**os.environ, "DRIFTCORE_LOG_DIR": tmp, "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True, text=True, timeout=30)
    log.write_text(p.stdout + p.stderr)
    return p.returncode, p.stdout + p.stderr


def main():
    out = Path(sys.argv[1]).resolve()
    out.mkdir(parents=True, exist_ok=False)
    results = []
    for name, path, before, after, test in CASES:
        with tempfile.TemporaryDirectory(prefix="authority-control-") as tmp:
            tree = Path(tmp) / "source"
            def ignored(directory, names):
                blocked = set(shutil.ignore_patterns(
                    "__pycache__", "logs", ".git", "*.zip")(directory, names))
                if Path(directory) == ROOT:
                    blocked.add("verification")
                return blocked
            shutil.copytree(ROOT, tree, ignore=ignored)
            target = tree / path
            original = target.read_text()
            if original.count(before) != 1:
                raise RuntimeError(f"{name}: mutation anchor must occur exactly once")
            healthy, _ = run(tree, test, out / (name + "-healthy.log"))
            if healthy:
                raise RuntimeError(f"{name}: original test failed")
            target.write_text(original.replace(before, after, 1))
            broken, output = run(tree, test, out / (name + "-broken.log"))
            if not broken or "AssertionError" not in output or "ERROR:" in output:
                raise RuntimeError(f"{name}: did not produce the required assertion failure")
            target.write_text(original)
            restored, _ = run(tree, test, out / (name + "-restored.log"))
            if restored:
                raise RuntimeError(f"{name}: restoration failed")
            results.append(dict(control=name, regression=test,
                healthy_exit=healthy, broken_exit=broken, restored_exit=restored))
            print(name + ": detected; restored control passed", flush=True)
    (out / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)}/{len(CASES)} mutation controls detected")


if __name__ == "__main__":
    main()
