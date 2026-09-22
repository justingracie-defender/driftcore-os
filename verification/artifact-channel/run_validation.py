# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import json
import os
import subprocess
import sys
import time

WORK = Path(__file__).resolve().parent
EVIDENCE = WORK / "evidence"
PYTHON = sys.executable
results = []


def run(name, tree, command, timeout=600):
    print("Starting " + name, flush=True)
    started = time.monotonic()
    proc = subprocess.run(command, cwd=WORK / "validation" / tree / "driftcore-os",
                          capture_output=True, text=True, timeout=timeout)
    output = proc.stdout + proc.stderr
    (EVIDENCE / (name + ".log")).write_text(output)
    (EVIDENCE / (name + ".exit")).write_text(str(proc.returncode) + "\n")
    results.append(dict(check=name, command=command, exit=proc.returncode,
                        seconds=round(time.monotonic()-started, 3),
                        tail=output.splitlines()[-6:]))
    (EVIDENCE / "final-checks.json").write_text(json.dumps(results, indent=2) + "\n")
    print(name + ": exit " + str(proc.returncode) + "\n" + "\n".join(output.splitlines()[-4:]), flush=True)


run("final-full-suite", "suite", ["bash", "scripts/count_tests.sh"])
run("baseline-full-suite", "baseline-suite", ["bash", "scripts/count_tests.sh"])
run("final-artifact-tests", "checks", [PYTHON, "test_artifact_channel.py"])
run("final-agent-boundary-tests", "checks", [PYTHON, "test_agent_boundary.py"])
for name, script in (
        ("artifact", "check_artifact_controls.py"),
        ("boundary", "check_agent_boundary_controls.py"),
        ("policy", "check_policy_binding_controls.py"),
        ("authority", "check_authority_controls.py")):
    run("final-" + name + "-controls", "checks",
        [PYTHON, "scripts/" + script, str(EVIDENCE / ("final-" + name + "-controls"))])
for tag, tree in (("baseline", "baseline-checks"), ("final", "checks")):
    for script, args in (("finite_guards.py", []), ("robot_surface.py", ["--check"]),
                         ("untested_modules.py", []), ("claims_ledger.py", [])):
        run(tag + "-" + script[:-3], tree, [PYTHON, "scripts/" + script, *args])
run("final-marshmallow", "checks", [PYTHON, "marshmallow/selftest.py"])
run("final-os-isolation", "checks", [PYTHON, "scripts/verify_authority_isolation.py"])
print("Validation finished", flush=True)
