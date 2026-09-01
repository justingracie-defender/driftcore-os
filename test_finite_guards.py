"""
test_finite_guards.py — the ratchet is a safety component, so it is tested like one.

# CLAIMS: scripts/finite_guards.py:scan-integrity
# CLAIMS: scripts/finite_guards.py:baseline-integrity
# CLAIMS: scripts/finite_guards.py:finding-identity
# CLAIMS: scripts/finite_guards.py:proof-locality
# CLAIMS: scripts/finite_guards.py:rejecting-polarity
# CLAIMS: scripts/finite_guards.py:heuristics-rank-they-do-not-gate

The first version of `finite_guards.py` contained the failure class it was built to
detect: empty scan root -> no findings -> exit 0, and a missing baseline ceiling
defaulting to the current count. An unverified state became an affirmative safety
result, which is structurally the same as NaN -> comparison false -> ALLOW.

Its self-test lives inside the script (it needs subprocess access to a copy of
itself), and this file runs it, so the scanner cannot quietly stop being tested when
someone stops running scripts by hand.

Run: python3 test_finite_guards.py
"""

import pathlib
import subprocess
import sys

SCRIPT = pathlib.Path(__file__).resolve().parent / "scripts" / "finite_guards.py"

_p = _t = 0


def check(label, cond):
    global _p, _t
    _t += 1
    if cond:
        _p += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


print("=== the scanner's own adversarial suite ===")

check("the scanner exists where the repo expects it", SCRIPT.exists())

_r = subprocess.run([sys.executable, str(SCRIPT), "--self-test"],
                    capture_output=True, text=True, timeout=600)
_out = _r.stdout + _r.stderr
check("the self-test passes", _r.returncode == 0)
check("and it reports as PASS, not merely exits quietly", "SELF-TEST: PASS" in _out)
check("it proves the MOTIVATING INCIDENT is detected",
      "ok   THE MOTIVATING INCIDENT is detected" in _out)
check("it proves an empty scan root fails closed",
      "ok   an empty scan root fails closed" in _out)
check("it proves a missing baseline fails closed",
      "ok   no baseline fails closed" in _out)
check("it proves swapping one finding for another fails",
      "ok   SWAPPING one finding for another fails" in _out)
check("it proves inverted polarity is a finding",
      "ok   INVERTED polarity is a finding" in _out)
check("it proves a finiteness check on another value does not bless this one",
      "ok   isfinite on ANOTHER value does not" in _out)
check("no case inside it failed", "FAIL" not in _out)


print("=== the live repository check ===")

_r2 = subprocess.run([sys.executable, str(SCRIPT)],
                     capture_output=True, text=True, timeout=600)
_out2 = _r2.stdout + _r2.stderr
check("the repo currently passes the ratchet", _r2.returncode == 0)
check("and the result is named, not implied", "RESULT: PASS" in _out2)
check("a green run states what it does NOT mean",
      "NOT: the repository has no non-finite bugs" in _out2)
check("coverage is reported, not assumed", "files parsed:" in _out2)

print("-" * 60)
print(f"  {_p}/{_t} tests passed")
if _p != _t:
    raise SystemExit(1)
