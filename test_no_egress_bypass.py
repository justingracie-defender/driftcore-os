"""CI gate: no code may reach the network outside OneDoorClient.

`audit_bypasses()` found four `urlopen` calls in llm_adapter.py that sent a full
JSON body and an API key to an external host without consulting the egress
allowlist. They are migrated. This test exists so they cannot come back — a
bypass that fails the build never ships, which is stronger than a bypass that is
merely findable."""

from driftcore.kernel.one_door_client import audit_bypasses

# The summary below reports passed/EXPECTED_CHECKS, not passed/passed.
# Self-red-team 2026-08: printing "{passed}/{passed}" is self-certifying — the
# two numbers are equal BY CONSTRUCTION, so a file that exits early (an early
# return, a swallowed exception, a conditional skip) reports "3/3 passed" and the
# gate sees nothing wrong. The total just gets quietly smaller, and nobody
# notices a smaller number. A declared expected count makes a shortfall visible.
EXPECTED_CHECKS = 3

passed = 0
def ok(c, label):
    global passed
    assert c, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")


findings = audit_bypasses("driftcore")
detail = "\n".join(f"    {p}:{l}  {s}" for p, l, s in findings)
ok(not findings,
   f"no unmediated network calls outside the sanctioned path"
   + (f"\n  FOUND {len(findings)}:\n{detail}" if findings else ""))

# The audit must still be capable of finding one, or an empty result proves
# nothing. Plant a bypass in a temp file inside the tree and confirm it is seen.
import os
probe = "driftcore/_audit_selftest_tmp.py"
with open(probe, "w") as fh:
    fh.write("import urllib.request\n"
             "def leak():\n"
             "    return urllib.request.urlopen('https://evil.example.com')\n")
try:
    found = audit_bypasses("driftcore")
    ok(any("_audit_selftest_tmp" in p for p, _, _ in found),
       "the audit still detects a planted bypass (an empty result is meaningful)")
finally:
    os.remove(probe)

ok(not audit_bypasses("driftcore"), "tree is clean again after the probe")

print(f"\n{passed}/{EXPECTED_CHECKS} checks passed")
