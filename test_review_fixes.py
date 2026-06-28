"""
test_review_fixes.py
=====================
Proves the three fixes applied to driftcore/review:

  #2  USER_FLAGGED_DRIFT is NOT counted as an injection attempt
  #1  Tamper is detected via verify_chain() and the shutdown-reason file,
      not via a SHUTDOWN audit entry that the system never writes
  #6  An UNREADABLE audit log raises a CRITICAL alert instead of a
      silent false all-clear

Run:  python3 test_review_fixes.py
"""

import os
import sys
import json
import time
import shutil
import tempfile

sys.path.insert(0, os.path.dirname(__file__))

from driftcore.review import (
    AuditReviewer, ReviewConfig, AlertLevel,
    INJECTION_ACTIONS, BENIGN_USER_ACTIONS,
)

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
_results = []


def check(name, cond):
    _results.append(cond)
    print(f"  [{PASS if cond else FAIL}] {name}")


def fresh_workspace():
    """Isolated cwd with its own logs/ dir so tests don't touch real chain."""
    d = tempfile.mkdtemp(prefix="review_test_")
    os.makedirs(os.path.join(d, "logs"), exist_ok=True)
    return d


def write_chain(workdir, entries):
    path = os.path.join(workdir, "logs", "audit_chain.jsonl")
    with open(path, "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
    return path


def make_entry(action, detail="", ts=None):
    return {
        "action": action,
        "memory_text": f"test {action}",
        "authorised_by": "test",
        "detail": detail,
        "timestamp": ts if ts is not None else time.time(),
    }


# Config that never actually sends (no smtp_user/admin_email) so _send_*
# short-circuit to print-and-return-False. We only inspect detected patterns.
def silent_config():
    return ReviewConfig(admin_email="", smtp_user="", sms_enabled=False)


# ──────────────────────────────────────────────────────────────────
# #2 — USER_FLAGGED_DRIFT must not be mislabeled as an injection
# ──────────────────────────────────────────────────────────────────
print("\n#2  USER_FLAGGED_DRIFT is not an injection attempt")

d = fresh_workspace()
cwd = os.getcwd()
os.chdir(d)
try:
    # A cooperative user flags drift several times. Nothing hostile happened.
    write_chain(d, [make_entry("USER_FLAGGED_DRIFT", "user reports tone shift")
                    for _ in range(4)])
    reviewer = AuditReviewer(config=silent_config())
    patterns = reviewer.run_review()
    ids = {p.pattern_id for p in patterns}

    check("USER_FLAGGED_DRIFT contains the substring 'FLAGGED'",
          "FLAGGED" in "USER_FLAGGED_DRIFT")
    check("no injection_attempt pattern raised", "injection_attempt" not in ids)
    check("USER_FLAGGED_DRIFT excluded from INJECTION_ACTIONS",
          "USER_FLAGGED_DRIFT" not in INJECTION_ACTIONS
          and "USER_FLAGGED_DRIFT" in BENIGN_USER_ACTIONS)

    # Control: a real FLAGGED entry STILL trips injection detection.
    write_chain(d, [make_entry("FLAGGED", "prompt injection blocked")])
    reviewer = AuditReviewer(config=silent_config())
    ids2 = {p.pattern_id for p in reviewer.run_review()}
    check("real FLAGGED still detected as injection",
          "injection_attempt" in ids2)
finally:
    os.chdir(cwd)
    shutil.rmtree(d, ignore_errors=True)


# ──────────────────────────────────────────────────────────────────
# #6 — an unreadable audit log raises CRITICAL, not a silent all-clear
# ──────────────────────────────────────────────────────────────────
print("\n#6  Unreadable audit log is not a false all-clear")

d = fresh_workspace()
os.chdir(d)
try:
    # Make the audit file exist but unreadable: a directory in its place
    # forces an IsADirectoryError on open() — a clean stand-in for an I/O
    # / permission failure that returns no entries.
    bad = os.path.join(d, "logs", "audit_chain.jsonl")
    os.makedirs(bad, exist_ok=True)  # path exists but cannot be read as a file

    reviewer = AuditReviewer(config=silent_config())
    patterns = reviewer.run_review()
    ids = {p.pattern_id for p in patterns}
    crit = {p.pattern_id for p in patterns if p.level == AlertLevel.CRITICAL}

    check("run_review did NOT return an empty/quiet result",
          len(patterns) > 0)
    check("audit_unreadable pattern raised", "audit_unreadable" in ids)
    check("it is CRITICAL severity", "audit_unreadable" in crit)
finally:
    os.chdir(cwd)
    shutil.rmtree(d, ignore_errors=True)


# ──────────────────────────────────────────────────────────────────
# #1 — tamper detected via the shutdown-reason file, no SHUTDOWN entry needed
# ──────────────────────────────────────────────────────────────────
print("\n#1  Tamper detected without a SHUTDOWN audit entry")

d = fresh_workspace()
os.chdir(d)
try:
    write_chain(d, [make_entry("DOMAIN_SWITCH", "childcare->general")
                    for _ in range(2)])
    with open(os.path.join(d, "logs", "CHAIN_SHUTDOWN_REASON.json"), "w") as f:
        json.dump({"reason": "hash mismatch at seq 41"}, f)

    reviewer = AuditReviewer(config=silent_config())
    crit = {p.pattern_id for p in reviewer.run_review()
            if p.level == AlertLevel.CRITICAL}

    check("no SHUTDOWN/TAMPER entry exists in the chain",
          all(e.get("action") not in {"SHUTDOWN", "TAMPER"}
              for e in reviewer._read_all_entries()))
    check("tamper detected via reason file", "tamper_reason_file" in crit)
finally:
    os.chdir(cwd)
    shutil.rmtree(d, ignore_errors=True)


# ──────────────────────────────────────────────────────────────────
# #1b — read-only verifier: correct on a REAL chain, and NO side effects
# ──────────────────────────────────────────────────────────────────
print("\n#1b Read-only verification is accurate and side-effect-free")

import driftcore.audit as audit

d = fresh_workspace()
os.chdir(d)
try:
    # Reset audit globals so we build a clean chain from genesis.
    audit._last_hash = None
    audit._sequence = 0
    audit._chain_compromised = False

    # Build a REAL, valid chain through the audit module itself.
    audit.record("STARTUP", "system up", "system")
    audit.record("DOMAIN_SWITCH", "general->childcare", "system")
    audit.record("SAFETY_DRIFT", "score nudge", "system")

    reviewer = AuditReviewer(config=silent_config())

    intact, reason = reviewer._verify_chain_readonly()
    check("valid chain verifies as intact (no false positive)", intact is True)

    # Now tamper: rewrite one entry's content but leave its stored hash.
    path = os.path.join(d, "logs", "audit_chain.jsonl")
    lines = open(path).read().splitlines()
    rec = json.loads(lines[1])
    rec["memory_text"] = "SILENTLY ALTERED"
    lines[1] = json.dumps(rec)
    open(path, "w").write("\n".join(lines) + "\n")

    # Snapshot side-effect surface BEFORE the reviewer looks at the tampered chain.
    audit._chain_compromised = False
    reason_file = os.path.join(d, "logs", "CHAIN_SHUTDOWN_REASON.json")
    if os.path.exists(reason_file):
        os.remove(reason_file)

    reviewer2 = AuditReviewer(config=silent_config())
    intact2, reason2 = reviewer2._verify_chain_readonly()
    check("tampered chain detected as compromised", intact2 is False)

    # The crucial property: detecting tamper must not CAUSE a shutdown.
    check("verification did NOT set audit compromised flag",
          audit.is_compromised() is False)
    check("verification did NOT write a shutdown-reason file",
          not os.path.exists(reason_file))
finally:
    os.chdir(cwd)
    shutil.rmtree(d, ignore_errors=True)


# ──────────────────────────────────────────────────────────────────
print("\n" + "=" * 50)
total, passed = len(_results), sum(_results)
print(f"{passed}/{total} checks passed")
sys.exit(0 if passed == total else 1)
