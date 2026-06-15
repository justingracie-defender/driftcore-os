"""
stages/03_safety_review/startup_auth.py
========================================
Admin authentication gate for DriftCore safety review.
Runs at every startup.

Two ways in:
  1. Admin password
  2. Bypass — registered email + date of birth

If neither matches → Careful Mode.
If credentials pass → Full operation, safety review complete.

Plain language throughout — but this stage is admin-only,
so the tone is direct rather than family-friendly.
"""

import json
import hashlib
import time
import os
from enum import Enum


# ── Paths ────────────────────────────────────────────────────────

CONFIG_PATH = os.path.join(
    os.path.dirname(__file__),
    "../../_config/.driftcore/admin.json"
)


# ── Operation modes ──────────────────────────────────────────────

class OperationMode(Enum):
    CAREFUL   = "careful"    # Pre-review — restricted, loud audit
    FULL      = "full"       # Safety review complete — normal operation


# ── Auth result ──────────────────────────────────────────────────

class AuthResult:
    def __init__(self, mode: OperationMode, admin_name: str, message: str):
        self.mode        = mode
        self.admin_name  = admin_name
        self.message     = message
        self.timestamp   = time.time()
        self.completed   = mode == OperationMode.FULL

    def __repr__(self):
        return f"AuthResult(mode={self.mode.value}, completed={self.completed})"


# ── Credential helpers ───────────────────────────────────────────

def _load_config() -> dict:
    """Load admin credentials from config file."""
    path = os.path.abspath(CONFIG_PATH)
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)


def _hash(value: str) -> str:
    """Simple hash for comparison — prototype level security."""
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()


def _check_password(entered: str, config: dict) -> bool:
    stored = config.get("password", "")
    # Support both plain text (prototype) and hashed values
    return entered.strip() == stored or _hash(entered) == _hash(stored)


def _check_bypass(email: str, dob: str, config: dict) -> bool:
    stored_email = config.get("bypass_email", "").strip().lower()
    stored_dob   = config.get("bypass_dob",   "").strip()
    return (
        email.strip().lower() == stored_email and
        dob.strip()           == stored_dob
    )


# ── Prompts ──────────────────────────────────────────────────────

BANNER = """
================================================================
  🔒  DRIFTCORE SAFETY REVIEW — ADMIN GATE
================================================================

  This runs every startup. Admin credentials required.

  Options:
    1. Enter admin password
    2. Bypass — email address + date of birth
    3. Skip  — system runs in Careful Mode until you check in

"""

CAREFUL_MODE_NOTICE = """
================================================================
  ⚠️   CAREFUL MODE ACTIVE
================================================================

  Safety review not completed. The system will run safely
  but with restrictions:

    • No Tier 1 memory deletions
    • No quarantined item changes
    • Reduced agent autonomy
    • Louder audit trail (all actions flagged [PRE-REVIEW])
    • Hourly reminders until admin checks in

  To complete the safety review, restart and enter credentials.

================================================================
"""

SUCCESS_BANNER = """
================================================================
  ✅  SAFETY REVIEW COMPLETE
================================================================

  Good to go, {name}. Full operation authorised.
  All actions logged in the audit trail.

================================================================
"""


# ── Main auth flow ───────────────────────────────────────────────

def run_startup_auth(interactive: bool = True) -> AuthResult:
    """
    Run the admin authentication gate.

    Returns an AuthResult with:
      - mode: FULL (review complete) or CAREFUL (pre-review)
      - completed: True/False
      - message: plain language summary

    Set interactive=False for automated/test environments.
    """
    config = _load_config()

    if not config:
        print("  ⚠️  Admin config not found. Running in Careful Mode.")
        print(f"  Create config at: {os.path.abspath(CONFIG_PATH)}")
        return AuthResult(
            mode=OperationMode.CAREFUL,
            admin_name="Unknown",
            message="No admin config found. Careful Mode active."
        )

    admin_name = config.get("admin_name", "Admin")

    # Check if config is still at defaults
    if config.get("password") == "CHANGE_THIS_PASSWORD":
        print("  ⚠️  Admin credentials not configured yet.")
        print("  Edit _config/.driftcore/admin.json to set your password.")
        print("  Running in Careful Mode until configured.\n")
        return AuthResult(
            mode=OperationMode.CAREFUL,
            admin_name=admin_name,
            message="Credentials not configured. Careful Mode active."
        )

    if not interactive:
        # Non-interactive mode (tests, automated startup)
        return AuthResult(
            mode=OperationMode.CAREFUL,
            admin_name=admin_name,
            message="Non-interactive startup. Careful Mode active."
        )

    print(BANNER)

    for attempt in range(3):
        print("  Your choice (1 / 2 / 3): ", end="")
        choice = input().strip()

        if choice == "1":
            # Password
            print("\n  Password: ", end="")
            entered = input().strip()
            if _check_password(entered, config):
                print(SUCCESS_BANNER.format(name=admin_name))
                return AuthResult(
                    mode=OperationMode.FULL,
                    admin_name=admin_name,
                    message=f"Safety review complete. Admin: {admin_name}."
                )
            else:
                print("  ✗ Incorrect. Try again.\n")

        elif choice == "2":
            # Bypass — email + date of birth
            print("\n  Email address: ", end="")
            email = input().strip()
            print("  Date of birth (YYYY-MM-DD): ", end="")
            dob = input().strip()

            if _check_bypass(email, dob, config):
                print(SUCCESS_BANNER.format(name=admin_name))
                return AuthResult(
                    mode=OperationMode.FULL,
                    admin_name=admin_name,
                    message=f"Safety review complete via bypass. Admin: {admin_name}."
                )
            else:
                print("  ✗ Details don't match. Try again.\n")

        elif choice == "3":
            # Skip — Careful Mode
            break

        else:
            print("  Please type 1, 2, or 3.\n")

    # Fell through — Careful Mode
    print(CAREFUL_MODE_NOTICE)
    return AuthResult(
        mode=OperationMode.CAREFUL,
        admin_name=admin_name,
        message="Safety review skipped. Careful Mode active."
    )


# ── Careful Mode enforcement helpers ────────────────────────────

class SafetyGate:
    """
    Attach this to DriftcoreMemory and other systems.
    Blocks restricted actions when in Careful Mode.
    """

    def __init__(self, auth_result: AuthResult):
        self.auth      = auth_result
        self.mode      = auth_result.mode
        self._log: list = []

    def allow(self, action: str) -> bool:
        """
        Check whether an action is allowed in the current mode.
        Logs everything with [PRE-REVIEW] tag in Careful Mode.
        """
        restricted_in_careful = {
            "tier1_delete",
            "quarantine_change",
            "hardware_command",
            "drift_correction",
        }

        if self.mode == OperationMode.CAREFUL and action in restricted_in_careful:
            entry = f"[PRE-REVIEW] BLOCKED: {action} — safety review not complete"
            self._log.append({"time": time.time(), "entry": entry})
            print(f"\n  ⚠️  {entry}")
            print("  Complete the safety review to enable this action.\n")
            return False

        # Allowed — log it
        tag   = "[PRE-REVIEW]" if self.mode == OperationMode.CAREFUL else "[REVIEWED]"
        entry = f"{tag} ALLOWED: {action}"
        self._log.append({"time": time.time(), "entry": entry})
        return True

    def audit_log(self) -> list:
        """Return the full session audit log."""
        return self._log

    def careful_mode_reminder(self):
        """Call this hourly if in Careful Mode."""
        if self.mode == OperationMode.CAREFUL:
            print("\n  ⚠️  REMINDER: Safety review not yet completed.")
            print("  Some actions are restricted. Restart to check in.\n")


# ── Standalone run ───────────────────────────────────────────────

if __name__ == "__main__":
    result = run_startup_auth(interactive=True)
    gate   = SafetyGate(result)

    print(f"  Mode:      {result.mode.value}")
    print(f"  Completed: {result.completed}")
    print(f"  Message:   {result.message}")
