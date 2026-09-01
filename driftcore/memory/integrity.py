"""
integrity.py — Memory Tamper Detection

If an agent's memory can be modified without detection,
the agent cannot be trusted.

This module verifies that stored memories have not been altered.

CLAIM unknown-is-not-clean: an entry with no registered checksum is reported as
UNREGISTERED, distinctly from both VERIFIED and TAMPERED — never silently as either.
CLAIM deletion-is-detected: an entry that was registered and is now missing is
reported, not passed over because it was absent from the input.
CLAIM reregistration-is-recorded: re-registering an existing key is refused unless
explicitly permitted, and a permitted overwrite is recorded with who did it.

DEFECTS FOUND WHEN THIS MODULE WAS FIRST TESTED (2026-08-14)
------------------------------------------------------------
It had no tests. All reproduced against the running code.

1. RE-REGISTRATION SILENTLY LAUNDERED A TAMPERED ENTRY. `register()` overwrote any
   existing checksum with no check and no record. Anything able to call it could
   alter a memory, re-register it, and produce a clean bill of health with nothing in
   the log. That is the whole threat model of the module, reachable in two calls.

2. DELETION WAS INVISIBLE. `tamper_report(entries)` iterated the entries it was
   GIVEN, so a memory that had been registered and then deleted appeared in no
   report — the checker looked only where it was pointed. Removing a memory is a
   tamper; it was the one tamper that could not be detected.

3. UNREGISTERED AND TAMPERED WERE THE SAME ANSWER. `verify()` returned False for
   both, and `tamper_report` labelled a never-registered entry "TAMPERED". A caller
   could not tell "this was altered" from "I have never seen this", and the false
   positives are what teach an operator to ignore the report.

4. `default=str` COLLAPSED DISTINCT VALUES. Reproduced: two different objects whose
   `__str__` both return "user_pref" produced the SAME checksum, as did the set
   `{1, 2}` and the literal string "{1, 2}". A checksum that cannot distinguish two
   values cannot detect a swap between them. Unserialisable values are now refused
   rather than stringified.

HONEST LIMIT: this detects alteration of entries it was told to watch, by comparing
against checksums held in the same process. It is not a defence against an attacker
who can write to the checksum store itself — for that the register must be durable
and append-only, which is `audit`'s job, not this module's.

Run: python3 test_memory_integrity.py
"""

import hashlib
import json
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional

VERIFIED = "VERIFIED"
TAMPERED = "TAMPERED"
UNREGISTERED = "UNREGISTERED"
MISSING = "MISSING"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_entry(entry: dict) -> str:
    """A checksum that distinguishes values, or refuses to produce one.

    CLAIM checksum-has-no-chosen-collisions: values that print alike but differ
    produce different checksums, and a value with no canonical form is refused
    rather than stringified.

    The previous `default=str` turned any unserialisable object into its printed
    form, so two different objects that print the same hashed the same. A checksum
    with collisions an attacker can choose is not a checksum.
    """
    try:
        serialized = json.dumps(entry, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError) as e:
        raise ValueError(
            f"entry cannot be canonically serialised, so no checksum can "
            f"distinguish it from another value: {e}") from e
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class IntegrityChecker:

    def __init__(self) -> None:
        self.checksums: Dict[str, dict] = {}
        self._log: List[dict] = []
        self._lock = threading.RLock()

    def register(self, key: str, entry: dict, *, replace: bool = False,
                 registered_by: Optional[str] = None) -> None:
        """Record a checksum. Overwriting an existing one must be deliberate."""
        if not isinstance(key, str) or not key:
            raise ValueError("key must be a non-empty string")
        digest = hash_entry(entry)
        with self._lock:
            if key in self.checksums and not replace:
                raise PermissionError(
                    f"{key!r} already has a checksum. Re-registering silently is how "
                    f"a tampered entry is laundered into a clean one — pass "
                    f"replace=True and registered_by=<who> if this is intended.")
            if key in self.checksums:
                if not isinstance(registered_by, str) or not registered_by.strip():
                    raise ValueError(
                        "replacing a checksum requires registered_by=<who>. An "
                        "unattributed overwrite is the laundering path with an "
                        "extra keyword.")
                self._log.append({
                    "event": "CHECKSUM_REPLACED", "key": key,
                    "old_hash": self.checksums[key]["hash"], "new_hash": digest,
                    "registered_by": registered_by, "at": _now()})
            self.checksums[key] = {"hash": digest, "registered": _now()}

    def status(self, key: str, entry: dict) -> str:
        """VERIFIED / TAMPERED / UNREGISTERED — three answers, not two."""
        with self._lock:
            if key not in self.checksums:
                return UNREGISTERED
            expected = self.checksums[key]["hash"]
        try:
            actual = hash_entry(entry)
        except ValueError:
            return TAMPERED     # unhashable now, hashable when registered
        return VERIFIED if expected == actual else TAMPERED

    def verify(self, key: str, entry: dict) -> bool:
        """True only for VERIFIED. Kept for existing callers; `status` says more."""
        return self.status(key, entry) == VERIFIED

    def tamper_report(self, entries: dict) -> List[dict]:
        """Every registered key is checked, including ones absent from `entries`.

        Iterating only what the caller passed in meant a DELETED memory produced no
        finding at all — the one tamper the module could not see.
        """
        if not isinstance(entries, dict):
            raise TypeError("entries must be a dict of {key: entry}")
        violations = []
        with self._lock:
            registered = set(self.checksums)
        for key in sorted(registered - set(entries)):
            violations.append({"key": key, "status": MISSING,
                               "detail": "registered but absent — deletion is a tamper",
                               "detected_at": _now()})
        for key, entry in entries.items():
            st = self.status(key, entry)
            if st == VERIFIED:
                continue
            violations.append({
                "key": key, "status": st,
                "detail": ("no checksum was ever registered for this entry"
                           if st == UNREGISTERED else "content does not match"),
                "detected_at": _now()})
        return violations

    def audit_log(self) -> List[dict]:
        with self._lock:
            return [dict(e) for e in self._log]
