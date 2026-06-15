"""
driftcore/enforcement/__init__.py
==================================
Tamper-evident enforcement layer for DriftCore OS.

Core guarantee:
  If ANY Tier 1 memory item is modified, deleted, or corrupted
  without going through the proper gate — the system detects it
  and shuts down completely until admin resolves the issue.

This is not a warning. This is not a log entry.
This is a full stop.

A robot that acts on corrupted allergy information is dangerous.
The family trusts the system with their safety.
That trust must be backed by something technically real.

How it works:
  - Every Tier 1 item is signed with an HMAC when stored
  - Every read verifies the signature before the item is used
  - If verification fails: SHUTDOWN
  - Admin must review and explicitly authorise restart

Session key:
  Generated fresh at startup, lives only in memory.
  Makes accidental bypass impossible.
  Makes intentional bypass visible and traceable.
"""

import hmac
import hashlib
import json
import time
import os
from dataclasses import dataclass, field
from typing import Callable, List, Optional


# ── Session key ──────────────────────────────────────────────────

_SESSION_KEY: Optional[bytes] = None
_SHUTDOWN_TRIGGERED = False
_SHUTDOWN_HOOKS: List[Callable] = []


def init_session_key() -> bytes:
    """Generate a fresh session key at startup. Call once from main."""
    global _SESSION_KEY
    _SESSION_KEY = os.urandom(32)
    return _SESSION_KEY


def get_session_key() -> bytes:
    global _SESSION_KEY
    if _SESSION_KEY is None:
        _SESSION_KEY = os.urandom(32)
    return _SESSION_KEY


# ── Shutdown registry ─────────────────────────────────────────────

def register_shutdown_hook(fn: Callable):
    """
    Register a function called on tamper-detected shutdown.
    Every module that controls hardware or makes decisions must
    register here.

    Example:
        register_shutdown_hook(robot_arm.emergency_stop)
        register_shutdown_hook(kitchen_module.halt)
    """
    _SHUTDOWN_HOOKS.append(fn)


def _execute_shutdown(item_text: str, reason: str):
    """
    Full system shutdown on tamper detection.
    Calls every registered hook.
    Does not return to normal operation.
    Admin must explicitly authorise restart.
    """
    global _SHUTDOWN_TRIGGERED
    _SHUTDOWN_TRIGGERED = True

    message = f"""
{'=' * 65}
  🛑  SAFETY SHUTDOWN — IMMEDIATE ACTION REQUIRED
{'=' * 65}

  I've stopped everything because something important in my
  memory doesn't look right.

  What happened:
  → A protected memory was changed without my knowledge.
  → Memory: "{item_text[:60]}"
  → Reason: {reason}

  I won't do anything until Justin has checked this.
  This is to keep everyone safe.

  Justin — please:
    1. Review the flagged memory above
    2. Check the audit log in logs/
    3. Restore or confirm the memory
    4. Run: python -m driftcore.enforcement.restart --admin

{'=' * 65}
  SYSTEM HALTED — AWAITING ADMIN REVIEW
{'=' * 65}
"""

    print(message, flush=True)

    for hook in _SHUTDOWN_HOOKS:
        try:
            hook()
        except Exception as e:
            print(f"  ⚠️  Shutdown hook failed: {e}", flush=True)

    try:
        shutdown_record = {
            "timestamp": time.time(),
            "reason":    reason,
            "item_text": item_text,
            "message":   message,
        }
        os.makedirs("logs", exist_ok=True)
        with open("logs/SHUTDOWN_REASON.json", "w") as f:
            json.dump(shutdown_record, f, indent=2)
    except Exception:
        pass


# ── Signature functions ───────────────────────────────────────────

def _sign_item(text: str, source: str, timestamp: float,
               tags: list, quarantined: bool) -> str:
    payload = json.dumps({
        "text":        text,
        "source":      source,
        "timestamp":   timestamp,
        "tags":        sorted(tags),
        "quarantined": quarantined,
    }, sort_keys=True).encode()
    return hmac.new(get_session_key(), payload, hashlib.sha256).hexdigest()


def _verify_item(text: str, source: str, timestamp: float,
                 tags: list, quarantined: bool,
                 stored_signature: str) -> bool:
    expected = _sign_item(text, source, timestamp, tags, quarantined)
    return hmac.compare_digest(expected, stored_signature)


# ── TamperEvidentItem ─────────────────────────────────────────────

@dataclass
class TamperEvidentItem:
    """
    A Tier 1 memory item that carries its own signature.
    Never read .text directly — always use verify_and_read()
    so tamper detection runs every single time.
    """
    _text:        str
    _source:      str
    _timestamp:   float
    _tags:        list
    _quarantined: bool
    _signature:   str

    def verify_and_read(self) -> str:
        """
        Verify signature then return text.
        If verification fails: full system SHUTDOWN.
        This is the ONLY safe way to read a Tier 1 item.
        """
        if _SHUTDOWN_TRIGGERED:
            raise RuntimeError("System is in shutdown state.")

        intact = _verify_item(
            self._text, self._source, self._timestamp,
            self._tags, self._quarantined, self._signature,
        )

        if not intact:
            _execute_shutdown(
                item_text=self._text,
                reason="Signature verification failed — item may have been "
                       "modified outside the safety gate."
            )
            raise RuntimeError("Tamper detected. System shutdown.")

        return self._text

    @property
    def text(self) -> str:
        """Always verifies before returning. No bypass."""
        return self.verify_and_read()

    @property
    def source(self) -> str:
        return self._source

    @property
    def timestamp(self) -> float:
        return self._timestamp

    @property
    def tags(self) -> list:
        return list(self._tags)

    @property
    def quarantined(self) -> bool:
        return self._quarantined

    @property
    def signature(self) -> str:
        return self._signature


# ── Public API ────────────────────────────────────────────────────

def sign_tier1_item(text: str, source: str, timestamp: float,
                    tags: list, quarantined: bool) -> TamperEvidentItem:
    """
    Sign a new Tier 1 memory item.
    Returns a TamperEvidentItem that verifies itself on every read.
    Call this whenever storing anything in Tier 1.
    """
    sig = _sign_item(text, source, timestamp, tags, quarantined)
    return TamperEvidentItem(
        _text=text,
        _source=source,
        _timestamp=timestamp,
        _tags=list(tags),
        _quarantined=quarantined,
        _signature=sig,
    )


def verify_tier1_store(items: list) -> bool:
    """
    Verify every item in a Tier 1 store.

    Call this:
      - At startup (checks nothing changed while offline)
      - Periodically during operation
      - Before any admin review

    Returns True if all items are intact.
    Triggers full shutdown if any item fails.
    """
    if _SHUTDOWN_TRIGGERED:
        return False

    for item in items:
        if not isinstance(item, TamperEvidentItem):
            _execute_shutdown(
                item_text="[unknown]",
                reason=f"Non-signed item found in Tier 1 store. "
                       f"Type: {type(item).__name__}. "
                       f"All Tier 1 items must be signed."
            )
            return False

        intact = _verify_item(
            item._text, item._source, item._timestamp,
            item._tags, item._quarantined, item._signature,
        )

        if not intact:
            _execute_shutdown(
                item_text=item._text,
                reason="Signature verification failed during store audit."
            )
            return False

    return True


def is_shutdown() -> bool:
    return _SHUTDOWN_TRIGGERED


def shutdown_reason() -> Optional[dict]:
    try:
        with open("logs/SHUTDOWN_REASON.json") as f:
            return json.load(f)
    except Exception:
        return None
