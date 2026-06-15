"""
driftcore/audit/__init__.py
============================
Append-only audit chain for DriftCore OS.

Core guarantee:
  Every Tier 1 memory mutation is recorded.
  Each record links to the previous one via hash.
  If any record is altered, deleted, or inserted,
  the chain breaks — and the system shuts down.

Shutdown is not death.
It means: "Something is wrong. I need to be fixed."
The system does not restart until an admin has reviewed,
understood, and corrected the issue.

Chain structure:
  Each entry contains:
    - sequence number
    - timestamp
    - action (CREATED, MODIFIED, DELETED, RESTORED, QUARANTINED)
    - memory text (what changed)
    - authorised_by (who or what authorised the change)
    - previous_hash (links to the prior entry)
    - entry_hash (hash of this entire entry)

If the chain file is tampered with:
  Full shutdown. Like cutting the brakes.
  You don't keep driving. You stop until it's fixed.
"""

import hashlib
import hmac
import json
import os
import time
from typing import Optional


# ── Chain file location ───────────────────────────────────────────

CHAIN_FILE = "logs/audit_chain.jsonl"

# ── Actions ───────────────────────────────────────────────────────

ACTION_CREATED     = "CREATED"
ACTION_MODIFIED    = "MODIFIED"
ACTION_DELETED     = "DELETED"
ACTION_RESTORED    = "RESTORED"
ACTION_QUARANTINED = "QUARANTINED"
ACTION_VERIFIED    = "VERIFIED"
ACTION_SHUTDOWN    = "SHUTDOWN"
ACTION_STARTUP     = "STARTUP"


# ── Chain state ───────────────────────────────────────────────────

_last_hash: Optional[str] = None
_sequence:  int = 0
_chain_compromised = False


def _hash_entry(entry: dict) -> str:
    """
    Hash a single audit entry.
    Produces a deterministic fingerprint of the entire record.
    """
    payload = json.dumps(entry, sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()


def _shutdown_on_chain_tamper(reason: str):
    """
    Full system shutdown when the audit chain is compromised.
    Like cutting the brakes — we do not keep driving.
    """
    global _chain_compromised
    _chain_compromised = True

    message = f"""
{'=' * 65}
  🛑  SAFETY SHUTDOWN — AUDIT CHAIN COMPROMISED
{'=' * 65}

  I've stopped everything because my record of changes
  doesn't look right. Someone may have altered my history.

  What happened:
  → {reason}

  I can't be trusted to act safely until Justin has reviewed
  what happened. This is like finding out the brakes were cut.
  I won't move until they're fixed.

  Shutdown is not death. It means: I need to be fixed.

  Justin — please:
    1. Read logs/audit_chain.jsonl carefully
    2. Find the entry that broke the chain
    3. Understand what changed and why
    4. Correct the issue
    5. Run: python -m driftcore.enforcement.restart --admin

{'=' * 65}
  SYSTEM HALTED — AUDIT CHAIN MUST BE REVIEWED
{'=' * 65}
"""
    print(message, flush=True)

    # Call enforcement shutdown hooks
    try:
        from driftcore.enforcement import _execute_shutdown
        _execute_shutdown(
            item_text="[audit chain]",
            reason=reason
        )
    except Exception:
        pass

    # Also write our own shutdown record
    try:
        os.makedirs("logs", exist_ok=True)
        with open("logs/CHAIN_SHUTDOWN_REASON.json", "w") as f:
            json.dump({
                "timestamp": time.time(),
                "reason":    reason,
                "message":   message,
            }, f, indent=2)
    except Exception:
        pass


# ── Write ─────────────────────────────────────────────────────────

def record(
    action:       str,
    memory_text:  str,
    authorised_by: str = "system",
    detail:       str = "",
) -> Optional[dict]:
    """
    Write a new entry to the audit chain.

    Parameters:
        action        — what happened (use ACTION_* constants)
        memory_text   — the memory that was affected
        authorised_by — who or what authorised this (admin name, "system", "auto-sign")
        detail        — optional extra context

    Returns the written entry, or None if chain is compromised.

    This is append-only. Entries are never modified or deleted.
    """
    global _last_hash, _sequence, _chain_compromised

    if _chain_compromised:
        return None

    _sequence += 1

    # Build the entry without its own hash first
    entry = {
        "sequence":      _sequence,
        "timestamp":     time.time(),
        "timestamp_human": _human_time(time.time()),
        "action":        action,
        "memory_text":   memory_text[:200],  # cap length
        "authorised_by": authorised_by,
        "detail":        detail,
        "previous_hash": _last_hash or "GENESIS",
    }

    # Hash the complete entry
    entry_hash = _hash_entry(entry)
    entry["entry_hash"] = entry_hash

    # Write to chain file (append only)
    try:
        os.makedirs("logs", exist_ok=True)
        with open(CHAIN_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        _shutdown_on_chain_tamper(
            f"Failed to write to audit chain: {e}. "
            f"Cannot proceed without audit trail."
        )
        return None

    _last_hash = entry_hash
    return entry


# ── Verify ────────────────────────────────────────────────────────

def verify_chain() -> bool:
    """
    Verify the entire audit chain from beginning to end.

    Checks:
      - Every entry's hash matches its content
      - Every entry's previous_hash matches the prior entry
      - No gaps in sequence numbers
      - No entries missing

    If any check fails: full shutdown.
    Returns True only if the chain is completely intact.

    Call this:
      - At startup
      - Before any admin review
      - Periodically during operation
    """
    global _chain_compromised

    if _chain_compromised:
        return False

    if not os.path.exists(CHAIN_FILE):
        # No chain yet — this is fine on first startup
        return True

    try:
        with open(CHAIN_FILE, "r") as f:
            lines = [l.strip() for l in f if l.strip()]
    except Exception as e:
        _shutdown_on_chain_tamper(
            f"Could not read audit chain file: {e}"
        )
        return False

    if not lines:
        return True

    prev_hash    = "GENESIS"
    prev_sequence = 0

    for i, line in enumerate(lines):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as e:
            _shutdown_on_chain_tamper(
                f"Audit chain entry {i + 1} is corrupted (invalid JSON): {e}"
            )
            return False

        # Check sequence continuity
        expected_seq = prev_sequence + 1
        if entry.get("sequence") != expected_seq:
            _shutdown_on_chain_tamper(
                f"Audit chain sequence gap detected. "
                f"Expected entry #{expected_seq}, "
                f"found #{entry.get('sequence')}. "
                f"An entry may have been deleted."
            )
            return False

        # Check previous_hash linkage
        if entry.get("previous_hash") != prev_hash:
            _shutdown_on_chain_tamper(
                f"Audit chain link broken at entry #{entry.get('sequence')}. "
                f"Previous hash mismatch — entry may have been inserted or altered."
            )
            return False

        # Verify this entry's own hash
        stored_hash = entry.pop("entry_hash", None)
        recomputed  = _hash_entry(entry)
        entry["entry_hash"] = stored_hash  # restore

        if stored_hash != recomputed:
            _shutdown_on_chain_tamper(
                f"Audit chain entry #{entry.get('sequence')} has been altered. "
                f"Content hash does not match stored hash. "
                f"Memory: \"{entry.get('memory_text', '[unknown]')[:60]}\""
            )
            return False

        prev_hash     = stored_hash
        prev_sequence = entry.get("sequence")

    return True


# ── Read / report ─────────────────────────────────────────────────

def read_chain() -> list:
    """
    Read and return all audit chain entries.
    Does NOT verify — call verify_chain() first if needed.
    """
    if not os.path.exists(CHAIN_FILE):
        return []
    entries = []
    with open(CHAIN_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass
    return entries


def plain_language_report(last_n: int = 20) -> str:
    """
    Return a plain-language summary of the last N audit entries.
    Readable by anyone — not just developers.
    """
    entries = read_chain()
    if not entries:
        return "No audit records yet. The system hasn't made any changes."

    recent   = entries[-last_n:]
    lines    = [
        f"{'=' * 60}",
        f"  AUDIT TRAIL — last {len(recent)} of {len(entries)} entries",
        f"{'=' * 60}",
        "",
    ]

    for e in recent:
        action  = e.get("action", "?")
        text    = e.get("memory_text", "[unknown]")[:60]
        auth    = e.get("authorised_by", "unknown")
        t_human = e.get("timestamp_human", "unknown time")
        seq     = e.get("sequence", "?")

        # Plain language action descriptions
        action_desc = {
            ACTION_CREATED:     "Added to memory",
            ACTION_MODIFIED:    "Changed",
            ACTION_DELETED:     "Removed from memory",
            ACTION_RESTORED:    "Restored",
            ACTION_QUARANTINED: "Marked sensitive",
            ACTION_VERIFIED:    "Checked and confirmed intact",
            ACTION_SHUTDOWN:    "⚠️  System was stopped",
            ACTION_STARTUP:     "System started",
        }.get(action, action)

        lines.append(f"  #{seq}  {t_human}")
        lines.append(f"       {action_desc}: \"{text}\"")
        lines.append(f"       Authorised by: {auth}")
        lines.append("")

    lines.append(f"{'=' * 60}")
    return "\n".join(lines)


def is_compromised() -> bool:
    return _chain_compromised


def sync_state():
    """
    Sync in-memory state (_last_hash, _sequence) with the chain file.
    Call at startup after verify_chain() passes.
    """
    global _last_hash, _sequence
    entries = read_chain()
    if entries:
        last         = entries[-1]
        _last_hash   = last.get("entry_hash")
        _sequence    = last.get("sequence", 0)


# ── Helpers ───────────────────────────────────────────────────────

def _human_time(ts: float) -> str:
    import datetime
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
