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
import threading
import time
from typing import Optional


# ── Chain file location ───────────────────────────────────────────

CHAIN_FILE = "logs/audit_chain.jsonl"

# (red-team 2026-09-05) HEAD ANCHOR.
#
# The chain's guarantee named three verbs — altered, deleted, inserted — and those
# are exactly the three a backward hash chain covers. Verified in a FRESH
# interpreter, the verbs it did not name all passed undetected: truncating the last
# record, emptying the file, and rebuilding a self-consistent chain from scratch.
# Removing the newest entry leaves a chain that is still internally consistent, an
# empty file has no broken link, and every check ran against the same file an
# attacker was editing.
#
# The consequence pointed the wrong way: DELETING the log was quieter than editing
# it, so an attacker hiding an action would truncate rather than alter.
#
# This is the smallest anchor that fixes that: a separate file naming the expected
# head (sequence + hash), HMAC'd so it cannot be rewritten from the chain alone.
#
# WHAT IT DOES NOT DO. An attacker who can write BOTH files and who holds the
# signing key defeats it — the key is a process session key, so in-process code
# can forge a head. This raises the cost from "delete one file" to "delete two
# files and forge a MAC", which is a real improvement and is not tamper-proof.
# Actual tamper-EVIDENCE needs an anchor outside the box: an append-only sink, a
# co-signature from another host, or physical media. That is open work and this
# comment is not a substitute for it.
HEAD_FILE = "logs/audit_head.json"


def _head_mac(sequence: int, entry_hash: str) -> str:
    """Deliberately NOT a MAC. See below.

    The first version of this anchor signed the head with
    `enforcement._sign_item`. The clean-chain control failed immediately, which
    is how the real problem surfaced: `enforcement._SESSION_KEY` is
    `os.urandom(32)` per PROCESS, with no loader and no derivation. A MAC written
    by one process cannot be verified by the next — and verifying after a restart
    is the entire threat model here, since the attacker edits the log while the
    system is down.

    So the anchor is an unauthenticated head pointer. It raises the cost of
    hiding an action from "truncate one file" to "truncate one file AND edit
    another", and it is honestly not more than that. Cryptographic
    tamper-evidence needs a signing key that survives a restart, which this
    project does not currently have (see AUDIT: signing-key custody), or an
    append-only sink outside the box.
    """
    return f"{sequence}|{entry_hash}"


def _write_head(sequence: int, entry_hash: str) -> None:
    try:
        os.makedirs(os.path.dirname(HEAD_FILE) or ".", exist_ok=True)
        tmp = HEAD_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"sequence": sequence, "entry_hash": entry_hash,
                       "mac": _head_mac(sequence, entry_hash)}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, HEAD_FILE)      # atomic: a crash leaves old or new, not half
    except Exception:
        # Best-effort, deliberately. A failure to write the anchor must not stop
        # the record that was already durably appended — losing the event is worse
        # than losing the anchor, and the next successful record restores it.
        pass


def _read_head():
    """(sequence, entry_hash) if a head pointer exists and its MAC checks, else None."""
    try:
        with open(HEAD_FILE) as f:
            h = json.load(f)
        seq, eh, mac = h.get("sequence"), h.get("entry_hash"), h.get("mac")
        if not isinstance(seq, int) or not isinstance(eh, str):
            return None
        if not hmac.compare_digest(str(mac), _head_mac(seq, eh)):
            return None                 # rewritten inconsistently — not usable
        return seq, eh
    except FileNotFoundError:
        return None
    except Exception:
        return None

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

# (external red-team, Astra, 2026-09-06 — R4) One writer at a time.
#
# `record()` is five steps: allocate a sequence, capture the previous head, append
# to the file, publish the new head in memory, write the head anchor. None of them
# were serialised, so two threads could interleave and both return success while
# the chain they produced fails verification. Reproduced: sequences written [2, 1],
# both calls non-None, a fresh interpreter reporting compromised=True.
#
# This is an RLock rather than a Lock because `_shutdown_on_chain_tamper` can be
# reached from inside the transaction, and it records. A non-reentrant lock would
# deadlock the failure path — turning "the chain broke" into "the process hangs",
# which is the worse of the two.
#
# SCOPE, stated because it is easy to over-read: this serialises THREADS in one
# interpreter. Two PROCESSES appending to the same file still race, and no
# in-process lock fixes that. The cross-process case needs a single writer service
# or file locking, and it is open.
_write_lock = threading.RLock()

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

    # The entire transaction is under one lock. Allocating the sequence outside
    # it — as this did — is enough on its own to produce out-of-order entries,
    # because two threads can both increment before either appends.
    with _write_lock:
        return _record_locked(action, memory_text, authorised_by, detail)


def _record_locked(action, memory_text, authorised_by, detail):
    """The record transaction. Callers hold `_write_lock`."""
    global _last_hash, _sequence, _chain_compromised

    if _chain_compromised:
        return None       # re-checked inside the lock: it may have flipped while waiting

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

    # Write to chain file (append only).
    # DURABILITY (external review, all three reviewers): this wrote with a plain
    # open(..., "a") and never fsynced, so the chain was tamper-EVIDENT but not
    # crash-DURABLE — a power loss or kill -9 took the most recent entries with it,
    # and those are precisely the ones describing whatever was happening when things
    # went wrong. Hugging Face reconstructed the July incident from 17,000 recorded
    # events; recording is what let them contain it. Evidence that does not survive
    # the event it describes is not evidence.
    #
    # fsync on the file, then on the directory, because a file can be durable while
    # the directory entry pointing at it is not.
    try:
        os.makedirs("logs", exist_ok=True)
        with open(CHAIN_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
        try:
            _dfd = os.open(os.path.dirname(CHAIN_FILE) or ".", os.O_RDONLY)
            try:
                os.fsync(_dfd)
            finally:
                os.close(_dfd)
        except OSError:
            pass          # directory fsync unsupported here; the file write still held
    except Exception as e:
        _shutdown_on_chain_tamper(
            f"Failed to write to audit chain: {e}. "
            f"Cannot proceed without audit trail."
        )
        return None

    _last_hash = entry_hash
    # CRASH WINDOW, named rather than hidden. The entry is durable on disk before
    # the anchor is updated, so a crash here leaves chain=N and anchor=N-1.
    # `verify_chain` treats a tail AHEAD of the anchor as tamper, which is the
    # wrong verdict for a crash and the right one for a truncation — the two are
    # indistinguishable from the files alone.
    #
    # The order is deliberate and this is the safe way round: entry-then-anchor
    # loses an anchor update, anchor-then-entry would claim an entry that does not
    # exist. Losing the event is worse than losing the pointer to it.
    #
    # Documented recovery: an operator confirms chain=anchor+1 and the tail entry
    # links correctly, then re-publishes the anchor. That procedure does not exist
    # yet and is open work; until it does, this case requires human review, which
    # is the honest outcome rather than an automatic repair that would also repair
    # a truncation.
    _write_head(_sequence, entry_hash)
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
        # (external red-team, Astra, 2026-09-06) This returned True before the
        # anchor was consulted, so DELETING the chain file bypassed the anchor
        # entirely — while TRUNCATING it to zero bytes was caught. Two
        # representations of "no entries", and the v113 fix enumerated one of
        # them. §0f, in the fix for the previous §0f finding, one day later.
        #
        # An anchor that survives only the deletion you thought of is not an
        # anchor. "No chain yet" is only true when there is also no record that
        # there ever was one.
        # (external red-team, Astra, 2026-09-06 — second pass) This refused only
        # when the anchor was READABLE. `_read_head()` returns None for two
        # different states — the file is absent, and the file exists but its
        # contents do not check — and collapsing them meant deleting the chain
        # AND corrupting the head walked straight through.
        #
        # A head file that EXISTS is positive evidence that a chain once existed,
        # whether or not its contents still verify. Corrupting it destroys the
        # evidence of WHAT was there; it does not destroy the evidence THAT
        # something was there. Only removing the file does that.
        #
        # Fourth time in this repo that a fix landed on part of a set. The set
        # here was {empty, deleted} x {intact, corrupt, deleted} — six cells, one
        # missed, found by someone who wrote the grid out.
        _h = _read_head()
        if _h is not None:
            _shutdown_on_chain_tamper(
                f"Audit chain file is MISSING but the head anchor records "
                f"{_h[0]} entries. The log was deleted, not never-created."
            )
            return False
        if os.path.exists(HEAD_FILE):
            _shutdown_on_chain_tamper(
                f"Audit chain file is MISSING and the head anchor ({HEAD_FILE}) "
                f"exists but does not verify. A first startup has neither file. "
                f"The presence of an anchor at all is evidence a chain existed; "
                f"corrupting it hides WHAT was logged, not THAT something was."
            )
            return False
        return True

    try:
        with open(CHAIN_FILE, "r") as f:
            lines = [l.strip() for l in f if l.strip()]
    except Exception as e:
        _shutdown_on_chain_tamper(
            f"Could not read audit chain file: {e}"
        )
        return False

    head = _read_head()

    if not lines:
        # An empty chain has no broken link, which is why emptying the file used to
        # pass. The anchor is the only thing that can tell "nothing has happened
        # yet" from "everything was deleted".
        if head is not None:
            _shutdown_on_chain_tamper(
                f"Audit chain is EMPTY but the head anchor records {head[0]} "
                f"entries. The log was truncated or deleted. Deleting the log is "
                f"not quieter than editing it."
            )
            return False
        # (external red-team, Astra, 2026-09-06) An attacker who can empty the log
        # can also reach the anchor. Emptying one and corrupting or deleting the
        # other silenced the check, because "no valid anchor" was read as "nothing
        # has happened yet".
        #
        # It is not. A fresh install has NO CHAIN FILE — the file is created by the
        # first record(), which also writes the anchor. A chain file that EXISTS,
        # is empty, and has no valid anchor is therefore not a fresh install: it is
        # either both files tampered, or a crash between creating the file and
        # writing the first entry. Both warrant refusing rather than proceeding.
        #
        # What this still does NOT catch: deleting BOTH files. That is
        # indistinguishable from a fresh install using only what is inside the box,
        # and no amount of local bookkeeping fixes it. It needs an anchor the
        # attacker cannot reach — an append-only sink, a co-signature from another
        # host, or physical media. Stated rather than papered over.
        _shutdown_on_chain_tamper(
            f"Audit chain file exists but is EMPTY and there is no valid head "
            f"anchor ({HEAD_FILE}). A first startup has no chain file at all — "
            f"this state is either both files tampered, or a crash between "
            f"creating the log and writing to it. Refusing either way."
        )
        return False

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

    # The chain is internally consistent. That is necessary and not sufficient: a
    # TRUNCATED chain is internally consistent too, and so is one an attacker
    # rebuilt from scratch. Compare the tail against the anchor.
    if head is not None:
        exp_seq, exp_hash = head
        if prev_sequence != exp_seq or prev_hash != exp_hash:
            _shutdown_on_chain_tamper(
                f"Audit chain tail does not match the head anchor. Expected entry "
                f"#{exp_seq}, found #{prev_sequence}. The chain is internally "
                f"consistent, which a truncated or rebuilt chain also is — the "
                f"anchor is what tells them apart."
            )
            return False
    elif lines:
        # A non-empty chain with no readable anchor. Either the anchor was deleted,
        # or its MAC no longer checks. Both are refusals: an anchor that can be
        # removed to silence the check is not an anchor.
        _shutdown_on_chain_tamper(
            f"Audit chain has {len(lines)} entries but no valid head anchor "
            f"({HEAD_FILE}). It was deleted, or its MAC does not verify. A chain "
            f"that verifies only against itself cannot detect truncation."
        )
        return False

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
