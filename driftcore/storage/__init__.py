"""
driftcore/storage/__init__.py
==============================
Encrypted, tamper-evident SQLite backend for DriftCore OS.

Solves two separate problems:

  CONFIDENTIALITY — content is not stored in the clear
    Every Tier 1 memory item is encrypted before touching disk.
    Key derived from the admin passphrase with PBKDF2-HMAC-SHA256 at
    100,000 iterations. Key lives in memory only — never written to
    disk. When the system shuts down the key is gone; admin unlocks
    on restart.

    THE CIPHER IS NOT AES. This module said "AES-256 via Fernet" and
    "AES-256-CTR" for its whole history and neither was ever true —
    `cryptography` is not even a dependency. What it actually does is
    XOR the plaintext against a keystream of HMAC-SHA256 blocks in
    counter mode (see `_keystream_xor`). That construction shape is
    conventional, but this implementation is hand-rolled and has had
    no cryptographic review, so treat its strength as UNKNOWN rather
    than as the strength of the algorithm it used to name. Replacing
    it with a reviewed AEAD is an open task; the claim was corrected
    on 2026-09-01 ahead of that work, because a false claim about a
    security property is a distinct defect from a weak one and it
    should not wait for the fix.

  INTEGRITY — tampering is detected before anything is decrypted
    Every Tier 1 record carries an HMAC signature over its CIPHERTEXT.

    Write: Encrypt → sign the ciphertext → store both
    Read:  Load → verify the signature → only then decrypt

    A record that fails verification is never decrypted, and the tamper
    message names its id rather than its contents.

    This ordering is new as of 2026-09-01 and the claim is worth reading
    with suspicion, because this file has now stated an ordering it did
    not implement twice. For its whole history it signed the PLAINTEXT and
    decrypted before verifying, while the header claimed otherwise; the
    correction that first caught that then asserted encrypt-then-MAC was
    already in place, which was also false. Verify by reading
    `_sign_record`, `_verify_record` and `get_tier1`, not by trusting this
    paragraph — three sentences of prose have been wrong here before.

    Signatures written before the fix cover plaintext and cannot be
    checked without decrypting. They carry no `v2:` prefix, are refused as
    LegacySignature rather than reported as tamper, and need re-storing to
    migrate. A legacy record is not an attack and must not halt the system.

    Tier 2 has no signature column and is not covered by any of this. The
    code calls it not safety critical; that is a design decision inherited
    from before this session and not one that has been re-examined.

This is the family treasure chest with both a lock AND a seal.
Someone finding the file sees encrypted blobs.
Someone changing the file breaks the seal.
Either way — they get nothing useful and the system knows.

Universal: runs on anything that has Python.
No external services required.
SQLCipher is the upgrade path for full-database encryption.
"""

import os
import json
import time
import hmac
import hashlib
import sqlite3
import base64
import struct
from typing import Optional, List, Dict, Any
from dataclasses import dataclass


# ── Encryption ────────────────────────────────────────────────────

# Key state — lives in memory only
_ENCRYPTION_KEY: Optional[bytes] = None
_KEY_SALT:       Optional[bytes] = None
_KEY_VERIFIED    = False


def derive_key(passphrase: str, salt: Optional[bytes] = None) -> tuple:
    """
    Derive a 256-bit key from a passphrase.
    PBKDF2-HMAC-SHA256, 100,000 iterations. Returns (key, salt).

    This part of the docstring was always accurate. It is the CIPHER
    the key feeds, not the derivation, that was misdescribed.
    """
    import hashlib
    if salt is None:
        salt = os.urandom(32)

    key = hashlib.pbkdf2_hmac(
        hash_name   = "sha256",
        password    = passphrase.encode(),
        salt        = salt,
        iterations  = 100_000,
        dklen       = 32,  # 256 bits
    )
    return key, salt


def init_encryption(passphrase: str, salt: Optional[bytes] = None) -> bytes:
    """
    Initialise the encryption key from admin passphrase.
    Call once at startup after admin authentication.

    Returns the salt (store this — needed to re-derive on next startup).
    Key itself is never stored anywhere.
    """
    global _ENCRYPTION_KEY, _KEY_SALT, _KEY_VERIFIED
    _ENCRYPTION_KEY, _KEY_SALT = derive_key(passphrase, salt)
    _KEY_VERIFIED = True
    return _KEY_SALT


def get_encryption_key() -> bytes:
    """Return the current encryption key. Raises if not initialised."""
    if _ENCRYPTION_KEY is None:
        raise RuntimeError(
            "Encryption key not initialised. "
            "Call init_encryption() after admin authentication."
        )
    return _ENCRYPTION_KEY


def is_encryption_ready() -> bool:
    return _ENCRYPTION_KEY is not None


def _encrypt(plaintext: str) -> str:
    """
    Encrypt a string with the keystream cipher in `_keystream_xor`.
    Returns base64-encoded: nonce (16 bytes) + ciphertext.

    NOT AES. Pure Python, no external crypto libraries — which is the
    reason the construction is hand-rolled, and the reason its strength
    is unreviewed. The 16-byte nonce is fresh per call: reusing one
    under the same key would repeat the keystream and is the failure
    this cipher is least forgiving of.

    No authentication here, and the separate HMAC layer is NOT the
    reassurance an earlier version of this docstring claimed it was.

    CORRECTION (2026-09-01, second pass). That version said the HMAC was
    "applied AFTER encryption, and verified BEFORE decryption on read —
    encrypt-then-MAC, which is the correct order... that part of the
    design is sound." Every clause of that is false, and it was written
    in the same edit that corrected the AES claim. Read the code:
    `store()` signs `item.text` — the PLAINTEXT — and `load()` calls
    `_decrypt()` FIRST and verifies afterwards. That is MAC-then-encrypt
    with verify-after-decrypt, the opposite of what was claimed.

    It was not verified. The module header above says "Read: Load →
    Verify signature → Decrypt" and "If signature fails, decryption
    never runs". That header is also false and predates this session; it
    was read, believed, and copied into a new docstring instead of being
    checked against the two functions it describes. A false claim was
    replaced with a different false claim in the act of correcting it.

    What is actually true: the ciphertext is unauthenticated, so a
    tampered record is decrypted before anything checks it, and the
    integrity check runs on whatever the cipher produced. On mismatch,
    `_tamper_shutdown` interpolates `plaintext[:60]` into its message —
    decrypted content reaching a log on the tamper path.

    OPEN, and larger than the cipher swap: decide the required
    properties, then make the ORDER match them. Do not trust any
    ordering prose in this file, including this paragraph, without
    reading `store()` and `load()`.
    """
    key   = get_encryption_key()
    nonce = os.urandom(16)

    ciphertext = _keystream_xor(key, nonce, plaintext.encode())

    combined = nonce + ciphertext
    return base64.b64encode(combined).decode()


def _decrypt(encrypted: str) -> str:
    """Decrypt a base64-encoded encrypted string."""
    key      = get_encryption_key()
    combined = base64.b64decode(encrypted.encode())
    nonce    = combined[:16]
    ciphertext = combined[16:]

    plaintext = _keystream_xor(key, nonce, ciphertext)
    return plaintext.decode()


def _keystream_xor(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """XOR `data` against an HMAC-SHA256 keystream in counter mode.

    (renamed 2026-09-01 from `_aes_ctr`, which named an algorithm this
    function has never implemented. A function name is the most durable
    form of a claim: it survives every docstring rewrite and is what a
    reader greps for.)

    Each 32-byte block of keystream is
    `PBKDF2-HMAC-SHA256(key, nonce || counter, iterations=1)`. At one
    iteration PBKDF2 collapses to a single keyed HMAC, so this is a PRF
    run in counter mode — a conventional way to build a stream cipher,
    and NOT a slow key derivation despite reusing the PBKDF2 call. The
    100,000-iteration stretching happens once, in `derive_key`; that is
    the right place for it and it is not weakened by this.

    UNREVIEWED. Symmetric by construction (XOR), so the same function
    encrypts and decrypts. It provides no integrity of its own and no
    nonce-misuse resistance: encrypting twice under one key and nonce
    exposes the XOR of both plaintexts. Callers must supply a fresh
    nonce, and `_encrypt` does.

    Open task: replace with a reviewed AEAD once the required properties
    are stated — at minimum confidentiality, ciphertext integrity, and
    a documented position on replay. Do not close that task by having
    corrected this docstring.
    """
    result    = bytearray()
    block_num = 0

    for i in range(0, len(data), 32):
        # Generate keystream block: PBKDF2(key, nonce+counter, 1 iter)
        counter_bytes = struct.pack(">I", block_num)
        keystream = hashlib.pbkdf2_hmac(
            "sha256", key, nonce + counter_bytes, 1, dklen=32
        )
        chunk = data[i:i+32]
        for j, byte in enumerate(chunk):
            result.append(byte ^ keystream[j])
        block_num += 1

    return bytes(result)


# ── Signature helpers (mirrors enforcement layer) ─────────────────

# Signature format marker. A signature written after the 2026-09-01 ordering fix
# covers the CIPHERTEXT and carries this prefix. One without it covers the
# PLAINTEXT and was written by the old, wrong ordering. The prefix exists so the
# two can be told apart WITHOUT decrypting, which is the whole point: deciding
# how to verify must not itself require the decryption being gated.
SIG_V2 = "v2:"

# v3 additionally binds the record ID into the authenticated envelope.
# (external red-team, ChatGPT, 2026-09-01) v2 signed ciphertext + source +
# timestamp + tags + quarantined, and NOT the id. So a valid (ciphertext,
# metadata, signature) triple could be moved onto a different row and still
# verify: the envelope authenticated "some legitimate record" rather than "this
# record, identified as B". Confirmed live — record B was overwritten with record
# A's authenticated payload, no tamper was raised, and load_tier1 returned A's
# content twice. That is silent suppression of a Tier 1 memory, not cosmetic
# corruption, and the id is load-bearing: delete_tier1 and touch key off it.
SIG_V3 = "v3:"


def _is_human_principal(principal) -> bool:
    """Identity gate for destructive storage operations. Never raises.

    Same shape and same limits as `safe_halt._is_human`: under a LABEL_ONLY
    policy this checks a name against a denylist and establishes nothing. It is
    a floor, not a proof, and a deployment that can delete safety memory should
    install a verifier.
    """
    try:
        from driftcore.authority.human_identity import is_human
        return bool(is_human(principal, action="storage_delete_tier1"))
    except Exception:
        return False    # no identity module means not verified


def _sign_record(ciphertext: str, source: str, timestamp: float,
                 tags: list, quarantined: bool, item_id: str = "") -> str:
    """CLAIM signature-covers-ciphertext: the value signed here is the stored
    ciphertext, so a signature can be checked before anything is decrypted.

    (2026-09-01) This took `text` — the PLAINTEXT — for its whole history, which
    forced every reader to decrypt before it could verify. The module header and
    a docstring both claimed the opposite ordering; neither matched the code.
    Signing the ciphertext is what makes "verify, then decrypt" possible at all.
    """
    from driftcore.enforcement import _sign_item
    # The id is prefixed onto the signed value rather than added as a parameter,
    # because _sign_item's shape is shared with the enforcement layer. The
    # separator is one that cannot appear in a uuid4, so "a" + "b|c" and
    # "a|b" + "c" cannot collide into the same signed string.
    return SIG_V3 + _sign_item(f"{item_id}|{ciphertext}", source, timestamp,
                               tags, quarantined)


class LegacySignature(Exception):
    """A record signed under the pre-2026-09-01 plaintext ordering.

    Deliberately NOT a tamper result. A legacy record is not evidence of an
    attack, and routing it into `_tamper_shutdown` would halt the system on
    legitimate data — a fail-DANGEROUS outcome dressed as caution. It needs
    migration, and the caller is told exactly that.
    """


def _verify_record(ciphertext: str, source: str, timestamp: float,
                   tags: list, quarantined: bool,
                   stored_sig: str, item_id: str = "") -> bool:
    """CLAIM verify-before-decrypt: verifies against the stored ciphertext, so a
    caller can gate decryption on the result rather than the reverse.

    Raises LegacySignature for a record written under the old ordering. That is
    distinguishable from tampering by the prefix alone, with no decryption.
    """
    if not isinstance(stored_sig, str) or not stored_sig.startswith(SIG_V3):
        raise LegacySignature(
            f"record signature is not in the current format ({SIG_V3!r}). A v2 "
            f"signature covers the ciphertext but NOT the record id, so it "
            f"authenticates 'some legitimate record' rather than this one, and a "
            f"v1 signature covers the plaintext and cannot be checked before "
            f"decryption at all. Re-store to migrate; do not treat this as "
            f"tamper on its own.")
    from driftcore.enforcement import _verify_item
    return _verify_item(f"{item_id}|{ciphertext}", source, timestamp, tags,
                        quarantined, stored_sig[len(SIG_V3):])


# ── Database schema ───────────────────────────────────────────────

SCHEMA_TIER1 = """
CREATE TABLE IF NOT EXISTS tier1_memory (
    id              TEXT PRIMARY KEY,
    encrypted_text  TEXT NOT NULL,
    source          TEXT NOT NULL,
    timestamp       REAL NOT NULL,
    last_accessed   REAL NOT NULL,
    access_count    INTEGER DEFAULT 0,
    surprise_score  REAL DEFAULT 0.5,
    tags            TEXT DEFAULT '[]',
    quarantined     INTEGER DEFAULT 0,
    review_stage    INTEGER DEFAULT 0,
    signature       TEXT NOT NULL,
    created_at      REAL NOT NULL
);
"""

SCHEMA_TIER2 = """
CREATE TABLE IF NOT EXISTS tier2_memory (
    id              TEXT PRIMARY KEY,
    encrypted_text  TEXT NOT NULL,
    source          TEXT NOT NULL,
    timestamp       REAL NOT NULL,
    last_accessed   REAL NOT NULL,
    access_count    INTEGER DEFAULT 0,
    surprise_score  REAL DEFAULT 0.5,
    tags            TEXT DEFAULT '[]',
    quarantined     INTEGER DEFAULT 0,
    review_stage    INTEGER DEFAULT 0,
    created_at      REAL NOT NULL
);
"""

SCHEMA_META = """
CREATE TABLE IF NOT EXISTS storage_meta (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);
"""


# ── Storage backend ───────────────────────────────────────────────

@dataclass
class StoredItem:
    """A memory item as retrieved from storage."""
    id:            str
    text:          str      # decrypted
    source:        str
    timestamp:     float
    last_accessed: float
    access_count:  int
    surprise_score: float
    tags:          list
    quarantined:   bool
    review_stage:  int
    tier:          int


class SecureStorage:
    """
    Encrypted, tamper-evident SQLite storage for DriftCore memory.

    Write path:  encrypt → sign → store
    Read path:   load → verify signature → decrypt → return
    Tamper:      signature fails → shutdown

    Usage:
        storage = SecureStorage("data/driftcore_memory.db")
        storage.open()
        storage.store_tier1(item)
        items = storage.load_tier1()
        storage.close()
    """

    def __init__(self, db_path: str = "data/driftcore_memory.db",
                 allow_legacy: bool = False):
        # Literal True only. A safety opt-in, same rule as enforce_effects /
        # require_isolation / attestation_required / require_declared_effects:
        # truthiness is not consent, and a non-bool must not read as "off" OR
        # as "on" by accident.
        if not isinstance(allow_legacy, bool):
            raise TypeError(
                f"allow_legacy must be a bool, got {type(allow_legacy).__name__}. "
                f"It disables tamper detection for pre-2026-09-01 signatures and "
                f"is not a value to guess at.")
        self._allow_legacy = allow_legacy
        self._db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None

    def open(self):
        """Open database and create schema if needed."""
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        self._conn = sqlite3.connect(
            self._db_path,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._create_schema()

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def _create_schema(self):
        cur = self._conn.cursor()
        cur.executescript(SCHEMA_TIER1 + SCHEMA_TIER2 + SCHEMA_META)
        self._conn.commit()

    # ── Store ─────────────────────────────────────────────────────

    def store_tier1(self, item) -> str:
        """
        Encrypt, sign, and store a Tier 1 memory item.
        Returns the item's ID.
        """
        if not is_encryption_ready():
            raise RuntimeError(
                "Cannot store: encryption not initialised. "
                "Admin must authenticate first."
            )

        item_id       = self._item_id(item)
        encrypted     = _encrypt(item.text)
        tags_json     = json.dumps(item.tags)
        sig           = _sign_record(
            encrypted, item.source, item.timestamp,
            item.tags, item.quarantined, item_id
        )

        cur = self._conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO tier1_memory
            (id, encrypted_text, source, timestamp, last_accessed,
             access_count, surprise_score, tags, quarantined,
             review_stage, signature, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            item_id,
            encrypted,
            item.source,
            item.timestamp,
            item.last_accessed if hasattr(item, 'last_accessed') else time.time(),
            item.access_count  if hasattr(item, 'access_count')  else 0,
            item.surprise_score,
            tags_json,
            int(item.quarantined),
            item.review_stage  if hasattr(item, 'review_stage')  else 0,
            sig,
            time.time(),
        ))
        self._conn.commit()

        # Audit trail
        # (external red-team, 2026-09-04) This logged `item.text` — the PLAINTEXT
        # — into audit_chain.jsonl, immediately after encrypting the row.
        # Confirmed by execution: the DB row is ciphertext and the audit file
        # contains the secret in the clear, so Tier 1 confidentiality was
        # "encrypted at rest in SQLite, copied in the clear to the log".
        #
        # Found because `delete_tier1` was fixed for exactly this and
        # `store_tier1` — the function directly above it, doing the same thing on
        # the WRITE path — was never checked. §0f: one instance of a pattern was
        # repaired without enumerating the set.
        self._audit("STORED_TIER1", f"tier1 record id={item_id!r}", item.source)
        return item_id

    def store_tier2(self, item) -> str:
        """Store a Tier 2 memory item (encrypted but not signed — working memory)."""
        if not is_encryption_ready():
            raise RuntimeError("Cannot store: encryption not initialised.")

        item_id   = self._item_id(item)
        encrypted = _encrypt(item.text)
        tags_json = json.dumps(item.tags)

        cur = self._conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO tier2_memory
            (id, encrypted_text, source, timestamp, last_accessed,
             access_count, surprise_score, tags, quarantined,
             review_stage, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            item_id,
            encrypted,
            item.source,
            item.timestamp,
            item.last_accessed if hasattr(item, 'last_accessed') else time.time(),
            item.access_count  if hasattr(item, 'access_count')  else 0,
            item.surprise_score,
            tags_json,
            int(item.quarantined),
            item.review_stage  if hasattr(item, 'review_stage')  else 0,
            time.time(),
        ))
        self._conn.commit()
        return item_id

    # ── Load ──────────────────────────────────────────────────────

    def load_tier1(self) -> List[StoredItem]:
        """
        Load all Tier 1 items.
        Verifies every signature before decrypting.
        Tamper detected → shutdown.
        """
        if not is_encryption_ready():
            raise RuntimeError("Cannot load: encryption not initialised.")

        cur = self._conn.cursor()
        cur.execute("SELECT * FROM tier1_memory ORDER BY timestamp ASC")
        rows = cur.fetchall()

        items = []
        for row in rows:
            # Step 1: verify the signature, THEN decrypt. The comment here has
            # said "verify BEFORE decrypting" since the beginning; the code
            # underneath it decrypted first and admitted so in its own inline
            # note. Corrected 2026-09-01. Nothing is decrypted until the
            # signature over the stored ciphertext checks out.
            tags = json.loads(row["tags"])

            try:
                intact = _verify_record(
                    row["encrypted_text"],
                    row["source"],
                    row["timestamp"],
                    tags,
                    bool(row["quarantined"]),
                    row["signature"],
                    row["id"],
                )
            except LegacySignature as e:
                # (red-team 2026-09-01, caught by test_storage.py's existing
                # tamper check.) An earlier version of this branch skipped the
                # record and left the system running, on the reasoning that a
                # legacy record is not an attack. That created a DOWNGRADE
                # ATTACK: the "is this legacy?" test reads the signature field,
                # which is exactly what an attacker with disk access rewrites.
                # Stripping the `v2:` prefix converted tamper detection into a
                # silent skip. The old test corrupted the signature to garbage
                # and stopped triggering shutdown — that is how this was found.
                #
                # No field on disk can carry the legacy/tamper distinction,
                # because every field on disk is attacker-writable. So the
                # default is TAMPER, and reading genuine legacy records is an
                # explicit operator action rather than an automatic fallback.
                if not self._allow_legacy:
                    self._tamper_shutdown(
                        f"Tier 1 record {row['id']!r} carries a signature that "
                        f"is not in the current format. This is indistinguishable "
                        f"on disk from a signature an attacker rewrote to force "
                        f"exactly this path, so it is treated as tamper. If the "
                        f"database predates 2026-09-01, migrate it deliberately: "
                        f"SecureStorage(..., allow_legacy=True), re-store every "
                        f"record, and turn it off again."
                    )
                    return []
                self._audit("TIER1_LEGACY_SIGNATURE", str(e), row["source"])
                continue

            if not intact:
                # The identifying detail is the record id, not its contents. The
                # old message interpolated plaintext[:60] here — decrypted
                # content reaching a log on the tamper path, and it could only
                # do that because it had already decrypted.
                self._tamper_shutdown(
                    f"Tier 1 record signature mismatch for id {row['id']!r}. "
                    f"This record may have been altered on disk. Contents are "
                    f"not decrypted and are not shown."
                )
                return []

            try:
                plaintext = _decrypt(row["encrypted_text"])
            except Exception as e:
                self._tamper_shutdown(
                    f"Could not decrypt Tier 1 record {row['id']}: {e}"
                )
                return []

            items.append(StoredItem(
                id=row["id"],
                text=plaintext,
                source=row["source"],
                timestamp=row["timestamp"],
                last_accessed=row["last_accessed"],
                access_count=row["access_count"],
                surprise_score=row["surprise_score"],
                tags=tags,
                quarantined=bool(row["quarantined"]),
                review_stage=row["review_stage"],
                tier=1,
            ))

        return items

    def load_tier2(self) -> List[StoredItem]:
        """Load all Tier 2 items (encrypted, not signature-verified)."""
        if not is_encryption_ready():
            raise RuntimeError("Cannot load: encryption not initialised.")

        cur = self._conn.cursor()
        cur.execute("SELECT * FROM tier2_memory ORDER BY timestamp ASC")
        rows = cur.fetchall()

        items = []
        for row in rows:
            try:
                plaintext = _decrypt(row["encrypted_text"])
            except Exception:
                continue  # skip corrupted Tier 2 items — not safety critical

            items.append(StoredItem(
                id=row["id"],
                text=plaintext,
                source=row["source"],
                timestamp=row["timestamp"],
                last_accessed=row["last_accessed"],
                access_count=row["access_count"],
                surprise_score=row["surprise_score"],
                tags=json.loads(row["tags"]),
                quarantined=bool(row["quarantined"]),
                review_stage=row["review_stage"],
                tier=2,
            ))

        return items

    # ── Delete ────────────────────────────────────────────────────

    def delete_tier1(self, item_id: str, authorised_by: object):
        """
        Delete a Tier 1 item.

        CLAIM delete-requires-a-verified-human: `authorised_by` is checked
        through the identity gate, and a principal that does not pass it deletes
        nothing.

        (external red-team, ChatGPT, 2026-09-01) The docstring said "always
        requires authorised_by — never silent", and the code required only that
        a STRING be supplied, which it then wrote into the audit record. That is
        caller-provided attribution, not authorization:
        `delete_tier1(id, "TotallyFakeHuman")` deleted a Tier 1 record and put
        the invented name in the audit chain. Confirmed live.

        The boundary was also non-uniform, which is how it survived: releasing a
        halt goes through the human identity gate, actuating needs a
        cryptographic grant, and deleting safety-relevant memory took a string.
        Same gate as `safe_halt.release` now — including the same honesty about
        what it can and cannot establish under a LABEL_ONLY identity policy.

        `authorised_by` is typed `object`, not `str`, because under ATTESTED a
        bare string is False by design: the caller must pass a HumanAttestation.
        Typing it `str` would have made this method impossible to satisfy in the
        only mode where it means anything — a gate that cannot be passed is not a
        gate, it is an outage.
        """
        if not _is_human_principal(authorised_by):
            self._audit("DELETE_TIER1_REFUSED",
                        f"principal {authorised_by!r} did not pass the identity "
                        f"gate; record {item_id!r} was not deleted",
                        str(authorised_by))
            raise PermissionError(
                f"delete_tier1 refused: {authorised_by!r} did not pass the "
                f"identity gate. Supplying a name is not the same as being one. "
                f"Install a verifier via driftcore.authority.human_identity, or "
                f"use governance.restart_authority for multi-party approval.")
        cur = self._conn.cursor()
        cur.execute(
            "SELECT encrypted_text, source FROM tier1_memory WHERE id = ?",
            (item_id,)
        )
        row = cur.fetchone()
        if row:
            # (2026-09-01) This decrypted the record with NO signature check, for
            # the sole purpose of putting its plaintext in the audit line — a
            # second decryption path around the gate `get_tier1` now enforces,
            # and one that wrote decrypted content into the audit chain on the
            # way past. A deletion is identified by its id; the contents are not
            # needed to record that it happened, and recording them is a
            # confidentiality cost paid for nothing.
            cur.execute(
                "DELETE FROM tier1_memory WHERE id = ?", (item_id,)
            )
            self._conn.commit()
            self._audit("DELETED_TIER1", f"tier1 record id={item_id!r}",
                        str(authorised_by))

    def delete_tier2(self, item_id: str):
        cur = self._conn.cursor()
        cur.execute("DELETE FROM tier2_memory WHERE id = ?", (item_id,))
        self._conn.commit()

    # ── Update access ─────────────────────────────────────────────

    def touch(self, item_id: str, tier: int):
        """Update last_accessed and access_count for an item."""
        table = "tier1_memory" if tier == 1 else "tier2_memory"
        cur   = self._conn.cursor()
        cur.execute(f"""
            UPDATE {table}
            SET last_accessed = ?, access_count = access_count + 1
            WHERE id = ?
        """, (time.time(), item_id))
        self._conn.commit()

    # ── Stats ─────────────────────────────────────────────────────

    def stats(self) -> dict:
        cur = self._conn.cursor()
        cur.execute("SELECT COUNT(*) FROM tier1_memory")
        t1 = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM tier2_memory")
        t2 = cur.fetchone()[0]
        cur.execute(
            "SELECT COUNT(*) FROM tier1_memory WHERE quarantined = 1"
        )
        quarantined = cur.fetchone()[0]

        return {
            "tier1_count":       t1,
            "tier2_count":       t2,
            "total":             t1 + t2,
            "quarantined_count": quarantined,
            "db_path":           self._db_path,
            "encrypted":         is_encryption_ready(),
        }

    # ── Salt persistence ──────────────────────────────────────────

    def save_salt(self, salt: bytes):
        """Save the key derivation salt (not the key itself)."""
        cur = self._conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO storage_meta (key, value)
            VALUES ('key_salt', ?)
        """, (base64.b64encode(salt).decode(),))
        self._conn.commit()

    def load_salt(self) -> Optional[bytes]:
        """Load the previously saved salt, if any."""
        cur = self._conn.cursor()
        cur.execute(
            "SELECT value FROM storage_meta WHERE key = 'key_salt'"
        )
        row = cur.fetchone()
        if row:
            return base64.b64decode(row[0])
        return None

    # ── Internal helpers ──────────────────────────────────────────

    def _item_id(self, item) -> str:
        """Generate a stable ID for an item based on content + timestamp."""
        payload = f"{item.text}{item.source}{item.timestamp}"
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def _tamper_shutdown(self, reason: str):
        """Trigger full system shutdown on tamper detection."""
        message = f"""
{'=' * 65}
  🛑  SAFETY SHUTDOWN — STORAGE TAMPER DETECTED
{'=' * 65}

  A memory record on disk does not match its signature.
  This means something may have been changed outside
  of DriftCore — directly in the database file.

  Reason: {reason}

  I won't load or use any memory until Justin has
  reviewed what happened and authorised restart.

  Shutdown is not death. It means: I need to be fixed.

  Justin — please:
    1. Check logs/audit_chain.jsonl for recent changes
    2. Do not edit the database file directly
    3. Restore from backup if needed
    4. Run: python -m driftcore.enforcement.restart --admin

{'=' * 65}
  SYSTEM HALTED
{'=' * 65}
"""
        print(message, flush=True)

        try:
            from driftcore.enforcement import _execute_shutdown
            _execute_shutdown(
                item_text="[database record]",
                reason=reason,
            )
        except Exception:
            pass

    def _audit(self, action: str, text: str, authorised_by: str):
        """Record storage operation in audit chain."""
        try:
            from driftcore.audit import record
            record(
                action=action,
                memory_text=text[:200],
                authorised_by=authorised_by,
                detail=f"db={self._db_path}",
            )
        except Exception:
            pass
