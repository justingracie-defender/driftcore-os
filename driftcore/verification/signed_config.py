"""
driftcore/verification/signed_config.py
=======================================
STATUS: PROPOSED (stdlib-only). Tamper-evident config loading.

THE HOLE THIS RAISES THE COST OF. Config that the system trusts and a COMPLIANT
agent follows — skills configs, domain state, serialized profiles, invariant
parameters — is only as trustworthy as the file it is read from. If the agent's
own process can WRITE that file, you do not need to jailbreak a rule-following
agent: you edit the rules it follows. The very compliance that makes such an agent
safe becomes the lever that steers it. (The hard constitutional floor in
invariant_guard.py is enforced as CODE, not loaded from JSON, so it is out of this
file's reach — but everything genuinely loaded from disk is in scope.)

WHAT THIS DOES. Signs config with an operator key (HMAC-SHA256 over a canonical
JSON encoding) and REFUSES TO LOAD anything whose signature does not verify. An
agent that rewrites the JSON cannot forge the signature without the key, so a
tampered config fails CLOSED instead of silently steering the agent. Unsigned
config is refused too — absence of a signature is not a pass.

THE HONEST LIMIT (turtles all the way down). The verification key lives in this
process's memory, exactly like the config. Anything that can READ this process's
memory can read the key and re-sign its own edit. So this is DEFENSE IN DEPTH, not
a wall:
  * It STOPS tampering by anything that lacks the key — naive file edits, wrong
    file permissions, a supply-chain package that can write files but cannot read
    our memory, a separate low-privilege process.
  * It RAISES THE COST for an in-process adversary (it now needs memory read, not
    just a file write).
  * It does NOT close the shared-address-space hole. Only moving the key AND the
    authoritative config into a SEPARATE PROCESS the agent cannot read or write
    (the broker / reference monitor) closes it.
This module is deliberately the FIRST BRICK of that broker: the broker runs
exactly this verification on its privileged side, where the key is finally out of
the agent's reach. Until then, pair it with OS file permissions (config read-only
to the agent's user) and, where available, hold the key via an OS keyring handle
(pass a callable as `key`) rather than a literal string. See THREAT_BOUNDARIES §6.
"""
from __future__ import annotations

import hmac
import json
import hashlib
from typing import Any, Callable, Union

KeyLike = Union[str, bytes, Callable[[], Union[str, bytes]]]

_ALG = "HMAC-SHA256"


class ConfigIntegrityError(Exception):
    """Raised whenever config cannot be proven authentic. ALWAYS fail closed on
    this — never fall back to the unverified bytes."""


def _canonical(obj: Any) -> bytes:
    # Deterministic: key order and whitespace cannot change the signed bytes,
    # so re-serialization by a different writer does not break a valid signature.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _resolve_key(key: KeyLike) -> bytes:
    """Accept a raw string/bytes OR a callable that returns one (e.g. an OS
    keyring lookup), so the literal secret need not be held in a variable."""
    if callable(key):
        key = key()
    if isinstance(key, str):
        key = key.encode("utf-8")
    if not isinstance(key, (bytes, bytearray)) or len(key) == 0:
        raise ConfigIntegrityError("invalid or empty signing key")
    return bytes(key)


def sign(config: Any, key: KeyLike, *, key_id: str = "") -> dict:
    """Return a signed envelope: {alg, key_id, config, sig}. `key_id` is recorded
    (unencrypted, for key rotation/audit) and is COVERED by the signature, so it
    cannot be swapped without detection."""
    payload = {"alg": _ALG, "key_id": key_id, "config": config}
    sig = hmac.new(_resolve_key(key), _canonical(payload), hashlib.sha256).hexdigest()
    return {**payload, "sig": sig}


def verify(envelope: Any, key: KeyLike) -> Any:
    """Return the config IFF the envelope's signature verifies; else raise. An
    envelope with no `sig`, a wrong `sig`, an unexpected `alg`, or the wrong key
    all fail closed."""
    if not isinstance(envelope, dict) or "sig" not in envelope:
        raise ConfigIntegrityError(
            "no signature present — refusing to load unsigned config (absence is not a pass)")
    if envelope.get("alg") != _ALG:
        raise ConfigIntegrityError(f"unexpected signature algorithm: {envelope.get('alg')!r}")
    provided = envelope["sig"]
    payload = {k: v for k, v in envelope.items() if k != "sig"}
    expected = hmac.new(_resolve_key(key), _canonical(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(provided), expected):   # constant-time
        raise ConfigIntegrityError(
            "signature mismatch — config has been altered, or the wrong key was used")
    return payload["config"]


def write_signed(path: str, config: Any, key: KeyLike, *, key_id: str = "") -> None:
    """Sign `config` and write the envelope to `path` as JSON."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sign(config, key, key_id=key_id), f, ensure_ascii=False, indent=2)


def load_verified(path: str, key: KeyLike) -> Any:
    """Read `path`, verify its signature, and return the config. Raises
    ConfigIntegrityError on a missing file being unreadable-as-JSON, a missing or
    bad signature, or the wrong key. Callers MUST treat the exception as a hard
    stop (use last-known-good or halt) — never load the raw bytes on failure."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            envelope = json.load(f)
    except (OSError, ValueError) as e:
        raise ConfigIntegrityError(f"config at {path!r} could not be read as JSON: {e}")
    return verify(envelope, key)


# ── detached mode: config file stays plain, signature in a sidecar ──
# Use when the config MUST remain human-readable/editable through the normal
# pipeline and you cannot wrap it in an envelope. The plain file + its .sig are
# verified together; editing either without the key fails closed.
def detached_signature(raw_bytes: bytes, key: KeyLike, *, key_id: str = "") -> dict:
    sig = hmac.new(_resolve_key(key), raw_bytes, hashlib.sha256).hexdigest()
    return {"alg": _ALG, "key_id": key_id, "sig": sig}


def verify_detached(raw_bytes: bytes, sidecar: dict, key: KeyLike) -> bool:
    if not isinstance(sidecar, dict) or sidecar.get("alg") != _ALG or "sig" not in sidecar:
        raise ConfigIntegrityError("missing or malformed detached signature")
    expected = hmac.new(_resolve_key(key), raw_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(sidecar["sig"]), expected):
        raise ConfigIntegrityError("detached signature mismatch — file altered or wrong key")
    return True
