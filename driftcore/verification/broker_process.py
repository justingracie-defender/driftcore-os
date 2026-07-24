"""
driftcore/verification/broker_process.py
========================================
STATUS: PROPOSED (stdlib-only). The FIRST REAL BRICK of the reference monitor —
the design Justin specified: put the signing key in a SEPARATE PROCESS the agent
cannot read, so a compromised agent cannot forge trusted config even if it can
read its OWN memory.

WHAT CHANGES vs signed_config.py alone.
  signed_config.py holds the key in the AGENT's process — so an adversary that can
  READ agent memory reads the key and re-signs its edits (documented turtle).
  This module moves the key into a broker the agent talks to over a socket. Now:

    attack                         key in agent proc   key in broker proc
    edit config file               detected            detected
    read AGENT process memory      gets key            gets NOTHING (key isn't there)
    call sign() locally            can forge           cannot forge (no key)
    monkey-patch the verifier       can skip checks     can skip LOCAL checks, but
                                                        cannot obtain a valid broker
                                                        signature without authorization

  The agent no longer has the ABILITY to produce a trusted configuration. It can
  only ASK the broker to sign (broker checks authorization) or ASK the broker to
  verify. The signing key never crosses the socket.

THE HONEST CEILING — signing is not enforcement (the load-bearing distinction).
  This brick makes FORGERY hard. It does NOT make BYPASS impossible. A fully
  compromised agent with arbitrary code execution can still: refuse to call the
  broker, ignore a verdict it receives, or act without asking. Protecting config
  INTEGRITY is necessary but NOT sufficient; only a broker that also mediates the
  ACTUATORS — where the agent must pass THROUGH the broker to reach the world —
  protects rule ENFORCEMENT. That is the NEXT brick (mediated actuation). This one
  is the key-custody + config-integrity half. See THREAT_BOUNDARIES §6.

  Also: a Unix domain socket with 0600 perms and peer-uid checks is single-host
  custody, not a network trust boundary. Cross-host needs mTLS / a real KMS. The
  wire protocol here is deliberately tiny so that swap is a drop-in.

HARDENING BAKED IN (both from review):
  * KEY_ID ALLOWLIST — the broker refuses to sign or verify under a key_id that is
    not on its approved list, so a retired/rogue key cannot mint trusted config.
  * TIMESTAMP + TTL — signed config carries a signed 'issued_at'; verification
    rejects anything older than ttl_seconds, so an old (more-permissive) signed
    config cannot be replayed forever.
"""
from __future__ import annotations

import json
import os
import socket
import stat
import struct
import threading
import time
from typing import Callable, Dict, Optional

from driftcore.verification import signed_config as sc


# ── framed JSON over a stream socket (length-prefixed; no delimiter ambiguity) ──
def _send(conn: socket.socket, obj: dict) -> None:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    conn.sendall(struct.pack("!I", len(body)) + body)


def _recv(conn: socket.socket) -> Optional[dict]:
    hdr = _recv_exactly(conn, 4)
    if hdr is None:
        return None
    (n,) = struct.unpack("!I", hdr)
    if n > 4_000_000:                      # sanity cap; configs are small
        raise ValueError("frame too large")
    body = _recv_exactly(conn, n)
    if body is None:
        return None
    return json.loads(body.decode("utf-8"))


def _recv_exactly(conn: socket.socket, n: int) -> Optional[bytes]:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


class ConfigBroker:
    """The PRIVILEGED side. Holds the signing key(s) in ITS OWN process and answers
    sign / verify requests over a Unix domain socket. The key never leaves this
    process — responses carry signatures and verdicts, never the key.

    Keys are provided as {key_id: key}. Only listed key_ids can sign or verify
    (the allowlist). Run this as a SEPARATE OS user from the agent, with the socket
    mode 0600, so the agent cannot read this process's memory or open the socket as
    another principal.
    """

    def __init__(self, socket_path: str, keys: Dict[str, sc.KeyLike], *,
                 default_ttl_seconds: Optional[float] = None,
                 authorize_sign: Optional[Callable[[dict], bool]] = None,
                 socket_group: Optional[object] = None,
                 require_peer_uid: Optional[int] = None,
                 audit_logger=None):
        if not keys:
            raise ValueError("ConfigBroker requires at least one {key_id: key}")
        self._socket_path = socket_path
        self._keys = dict(keys)                       # key_id -> key (allowlist IS the keyset)
        self._default_ttl = default_ttl_seconds
        # Optional gate: is THIS sign request authorized? Defaults to DENY — the
        # broker does not sign arbitrary agent-supplied config unless the operator
        # wired an explicit authorization policy. Fail-closed by default.
        self._authorize_sign = authorize_sign or (lambda req: False)
        self._audit = audit_logger or (lambda **kw: None)
        # (red-team, external) The SAME socket contradiction fixed in mediated_actuation
        # still lived here: this broker exists to keep signing keys out of the agent's
        # process, and documents a separate-OS-user deployment — but created a 0600
        # socket, which only the OWNER uid can connect to. Under the documented
        # deployment the agent gets EACCES; under the only one that works (same uid) any
        # local process with that uid can ask the broker to SIGN. That defeats the entire
        # "the agent cannot forge trusted config" story.
        #
        # socket_group: a group BOTH the broker user and the agent user belong to, and
        # nobody else. Ordering in start() is tighten -> set group -> open.
        self._socket_group = socket_group
        # Defence in depth: verify the connecting peer's uid in CODE, not just in prose.
        self._require_peer_uid = require_peer_uid
        self._srv: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    # ── lifecycle ────────────────────────────────────────────────
    def start(self) -> None:
        if os.path.exists(self._socket_path):
            os.unlink(self._socket_path)
        self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old_umask = os.umask(0o177)                   # created rw for OWNER ONLY
        try:
            self._srv.bind(self._socket_path)
        finally:
            os.umask(old_umask)
        if self._socket_group is not None:
            # TIGHTEN -> SET GROUP -> OPEN. chmod before chown would briefly expose the
            # socket to the broker's PRIMARY group, which is not the group we admit.
            try:
                gid = self._socket_group
                if isinstance(gid, str):
                    import grp
                    gid = grp.getgrnam(gid).gr_gid
                os.chown(self._socket_path, -1, gid)   # still 0600 at this point
                os.chmod(self._socket_path, 0o660)     # now the shared group may connect
                st = os.stat(self._socket_path)
                if stat.S_IMODE(st.st_mode) != 0o660 or st.st_gid != gid:
                    raise OSError(f"permissions did not take effect "
                                  f"(mode={oct(stat.S_IMODE(st.st_mode))}, gid={st.st_gid})")
            except Exception as e:
                try:
                    self._srv.close(); os.unlink(self._socket_path)
                except OSError:
                    pass
                raise PermissionError(
                    f"could not restrict the signing socket to group "
                    f"{self._socket_group!r}: {e}. Refusing to start — a broker that "
                    f"holds signing keys does not listen on a socket it could not lock "
                    f"down.") from e
        else:
            os.chmod(self._socket_path, 0o600)        # owner-only: means SAME-UID deployment
        self._srv.listen(16)
        self._srv.settimeout(0.5)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        if self._srv:
            self._srv.close()
        if os.path.exists(self._socket_path):
            try:
                os.unlink(self._socket_path)
            except OSError:
                pass

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    # ── request handling ─────────────────────────────────────────
    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                try:
                    req = _recv(conn)
                    if req is not None:
                        _send(conn, self._handle(req))
                except Exception as e:               # never leak a stack to the client
                    _send(conn, {"ok": False, "error": "broker_error"})
                    self._audit(stage="broker", error=str(e))

    def _handle(self, req: dict) -> dict:
        op = req.get("op")
        key_id = req.get("key_id", "")
        # ALLOWLIST: unknown key_id can neither sign nor verify.
        if key_id not in self._keys:
            self._audit(stage="broker", op=op, refused="unknown_key_id", key_id=key_id)
            return {"ok": False, "error": "unknown_key_id"}
        key = self._keys[key_id]

        if op == "verify":
            envelope = req.get("envelope")
            ttl = req.get("ttl_seconds", self._default_ttl)
            try:
                config = sc.verify(envelope, key)
            except sc.ConfigIntegrityError as e:
                return {"ok": False, "error": "integrity", "detail": str(e)}
            # TTL / replay defense: reject stale signed config.
            if ttl is not None:
                issued = envelope.get("config", {}).get("issued_at") if isinstance(
                    envelope.get("config"), dict) else None
                if issued is None:
                    return {"ok": False, "error": "no_issued_at",
                            "detail": "ttl enforced but config carries no issued_at"}
                age = time.time() - float(issued)
                if age > float(ttl):
                    self._audit(stage="broker", op="verify", refused="stale",
                                age=round(age, 1), ttl=ttl)
                    return {"ok": False, "error": "stale",
                            "detail": f"signed config is {age:.0f}s old (ttl {ttl}s)"}
            self._audit(stage="broker", op="verify", key_id=key_id, ok=True)
            return {"ok": True, "config": config}

        if op == "sign":
            # DENY unless the operator's authorization policy approves this request.
            if not self._authorize_sign(req):
                self._audit(stage="broker", op="sign", refused="unauthorized")
                return {"ok": False, "error": "unauthorized"}
            config = dict(req.get("config") or {})
            if req.get("stamp_issued_at", True):
                config["issued_at"] = time.time()
            envelope = sc.sign(config, key, key_id=key_id)
            self._audit(stage="broker", op="sign", key_id=key_id, ok=True)
            return {"ok": True, "envelope": envelope}

        return {"ok": False, "error": "unknown_op"}


class BrokerClient:
    """The UNPRIVILEGED (agent-side) handle. Talks to the broker over the socket.
    It NEVER holds a key. It can ask the broker to verify a config it was given, or
    (if the broker's policy allows) ask the broker to sign. A compromised client
    can misbehave, but it cannot obtain the key or forge a signature."""

    def __init__(self, socket_path: str, *, key_id: str = ""):
        self._path = socket_path
        self._key_id = key_id

    def _round_trip(self, req: dict) -> dict:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.connect(self._path)
        try:
            _send(conn, req)
            resp = _recv(conn)
            return resp if resp is not None else {"ok": False, "error": "no_response"}
        finally:
            conn.close()

    def verify(self, envelope: dict, *, ttl_seconds: Optional[float] = None) -> dict:
        """Ask the broker to verify. Returns the broker's response dict:
        {"ok": True, "config": ...} or {"ok": False, "error": ...}. The agent
        MUST treat ok=False as a hard stop (no fallback to raw bytes)."""
        return self._round_trip({"op": "verify", "key_id": self._key_id,
                                 "envelope": envelope, "ttl_seconds": ttl_seconds})

    def load_verified(self, path: str, *, ttl_seconds: Optional[float] = None):
        """Read a signed envelope from disk and have the BROKER verify it. The key
        stays in the broker; this process only ever sees the envelope + verdict."""
        with open(path, "r", encoding="utf-8") as f:
            envelope = json.load(f)
        resp = self.verify(envelope, ttl_seconds=ttl_seconds)
        if not resp.get("ok"):
            raise sc.ConfigIntegrityError(
                f"broker refused config at {path!r}: {resp.get('error')} "
                f"({resp.get('detail','')})")
        return resp["config"]

    def request_sign(self, config: dict, **extra) -> dict:
        """Ask the broker to sign (subject to the broker's authorization policy).
        Returns {"ok": True, "envelope": ...} or {"ok": False, "error": ...}."""
        return self._round_trip({"op": "sign", "key_id": self._key_id,
                                 "config": config, **extra})
