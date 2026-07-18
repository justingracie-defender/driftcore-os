"""
driftcore/verification/mediated_actuation.py
============================================
STATUS: PROPOSED (stdlib-only). **THE WALL.** The enforcement half of the reference
monitor — the piece every red-team round has converged on.

    ┌────────────────────────── THE DISTINCTION ─────────────────────────────┐
    │  signed_config / signed_permission / broker(sign)  =  INTEGRITY.        │
    │      They make FORGERY hard. A compromised agent cannot mint            │
    │      authorization it was not given.                                    │
    │                                                                        │
    │  MEDIATED ACTUATION                               =  ENFORCEMENT.       │
    │      It makes BYPASS IMPOSSIBLE. A compromised agent cannot SKIP the    │
    │      check, because the actuator is on the OTHER SIDE OF THE WALL and   │
    │      the only route to it runs through the guard.                       │
    └────────────────────────────────────────────────────────────────────────┘

╔══════════════════════════════════════════════════════════════════════════════╗
║  ⚠  THE LOAD-BEARING ASSUMPTION (read this — the entire guarantee rests here) ║
║  "Skipping the check means not acting at all" is TRUE ONLY IF every           ║
║  security-relevant actuator is reachable EXCLUSIVELY through this broker.      ║
║  The reference-monitor property is a property of the DEPLOYMENT, not just     ║
║  this code. If anyone later adds a direct actuation path in the agent         ║
║  process — `requests.post(...)`, `subprocess.run(...)`, `os.system(...)`, a   ║
║  raw socket to a device, an imported hardware SDK — the wall is silently      ║
║  bypassed, NOT because the broker failed, but because a new hole was cut      ║
║  beside it. The architecture cannot enforce this; only deployment discipline  ║
║  can. State it, audit for it, and treat any in-agent actuation path as a      ║
║  break of the whole model. (Named after a red-team review correctly warned    ║
║  the prose over-promised without this caveat.)                                ║
╚══════════════════════════════════════════════════════════════════════════════╝

WHY THE OLD DESIGN COULD BE BYPASSED. `GovernedActuator` verifies a grant before
acting — but it lives in the AGENT'S process. An agent with code execution simply
calls the underlying `_actuate()` directly, monkey-patches `verify`, or ignores the
`False` return. In-process software cannot stop an uncooperative agent that shares
its privilege. This is close to a theorem, not a limitation of our code: a rulebook
handed to a prisoner is not a wall.

WHAT THIS DOES. Actuators are REGISTERED IN THE BROKER PROCESS and are NOT importable
or reachable from the agent's process at all. The agent holds only an
`ActuatorProxy`: a handle whose ONLY capability is to send a request over a socket
and receive a verdict. There is no `_actuate` for it to reach past. The reference
monitor properties hold:

  * TAMPER-PROOF  — the actuator and the verifying key live in a separate process
                    (separate OS user, 0600 socket). The agent cannot read or patch
                    them.
  * ALWAYS INVOKED — there is no path from the agent to the actuator that does not
                    cross the socket. Skipping the check means not acting at all.
  * SMALL         — the mediation surface is one `execute` handler; auditable by eye.

THE TOCTOU FIX (the #1 finding of two independent reviews). The coordinator verifies
`command="pick_up_cup"` — and nothing stopped the executor from running
`pick_up_knife`, or swapping an approved recipient for `attacker@evil.com`. Here, the
Grant carries an `action_binding` (a hash over actuator+command+params, from
signed_permission). At the moment of execution, the BROKER recomputes that hash from
the action it is ABOUT TO PERFORM and refuses if it does not match. **The bytes that
get executed are the bytes that were approved**, or nothing executes. Verification and
execution are no longer separable.

HONEST LIMITS (stated, not hidden):
  * PERSUASION IS NOT MEDIATED. The agent's words to a human are an actuator this
    wall does not cover. A compromised agent's best remaining move is to convince a
    HUMAN to act for it. That is second_reader / review_router territory, and it is
    named as an open frontier in THREAT_BOUNDARIES §10.
  * COMPOSITION / PAYLOAD BLINDNESS. The wall enforces *what was approved*; it cannot
    see that fifty individually-approved actions compose into harm. That is the
    cumulative_ledger's job, and it should run on the BROKER side (see `LedgerHook`).
  * SINGLE-HOST. A Unix socket with peer-uid checking is single-host custody, not a
    network trust boundary. Cross-host needs mTLS/attestation; the wire protocol is
    deliberately tiny so that swap is a drop-in.
  * THE BROKER IS NOW THE TCB. If the broker process is compromised, everything is.
    That is the trade the reference-monitor pattern makes on purpose: it shrinks the
    thing you must trust from "the whole agent" to "one small, auditable mediator."
  * NONCE DURABILITY (found in self-red-team). Burned nonces live in the
    PermissionVerifier's in-memory set. If the broker restarts with a FRESH verifier,
    it forgets which nonces were spent -> a replay window across restarts. For
    production, back the verifier's `used_nonces` with the durable, hash-chained
    AuthorizationState store (the nonce-check shape is already compatible). Single
    long-lived broker process: not an issue. Restart-heavy deployment: wire the
    durable store.
  * CROSS-BROKER REPLAY (found in adversarial battery — NOW CLOSABLE). Because nonces
    are tracked per-broker, a grant approved for one broker could be replayed against a
    DIFFERENT broker that shares the signing key (each broker's nonce set has never
    seen it). Closed by giving each broker a distinct `broker_id`: the action_binding
    is then computed WITH the broker_id, so a grant for broker-A does not match
    broker-B and is refused. REQUIRED whenever multiple brokers share a key across a
    trust boundary; unnecessary (and off by default, fully backward-compatible) for a
    single-broker deployment.
  * PARAMETER CANONICALIZATION (fuzzed in red-team — SAFE but slightly BRITTLE). The
    action_binding hash is over `json.dumps(sort_keys=True)`, so dict key order and
    nesting order do NOT affect it (verified). Different actions correctly produce
    different hashes ("cup" != " cup ", cmd x != cmd y, actuator a != actuator b),
    and — checked explicitly — NO two *different* actions were found to collide to the
    same hash (the security-critical direction). The brittleness is the benign
    direction: `1` vs `1.0` and `True` vs `1` hash DIFFERENTLY, and Unicode NFC vs NFD
    forms of the same string differ. So a caller that mints a grant with `1` and then
    executes with `1.0` will be REFUSED (fail-closed — safe, but a legitimate action
    can flake on type drift). This is intentionally NOT "fixed" by coercing types,
    because coercion is exactly what could CREATE a dangerous collision. Deployment
    guidance: mint and execute with the same JSON types (they usually are, since both
    sides serialize the same params), and NFC-normalize string params upstream if
    Unicode equivalence matters. Documented rather than silently coerced.
    accept loop handles one connection at a time. A per-connection `conn_timeout`
    (default 5s) now bounds any single stalled client so it can no longer freeze the
    wall indefinitely — but a *flood* of many slow clients can still degrade
    actuation throughput (each ties up the loop for up to conn_timeout). For a home
    robot with a handful of trusted local callers this is fine; a high-concurrency or
    exposed deployment should move to a threaded/async accept loop or a connection
    pool. The socket is 0600 single-host, so the attack surface is local processes,
    not the network — but a compromised co-located process is exactly the threat
    model, so tune conn_timeout down and consider concurrency for anything beyond a
    single trusted agent.
"""
from __future__ import annotations

import json
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple

from driftcore.verification.signed_permission import (
    Grant, PermissionVerifier, PermissionError_,
)


# ── framed JSON (length-prefixed; identical discipline to broker_process) ──
def _send(conn: socket.socket, obj: dict) -> None:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    conn.sendall(struct.pack("!I", len(body)) + body)


def _recv_exactly(conn: socket.socket, n: int) -> Optional[bytes]:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _recv(conn: socket.socket) -> Optional[dict]:
    hdr = _recv_exactly(conn, 4)
    if hdr is None:
        return None
    (n,) = struct.unpack("!I", hdr)
    if n > 4_000_000:
        raise ValueError("frame too large")
    body = _recv_exactly(conn, n)
    if body is None:
        return None
    return json.loads(body.decode("utf-8"))


class ActuationRefused(Exception):
    """Raised agent-side when the wall refuses. Carries the broker's reason."""


@dataclass(frozen=True)
class ActuationRecord:
    """Append-only evidence of a mediated actuation attempt (broker-side)."""
    ts: float
    actuator_id: str
    command: str
    allowed: bool
    reason: str
    nonce: str = ""
    def to_dict(self) -> dict:
        return {"ts": self.ts, "actuator_id": self.actuator_id, "command": self.command,
                "allowed": self.allowed, "reason": self.reason, "nonce": self.nonce}


class ActuationBroker:
    """THE PRIVILEGED SIDE. Owns the actuators, the verifying keys, and the audit.
    Run as a SEPARATE OS USER from the agent, socket mode 0600.

    Registration is done HERE, in this process, by the operator — never by the agent.
    The agent never receives an actuator object; it receives a proxy that can only
    talk to this socket."""

    def __init__(self, socket_path: str, verifier: PermissionVerifier, *,
                 ledger_hook: Optional[Callable[[str, str, dict], Optional[str]]] = None,
                 conn_timeout: float = 5.0,
                 require_peer_uid: Optional[int] = None,
                 broker_id: Optional[str] = None,
                 expected_subject: Optional[str] = None,
                 audit_logger=None):
        self._socket_path = socket_path
        self._verifier = verifier
        # Per-connection recv timeout. Without this, a client that connects and then
        # STALLS (sends a length header, no body) blocks the single accept loop
        # forever — a one-client DoS on the whole wall. Found in cold red-team.
        self._conn_timeout = conn_timeout
        # PEER-UID CHECK (red-team fix, defense-in-depth — with an HONEST caveat).
        # If set, the broker verifies the connecting process's uid via SO_PEERCRED and
        # refuses any other uid. IMPORTANT and stated plainly so this is not oversold:
        # this ONLY helps when the agent runs as a DIFFERENT uid than the broker (the
        # deployment the docs already require). If agent and broker share a uid, this
        # does nothing — the agent legitimately IS that uid. And if the agent can
        # ptrace/inject, it is already game over. Peer-uid is belt-and-suspenders on
        # top of separate-users, never a substitute for it.
        self._require_peer_uid = require_peer_uid
        # BROKER IDENTITY (closes cross-broker grant replay, found in adversarial
        # battery). If set, this broker only accepts grants whose action_binding was
        # computed WITH this broker_id — so a grant approved for another broker (even
        # one sharing the signing key) will not match here and is refused. Omit it for
        # single-broker deployments (no behavior change; grants bind without a broker
        # component). Set a DISTINCT id on each broker when multiple brokers share a
        # key, so an approval for one cannot be replayed against another.
        self._broker_id = broker_id
        # SUBJECT BINDING (red-team: a grant's `subject` was verified only if the
        # caller passed expected_subject, and the wall never did — so a grant issued
        # for subject 'robot-1' could drive 'robot-2's broker if they shared a key,
        # the same shape as cross-broker replay). If set, this broker only accepts
        # grants whose subject matches. Omit for single-subject deployments.
        self._expected_subject = expected_subject
        # actuator_id -> (callable, required_scope tuple)
        self._actuators: Dict[str, Tuple[Callable[..., object], Tuple[str, ...]]] = {}
        # Optional cross-action gate run on the BROKER side (cumulative_ledger).
        # Returns None to allow, or a string reason to REFUSE.
        self._ledger_hook = ledger_hook
        self._audit = audit_logger or (lambda **kw: None)
        self.records: list = []          # append-only actuation evidence
        self._srv: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.RLock()

    # ── operator-side registration (NOT reachable from the agent) ──
    def register_actuator(self, actuator_id: str, fn: Callable[..., object], *,
                          required_scope: Tuple[str, ...] = (),
                          allow_any_scope: bool = False) -> None:
        """Operator registers a real actuator IN THIS PROCESS. `required_scope` is the
        capability the Grant must cover to drive it. The agent has no equivalent of
        this method — it cannot register, replace, or reach an actuator.

        FAIL-CLOSED ON EMPTY SCOPE (red-team fix): an actuator with no required scope
        accepts ANY validly-signed, bound, unexpired grant regardless of capability —
        a sharp footgun if registered by accident. Empty scope is now REFUSED unless
        the operator explicitly opts in with allow_any_scope=True. A silent config
        smell becomes a loud, deliberate choice."""
        if not required_scope and not allow_any_scope:
            raise ValueError(
                f"actuator {actuator_id!r} registered with empty required_scope. This "
                f"accepts ANY valid grant. If that is truly intended, pass "
                f"allow_any_scope=True; otherwise give it a real scope.")
        with self._lock:
            self._actuators[actuator_id] = (fn, tuple(required_scope))

    # ── lifecycle ──
    def start(self) -> None:
        # SOCKET-STARTUP RACE FIX (red-team). The old sequence exists()->unlink()->
        # bind()->chmod() left two gaps: (a) a window between unlink and bind where a
        # same-uid attacker could plant a file/symlink, and (b) a window between bind
        # and chmod where the socket briefly had default (permissive) permissions.
        # Mitigations: (1) set a restrictive umask around bind so the socket is
        # created 0600 ATOMICALLY, never briefly wider; (2) refuse to start if the
        # path exists and is not a socket we can safely replace. For real isolation
        # the socket should live in a directory only the broker's uid can write —
        # documented as a deployment requirement.
        if os.path.exists(self._socket_path):
            # Only remove it if it is a socket (avoid clobbering a planted regular
            # file/symlink as if it were our stale socket).
            import stat as _stat
            mode = os.lstat(self._socket_path).st_mode
            if not _stat.S_ISSOCK(mode):
                raise RuntimeError(
                    f"refusing to start: {self._socket_path!r} exists and is not a "
                    f"socket (possible tampering); remove it manually after checking")
            os.unlink(self._socket_path)
        self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old_umask = os.umask(0o177)          # -> socket created rw for owner only
        try:
            self._srv.bind(self._socket_path)
        finally:
            os.umask(old_umask)
        try:
            os.chmod(self._socket_path, 0o600)   # belt-and-suspenders
        except OSError:
            pass
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

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                # Bound how long a single client may hold the loop. A stalled or
                # slow client now hits this timeout instead of freezing the wall.
                conn.settimeout(self._conn_timeout)
                # PEER-UID CHECK (defense-in-depth; see the honest caveat at __init__).
                if self._require_peer_uid is not None and not self._peer_uid_ok(conn):
                    try:
                        _send(conn, {"ok": False, "error": "peer_uid_rejected"})
                    except OSError:
                        pass
                    self._audit(stage="actuation_broker", refused="peer_uid")
                    continue
                try:
                    req = _recv(conn)
                    if req is not None:
                        _send(conn, self._handle(req))
                except (socket.timeout, OSError, ValueError) as e:
                    # Client stalled, disconnected, or sent a bad frame. Try to tell
                    # them, but NEVER let a failed send on a dead socket escape and
                    # kill the serve thread (found in cold red-team: BrokenPipe in the
                    # error path re-raised and could take down the wall).
                    try:
                        _send(conn, {"ok": False, "error": "bad_request"})
                    except OSError:
                        pass
                    self._audit(stage="actuation_broker", conn_error=str(e))
                except Exception as e:
                    try:
                        _send(conn, {"ok": False, "error": "broker_error"})
                    except OSError:
                        pass
                    self._audit(stage="actuation_broker", error=str(e))

    def _peer_uid_ok(self, conn: socket.socket) -> bool:
        """Verify the connecting process's uid via SO_PEERCRED. Fail-closed: if the
        credential cannot be read, reject. Only meaningful when agent and broker run
        as different uids (see __init__ caveat)."""
        try:
            import struct as _struct
            creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                    _struct.calcsize("3i"))
            _pid, uid, _gid = _struct.unpack("3i", creds)
            return uid == self._require_peer_uid
        except Exception:
            return False   # cannot verify -> refuse

    def _record(self, actuator_id: str, command: str, allowed: bool, reason: str,
                nonce: str = "") -> None:
        rec = ActuationRecord(time.time(), actuator_id, command, allowed, reason, nonce)
        self.records.append(rec)          # in-broker evidence: always kept first
        try:
            self._audit(stage="actuation_broker", **rec.to_dict())
        except Exception:
            # A broken external audit sink must not crash the wall or block mediation.
            # The authoritative record is self.records (kept above); the external
            # logger is best-effort. (Policy stated: audit-sink failure is
            # loggable-and-continue; it never silently lets an UNRECORDED action
            # through, because the in-broker record is written unconditionally.)
            pass

    def _handle(self, req: dict) -> dict:
        """The ENTIRE mediation surface. Small enough to audit by eye — that is the
        point of a reference monitor."""
        if req.get("op") != "execute":
            return {"ok": False, "error": "unknown_op"}

        actuator_id = str(req.get("actuator_id", ""))
        command = str(req.get("command", ""))
        params = req.get("params") or {}
        grant_d = req.get("grant")

        with self._lock:
            entry = self._actuators.get(actuator_id)

        if entry is None:
            self._record(actuator_id, command, False, "unknown actuator")
            return {"ok": False, "error": "unknown_actuator"}
        fn, required_scope = entry

        # 1. A GRANT IS MANDATORY. No grant -> nothing happens. Fail closed.
        if not grant_d:
            self._record(actuator_id, command, False, "no grant presented")
            return {"ok": False, "error": "no_grant"}

        try:
            grant = Grant.from_dict(grant_d)
        except Exception:
            self._record(actuator_id, command, False, "malformed grant")
            return {"ok": False, "error": "malformed_grant"}

        # 2. THE TOCTOU FIX. Recompute the binding from the action we are ABOUT TO
        #    PERFORM and require the grant to be bound to exactly THAT. The executor
        #    cannot substitute pick_up_knife for an approved pick_up_cup: the hash
        #    would not match, and we refuse. Verification and execution are welded.
        binding_now = PermissionVerifier.bind_action(actuator_id, command, params,
                                                     broker_id=self._broker_id)

        # 3. Verify signature / expiry / replay / scope / binding — all in ONE place,
        #    on the PRIVILEGED side, with the key the agent does not have.
        try:
            self._verifier.verify(grant, required_scope=required_scope,
                                  expected_subject=self._expected_subject,
                                  action_binding=binding_now)
        except PermissionError_ as e:
            self._record(actuator_id, command, False, f"grant rejected: {e}", grant.nonce)
            return {"ok": False, "error": "grant_rejected", "detail": str(e)}

        # 4. Cross-action gate (cumulative_ledger), run on the BROKER side so the
        #    agent cannot bypass the accounting by simply not calling it.
        #    FAIL-CLOSED (red-team fix): a ledger_hook that RAISES must be treated as a
        #    REFUSAL, not allowed to fall through to a generic broker_error (which
        #    could read as "try again" and, worse, leaves the reason unrecorded). An
        #    exception in the safety gate means the action does NOT happen.
        if self._ledger_hook is not None:
            try:
                refusal = self._ledger_hook(actuator_id, command, params)
            except Exception as e:
                self._record(actuator_id, command, False,
                             f"ledger hook raised (fail-closed): {e}", grant.nonce)
                return {"ok": False, "error": "ledger_error", "detail": "safety gate failed closed"}
            if refusal:
                self._record(actuator_id, command, False, f"ledger refused: {refusal}",
                             grant.nonce)
                return {"ok": False, "error": "ledger_refused", "detail": refusal}

        # 5. BURN THE NONCE, THEN ACT. Single-use: a replayed grant cannot re-actuate.
        self._verifier.consume(grant)
        try:
            result = fn(**params) if params else fn()
        except Exception as e:
            self._record(actuator_id, command, False, f"actuator raised: {e}", grant.nonce)
            return {"ok": False, "error": "actuator_failed", "detail": str(e)}

        self._record(actuator_id, command, True, "executed", grant.nonce)
        return {"ok": True, "result": result}


class ActuatorProxy:
    """THE UNPRIVILEGED (agent-side) HANDLE. **This is the ONLY thing the agent has.**

    Note what is absent: no actuator function, no key, no `_actuate`, no verifier, no
    registration. There is nothing here to monkey-patch that would help — the checks
    do not run in this process. The proxy's entire power is 'send bytes to a socket
    and read the answer.' An agent that skips the proxy does not bypass the guard; it
    simply does not act, because the actuator is not in its address space at all."""

    def __init__(self, socket_path: str, actuator_id: str):
        self._path = socket_path
        self.actuator_id = actuator_id

    def execute(self, command: str, grant: Grant, **params):
        """Ask the wall to perform an action. Raises ActuationRefused if the wall says
        no — and there is no other way through."""
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.connect(self._path)
        try:
            _send(conn, {"op": "execute", "actuator_id": self.actuator_id,
                         "command": command, "params": params,
                         "grant": grant.to_dict()})
            resp = _recv(conn) or {"ok": False, "error": "no_response"}
        finally:
            conn.close()
        if not resp.get("ok"):
            raise ActuationRefused(
                f"{resp.get('error')}: {resp.get('detail', '')}".strip(": "))
        return resp.get("result")
