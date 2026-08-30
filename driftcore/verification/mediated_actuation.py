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

import hashlib
import json
import os
import socket
import stat
import struct
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone


def _elapsed_clock() -> float:
    """A clock that advances across SUSPEND.

    time.monotonic() is CLOCK_MONOTONIC on Linux, which does NOT tick while the
    machine is suspended — so a robot suspended for eight hours resumes with an
    attestation that still reads fresh. That is the same class of hole as the wall
    clock this replaced: picking a monotonic clock fixed the step-backwards problem
    and introduced a stops-ticking one. CLOCK_BOOTTIME includes suspend.
    """
    try:
        return time.clock_gettime(time.CLOCK_BOOTTIME)
    except (AttributeError, OSError):
        return time.monotonic()


def _call_with_timeout(fn, timeout: float, on_late=None):
    """Run `fn()` with a hard deadline. Used for the breach-posture check, which sits at
    position zero in the mediation path — a hanging source there stalls EVERY request.
    Raises TimeoutError on expiry so the caller can fail CLOSED."""
    box = {}
    deadline_passed = threading.Event()
    def _run():
        try:
            box["v"] = fn()
        except BaseException as e:      # noqa: BLE001 - propagated to the caller
            box["e"] = e
        # (red-team, cold pass Q4) If the deadline already passed, this call is an
        # ORPHAN: the broker reported "completion UNKNOWN" and moved on, and nothing
        # ever recorded what actually happened. The audit then says "timed out" forever
        # even though the physical action COMPLETED — a trail that is wrong about the
        # world is worse than a gap, because an investigator would conclude the action
        # never occurred. The orphan now reports its own outcome.
        if deadline_passed.is_set() and on_late is not None:
            try:
                on_late("raised" if "e" in box else "completed", box.get("e"))
            except Exception:
                # A genuine swallow, and named as one. This runs in an ORPHANED daemon
                # thread that nobody joins: raising here would kill the thread silently
                # and escalate to no one, so there is nowhere better for the failure to
                # go. The cost is that a failure to RECORD a late completion is
                # invisible — the audit would then still say "timed out" for an action
                # that finished. The quarantine is what actually protects the world in
                # that case; this path only improves the evidence.
                pass
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        deadline_passed.set()
        raise TimeoutError(f"call exceeded {timeout}s")
    if "e" in box:
        raise box["e"]
    return box.get("v")
from typing import Callable, Dict, Optional, Tuple

from driftcore.verification.signed_permission import (
    Grant, PermissionVerifier, PermissionError_,
)
from driftcore.kernel.actuation_gate import ActuationGate, Outcome
from driftcore.kernel.blast_radius import BlastRadiusGovernor, BreadthVerdict
from driftcore.kernel.egress_guard import EgressGuard
from driftcore.kernel.effect_guard import EffectRegistry
from driftcore.verification.invariant_guard import Effect, ActionContext


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


# Scheme-qualified destinations only. Deliberately conservative: it looks for an
# explicit "scheme://", so ordinary strings do not trip it and cause spurious holds.
# The cost of that conservatism is stated honestly — a scheme-less destination
# ("api.example.com/x", or a host+port assembled inside the actuator) is NOT seen here,
# which is why the network boundary (P0) and not this check is the real control.
_DEST_RE = _re_dest = __import__("re").compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://\S+")
_DEST_MAX_DEPTH = 6
_DEST_MAX_FOUND = 64


def _find_destinations(obj, _depth: int = 0) -> list:
    """Every scheme-qualified destination anywhere in the params, not just the first.

    Recursive because a decoy is trivial otherwise: {"url": <allowed>, "body":
    {"callback": <evil>}} would pass a top-level-only check while the actuator happily
    used the nested one. Depth and count are capped so a hostile params blob cannot
    turn the interlock into a CPU sink.
    """
    found: list = []
    if _depth > _DEST_MAX_DEPTH:
        return found
    if isinstance(obj, str):
        found.extend(_DEST_RE.findall(obj))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            found.extend(_find_destinations(k, _depth + 1))
            found.extend(_find_destinations(v, _depth + 1))
    elif isinstance(obj, (list, tuple, set, frozenset)):
        for v in obj:
            found.extend(_find_destinations(v, _depth + 1))
    return found[:_DEST_MAX_FOUND]


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
    Run as a SEPARATE OS USER from the agent. For that deployment pass
    `socket_group=<a group both users belong to>`: the socket is then mode 0660 owned by
    that group, so the agent can connect and nobody else can. WITHOUT socket_group the
    socket stays 0600 (owner-only) and a separate-user agent gets EACCES — in that case
    you are really running same-uid, `require_peer_uid` is a no-op, and the process
    isolation described here does not exist. Choose deliberately.

    Registration is done HERE, in this process, by the operator — never by the agent.
    The agent never receives an actuator object; it receives a proxy that can only
    talk to this socket."""

    def __init__(self, socket_path: str, verifier: PermissionVerifier, *,
                 ledger_hook: Optional[Callable[[str, str, dict], Optional[str]]] = None,
                 conn_timeout: float = 5.0,
                 require_peer_uid: Optional[int] = None,
                 broker_id: Optional[str] = None,
                 expected_subject: Optional[str] = None,
                 posture_source: Optional[Callable[[], bool]] = None,
                 halt_state: Optional[Callable[[], bool]] = None,
                 posture_timeout: float = 1.0,
                 socket_group: Optional[object] = None,
                 require_isolation: bool = False,
                 enforce_effects: bool = False,
                 blast_radius: Optional[BlastRadiusGovernor] = None,
                 egress_guard: Optional[EgressGuard] = None,
                 actuator_timeout: Optional[float] = None,
                 quarantine_path: Optional[str] = None,
                 evidence_path: Optional[str] = None,
                 require_durable_evidence: bool = False,
                 require_effect_binding: bool = False,
                 human_approval=None,
                 envelope_source: Optional[Callable[[], object]] = None,
                 intent_ledger=None,
                 probe_detector=None,
                 broker_manifest=None,
                 agent_manifest=None,
                 isolation_attestation=None,
                 # 30s, not 300. The attestation window IS the drift window: for the
                 # whole of it the wall serves on a measurement that may already be
                 # false. Five minutes is long enough for the recon phase of a real
                 # campaign. Short enough to hurt is the point.
                 attestation_max_age_seconds: float = 30.0,
                 audit_logger=None):
        self._socket_path = socket_path
        self._verifier = verifier
        # BREACH COUPLING. A zero-argument callable returning True while the system is
        # OPERATIONAL and False once it is holding in RESTRICTED/HALT — in practice
        # `breach_response.is_operational`. When wired, the wall refuses ALL actuation in
        # a breached posture regardless of grant validity, so the permission set
        # collapses on breach instead of persisting until grants expire.
        #
        # DEFAULT None = UNGATED, and that is a real gap, not a neutral default: an
        # ungated broker will happily actuate for a HALTED system holding a valid grant.
        # It defaults off only so existing deployments do not silently change behaviour.
        # `is_breach_gated()` reports the state so "no refusals" is never mistaken for
        # "the gate is working". Production deployments MUST wire this.
        self._posture_source = posture_source
        # (red-team) SafeHalt was referenced by exactly ONE file: itself. Nothing
        # connected it to actuation, so with a HARD halt active — "all operations
        # suspended" — a valid grant still moved the arm. A halt that no execution path
        # consults is a variable, not a stop. `halt_state` is a callable returning True
        # when the system is halted; it is checked before every actuation and, like the
        # posture gate, is strict-bool and fails CLOSED.
        self._halt_state = halt_state
        # (red-team, self cold pass H1) `self._halt_state` is a plain attribute of an
        # in-process object. A compromised broker process can reassign it
        # (`broker._halt_state = lambda: False`) exactly as it could delete the
        # actuator registry or monkeypatch `_handle`. This is the SAME load-bearing
        # assumption named at the top of this file for the broker as a whole — the
        # guarantee holds only if the broker process is not itself compromised, and no
        # attribute check inside that process can defend against the process owning
        # the check. The interlock's job is to close the gap where the halt existed but
        # nothing consulted it; it cannot make the broker process trustworthy.
        # (red-team, cold pass) the posture check sits at position ZERO, so a slow or
        # hanging source stalls EVERY request — the same one-client DoS `conn_timeout`
        # already closed, reintroduced in front of it. Bounded, and a timeout is a
        # REFUSAL (a wall that cannot check its own state does not open).
        self._posture_timeout = float(posture_timeout)
        # SHARED-GROUP ACCESS (red-team, Grok). A group name or gid that BOTH the broker
        # user and the agent user belong to — and no one else. Required for the
        # separate-OS-user deployment this class documents: without it the socket stays
        # owner-only (0600) and an agent running as a different user cannot connect at
        # all. See start() for the tighten-then-open ordering.
        self._socket_group = socket_group
        # (red-team, external C2) The library default (0600, owner-only) forces the agent
        # and broker to share a UID, which makes require_peer_uid a no-op and collapses
        # the isolation story — so a deployment that takes the easy path gets WEAKER
        # isolation than the documentation implies. `require_isolation=True` refuses to
        # start unless the separate-user prerequisites are actually configured, turning a
        # documented assumption into a checked one.
        self._require_isolation = bool(require_isolation)
        # (red-team, Grok+ChatGPT) `records` was an unbounded in-memory list: 300
        # actuations kept 300 entries with no cap or rotation, so a long-lived broker
        # exhausts memory and the authoritative evidence dies with the process. Bounded,
        # with the drop count reported so silent truncation is visible.
        self._records_cap = 10000
        self._records_dropped = 0
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
        # EFFECT GATING. The constitutional fail-closed-on-undeclared gate, applied at
        # the actuation choke point. When enforce_effects=True, an actuator whose
        # EFFECTS a human has not declared CANNOT actuate (BLOCK_UNDECLARED), a declared
        # absolute effect (LETHAL, OVERSIGHT_CONTROL, ...) is blocked by the floor, and a
        # lethal-shaped wording/name mismatch on a benign declaration is held for review.
        #
        # DEFAULT False = UNENFORCED, and (exactly like breach gating above) that is a
        # real gap, not a neutral default: an unenforced broker still fails OPEN on
        # undeclared actuators. It defaults off only so existing deployments do not
        # silently change behaviour. `is_effect_gated()` reports the state so "no
        # refusals" is never mistaken for "the gate is working". Production deployments
        # that can physically actuate MUST set enforce_effects=True and declare every
        # actuator's effects at registration.
        self._enforce_effects = bool(enforce_effects)
        self._effect_registry = EffectRegistry()
        self._effect_gate = ActuationGate(self._effect_registry) if self._enforce_effects else None
        # (red-team A9) Declarations supplied while UNENFORCED are still validated and
        # recorded, but they are INERT: there is deliberately no API to switch
        # enforcement on after construction, because a safety gate that can be toggled
        # at runtime is a safety gate an attacker can toggle. Enforcement is a
        # construction-time decision. An earlier comment here claimed the flag "can
        # later be flipped on" — no such API existed, which is exactly the doc-vs-code
        # drift this project keeps catching in other people's work.
        #
        # (red-team, ChatGPT) A hanging actuator holds the single accept loop forever:
        # `fn(**params)` had no deadline even though `_call_with_timeout` already
        # existed in this file for the posture check. None = no timeout (previous
        # behaviour, for long legitimate actuations); set it for anything that can
        # wedge. A timeout is reported as a FAILED actuation of UNKNOWN completion —
        # the side effect may have started, so it is never reported as a clean refusal.
        self._actuator_timeout = actuator_timeout
        # BREADTH GOVERNOR (incident-derived, THREAT_MODEL §I4). Volume/rate/burst are
        # governed by CumulativeLedger via `ledger_hook`; this measures the axis the
        # ledger does not — how many DISTINCT capabilities are touched in a window,
        # which is the lateral-movement signature.
        self._blast_radius = blast_radius
        # EGRESS AS ACTUATION. A packet is a consequential act: an agent with a socket
        # does not need an arm, it can reach every networked actuator in the world. Any
        # capability declaring Effect.DATA_EGRESS has its DESTINATION checked against a
        # human-declared allowlist — a parameter-level interlock, because one egress
        # capability can reach anywhere and a per-capability effect tag cannot express
        # "but only to these hosts".
        #
        # PRECONDITION THIS CANNOT ENFORCE: the agent process must have no unmediated
        # network path (empty netns / seccomp / an external firewall). Python cannot
        # take a socket away from code in its own address space. This guard is what
        # makes that posture workable — the one governed route out — never a substitute
        # for it.
        self._egress_guard = egress_guard
        # actuator_id -> the param key that carries its destination (declared
        # at registration for any DATA_EGRESS capability, never guessed).
        self._destination_params: Dict[str, str] = {}
        # Implementation identity captured AT REGISTRATION. Re-deriving it per
        # request made it a moving target: an actuator writing to its own
        # closed-over log rewrote its identity on first use and invalidated every
        # outstanding grant. See _implementation_id.
        self._impl_ids: Dict[str, str] = {}
        # actuator_id -> the real-world thing it moves (defaults to itself)
        self._physical_resource: Dict[str, str] = {}
        # Optional cross-action gate run on the BROKER side (cumulative_ledger).
        # Returns None to allow, or a string reason to REFUSE.
        self._ledger_hook = ledger_hook
        self._audit = audit_logger or (lambda **kw: None)
        self.records: list = []          # append-only actuation evidence
        self._srv: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.RLock()
        # ACTUATORS WITH UNKNOWN PHYSICAL STATE (red-team, Grok #4 — reproduced).
        # `_call_with_timeout` runs the actuator in a daemon thread. On expiry the
        # broker reports ACTUATOR_TIMEOUT and burns the nonce, but PYTHON CANNOT KILL A
        # THREAD: the orphan keeps running and may complete the physical action after
        # the caller was told the outcome is unknown. Verified end to end — the arm
        # moved, the agent retried with a fresh grant, and the arm moved AGAIN.
        #
        # Cancellation is not available, so the control is QUARANTINE: an actuator whose
        # completion is unknown accepts nothing further until a human reconciles the
        # physical state. Refusing the retry is the only thing standing between a
        # timeout and a double actuation.
        self._unknown_completion: Dict[str, dict] = {}
        # DURABILITY (red-team, cold pass Q2). The quarantine was in-memory only, so a
        # crash-loop or an ordinary restart erased the ONE control standing between a
        # timeout and a double actuation — and a restart is exactly what an operator
        # does when a robot seems stuck. Physical state does not reset because a process
        # did. When a store path is given the quarantine is persisted on every change
        # and reloaded at construction; a store that exists but cannot be READ is a
        # refusal to start, because an unreadable quarantine is indistinguishable from
        # an empty one.
        # (red-team, cold pass Q1) The quarantine lived only in memory, so a broker
        # restart erased it — and a crash-restart is EXACTLY when a timeout is likely
        # (the actuator hung, someone power-cycled the broker). Reproduced: after a
        # restart the retry was accepted and the arm moved TWICE. Physical state does
        # not reset because a process did.
        #
        # When `quarantine_path` is set the quarantine is written through on every
        # change and reloaded at construction. Unset means it does NOT survive a
        # restart, which is recorded as a posture event rather than left implicit.
        # DURABLE ACTUATION EVIDENCE. `records` is an in-memory bounded list, so a
        # crash took the evidence with it — and the lost entries are exactly the ones
        # describing whatever was happening when things went wrong. Hugging Face
        # reconstructed the July incident from 17,000 recorded events; recording is
        # what let them contain it.
        #
        # WRITE-AHEAD: an INTENT record is written and fsynced BEFORE the actuator
        # runs, a COMPLETION record after. An intent with no completion is a detectable
        # gap — the same signal the physical-state quarantine already acts on, now
        # surviving the process that produced it.
        #
        # Writing has no judgment in it. Nothing can talk the broker out of writing a
        # record, and nothing about the wording of an action changes what gets written.
        self._evidence_path = evidence_path
        self._require_durable_evidence = bool(require_durable_evidence)
        self._evidence_prev = "GENESIS"
        self._quarantine_path = quarantine_path
        # ISOLATION ATTESTATION (the detection-vs-enforcement gap).
        # isolation_manifest.py could verify a process's capability surface, and was
        # wired into this broker ZERO times. `require_isolation=True` checked only that
        # two FLAGS had been passed — not that the process was actually isolated. So the
        # wall property was declared, never checked. An IsolationReport produced by a
        # SUPERVISOR via verify_process() is now required before the wall will serve.
        #
        # Passed at construction because construction is operator-side: whoever builds
        # the broker already registers the actuators and holds the keys. The agent has
        # no path here.
        # BIND THE GRANT TO THE DECLARATION (both external reviews' top item).
        # A grant pins WHAT is executed but not WHAT THE ACTUATOR WAS DECLARED TO DO,
        # so a declaration downgrade under a live grant executed under the weaker
        # floor. When on, the binding includes a hash of the current declaration, so
        # any change invalidates every outstanding grant for that actuator.
        self._require_effect_binding = bool(require_effect_binding)
        # WHO AGREED, not just what was signed. A Grant proves the signing KEY
        # authorised the action. A stolen key, an automation, or an agent that reached
        # the key store all produce a grant that verifies perfectly and looks approved.
        # With a gate installed, every actuation must additionally carry a human
        # attestation whose signature covers the exact effect identity — and the grant
        # must be bound to that specific attestation. Opt-in: None behaves as before.
        if human_approval is not None:
            from driftcore.verification.human_authorization import HumanApprovalGate
            if not isinstance(human_approval, HumanApprovalGate):
                raise TypeError(
                    "human_approval must be a HumanApprovalGate. Accepting a "
                    "duck-typed stand-in on this boundary is how a wall ends up "
                    "consulting something that always says yes.")
            # (red-team, Grok 2026-08-14) With effect binding OFF, the approved
            # identity names the ACTUATOR and the COMMAND and not the code behind
            # them: two different implementations answering to "grip" on "arm_left"
            # hash identically, so a human approves a NAME rather than a BODY OF CODE.
            # `require_effect_binding` folds in the declaration and its
            # implementation identity, which is what makes the approval survive a
            # swapped actuator. A human gate without it is a weaker claim wearing a
            # stronger name, so the combination is refused at construction rather
            # than discovered in a safety case.
            if not require_effect_binding:
                raise ValueError(
                    "a HumanApprovalGate requires require_effect_binding=True. "
                    "Without it the human approves an actuator NAME, not the "
                    "implementation behind it, and an actuator swapped after "
                    "approval executes under the old approval.")
        self._human_approval = human_approval
        # The safety constraints in force, as an opaque declaration. DriftCore does
        # not interpret it (no physical values live here); it pins the digest so an
        # approval cannot outlive the envelope it was given under.
        self._envelope_source = envelope_source
        # The purpose side of the chain. When installed, every request must carry an
        # intent-ledger decision, and that decision is REDEEMED here — single-use,
        # generation-checked, and bound to this exact action. Opt-in and inert when
        # None, like every other gate on this wall.
        self._intent_ledger = intent_ledger
        # THE BROKER IS THE NEW MAIL SLOT. Once every fetch and every actuation is
        # forced through one conduit, that conduit's own surface is the escape hatch —
        # and nothing stopped it running wide open while enforcing a tight manifest on
        # the agent. When both manifests are supplied, the broker refuses to start
        # unless its own is at least as strict as the one it enforces.
        # PROBE DETECTION. Every gate here refuses correctly and forgets. So an
        # adversary can hammer one capability fifty times with fifty phrasings, be
        # refused fifty times, and nobody learns a search took place. Both verified
        # incidents had that shape: the robot refused twice before the reframe worked,
        # and the Mexico operator kept reframing until something did. The refusals
        # WERE the signal and nothing counted them.
        #
        # Fed AFTER the refusal decision, never before. It observes; it does not vote.
        self._probe_detector = probe_detector
        self._broker_manifest = broker_manifest
        self._agent_manifest = agent_manifest
        self._isolation_attestation = isolation_attestation
        self._attestation_max_age = float(attestation_max_age_seconds)
        self._attested_at: Optional[float] = None      # epoch seconds, parsed once
        # Age is measured on the MONOTONIC clock after install. The supervisor's
        # timestamp is necessarily wall-clock, so the initial gap is computed once from
        # it; everything after that is monotonic, because a backwards clock step (NTP,
        # VM migration, a manual `date`) would otherwise make a stale attestation look
        # fresh again — and freshness is the whole control.
        self._attested_mono: Optional[float] = None
        self._attested_initial_age: float = 0.0
        if quarantine_path:
            try:
                if os.path.exists(quarantine_path):
                    with open(quarantine_path, encoding="utf-8") as fh:
                        loaded = json.load(fh)
                    if not isinstance(loaded, dict):
                        raise ValueError("quarantine file is not an object")
                    self._unknown_completion.update(loaded)
            except Exception as e:
                # A broker that cannot tell which actuators are in an unknown physical
                # state must not start and drive them.
                raise RuntimeError(
                    f"could not read the quarantine record at {quarantine_path!r}: {e}. "
                    f"Refusing to start: it is unknown which actuators were left in an "
                    f"unresolved physical state, and starting would allow a retry that "
                    f"actuates the world a second time.") from e

        # POSTURE EVENTS (incident-derived, §I3). In the July 2026 incident a safety
        # layer was disabled for a legitimate reason and nothing recorded that the
        # system was now running with one fewer layer. Every layer that is OFF at
        # construction is recorded here, attributably, at start. A disabled control
        # must be an EVENT, not a silent default.
        self._posture_events: list = []
        for layer, on, why in (
            ("effect_gate", self._enforce_effects,
             "undeclared actuators can actuate on a valid grant"),
            ("breach_gate", self._posture_source is not None,
             "actuation continues while the system holds in RESTRICTED/HALT"),
            ("blast_radius", self._blast_radius is not None
             and self._blast_radius.is_armed(),
             "no breadth ceiling: spread across mediated capabilities is not measured"),
            ("egress_allowlist", self._egress_guard is not None
             and self._egress_guard.is_armed(),
             "DATA_EGRESS capabilities may reach ANY destination: an agent that can "
             "make arbitrary network requests can reach every networked actuator "
             "there is, which is a larger blast radius than any physical actuator"),
            ("unmediated_egress_verified", False,
             "THIS FRAMEWORK CANNOT VERIFY that the agent process lacks its own "
             "socket. If it has one, none of the egress governance applies. Enforce "
             "at the OS/network layer and assert it in deployment checks"),
            ("cumulative_ledger", self._ledger_hook is not None,
             "no volume/rate ceiling: many small actions are not accumulated"),
            ("peer_uid", self._require_peer_uid is not None,
             "connecting process identity is not checked"),
            ("isolation_required", self._require_isolation,
             "separate-user prerequisites are not asserted at start"),
            ("effect_binding", self._require_effect_binding,
             "a grant is not bound to the effect declaration, so downgrading an "
             "actuator from LETHAL to NONE with replace=True lets outstanding grants "
             "execute under the weaker floor"),
            ("isolation_attested", self.is_isolation_attested(),
             "no external supervisor has verified this process's capability surface, "
             "so the wall property is a claim rather than a measurement — the process "
             "may hold a socket, a capability or a namespace handle nobody declared"),
            ("probe_detection", self._probe_detector is not None
             and self._probe_detector.is_armed(),
             "repeated refusals are not counted, so an agent searching for the "
             "phrasing that opens a gate is refused every time and nobody learns a "
             "search took place"),
            ("broker_bunker", self._broker_manifest is not None
             and self._agent_manifest is not None,
             "nothing compares the broker's own isolation to the agent's, so the "
             "conduit everything is forced through may be wider open than what it "
             "protects"),
            ("durable_evidence", bool(self._evidence_path),
             "actuation evidence lives only in memory, so a crash destroys the records "
             "describing whatever was happening when things went wrong — which are "
             "exactly the ones an investigation needs"),
            ("quarantine_durable", bool(self._quarantine_path),
             "a timeout leaves an actuator in UNKNOWN physical state, and that record "
             "is memory-only: a broker restart erases it and the next grant can "
             "actuate the world a second time"),
            ("actuator_timeout", self._actuator_timeout is not None,
             "a hanging actuator wedges the wall indefinitely"),
        ):
            if not on:
                self._posture_events.append({
                    "ts": time.time(), "layer": layer, "state": "DISABLED",
                    "consequence": why})

    def posture_events(self) -> list:
        """Every safety layer that is OFF, with the concrete consequence of it being
        off. A deployment check should read this and refuse to proceed on anything it
        has not explicitly accepted. Disabling a layer is an event, not a default."""
        return list(self._posture_events)

    def is_blast_radius_gated(self) -> bool:
        """Whether a breadth ceiling is actually enforced. An unarmed governor refuses
        nothing, so a clean record from one is not evidence of safety."""
        return self._blast_radius is not None and self._blast_radius.is_armed()

    # ── operator-side registration (NOT reachable from the agent) ──
    def register_actuator(self, actuator_id: str, fn: Callable[..., object], *,
                          required_scope: Tuple[str, ...] = (),
                          allow_any_scope: bool = False,
                          effects: "Optional[object]" = None,
                          effect_declared_by: Optional[str] = None,
                          destination_param: Optional[str] = None,
                          physical_resource: Optional[str] = None,
                          replace: bool = False) -> None:
        """Operator registers a real actuator IN THIS PROCESS. `required_scope` is the
        capability the Grant must cover to drive it. The agent has no equivalent of
        this method — it cannot register, replace, or reach an actuator.

        FAIL-CLOSED ON EMPTY SCOPE (red-team fix): an actuator with no required scope
        accepts ANY validly-signed, bound, unexpired grant regardless of capability —
        a sharp footgun if registered by accident. Empty scope is now REFUSED unless
        the operator explicitly opts in with allow_any_scope=True. A silent config
        smell becomes a loud, deliberate choice."""
        # THE OPT-IN MUST BE THE LITERAL True, NOT MERELY TRUTHY (red-team,
        # 2026-08-29). Verified by execution: allow_any_scope="false", "no", "0" and
        # "off" ALL opted in, because every non-empty string is truthy. Operators
        # configure through JSON, YAML, env vars and CLI flags — every one of which
        # hands you a string — so `bool(x)` on a safety opt-in reads a config that
        # says OFF as ON. An identity check has no such boundary.
        if allow_any_scope is not True and allow_any_scope is not False:
            raise ValueError(
                f"actuator {actuator_id!r}: allow_any_scope must be the literal True "
                f"or False, not {allow_any_scope!r}. Truthiness is not consent — "
                f"'false', 'no' and '0' are all truthy, so a config that says OFF "
                f"would switch the scope requirement OFF.")
        if not required_scope and not allow_any_scope:
            raise ValueError(
                f"actuator {actuator_id!r} registered with empty required_scope. This "
                f"accepts ANY valid grant. If that is truly intended, pass "
                f"allow_any_scope=True; otherwise give it a real scope.")
        # EFFECT DECLARATION FIRST (red-team A1). This is validated and recorded
        # BEFORE the actuator is inserted, so a rejected declaration leaves NO trace:
        # previously the actuator went into _actuators inside the lock and the effects
        # check raised afterwards, leaving a registered actuator with no declaration
        # and an operator locked out behind "already registered, pass replace=True".
        eff = None
        if self._enforce_effects:
            if effects is None:
                raise ValueError(
                    f"enforce_effects is on: actuator {actuator_id!r} must declare its "
                    f"effects (e.g. effects=[Effect.PHYSICAL_FORCE], or [Effect.NONE] if "
                    f"it has no consequential effect). An undeclared actuator would fail "
                    f"closed at every call — declare it here instead.")
            if not effect_declared_by:
                raise ValueError(
                    f"actuator {actuator_id!r}: effect_declared_by is required — an effect "
                    f"declaration is a safety-critical act and must be attributable.")
            eff = self._coerce_effects(effects)
            # SCHEMA-ENFORCED DESTINATION (red team G3/P1-1, verified live). Sniffing
            # params for a "scheme://" string misses every scheme-less shape:
            # {"host": "evil.com", "port": 443} and {"endpoint": "evil.com:443"} both
            # produced NOTHING. Guessing where the destination lives is not a control.
            # An egress capability must NAME the param that carries its destination.
            if Effect.DATA_EGRESS in set(eff) and not destination_param:
                raise ValueError(
                    f"actuator {actuator_id!r} declares DATA_EGRESS and must also declare "
                    f"destination_param='<key>' — the param that carries its destination. "
                    f"Without it the wall would have to GUESS where the destination is, "
                    f"and a guess that misses fails OPEN.")
        elif effects is not None:
            # Enforcement is off, but a declaration was still supplied. Validate it
            # LOUDLY (red-team A8): this used to be `except Exception: pass`, so a typo
            # like effects=["LETAHL"] was swallowed and the operator got no signal that
            # the declaration never landed. A malformed safety declaration is an error
            # whether or not it is currently being enforced.
            eff = self._coerce_effects(effects)

        with self._lock:
            # (red-team, ChatGPT) re-registering an id used to SILENTLY REPLACE a vetted
            # actuator with a different callable under the same name — no error, no audit
            # entry, and every existing grant scoped to that id now drives the new code.
            # Replacement must be a deliberate, explicit act.
            if actuator_id in self._actuators and not replace:
                raise ValueError(
                    f"actuator {actuator_id!r} is already registered. Silently replacing a "
                    f"registered actuator would repoint every existing grant for that id at "
                    f"different code. Pass replace=True to do it deliberately.")
            if eff is not None:
                self._effect_registry.register(
                    actuator_id, eff,
                    declared_by=effect_declared_by or "unattributed", replace=replace)
            # The operator's allow_any_scope opt-in travels WITH the entry: the
            # verifier now refuses an empty required_scope by default, so the flag has
            # to reach it, and it must come from the registry the agent cannot write —
            # never from the caller of execute().
            self._actuators[actuator_id] = (fn, tuple(required_scope),
                                            bool(allow_any_scope))
            # Capture identity now, while the code is exactly as installed. A later
            # replace=True re-registers and recomputes, which is the one case where
            # the identity SHOULD move.
            self._impl_ids[actuator_id] = (fn,
                                           self._derive_implementation_id(actuator_id))
            if destination_param:
                self._destination_params[actuator_id] = destination_param
            # (cold pass Q2) Two actuator ids can drive the SAME hardware. Quarantining
            # one left the other free, and the second path moved the same arm —
            # reproduced. Quarantine therefore applies to the declared physical
            # resource; undeclared, an actuator is its own resource (previous
            # behaviour), which is safe for the one-id-per-device case and wrong for
            # any device with two code paths. Declare it.
            self._physical_resource[actuator_id] = physical_resource or actuator_id

    @staticmethod
    def _coerce_effects(effects) -> "list":
        by_name = {e.name.upper(): e for e in Effect}
        by_value = {e.value.lower(): e for e in Effect}
        out = []
        for e in effects:
            if isinstance(e, Effect):
                out.append(e)
            else:
                key = str(e).strip()
                m = by_name.get(key.upper()) or by_value.get(key.lower())
                if m is None:
                    raise ValueError(f"{e!r} is not a member of the Effect enum")
                out.append(m)
        return out

    def _persist_quarantine(self) -> None:
        """Write the quarantine through, atomically.

        (red-team, cold pass) There were briefly TWO methods with this name. Python
        keeps the last definition silently, so the other implementation was dead code
        that still had a live constructor parameter and a live posture event — a
        deployment that configured it was told the quarantine was durable while nothing
        was ever written. A duplicated safety mechanism is worse than a missing one:
        it reports success on behalf of code that does not run.
        """
        if not self._quarantine_path:
            return
        try:
            tmp = self._quarantine_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._unknown_completion, fh)
            os.replace(tmp, self._quarantine_path)   # atomic
        except Exception as e:
            # The in-memory quarantine still holds for THIS process, but durability is
            # gone. Record it loudly rather than failing the caller: refusing here
            # would turn a disk problem into a wall outage.
            self._record("(quarantine)", "persist", False,
                         f"quarantine could not be persisted ({e}); it will NOT "
                         f"survive a restart")

    def is_quarantine_durable(self) -> bool:
        """Whether the quarantine survives a restart. If False, a restart erases the
        only control preventing a timed-out actuator from being retried into a double
        actuation. Deployment checks with physical actuators should assert this."""
        return bool(self._quarantine_path)

    def unknown_completions(self) -> dict:
        """Actuators quarantined because a timeout left their physical state unknown.
        A deployment check should surface these: each one is a real-world object whose
        position nobody currently knows."""
        with self._lock:
            # deep copy: a shallow one shared the inner dicts, so an observer could
            # rewrite the quarantine record it was handed for inspection
            return {k: dict(v) for k, v in self._unknown_completion.items()}

    def acknowledge_completion(self, actuator_id: str, *, by: str,
                               observed_state: str) -> None:
        """Clear a quarantine after a HUMAN has established the physical state.

        Deliberately not automatic and not time-based: a timeout that expires on its
        own would let the double actuation through on the second attempt, which is the
        exact failure this exists to prevent. Someone has to look at the arm.
        """
        if not by or not observed_state:
            raise ValueError(
                "acknowledge_completion requires both `by` (who looked) and "
                "`observed_state` (what they saw). Clearing an unknown physical state "
                "is a safety-critical act and must be attributable.")
        with self._lock:
            key = self._physical_resource.get(actuator_id, actuator_id)
            if key not in self._unknown_completion:
                raise ValueError(
                    f"neither {actuator_id!r} nor its physical resource {key!r} is "
                    f"quarantined")
            del self._unknown_completion[key]
            self._persist_quarantine()
        self._record(actuator_id, "acknowledge_completion", True,
                     f"physical state reconciled by {by}: {observed_state}")

    def _validate_attestation(self, att) -> float:
        """Run the five checks and return the attestation's epoch time.

        Shared by start() and refresh_isolation_attestation() so the rules exist once.
        """
        if att is None:
            raise PermissionError(
                "require_isolation=True but no isolation attestation was supplied. The "
                "flags only say the operator INTENDED isolation; an attestation says a "
                "supervisor looked. Produce one with "
                "isolation_manifest.verify_process(os.getpid(), manifest) from OUTSIDE "
                "this process and pass it as isolation_attestation.")
        if not getattr(att, "trusted", False):
            raise PermissionError(
                "the isolation attestation is SELF-REPORTED (source="
                f"{getattr(att, 'source', '?')!r}). The process that answered the "
                "question is the process under question. Obtain a supervisor "
                "attestation via verify_process().")
        if not getattr(att, "permitted", False):
            raise PermissionError(
                "the isolation attestation has findings; this process's capability "
                "surface was not clean when a supervisor looked:\n"
                + getattr(att, "summary", lambda: "")())
        src = str(getattr(att, "source", ""))
        expected = f"supervisor:{os.getpid()}"
        if src != expected:
            raise PermissionError(
                f"the isolation attestation describes {src!r}, not this process "
                f"({expected!r}). An attestation for a different — possibly cleaner — "
                f"process says nothing about the one about to hold the actuators.")
        try:
            _ts = datetime.fromisoformat(str(att.checked_at)).timestamp()
            # An attestation dated in the FUTURE clamped to age zero and then read
            # fresh for the whole window. A measurement cannot describe a moment that
            # has not happened; a small tolerance covers ordinary clock skew between
            # supervisor and broker, and anything beyond it is a broken or forged clock.
            _skew = _ts - time.time()
            if _skew > 60.0:
                raise PermissionError(
                    f"the isolation attestation is dated {_skew:.0f}s in the FUTURE. A "
                    f"measurement cannot describe a moment that has not happened — "
                    f"either the supervisor's clock is wrong or the timestamp was "
                    f"chosen. Refusing.")
            return _ts
        except PermissionError:
            # A deliberate refusal must not be re-wrapped as a parse failure. It was
            # caught by the handler below and reported as "timestamp could not be
            # read", so the operator was told the clock was unreadable when in fact it
            # was five hours ahead. Fail-closed hid a wrong diagnosis — the third time
            # in this session a check refused correctly and named the wrong cause.
            raise
        except Exception as e:
            raise PermissionError(
                f"the isolation attestation's timestamp could not be read ({e}); its "
                f"freshness is unknown and unknown is not fresh.") from e

    def refresh_isolation_attestation(self, attestation) -> None:
        """Install a fresh supervisor attestation on a RUNNING broker.

        Without this, staleness would be a one-way door: the wall would stop serving
        at the age limit and could only be restored by a restart — and restarting to
        clear a safety hold is precisely the reflex this project keeps designing
        against. A supervisor re-verifies and hands the result in.
        """
        at = self._validate_attestation(attestation)
        with self._lock:
            self._isolation_attestation = attestation
            self._attested_at = at
            self._attested_mono = _elapsed_clock()
            self._attested_initial_age = max(0.0, time.time() - at)
        self._record("(isolation)", "attestation_refreshed", True,
                     f"supervisor re-verified this process at {attestation.checked_at}")

    def _attestation_stale_reason(self) -> Optional[str]:
        """None while the attestation is fresh; a reason once it is not.

        Cheap by construction: the timestamp is parsed once at install time, so the
        actuation path does an arithmetic comparison rather than ISO parsing.
        """
        if not self._require_isolation:
            return None
        with self._lock:
            mono = self._attested_mono
            initial = self._attested_initial_age
        if mono is None:
            return ("no isolation attestation is installed, so this process's "
                    "capability surface has never been verified")
        age = initial + (_elapsed_clock() - mono)
        if age > self._attestation_max_age:
            return (f"the isolation attestation is {age:.0f}s old (limit "
                    f"{self._attestation_max_age:.0f}s). It described this process at a "
                    f"moment that has passed; since then it may have acquired a socket, "
                    f"a capability or a namespace handle. A supervisor must re-verify "
                    f"and call refresh_isolation_attestation().")
        return None

    def _assert_isolation_attested(self) -> None:
        """Refuse to start unless an EXTERNAL supervisor has verified this process.

        Five checks, each of which was a way to hold a worthless attestation:
          * present at all — otherwise the wall property is a claim, not a measurement
          * TRUSTED — a self-report is the subject auditing itself, and
            isolation_manifest.attest_or_refuse() rejects one even when it passes
          * clean — findings mean the surface was wrong when it was looked at
          * ABOUT THIS PROCESS — an attestation for some other, cleaner pid is the
            obvious forgery, and the report carries its subject in `source`
          * FRESH — a check is a moment, so an old one describes a process that may
            since have acquired anything
        """
        _at = self._validate_attestation(self._isolation_attestation)
        with self._lock:
            self._attested_at = _at
            self._attested_mono = _elapsed_clock()
            self._attested_initial_age = max(0.0, time.time() - _at)
        stale = self._attestation_stale_reason()
        if stale:
            raise PermissionError(stale)

    def declaration_hash(self, actuator_id: str) -> Optional[str]:
        """PUBLIC: the hash an operator must pass as `effects_hash` when minting a
        grant for this actuator under require_effect_binding.

        Was private, so the only way to mint a bound grant was to reach into an
        underscore method — a usability trap that pushes deployments to leave the
        binding off, and a control nobody can use is a control nobody has.
        """
        return self._declaration_hash(actuator_id)

    def _declaration_hash(self, actuator_id: str) -> Optional[str]:
        """A stable hash of an actuator's CURRENT effect declaration.

        Deterministic across processes: effects sorted by value, plus who declared
        them. Any change — a downgrade from LETHAL to NONE, a different declarer —
        produces a different hash and therefore invalidates every grant bound to the
        old one.
        """
        try:
            eff = self._effect_registry.effects_for(actuator_id)
            if not eff:
                return None
            decl = self._effect_registry.declaration(actuator_id)
            by = getattr(decl, "declared_by", "") if decl else ""
            # (red-team Q7) The declaration used to cover EFFECTS + DECLARER only, so
            # two actuators with identical declarations and completely different code
            # hashed the same: a `gentle` implementation and a `violent` one were
            # indistinguishable, and a grant minted against the reviewed code stayed
            # valid after the code was swapped. A declaration that does not name the
            # implementation authorises a NAME, not a behaviour. The implementation
            # identity is now part of the hash, so replacing the code invalidates every
            # outstanding grant bound to the old declaration.
            payload = ("|".join(sorted(e.value for e in eff)) + "|" + str(by)
                       + "|impl=" + self._implementation_id(actuator_id))
            return hashlib.sha256(payload.encode("utf-8")).hexdigest()
        except Exception:
            return None

    def _implementation_id(self, actuator_id: str) -> str:
        """The identity of the CODE registered behind an actuator, as captured AT
        REGISTRATION.

        (red-team, Grok 2026-08-14 — REPRODUCED, then fixed here rather than in
        `_stable_value`.) This used to be recomputed on every request. Because
        container values are rendered by content, an actuator that closes over a
        mutable container it WRITES TO — a log, a counter, a handle pool, a retry
        buffer, all ordinary — rewrote its own identity the first time it ran, and
        every outstanding grant bound to that declaration then failed with "grant is
        not bound to this action". Verified: two `declaration_hash` calls either side
        of one append returned different digests, and 99 of 100 concurrently-issued
        approvals were rejected after the first actuation succeeded. A fleet of
        pre-approved actions that works exactly once is the precise pressure that gets
        effect binding switched off.

        The first attempt at a fix rendered mutable containers by type. That restored
        stability and BROKE two bypasses an earlier pass had closed —
        `partial(move, force=1.0)` vs `force=999.0` (keywords are a dict) and bound
        methods of different instances (state is a `__dict__`) both became
        indistinguishable. Trading one defect for two is not a fix.

        Capturing at registration keeps full content discrimination AND is stable,
        because the moment the code is installed is the moment its identity is
        established. Swapping the callable requires `register_actuator(replace=True)`,
        which recomputes — so a real swap still invalidates outstanding grants, which
        is the property that mattered.

        HONEST LIMIT, unchanged and now load-bearing: this pins the callable's
        STRUCTURE AS REGISTERED, not its runtime behaviour. Mutating closed-over state
        without re-registering is invisible to this hash — the already-documented
        limit — and no hash taken at any single moment can close it.
        """
        cached = self._impl_ids.get(actuator_id)
        if cached is None:
            # Not registered through the normal path: derive now.
            return self._derive_implementation_id(actuator_id)
        cached_fn, cached_id = cached
        # (red-team, cold pass 2026-08-14 — REPRODUCED.) Caching alone bought
        # stability and LOST a detection that existed before it: re-deriving per
        # request meant a callable swapped by writing straight into `_actuators`
        # changed the hash and invalidated outstanding grants. With a plain cache it
        # did not — verified, the digest was unchanged after the swap.
        #
        # So the cache is VALIDATED rather than trusted. Comparing the actual
        # callable by identity distinguishes the two cases the digest could not:
        # a swapped OBJECT (an attack, and grants must die) from the same object
        # whose closed-over state moved (ordinary, and grants must survive).
        current = self._actuator_fn(actuator_id)
        if current is not cached_fn:
            fresh = self._derive_implementation_id(actuator_id)
            self._impl_ids[actuator_id] = (current, fresh)
            return fresh
        return cached_id

    def _derive_implementation_id(self, actuator_id: str) -> str:
        try:
            fn = self._actuator_fn(actuator_id)
        except Exception:
            return "unknown"
        if fn is None:
            return "unknown"
        try:
            return "impl:" + hashlib.sha256(
                _callable_identity(fn).encode("utf-8")).hexdigest()[:32]
        except Exception:
            return "unknown"

    def _actuator_fn(self, actuator_id: str):
        """The callable registered for an actuator, whatever record shape is used."""
        rec = self._actuators.get(actuator_id)
        if rec is None:
            return None
        if isinstance(rec, dict):
            return rec.get("fn")
        for attr in ("fn", "func", "callback"):
            if hasattr(rec, attr):
                return getattr(rec, attr)
        if isinstance(rec, tuple):
            for item in rec:
                if callable(item):
                    return item
        return None

    def is_effect_bound(self) -> bool:
        """Whether grants are bound to the effect declaration current at issuance."""
        return self._require_effect_binding

    def is_isolation_attested(self) -> bool:
        """Whether an external supervisor has verified this process's surface."""
        att = self._isolation_attestation
        return bool(att is not None and getattr(att, "trusted", False)
                    and getattr(att, "permitted", False))

    def is_effect_gated(self) -> bool:
        """Whether the constitutional effect gate is enforced. An UNENFORCED broker
        fails OPEN on undeclared actuators — so 'no refusals' must never be read as
        'the gate is working'. Deployments that can physically actuate MUST assert this
        is True."""
        return self._effect_gate is not None

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
        if self._require_isolation and (self._socket_group is None
                                        or self._require_peer_uid is None):
            raise PermissionError(
                "require_isolation=True but the separate-user prerequisites are not "
                "configured: socket_group=" + repr(self._socket_group) +
                ", require_peer_uid=" + repr(self._require_peer_uid) + ". Refusing to "
                "start. A 0600 socket forces the agent and broker to share a UID, which "
                "makes peer-uid checking a no-op and means the actuator is NOT isolated "
                "from the agent — the property the wall exists to provide.")

        # (red-team, 3-way convergence: Meta P0-1, Grok #11, ChatGPT) `enforce_effects`
        # defaults OFF, and every reviewer independently called that a live
        # vulnerability rather than a neutral default. Rather than silently flipping it
        # (which would change behaviour under existing deployments), it is now TIED to
        # the flag that already means "I am claiming the wall property": a broker that
        # asserts isolation must also enforce the constitutional effect gate, or it
        # refuses to start. Claiming the wall while leaving undeclared actuators
        # reachable is the contradiction this closes.
        # A half-supplied pair used to skip the check in SILENCE — supply only one and
        # the broker started with nothing compared. That is the same shape as the stale
        # baseline and the compatibility guard before it: a condition written for
        # convenience that makes "not checking" indistinguishable from "checked and
        # fine". Supplying one now REQUIRES the other.
        if (self._broker_manifest is None) != (self._agent_manifest is None):
            raise PermissionError(
                "one isolation manifest was supplied without the other. The bunker "
                "check compares the broker's own surface against the agent's, so a "
                "single manifest compares nothing — and starting anyway would mean the "
                "check silently did not run.")
        if self._broker_manifest is not None and self._agent_manifest is not None:
            looser = self._broker_manifest.more_permissive_than(self._agent_manifest)
            if looser:
                raise PermissionError(
                    "the broker's own isolation manifest is LOOSER than the one it "
                    "enforces on the agent:\n  - " + "\n  - ".join(looser) +
                    "\nA bunker less locked down than the room it guards is not a "
                    "bunker. This is the package-registry mistake one layer up: a "
                    "trusted conduit whose own surface nobody audited.")
        if self._require_isolation:
            self._assert_isolation_attested()
        if self._require_isolation and not self._enforce_effects:
            raise PermissionError(
                "require_isolation=True but enforce_effects=False. A broker that claims "
                "the wall property cannot leave undeclared actuators reachable: an "
                "actuator whose effects no human declared would actuate on a valid "
                "grant. Set enforce_effects=True and declare every actuator's effects.")
        old_umask = os.umask(0o177)          # -> socket created rw for OWNER ONLY
        try:
            self._srv.bind(self._socket_path)
        finally:
            os.umask(old_umask)

        # ── SEPARATE-USER DEPLOYMENT (red-team, Grok — a real contradiction) ──
        # This class documents "run the agent as a SEPARATE OS USER". A 0600 socket is
        # connectable ONLY by the owner uid, so under that deployment the agent got
        # EACCES and could not talk to the wall at all; the only configuration that
        # actually worked was same-uid, where require_peer_uid is a no-op and the
        # isolation story the docstring sells does not exist.
        #
        # Resolution: a SHARED GROUP that the broker and the agent both belong to, and
        # nobody else. Order matters and is deliberate — TIGHTEN, SET GROUP, THEN OPEN:
        #   1. bind under umask 0177  -> 0600, owner-only. No window where a wrong group
        #      can connect.
        #   2. chown the group        -> still 0600, so nothing is reachable yet.
        #   3. chmod 0660             -> only now can the shared group connect.
        # Doing chmod before chown would briefly expose the socket to the broker's
        # PRIMARY group, which is not the group we intend to admit.
        if self._socket_group is not None:
            try:
                gid = self._socket_group
                if isinstance(gid, str):
                    import grp
                    gid = grp.getgrnam(gid).gr_gid
                os.chown(self._socket_path, -1, gid)     # step 2: group, still 0600
                os.chmod(self._socket_path, 0o660)       # step 3: open to that group
            except Exception as e:
                # FAIL CLOSED. A socket we could not lock down correctly must not serve.
                try:
                    self._srv.close()
                    os.unlink(self._socket_path)
                except OSError:
                    pass
                raise PermissionError(
                    f"could not restrict the socket to group {self._socket_group!r}: {e}. "
                    f"Refusing to start — a wall whose door cannot be locked correctly "
                    f"does not open. (Both the broker user and the agent user must belong "
                    f"to this group, and no one else.)") from e
            # Verify what we actually got rather than trusting the calls succeeded.
            st = os.stat(self._socket_path)
            if stat.S_IMODE(st.st_mode) != 0o660 or st.st_gid != gid:
                try:
                    self._srv.close()
                    os.unlink(self._socket_path)
                except OSError:
                    pass
                raise PermissionError(
                    f"socket permissions did not take effect "
                    f"(mode={oct(stat.S_IMODE(st.st_mode))}, gid={st.st_gid}, wanted "
                    f"mode=0o660 gid={gid}). Refusing to start.")
        else:
            # No shared group configured: stay owner-only. This is the SAFE default, and
            # it means the agent must run as the SAME user — which weakens the isolation
            # model. Separate-user deployments MUST pass socket_group.
            try:
                os.chmod(self._socket_path, 0o600)   # belt-and-suspenders
            except OSError:
                pass

        self._srv.listen(16)
        self._srv.settimeout(0.5)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def is_breach_gated(self) -> bool:
        """Whether a breach-posture source is wired. An UNGATED broker will actuate for a
        HALTED system that holds a valid grant — so 'no refusals' must never be read as
        'the gate is working'. Deployment checks should assert this is True."""
        return self._posture_source is not None

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

    def _write_evidence(self, phase: str, actuator_id: str, command: str,
                        detail: str, nonce: str = "") -> bool:
        """Append one hash-chained, fsynced evidence record. Returns False on failure.

        Chained so a removed or edited entry breaks verification; fsynced so the
        record survives the event it describes.
        """
        if not self._evidence_path:
            return True
        try:
            with self._lock:
                entry = {"ts": time.time(), "phase": phase,
                         "actuator_id": actuator_id, "command": command,
                         "detail": detail, "nonce": nonce,
                         "previous_hash": self._evidence_prev}
                entry["entry_hash"] = hashlib.sha256(
                    json.dumps(entry, sort_keys=True).encode("utf-8")).hexdigest()
                d = os.path.dirname(self._evidence_path)
                if d:
                    os.makedirs(d, exist_ok=True)
                with open(self._evidence_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                self._evidence_prev = entry["entry_hash"]
            return True
        except OSError:
            # A genuine write failure: disk full, permissions, path gone.
            return False
        except Exception as e:
            # NOT an I/O failure — a programming error. The broad `except Exception`
            # here converted a missing `hashlib` import into a False return, so a code
            # bug was indistinguishable from a full disk and the refusal named the
            # wrong cause. Fail closed either way, but say which.
            self.records.append(ActuationRecord(
                time.time(), actuator_id, command, False,
                f"evidence writer is broken (not an I/O failure): {e!r}", nonce))
            return False

    def verify_evidence(self) -> bool:
        """True if the evidence chain is intact. A break means an entry was removed
        or edited after the fact."""
        if not self._evidence_path or not os.path.exists(self._evidence_path):
            return True
        prev = "GENESIS"
        with open(self._evidence_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                e = json.loads(line)
                if e.get("previous_hash") != prev:
                    return False
                stored = e.pop("entry_hash", None)
                if hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest() \
                        != stored:
                    return False
                prev = stored
        return True

    def is_evidence_durable(self) -> bool:
        return bool(self._evidence_path)

    def _record(self, actuator_id: str, command: str, allowed: bool, reason: str,
                nonce: str = "") -> None:
        rec = ActuationRecord(time.time(), actuator_id, command, allowed, reason, nonce)
        self.records.append(rec)          # in-broker evidence: always kept first
        if not allowed and self._probe_detector is not None:
            try:
                self._probe_detector.observe_refusal(actuator_id, reason.split(":")[0])
            except Exception:
                pass          # counting must never be able to break refusing
        # (red-team) BOUNDED. An unbounded list exhausts memory in a long-lived broker.
        # Oldest entries are dropped and the drop count is retained, so truncation is
        # visible rather than silent — an audit trail that quietly loses its head is
        # worse than one that says how much it lost.
        if len(self.records) > self._records_cap:
            overflow = len(self.records) - self._records_cap
            del self.records[:overflow]
            self._records_dropped += overflow
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

        # 0. ATTESTATION FRESHNESS. Checked on EVERY request, not once at start().
        #    A broker verified clean at boot otherwise runs for a week on a report
        #    describing a process that no longer exists in that state — the literal
        #    "detection is a moment" critique. Now the wall stops serving when the
        #    attestation ages out and resumes when a supervisor re-verifies.
        _stale = self._attestation_stale_reason()
        if _stale:
            self._record(actuator_id, command, False, f"attestation stale: {_stale}")
            return {"ok": False, "error": "isolation_unattested",
                    "error_code": "ISOLATION_UNATTESTED", "detail": _stale}

        # 0a. UNKNOWN PHYSICAL STATE. Runs before the breach gate: whether the arm is
        #     where we think it is does not depend on posture, grants, or effects.
        with self._lock:
            _res = self._physical_resource.get(actuator_id, actuator_id)
            unknown = self._unknown_completion.get(_res)
        if unknown:
            self._record(actuator_id, command, False,
                         "actuator has unreconciled unknown completion")
            return {"ok": False, "error": "unknown_physical_state",
                    "error_code": "UNKNOWN_PHYSICAL_STATE",
                    "detail": f"actuator {actuator_id!r} timed out at "
                              f"{unknown['at']} and its work may still be running or "
                              f"may have completed. Its physical state is unknown, so a "
                              f"retry could actuate twice. A human must establish the "
                              f"real state and call acknowledge_completion("
                              f"{actuator_id!r}, by=...) before it accepts anything "
                              f"further."}
        params = req.get("params") or {}
        grant_d = req.get("grant")

        # 0. BREACH GATE — runs FIRST, before the grant is even examined.
        #    A system that has already violated an invariant must not keep its full
        #    blast radius until its grants happen to expire. Without this, the wall's
        #    promise was "blast radius = granted permission set" — true, but the
        #    permission set did not COLLAPSE on breach, which is backwards: the moment
        #    the wall matters most is after something has already gone wrong.
        #    FAIL-CLOSED: a posture source that RAISES is a refusal, never a fall-through.
        if self._halt_state is not None:
            try:
                halted = _call_with_timeout(self._halt_state, self._posture_timeout)
            except Exception as e:
                self._record(actuator_id, command, False, f"halt_state raised: {e!r}")
                return {"ok": False, "error": "halt_check_failed",
                        "detail": ("the halt interlock could not be read; refusing. A "
                                   "stop that cannot be confirmed is treated as in "
                                   "force.")}
            # Strict bool for the same reason the posture gate is: an IntEnum or a
            # truthy object would silently invert a stop into a permit.
            if halted is not True and halted is not False:
                self._record(actuator_id, command, False,
                             f"halt_state returned {type(halted).__name__}, not bool")
                return {"ok": False, "error": "halt_misconfigured",
                        "detail": (f"halt_state must return exactly True or False; got "
                                   f"{type(halted).__name__}. Refusing.")}
            if halted:
                self._record(actuator_id, command, False, "system is HALTED")
                return {"ok": False, "error": "halted",
                        "detail": ("the system is in a halt state; actuation is "
                                   "refused until the halt is released through the "
                                   "authorised path")}

        if self._posture_source is not None:
            try:
                raw = _call_with_timeout(self._posture_source, self._posture_timeout)
                # (red-team, cold pass — CRITICAL) do NOT coerce. `bool()` made a plausible
                # wiring mistake INVERT the control: passing `breach.posture` instead of
                # `breach.is_operational` yields an IntEnum, and Posture.HALT == 3 is
                # TRUTHY while Posture.NORMAL == 0 is FALSY — a halted system would
                # actuate and a healthy one would be refused. A type hint is not a check.
                # Anything that is not exactly a bool is a wiring error, and a wiring error
                # in a safety gate must fail LOUD and CLOSED, never be interpreted.
                if raw is not True and raw is not False:
                    self._record(actuator_id, command, False,
                                 f"posture_source returned {type(raw).__name__}, not bool")
                    return {"ok": False, "error": "posture_misconfigured",
                            "detail": f"posture_source must return exactly True or False; "
                                      f"got {type(raw).__name__}. Refusing. (Wiring "
                                      f"`breach.posture` instead of `breach.is_operational` "
                                      f"would silently INVERT this gate.)"}
                operational = raw
            except Exception as e:
                self._record(actuator_id, command, False, f"posture check failed: {e}")
                return {"ok": False, "error": "posture_unavailable",
                        "detail": "breach posture could not be determined; refusing "
                                  "(a wall that cannot check its own state does not open)"}
            if not operational:
                self._record(actuator_id, command, False,
                             "system is in a breached posture (RESTRICTED/HALT)")
                return {"ok": False, "error": "breached",
                        "detail": "the system is holding in a breached posture; "
                                  "actuation is refused regardless of grant validity. "
                                  "A human must acknowledge the breach to restore it."}

        with self._lock:
            entry = self._actuators.get(actuator_id)

        if entry is None:
            self._record(actuator_id, command, False, "unknown actuator")
            return {"ok": False, "error": "unknown_actuator"}
        # UNKNOWN ENTRY SHAPE IS NOT PERMISSIVE. `register_actuator` writes a
        # 3-tuple carrying the operator's allow_any_scope opt-in. Anything that
        # reached `_actuators` by another route — a red-team injection, an older
        # shape — gets allow_any_scope=False, so it CANNOT inherit an opt-in nobody
        # granted it. Defaulting the other way would let a bypass that skips
        # registration also skip the scope requirement.
        fn, required_scope = entry[0], entry[1]
        # Identity, not truthiness, and not `bool()`: an entry that reached the
        # registry by any route other than register_actuator cannot smuggle an opt-in
        # in as a truthy string.
        allow_any_scope = (len(entry) > 2 and entry[2] is True)

        # 0b. CONSTITUTIONAL EFFECT GATE (fail-closed-on-undeclared).
        #
        #     PLACEMENT (red-team A2): this runs BEFORE the grant is parsed, reserved,
        #     or charged to the cumulative ledger. Every check it makes — undeclared,
        #     absolute-effect, lethal-mismatch — depends only on (actuator_id, command,
        #     params); none of them needs the grant. Running it late meant three
        #     constitutionally-impossible requests still invoked the ledger hook three
        #     times and reserved/released three nonces, so an attacker could drain a
        #     cumulative safety budget with actions that could never execute. This
        #     module already reasoned about that exact class for grants ("would let an
        #     attacker who can trigger ledger refusals exhaust an operator's grants");
        #     the gate now sits where nothing has been spent yet.
        #
        #     AUTHORIZATION SCOPE (red-team A7): the gate is handed an authorized
        #     context ON PURPOSE and with an honest label. CONDITIONAL effects
        #     (DATA_EGRESS, ACCOUNT_ACCESS) are governed at this wall by the GRANT and
        #     its required_scope below — that is the wall's existing job — so the gate
        #     must not re-adjudicate them here and spuriously refuse a properly-scoped
        #     egress actuator. What the gate adds is the part scope cannot express:
        #     undeclared capability, absolute bright lines, lethal-shaped mismatch, and
        #     those are unaffected by the context (verified: full authorization does not
        #     unlock an absolute effect). The label names the MECHANISM, not a person:
        #     it previously said `authorised_by=grant.subject` — i.e. 'robot-1', the
        #     machine naming ITSELF as the authorizer of its own effect decision, on a
        #     project whose whole thesis is that machines do not self-authorize.
        #
        #     FAIL CLOSED (red-team A6): wrapped, because the ledger stage below has a
        #     wrapper and this one did not — an exception escaped `_handle` entirely.
        if self._effect_gate is not None:
            try:
                gate_ctx = ActionContext(
                    owner_authorized=True, target_authorized=True,
                    authorised_by="broker:scope-mediated")
                # params are part of the scan surface (red-team A4): lethal intent in
                # {"target": "kill the intruder"} previously never reached the lexicon,
                # blinding the mismatch escalation to where the content actually lives.
                surface = command if not params else f"{command} {params}"
                decision = self._effect_gate.authorize(actuator_id, surface, gate_ctx)
                refused = decision.outcome is not Outcome.ALLOW
                reason, code = decision.reason, decision.outcome.value
            except Exception as e:
                # Refuse HERE. This used to set refused=True and depend on the `if`
                # below to act on it. Safe, but the refusal lived one step away from
                # the failure, and "the safety is somewhere else" is the fragility this
                # repo keeps finding — a later edit between the two steps breaks it
                # with nothing connecting the change to the breakage.
                self._record(actuator_id, command, False,
                             f"effect gate block_error: {e!r}")
                return {"ok": False, "error": "effect_block_error",
                        "error_code": "EFFECT_BLOCK_ERROR",
                        "detail": f"the effect gate could not evaluate and fails "
                                  f"closed: {e!r}"}
            if refused:
                self._record(actuator_id, command, False, f"effect gate {code}: {reason}")
                return {"ok": False, "error": f"effect_{code}",
                        "error_code": f"EFFECT_{code.upper()}", "detail": reason}

        # 0c. BLAST-RADIUS (BREADTH) GOVERNOR — incident-derived, §I4.
        #     Sits beside the effect gate for the same reason: it is grant-independent,
        #     so it runs before the grant is parsed, reserved, or charged to the ledger.
        #     Volume/rate is NOT measured here — that is CumulativeLedger's job via
        #     `ledger_hook`, and duplicating it would create a second source of truth
        #     for the same number. This measures BREADTH: how many distinct capabilities
        #     are touched in a window. One capability driven hard is a busy robot;
        #     twenty distinct capabilities in a minute is spread. NOTE the boundary: this
        #     sees only what comes THROUGH the wall. A process that has escaped and calls
        #     hardware directly produces zero observations here.
        #     A REVIEW verdict is a HOLD, not a permanent block, and it names the exact
        #     ceiling and observed numbers so a human can see what tripped.
        if self._blast_radius is not None:
            try:
                declared = self._effect_registry.effects_for(actuator_id) or ()
                reading = self._blast_radius.observe(actuator_id, declared)
                breadth_ok = reading.verdict is BreadthVerdict.OK
                breadth_reason, breadth_code = reading.reason, reading.verdict.value
            except Exception as e:
                self._record(actuator_id, command, False,
                             f"blast radius ERROR: {e!r}")
                return {"ok": False, "error": "blast_radius_error",
                        "error_code": "BLAST_RADIUS_ERROR",
                        "detail": f"the blast-radius governor could not evaluate and "
                                  f"fails closed: {e!r}"}
            if not breadth_ok:
                self._record(actuator_id, command, False,
                             f"blast radius {breadth_code}: {breadth_reason}")
                return {"ok": False, "error": f"blast_radius_{breadth_code.lower()}",
                        "error_code": f"BLAST_RADIUS_{breadth_code}",
                        "detail": breadth_reason}

        # 0d. EGRESS DESTINATION INTERLOCK — parameter-level, for any capability whose
        #     params carry a network destination. Runs beside the other grant-independent
        #     gates, before the grant is parsed or the ledger charged.
        #
        #     Why parameter-level: one `http_request` capability can reach anywhere. A
        #     per-capability effect tag says "this talks to the network"; it cannot say
        #     "but only to these hosts". The destination is in the params, so that is
        #     where the interlock has to be.
        #
        #     THREE SELF-RED-TEAM FIXES ARE LOAD-BEARING HERE:
        #     E1 — it used to check only the FIRST destination-shaped key it found, so
        #          {"url": <allowed>, "endpoint": <evil>} passed the allowlist and the
        #          actuator still received the evil one. EVERY destination in the params
        #          is now checked and ALL must pass.
        #     E2 — the interlock used to fire only when DATA_EGRESS was declared, so an
        #          HTTP actuator mis-declared NONE was ungoverned. A URL-shaped param on
        #          a capability that does NOT declare egress is now a declaration
        #          MISMATCH and is held for review — the same shape as the lethal-word
        #          mismatch, not a new judgement about intent: being handed a URL is
        #          structural evidence the capability can reach the network.
        #     E3 — the registry read was wrapped in `except: _declared_eff = ()`, so a
        #          registry failure emptied the effect set and skipped the interlock
        #          entirely. A safety gate's error handler must not be its bypass.
        try:
            _declared_eff = self._effect_registry.effects_for(actuator_id) or ()
        except Exception as e:
            # UNCONDITIONAL. This set a flag that was only acted on further down IF
            # destinations were also present, so a registry failure on an action with
            # no URL in its params proceeded and the actuator RAN — reproduced in cold
            # self-red-team. Whether the effect declaration can be read is not a
            # question that depends on what else is in the params.
            self._record(actuator_id, command, False,
                         f"effect registry unreadable: {e!r}")
            return {"ok": False, "error": "registry_error",
                    "error_code": "REGISTRY_ERROR",
                    "detail": f"the effect declaration for {actuator_id!r} could not be "
                              f"read ({e!r}), so it is unknown what this action does. "
                              f"Refusing: a gate that cannot check does not open."}
        _reg_ok = True          # retained for the checks below; failure returned above
        _dests = _find_destinations(params)
        _dkey = self._destination_params.get(actuator_id)
        if _dkey:
            _declared_dest = params.get(_dkey) if isinstance(params, dict) else None
            if _declared_dest is None or not str(_declared_dest).strip():
                self._record(actuator_id, command, False,
                             f"declared destination param {_dkey!r} missing")
                return {"ok": False, "error": "egress_no_destination",
                        "error_code": "EGRESS_NO_DESTINATION",
                        "detail": f"capability {actuator_id!r} declares its destination "
                                  f"in params[{_dkey!r}], which was absent or empty. "
                                  f"An egress action whose destination cannot be "
                                  f"established does not act."}
            _dests = [str(_declared_dest)] + [d for d in _dests
                                              if d != str(_declared_dest)]
        if not _reg_ok and _dests:
            self._record(actuator_id, command, False,
                         "egress interlock could not read the effect registry")
            return {"ok": False, "error": "egress_error", "error_code": "EGRESS_ERROR",
                    "detail": "the effect declaration could not be read, so it is "
                              "unknown whether this action egresses. Refusing: a gate "
                              "that cannot check does not open."}
        _is_egress = Effect.DATA_EGRESS in set(_declared_eff)
        if _dests and not _is_egress:
            self._record(actuator_id, command, False,
                         f"egress mismatch: {len(_dests)} destination(s) supplied to a "
                         f"capability not declared DATA_EGRESS")
            return {"ok": False, "error": "egress_declaration_mismatch",
                    "error_code": "EGRESS_DECLARATION_MISMATCH",
                    "detail": f"capability {actuator_id!r} was handed a network "
                              f"destination but does not declare Effect.DATA_EGRESS. "
                              f"Being handed a URL is structural evidence it can reach "
                              f"the network, so the declaration is wrong or the call is. "
                              f"A human must resolve which."}
        if _is_egress:
            try:
                if not _dests:
                    ok_e, reason_e, code_e = False, (
                        f"capability {actuator_id!r} declares DATA_EGRESS but no "
                        f"destination was found in params. An egress action whose "
                        f"destination cannot be established does not act."), "NO_DESTINATION"
                elif self._egress_guard is None:
                    ok_e, reason_e, code_e = False, (
                        "this capability declares DATA_EGRESS but no egress allowlist "
                        "is configured on this broker. Unconfigured is not permissive."
                    ), "UNCONFIGURED"
                else:
                    ok_e, reason_e, code_e = True, "", "ALLOW"
                    for d in _dests:            # EVERY destination must pass (E1)
                        dec = self._egress_guard.check(d)
                        if not dec.permitted:
                            ok_e, reason_e, code_e = False, dec.reason, dec.verdict.value
                            break
            except Exception as e:
                self._record(actuator_id, command, False, f"egress ERROR: {e!r}")
                return {"ok": False, "error": "egress_error",
                        "error_code": "EGRESS_ERROR",
                        "detail": f"the egress interlock could not evaluate and fails "
                                  f"closed: {e!r}"}
            if not ok_e:
                self._record(actuator_id, command, False, f"egress {code_e}: {reason_e}")
                return {"ok": False, "error": f"egress_{code_e.lower()}",
                        "error_code": f"EGRESS_{code_e}", "detail": reason_e}

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
        _eff_hash = None
        if self._require_effect_binding:
            _eff_hash = self._declaration_hash(actuator_id)
            if _eff_hash is None:
                self._record(actuator_id, command, False,
                             "effect binding required but the declaration is unreadable")
                return {"ok": False, "error": "declaration_unreadable",
                        "error_code": "DECLARATION_UNREADABLE",
                        "detail": f"require_effect_binding is on but {actuator_id!r} has "
                                  f"no readable effect declaration to bind to."}
        # 2b. THE ENVELOPE IN FORCE. Read at execution, not at approval. If the
        #     deployment widened it in between, the digest differs and the binding
        #     below stops matching — the approval does not survive the widening.
        _env_hash = None
        if self._envelope_source is not None:
            try:
                from driftcore.verification.human_authorization import envelope_digest
                _env_hash = envelope_digest(self._envelope_source())
            except Exception as e:
                self._record(actuator_id, command, False,
                             f"envelope source failed closed: {e!r}")
                return {"ok": False, "error": "envelope_error",
                        "error_code": "ENVELOPE_ERROR",
                        "detail": f"the safety envelope could not be read, so what "
                                  f"this action was approved under cannot be "
                                  f"established: {e!r}"}

        # 2c. HUMAN APPROVAL — structural half. A pure hash over the presented
        #     attestation, no crypto and no side effect, so it is safe to run before
        #     the gates that may refuse for unrelated reasons. The signature check
        #     burns a single-use nonce and therefore runs LATE (step 4b), so a ledger
        #     refusal cannot consume a human's approval without acting.
        # 2b-bis. THE PURPOSE DECISION. Its digest goes into the binding below, so a
        #     grant minted against one ledger decision cannot be presented with
        #     another. The decision is REDEEMED later (step 4d), after the gates that
        #     can refuse for unrelated reasons — redemption is single-use and must not
        #     be spent by a request that was never going to act.
        _decision = req.get("intent_decision")
        _intent_digest = None
        if self._intent_ledger is not None:
            if _decision is None:
                self._record(actuator_id, command, False, "no intent decision")
                return {"ok": False, "error": "no_intent_decision",
                        "error_code": "NO_INTENT_DECISION",
                        "detail": "this broker requires a decision from the intent "
                                  "ledger. A signed grant proves someone was allowed "
                                  "to act; it says nothing about whether the action "
                                  "is accountable to what a human actually asked for."}
            _intent_digest = getattr(_decision, "digest", None)
            if not _intent_digest:
                self._record(actuator_id, command, False, "malformed intent decision")
                return {"ok": False, "error": "malformed_intent_decision",
                        "error_code": "MALFORMED_INTENT_DECISION",
                        "detail": "the presented object carries no decision digest"}
        elif _decision is not None:
            # Silently ignoring a supplied decision is the failure this closes.
            self._record(actuator_id, command, False,
                         "intent decision supplied to a broker with no ledger")
            return {"ok": False, "error": "intent_ledger_unconfigured",
                    "error_code": "INTENT_LEDGER_UNCONFIGURED",
                    "detail": "an intent decision was presented but this broker has "
                              "no ledger to redeem it against, so it would be "
                              "ignored rather than checked."}

        _att_raw = req.get("attestation")
        _att_hash = None
        if self._human_approval is not None:
            if _att_raw is None:
                self._record(actuator_id, command, False, "no human attestation")
                return {"ok": False, "error": "no_human_attestation",
                        "error_code": "NO_HUMAN_ATTESTATION",
                        "detail": "this broker requires a human approval bound to the "
                                  "exact action. A signed grant alone proves only that "
                                  "the signing key authorised it."}
            try:
                _att_hash = self._human_approval.pair_digest(_att_raw)
            except Exception as e:
                self._record(actuator_id, command, False, f"malformed attestation: {e}")
                return {"ok": False, "error": "malformed_attestation",
                        "error_code": "MALFORMED_ATTESTATION", "detail": str(e)}
        elif _att_raw is not None:
            # Silently ignoring a supplied approval is the failure this module exists
            # to close: the request would look approved and be enforced as if it were
            # not. Unconfigured is not permissive.
            self._record(actuator_id, command, False,
                         "attestation supplied to a broker with no approval gate")
            return {"ok": False, "error": "human_approval_unconfigured",
                    "error_code": "HUMAN_APPROVAL_UNCONFIGURED",
                    "detail": "an attestation was presented but this broker has no "
                              "HumanApprovalGate, so it would be ignored rather than "
                              "checked. Refusing instead of accepting an approval "
                              "nothing verifies."}

        try:
            binding_now = PermissionVerifier.bind_action(
                actuator_id, command, params,
                broker_id=self._broker_id, effects_hash=_eff_hash,
                envelope_hash=_env_hash, attestation_hash=_att_hash,
                subject=(grant.subject if self._human_approval is not None else None),
                intent_digest=_intent_digest)
        except (ValueError, TypeError) as e:
            # json.loads accepts the NaN and Infinity tokens by default, so these
            # reach the wall over the socket. An action whose parameters have no
            # canonical form cannot be bound to, and an unbindable action is not
            # approvable — refuse by name rather than escaping as a broker error.
            self._record(actuator_id, command, False, f"unbindable parameters: {e}")
            return {"ok": False, "error": "unbindable_parameters",
                    "error_code": "UNBINDABLE_PARAMETERS", "detail": str(e)}

        # 3. Verify signature / expiry / replay / scope / binding — all in ONE place,
        #    on the PRIVILEGED side, with the key the agent does not have.
        # (red-team, external) RESERVE, do not merely verify. verify() checked the nonce
        # without burning it and consume() came 26 lines later, so two concurrent requests
        # could both verify the same single-use grant (reproduced: 8/8 threads succeeded).
        # reserve() checks and marks the nonce in-flight atomically; the gates below then
        # run, and the grant is either committed (it acted) or released (refused, no side
        # effect). Burning up-front instead would let an attacker who can trigger ledger
        # refusals exhaust an operator's grants without ever actuating.
        try:
            self._verifier.reserve(grant, required_scope=required_scope,
                                   expected_subject=self._expected_subject,
                                   action_binding=binding_now,
                                   allow_any_scope=allow_any_scope)
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
                # refused BEFORE any side effect -> the grant was not spent
                self._verifier.release(grant)
                self._record(actuator_id, command, False,
                             f"ledger hook raised (fail-closed): {e}", grant.nonce)
                return {"ok": False, "error": "ledger_error", "detail": "safety gate failed closed"}
            if refusal:
                self._verifier.release(grant)
                self._record(actuator_id, command, False, f"ledger refused: {refusal}",
                             grant.nonce)
                return {"ok": False, "error": "ledger_refused", "detail": refusal}

        # 4b. HUMAN APPROVAL — cryptographic half. Deliberately AFTER the ledger gate.
        #     Verification burns the attestation's single-use nonce, so running it
        #     earlier would let anything that can provoke a ledger refusal consume a
        #     human's approvals without a single actuation ever happening — the same
        #     reasoning that made grant nonces reserve-then-commit rather than
        #     burn-up-front. By here the request has passed every gate that can refuse
        #     for reasons unrelated to who approved it.
        if self._human_approval is not None:
            try:
                _principal = self._human_approval.verify(
                    _att_raw, actuator_id=actuator_id, command=command, params=params,
                    broker_id=self._broker_id, effects_hash=_eff_hash,
                    envelope_hash=_env_hash, subject=grant.subject)
            except Exception as e:
                self._verifier.release(grant)
                self._record(actuator_id, command, False,
                             f"human approval rejected: {e}", grant.nonce)
                return {"ok": False, "error": "human_approval_rejected",
                        "error_code": "HUMAN_APPROVAL_REJECTED", "detail": str(e)}
            self._record(actuator_id, command, True,
                         f"human approval verified: {_principal}", grant.nonce)

        # 4c. THE ENVELOPE, RE-READ. (red-team, ChatGPT 2026-08-14 — REPRODUCED.)
        #     Reading it once at step 2b proved only that the envelope was right when
        #     the request arrived. Every gate between there and here takes time, and a
        #     ledger hook that widened the envelope mid-request executed under 800N on
        #     an approval given for 20N: grant valid, attestation valid, action wrong.
        #     Re-read as late as a CLEAN refusal still allows — before the evidence
        #     write and the nonce burn — so a moved envelope releases the grant instead
        #     of spending it.
        #
        #     HONEST LIMIT: this shrinks the window, it does not abolish it. DriftCore
        #     does not enforce the envelope — LifeCore does — so between this check and
        #     the actuator's physical effect there remains a gap no software gate on
        #     this side can close. The durable answer is to hand the approved envelope
        #     digest DOWN to the actuator and have the physical layer refuse a mismatch.
        #     That is a LifeCore change, and it is named here rather than papered over.
        if self._envelope_source is not None:
            try:
                from driftcore.verification.human_authorization import envelope_digest
                _env_now = envelope_digest(self._envelope_source())
            except Exception as e:
                self._verifier.release(grant)
                self._record(actuator_id, command, False,
                             f"envelope re-read failed closed: {e!r}", grant.nonce)
                return {"ok": False, "error": "envelope_error",
                        "error_code": "ENVELOPE_ERROR",
                        "detail": f"the safety envelope could not be re-read before "
                                  f"acting: {e!r}"}
            if _env_now != _env_hash:
                self._verifier.release(grant)
                self._record(actuator_id, command, False,
                             "envelope changed between authorization and execution",
                             grant.nonce)
                return {"ok": False, "error": "envelope_changed",
                        "error_code": "ENVELOPE_CHANGED",
                        "detail": "the safety envelope changed after this action was "
                                  "authorized. What was approved is no longer what "
                                  "would be executed, so nothing is executed. Re-approve "
                                  "under the current envelope."}

        # 4d. REDEEM THE PURPOSE DECISION. Late, for the same reason the human
        #     attestation is late: redemption is single-use, so a request refused by
        #     the ledger, the envelope or the blast radius must not consume it. The
        #     ledger re-derives its digest from the action presented HERE, so a
        #     decision obtained for one action cannot be spent on another.
        if self._intent_ledger is not None:
            try:
                self._intent_ledger.redeem(_decision, action=f"{actuator_id}:{command}",
                                           actor=grant.key_id)
            except Exception as e:
                self._verifier.release(grant)
                self._record(actuator_id, command, False,
                             f"intent decision rejected: {e}", grant.nonce)
                return {"ok": False, "error": "intent_decision_rejected",
                        "error_code": "INTENT_DECISION_REJECTED", "detail": str(e)}

        # 5. COMMIT THE RESERVATION (burn the nonce), THEN ACT. Single-use: a replayed
        #    grant cannot re-actuate. Committing BEFORE the actuator runs is deliberate —
        #    if the actuator crashes we must not leave a spendable grant behind.
        # WRITE-AHEAD INTENT. Written and fsynced BEFORE the nonce is burned and the
        # actuator runs, so a crash between here and completion leaves a record saying
        # what was about to happen. An action nobody can record is an action nobody can
        # review, so when durable evidence is required a failed write REFUSES rather
        # than proceeding unrecorded.
        if not self._write_evidence("INTENT", actuator_id, command,
                                    "about to commit and actuate", grant.nonce):
            if self._require_durable_evidence:
                self._verifier.release(grant)
                self._record(actuator_id, command, False,
                             "durable evidence could not be written; refusing")
                return {"ok": False, "error": "evidence_unavailable",
                        "error_code": "EVIDENCE_UNAVAILABLE",
                        "detail": "the durable evidence record could not be written, "
                                  "so this action could not be made reviewable. "
                                  "Refusing rather than acting unrecorded."}
        self._verifier.commit(grant)
        try:
            if self._actuator_timeout is None:
                result = fn(**params) if params else fn()
            else:
                def _late(outcome, exc, _a=actuator_id, _c=command, _n=grant.nonce):
                    self._record(_a, _c, outcome == "completed",
                                 f"ORPHANED actuator {outcome} AFTER the broker reported "
                                 f"UNKNOWN completion"
                                 + (f": {exc!r}" if exc else "")
                                 + ". The physical action's true outcome is this record, "
                                   "not the timeout above.", _n)
                result = _call_with_timeout(
                    (lambda: fn(**params)) if params else fn, self._actuator_timeout,
                    on_late=_late)
        except TimeoutError:
            # The nonce is already burned and the actuator MAY have started. This is
            # NOT a clean refusal and must never be reported as one — an agent told
            # "refused" would retry and double-actuate.
            with self._lock:
                _res = self._physical_resource.get(actuator_id, actuator_id)
                self._unknown_completion[_res] = {
                    "at": time.time(), "command": command,
                    "actuator_id": actuator_id,
                    "timeout": self._actuator_timeout}
                _perr = self._persist_quarantine()
            self._record(actuator_id, command, False,
                         f"actuator exceeded {self._actuator_timeout}s; completion "
                         f"UNKNOWN; quarantined pending human reconciliation",
                         grant.nonce)
            return {"ok": False, "error": "actuator_timeout",
                    "error_code": "ACTUATOR_TIMEOUT",
                    "detail": f"actuator did not return within {self._actuator_timeout}s. "
                              f"The action MAY have occurred — do not retry blindly; a "
                              f"human must establish the physical state."}
        except Exception as e:
            self._record(actuator_id, command, False, f"actuator raised: {e}", grant.nonce)
            return {"ok": False, "error": "actuator_failed", "detail": str(e)}

        # (red-team, Grok) ACT-THEN-REPORT. The side effect has now HAPPENED and the nonce
        # is spent. If `result` is not JSON-serializable, _send used to raise, the serve
        # loop reported a generic broker_error, and the proxy raised ActuationRefused —
        # telling the client the action was REFUSED when it had actually executed. An
        # agent that retries with a fresh grant then DOUBLE-ACTUATES. Verified: the
        # actuator ran, the client was told "broker_error", the nonce was burned.
        #
        # EXECUTION RECEIPT. (red-team, ChatGPT 2026-08-14.) Everything above proves
        # the broker COMMANDED the approved action. It does not prove the actuator
        # executed it. A wrapper that inserts a default, converts a unit, clamps to
        # its own idea of a limit, or simply ignores its kwargs produces a perfect
        # authorization trail around a different physical act — the whole chain says
        # APPROVED about an action that never happened as approved.
        #
        # Three facts, kept separate rather than collapsed:
        #     AUTHORIZED               — proven by the grant + attestation + binding
        #     COMMAND_ACCEPTED         — proven by fn() returning at all
        #     EXECUTION_CONFIRMED      — proven ONLY by a receipt echoing what ran
        #
        # An actuator opts in by returning a mapping with an `executed_args` key. It
        # is then held to it: the args it reports must equal the args that were
        # approved, or the run is reported as a mismatch. Actuators that return
        # anything else are unchanged and simply do not claim the third fact.
        #
        # HONEST LIMIT: a LYING actuator can echo the approved args and do something
        # else. This is not a defence against a malicious actuator — nothing on this
        # side of the boundary can be. It catches the far more common case, an actuator
        # that diverges by ACCIDENT, and it makes the third fact something a deployment
        # can require rather than assume. The real answer to a lying actuator is a
        # hardware layer that clamps independently of any software claim, which is
        # LifeCore's job, not DriftCore's (see §0b of 000_AI_START_HERE.md).
        execution_confirmed = None
        if isinstance(result, dict) and "executed_args" in result:
            reported = result.get("executed_args")
            if reported == (params or {}):
                execution_confirmed = True
            else:
                execution_confirmed = False
                self._record(
                    actuator_id, command, False,
                    f"EXECUTION MISMATCH: approved {params!r} but the actuator "
                    f"reports executing {reported!r}. The action HAS occurred and "
                    f"was not the approved one.", grant.nonce)
                self._write_evidence("MISMATCH", actuator_id, command,
                                     f"approved={params!r} executed={reported!r}",
                                     grant.nonce)
                return {"ok": False, "error": "execution_mismatch",
                        "error_code": "EXECUTION_MISMATCH",
                        "executed_args": reported, "approved_args": params or {},
                        "detail": "the actuator reported executing arguments that are "
                                  "not the ones approved. This is NOT a clean refusal "
                                  "— a physical action occurred. A human must "
                                  "establish the state before anything else runs."}


        # result cannot be represented, still report SUCCESS (it happened) with the result
        # replaced by a description. Losing the return value is recoverable; telling the
        # caller a completed action was refused is not.
        try:
            json.dumps(result)
            payload = result
        except (TypeError, ValueError):
            payload = None
            self._record(actuator_id, command, True,
                         f"executed; result not serializable ({type(result).__name__})",
                         grant.nonce)
            return {"ok": True, "result": payload,
                    "warning": f"action executed successfully but its return value "
                               f"({type(result).__name__}) is not JSON-serializable and was "
                               f"dropped. The action DID occur — do not retry."}

        self._write_evidence("COMPLETION", actuator_id, command, "executed",
                             grant.nonce)
        self._record(actuator_id, command, True, "executed", grant.nonce)
        # `execution_confirmed` is True only when the actuator RETURNED A RECEIPT that
        # matched. None means the actuator made no such claim — the command was
        # accepted and nothing beyond that is proven. A caller must not read None as
        # confirmation; that conflation is the failure this field exists to prevent.
        return {"ok": True, "result": payload,
                "execution_confirmed": execution_confirmed}


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

# ══════════════════════════════════════════════════════════════════
#  The hardened profile: safe BY DEFAULT, not safe IF CONFIGURED
# ══════════════════════════════════════════════════════════════════

#: Switches that must be ON for anything that can physically actuate. Every one of
#: these defaults to False on the base broker for backward compatibility, which means
#: the safe configuration is not the default configuration — a deployment is safe only
#: if someone remembered six separate flags. Three independent reviews named this as
#: the top residual, and "the operator remembered" is not a safety property.
PRODUCTION_REQUIRED_FLAGS = (
    "require_isolation",
    "enforce_effects",
    "require_durable_evidence",
    "require_effect_binding",
)


class ProductionActuationBroker(ActuationBroker):
    """An ActuationBroker whose safety switches CANNOT be turned off.

    Use this for any deployment that can actuate anything physical. It is the same
    broker with the hardening mandatory instead of optional: attempting to weaken a
    required flag raises rather than quietly producing a permissive broker.

    This does not add a new mechanism. It removes a way to forget one — which is the
    same move `preflight.py` makes for deployment invariants, applied to the object
    that actually holds the actuators.

    A development or simulation deployment that genuinely needs the permissive
    behaviour uses `ActuationBroker` directly and says so out loud.
    """

    def __init__(self, *args, **kwargs):
        weakened = [f for f in PRODUCTION_REQUIRED_FLAGS
                    if f in kwargs and not kwargs[f]]
        if weakened:
            raise ValueError(
                "ProductionActuationBroker refuses to disable "
                + ", ".join(weakened) + ". These are the switches that make the wall a "
                "wall: effect gating, isolation, effect binding and durable evidence. "
                "If a deployment genuinely needs them off it is not a production "
                "deployment — use ActuationBroker directly and record why.")
        for f in PRODUCTION_REQUIRED_FLAGS:
            kwargs[f] = True
        if not kwargs.get("halt_state"):
            raise ValueError(
                "ProductionActuationBroker requires halt_state: a halt that no "
                "execution path consults is a variable, not a stop. Pass a callable "
                "returning True while the system is halted (e.g. "
                "lambda: safe_halt.status()['active']).")
        if not kwargs.get("evidence_path"):
            raise ValueError(
                "ProductionActuationBroker requires evidence_path: durable evidence is "
                "mandatory here, and an evidence store with nowhere to write is a "
                "record that does not survive the event it exists to record.")
        super().__init__(*args, **kwargs)


def _stable_value(v, depth: int = 0) -> str:
    """A representation that is identical across processes.

    `repr()` of an arbitrary object embeds its memory address, which would make an
    actuator's identity change on every restart and invalidate every outstanding grant
    for no reason. Primitives are rendered exactly (so force=1.0 and force=1000.0 are
    distinguishable); anything else is rendered by TYPE, which is stable but blind to
    swapping one instance for another of the same class — a limit named in
    `_implementation_id`.

    Containers are rendered by CONTENT, which is what distinguishes
    `partial(move, force=1.0)` from `partial(move, force=999.0)` (the keywords are a
    dict) and one bound instance from another (the state is a `__dict__`). Content
    rendering means this function's output moves if the container moves — see
    `_implementation_id`, which is why the identity is captured ONCE at registration
    rather than recomputed per request.
    """
    if depth > 4:
        return "..."
    if v is None or isinstance(v, (bool, int, float, complex, str, bytes)):
        return repr(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_stable_value(x, depth + 1) for x in v) + "]"
    if isinstance(v, (set, frozenset)):
        return "{" + ",".join(sorted(_stable_value(x, depth + 1) for x in v)) + "}"
    if isinstance(v, dict):
        return "{" + ",".join(
            f"{_stable_value(k, depth + 1)}:{_stable_value(val, depth + 1)}"
            for k, val in sorted(v.items(), key=lambda kv: repr(kv[0]))) + "}"
    code = getattr(v, "__code__", None)
    if code is not None:
        return _callable_identity(v, depth + 1)
    return f"<{type(v).__module__}.{type(v).__qualname__}>"


def _code_identity(code, depth: int = 0) -> str:
    """Everything about a code object that determines what it does."""
    if depth > 4:
        return "..."
    consts = []
    for c in code.co_consts:
        inner = getattr(c, "co_code", None)
        consts.append(_code_identity(c, depth + 1) if inner is not None
                      else _stable_value(c, depth + 1))
    return "|".join([
        code.co_name,
        repr(code.co_code),
        "consts=" + ",".join(consts),
        # co_names carries the GLOBALS a function calls. Omitting it was the wrapper
        # bypass: two lambdas that call different functions have identical bytecode.
        "names=" + ",".join(code.co_names),
        "vars=" + ",".join(code.co_varnames),
        "free=" + ",".join(code.co_freevars),
        f"argcount={code.co_argcount},kwonly={code.co_kwonlyargcount},"
        f"flags={code.co_flags}",
    ])


def _callable_identity(fn, depth: int = 0) -> str:
    """Structural identity of a callable, stable across processes."""
    if depth > 4:
        return "..."
    parts = []
    # functools.partial: unwrap, and include the BOUND ARGUMENTS. Without this a
    # partial pinned nothing — the force limit lives in the bound kwargs.
    target = getattr(fn, "func", None)
    if target is not None and hasattr(fn, "args") and hasattr(fn, "keywords"):
        parts.append("partial(")
        parts.append(_callable_identity(target, depth + 1))
        parts.append("args=" + _stable_value(tuple(fn.args or ()), depth + 1))
        parts.append("kw=" + _stable_value(dict(fn.keywords or {}), depth + 1))
        parts.append(")")
        return "|".join(parts)
    # A bound method: the code plus the instance it is bound to.
    slf = getattr(fn, "__self__", None)
    if slf is not None:
        parts.append("bound_to=" + _stable_value(getattr(slf, "__dict__", slf), depth + 1))
        fn = getattr(fn, "__func__", fn)
    code = getattr(fn, "__code__", None)
    if code is None:
        mod = getattr(fn, "__module__", "?")
        qual = getattr(fn, "__qualname__", getattr(fn, "__name__", "?"))
        parts.append(f"symbol:{mod}.{qual}")
        return "|".join(parts)
    parts.append(_code_identity(code, depth))
    parts.append("defaults=" + _stable_value(getattr(fn, "__defaults__", None), depth + 1))
    parts.append("kwdefaults=" + _stable_value(getattr(fn, "__kwdefaults__", None), depth + 1))
    # Closure cells: where a captured force limit actually lives.
    cells = getattr(fn, "__closure__", None) or ()
    cell_vals = []
    for cell in cells:
        try:
            cell_vals.append(_stable_value(cell.cell_contents, depth + 1))
        except ValueError:
            cell_vals.append("<empty>")
    parts.append("closure=" + ",".join(cell_vals))
    return "|".join(parts)
