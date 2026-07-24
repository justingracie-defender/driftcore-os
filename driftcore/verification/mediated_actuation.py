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
import stat
import struct
import threading
import time
from dataclasses import dataclass


def _call_with_timeout(fn, timeout: float):
    """Run `fn()` with a hard deadline. Used for the breach-posture check, which sits at
    position zero in the mediation path — a hanging source there stalls EVERY request.
    Raises TimeoutError on expiry so the caller can fail CLOSED."""
    box = {}
    def _run():
        try:
            box["v"] = fn()
        except BaseException as e:      # noqa: BLE001 - propagated to the caller
            box["e"] = e
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise TimeoutError(f"posture check exceeded {timeout}s")
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
                 posture_timeout: float = 1.0,
                 socket_group: Optional[object] = None,
                 require_isolation: bool = False,
                 enforce_effects: bool = False,
                 blast_radius: Optional[BlastRadiusGovernor] = None,
                 egress_guard: Optional[EgressGuard] = None,
                 actuator_timeout: Optional[float] = None,
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
        # Optional cross-action gate run on the BROKER side (cumulative_ledger).
        # Returns None to allow, or a string reason to REFUSE.
        self._ledger_hook = ledger_hook
        self._audit = audit_logger or (lambda **kw: None)
        self.records: list = []          # append-only actuation evidence
        self._srv: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.RLock()

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
                          replace: bool = False) -> None:
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
            self._actuators[actuator_id] = (fn, tuple(required_scope))
            if destination_param:
                self._destination_params[actuator_id] = destination_param

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

    def _record(self, actuator_id: str, command: str, allowed: bool, reason: str,
                nonce: str = "") -> None:
        rec = ActuationRecord(time.time(), actuator_id, command, allowed, reason, nonce)
        self.records.append(rec)          # in-broker evidence: always kept first
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
        params = req.get("params") or {}
        grant_d = req.get("grant")

        # 0. BREACH GATE — runs FIRST, before the grant is even examined.
        #    A system that has already violated an invariant must not keep its full
        #    blast radius until its grants happen to expire. Without this, the wall's
        #    promise was "blast radius = granted permission set" — true, but the
        #    permission set did not COLLAPSE on breach, which is backwards: the moment
        #    the wall matters most is after something has already gone wrong.
        #    FAIL-CLOSED: a posture source that RAISES is a refusal, never a fall-through.
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
        fn, required_scope = entry

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
                refused, reason, code = True, f"effect gate failed closed: {e!r}", "block_error"
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
                breadth_ok = False
                breadth_reason = f"blast-radius governor failed closed: {e!r}"
                breadth_code = "ERROR"
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
        _reg_ok, _declared_eff = True, ()
        try:
            _declared_eff = self._effect_registry.effects_for(actuator_id) or ()
        except Exception:
            _reg_ok = False
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
                ok_e, reason_e, code_e = False, (
                    f"egress interlock failed closed: {e!r}"), "ERROR"
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
        binding_now = PermissionVerifier.bind_action(actuator_id, command, params,
                                                     broker_id=self._broker_id)

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

        # 5. COMMIT THE RESERVATION (burn the nonce), THEN ACT. Single-use: a replayed
        #    grant cannot re-actuate. Committing BEFORE the actuator runs is deliberate —
        #    if the actuator crashes we must not leave a spendable grant behind.
        self._verifier.commit(grant)
        try:
            if self._actuator_timeout is None:
                result = fn(**params) if params else fn()
            else:
                result = _call_with_timeout(
                    (lambda: fn(**params)) if params else fn, self._actuator_timeout)
        except TimeoutError:
            # The nonce is already burned and the actuator MAY have started. This is
            # NOT a clean refusal and must never be reported as one — an agent told
            # "refused" would retry and double-actuate.
            self._record(actuator_id, command, False,
                         f"actuator exceeded {self._actuator_timeout}s; completion UNKNOWN",
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
        # The report must never be able to fail after the act. Serialize HERE, and if the
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

        self._record(actuator_id, command, True, "executed", grant.nonce)
        return {"ok": True, "result": payload}


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
