"""
driftcore/verification/governed_actuator.py
============================================
Reviewer's #1 priority: move actuation from VOLUNTARY compliance toward
ENFORCED compliance.

The driver contract here makes a physical action impossible without a
GRANT that only the coordinator can mint. An agent (or plugin) that holds
the actuator object still cannot make it move, because `actuate()` demands
a grant that is:

  - signed by the coordinator's GrantAuthority (the agent has no secret),
  - bound to this specific actuator_id AND this specific command,
  - single-use (the nonce is spent on first use),
  - short-lived (expires in seconds).

So "motor.move()" on its own does nothing useful: the only path to a valid
grant is `coordinator.evaluate(...)` returning PROCEED.

    Hardware
       ↑
    GovernedActuator.actuate(command, grant)   ← refuses without a grant
       ↑
    Coordinator (mints the grant only after Intent→Guard→Risk pass)
       ↑
    Everything else

HONEST LIMIT — this raises the bar from "voluntary" to "cryptographic"
compliance AT THE DRIVER LAYER. It does NOT achieve true OS-level
non-bypassability. Code that ignores this contract and pokes raw hardware
(its own GPIO/serial library, a separate process) is not stopped by
anything in Python. Real non-bypassability needs the actuator's *firmware*
to reject commands lacking a coordinator signature, plus OS process
isolation. That is hardware/OS work, not library work — and it stays in
the limitations register until it exists.

PROTOTYPE NOTE: GrantAuthority uses HMAC (shared secret between coordinator
and actuator). Production: the coordinator signs with a private key and the
actuator firmware verifies with the coordinator's public key.
"""

import functools
import hashlib
import hmac
import inspect
import os
import threading
import time
from typing import Optional


class GrantAuthority:
    """Mints and verifies single-use, expiring, bound actuation grants.
    Held by the coordinator. The actuator is given the SAME authority so it
    can verify (prototype: shared secret; production: pub/priv split)."""

    def __init__(self, secret: Optional[bytes] = None, *,
                 in_process_only: bool = False):
        """CLAIM in-process-authority-requires-opt-in: constructing this without
        the literal `in_process_only=True` raises, so no deployment receives a
        forgeable authority by not deciding.

        This authority signs and verifies with the SAME secret, in the SAME
        interpreter as the agent. Anything that can reach it calls `mint()` and
        gets a valid grant for any actuator and any command — demonstrated in
        `probes/probe_broker_forgery.py`, where a "compromised process" needs no
        exploit, only a reference. The grant check then checks a key the caller
        also holds.

        It used to be the default: `VerificationCoordinator` did
        `grant_authority or GrantAuthority()`, so a deployment that wired nothing
        got the forgeable path while the socket broker that fixes it sat opt-in
        and unused. The architecture was right and the default was not, which is
        the only one of the two most deployments ever run.

        So it is still available — a test suite and a development machine have
        no business standing up a separate OS user — but it now has to be asked
        for in a sentence a reviewer can grep for. The real boundary is
        `mediated_actuation`: a broker in another process under another user,
        holding keys this one never sees. Authority that the agent can reach is
        authority the agent has.
        """
        # Literal True. Same rule as enforce_effects / require_isolation /
        # attestation_required / require_declared_effects / allow_legacy.
        if in_process_only is not True:
            raise ValueError(
                "GrantAuthority signs and verifies with one secret inside the "
                "agent's own process, so anything that can reach it can mint a "
                "grant for anything. Pass in_process_only=True to state that you "
                "accept that — appropriate for tests and single-process "
                "development, not for anything that moves. For a real boundary "
                "use driftcore.verification.mediated_actuation, which puts the "
                "key in a separate process under a separate user.")
        self._secret = secret or os.urandom(32)
        self._consumed = set()
        # (red-team, external) there was no lock here at all — check and burn
        # were not atomic, and `consume=False` split them by construction.
        self._lock = threading.RLock()
        self._reserved: set = set()

    def mint(self, actuator_id: str, command: str, ttl_seconds: float = 5.0) -> dict:
        """CLAIM mint-refuses-non-finite-ttl: a NaN or infinite lifetime is refused
        at issue, never minted as a grant that cannot time out.

        (2026-09-06) `age > ttl` is False for NaN, because every comparison with
        NaN is False. Confirmed live: a NaN-TTL grant still actuated 0.2s later
        while a real 0.01s grant was correctly refused. Single-use still held, so
        the result was a one-shot grant with no time bound rather than an unlimited
        one — bounded, and still the time bound defeated.

        `signed_permission` already refuses this at issue and documents why; this
        module did not. Same defect, same repo, two modules — found by enumerating
        every expiry comparison rather than fixing only the one reported. Standing
        rule 4 names the set: non-finite is {NaN, +inf, -inf}.
        """
        t = ttl_seconds
        if not isinstance(t, (int, float)) or isinstance(t, bool) \
                or t != t or t in (float("inf"), float("-inf")) or t <= 0:
            raise ValueError(
                f"ttl_seconds must be a positive finite number, got {ttl_seconds!r}. "
                f"A non-finite lifetime does not mean 'long'; it means the expiry "
                f"comparison silently never fires.")
        nonce   = os.urandom(8).hex()
        expires = time.time() + ttl_seconds
        payload = f"{actuator_id}|{command}|{nonce}|{expires}".encode()
        sig = hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        return {"actuator_id": actuator_id, "command": command,
                "nonce": nonce, "expires": expires, "sig": sig}

    def reserve(self, grant: object, actuator_id: str, command: str) -> bool:
        """ATOMIC check-and-hold, mirroring `signed_permission.PermissionVerifier`.

        (red-team, external) `verify(consume=False)` is the documented "check now, act
        later" pattern, and it is RACY: 8 threads verifying one single-use grant all
        succeeded. `verify(consume=True)` held under test only because the check and the
        add sit in adjacent bytecode — that is GIL luck, not a guarantee, and there was
        no lock at all.

        Follow with exactly one of `commit()` or `release()`. A crash in between leaves
        the nonce reserved and therefore unusable — fail-closed, the safe direction for a
        single-use credential.
        """

        with self._lock:
            nonce = grant.get("nonce") if isinstance(grant, dict) else None
            if nonce is not None and nonce in self._reserved:
                return False                      # already in flight
            if not self._verify_locked(grant, actuator_id, command, consume=False):
                return False
            self._reserved.add(nonce)
            return True

    def commit(self, grant: object) -> None:
        """The action happened: burn the nonce permanently."""
        with self._lock:
            nonce = grant.get("nonce") if isinstance(grant, dict) else None
            if nonce is not None:
                self._consumed.add(nonce)
                self._reserved.discard(nonce)

    def release(self, grant: object) -> None:
        """Refused BEFORE any side effect: return the grant to the pool. Never call this
        after the actuator has run."""
        with self._lock:
            nonce = grant.get("nonce") if isinstance(grant, dict) else None
            if nonce is not None:
                self._reserved.discard(nonce)

    def verify(self, grant: object, actuator_id: str, command: str,
               consume: bool = True) -> bool:
        """Verify a grant. NOTE: `consume=False` is RACY by construction — it separates
        the check from the burn, so two callers can both pass. Use reserve/commit/release
        for any path that runs further gates between verification and actuation."""
        with self._lock:
            return self._verify_locked(grant, actuator_id, command, consume=consume)

    def _verify_locked(self, grant: object, actuator_id: str, command: str,
                       consume: bool = True) -> bool:
        if not isinstance(grant, dict):
            return False
        try:
            aid, cmd, nonce = grant["actuator_id"], grant["command"], grant["nonce"]
            expires, sig = float(grant["expires"]), grant["sig"]
        except (KeyError, TypeError, ValueError):
            return False
        if not all(isinstance(x, str) for x in (aid, cmd, nonce, sig)):
            return False
        if aid != actuator_id or cmd != command:   # bound to actuator + command
            return False
        if time.time() > expires:                  # expired
            return False
        if nonce in self._consumed:                # single-use
            return False
        if nonce in self._reserved:                # in flight elsewhere
            return False
        expected = hmac.new(self._secret, f"{aid}|{cmd}|{nonce}|{expires}".encode(),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return False
        if consume:
            self._consumed.add(nonce)
        return True


def _grant_gated(fn):
    """CLAIM ungoverned-call-raises: a call that did not come through
    `actuate()` raises and is appended to `ungoverned_attempts` instead of
    actuating."""
    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _governed_depth(self) <= 0:
            self.ungoverned_attempts.append({
                "actuator_id": getattr(self, "actuator_id", "?"),
                "args": [str(x) for x in a],
                "timestamp": time.time(),
                "caller": _caller_frame(),
            })
            raise PermissionError(
                f"_actuate on {getattr(self, 'actuator_id', '?')!r} was called "
                f"directly, bypassing the grant check in actuate(). A single "
                f"underscore is a convention Python does not enforce, so this is "
                f"refused and recorded rather than left to work silently. If a "
                f"driver needs to move without a grant, that is a deployment "
                f"decision and it does not get made by choosing a method name.")
        return fn(self, *a, **kw)
    return _wrapped


def _governed_depth(actuator) -> int:
    """How deep THIS THREAD is inside a governed call on this actuator.

    (external red-team, ChatGPT, 2026-09-01) Was `self._in_governed_call`, one
    boolean on the instance. Confirmed live: with thread A parked inside a
    legitimate `_actuate`, thread B called `_actuate` directly with no grant, saw
    A's window open, and MOVED THE ACTUATOR — recording nothing in
    `ungoverned_attempts`, so the bypass was silent as well as successful.

    An authorization granted to A must not authorize B. The window therefore
    belongs to the thread that earned it, not to the object.

    A depth counter rather than a thread-local boolean, because a driver whose
    `_actuate` legitimately re-enters `actuate()` would otherwise have its window
    closed by the inner call's `finally` while the outer call is still running —
    trading a concurrency bypass for a reentrancy false-refusal.
    """
    store = getattr(actuator, "_governed_tls", None)
    if store is None:
        return 0
    return getattr(store, "depth", 0)


def _caller_frame() -> str:
    """The first frame outside this module — who reached for `_actuate`.

    A fixed stack index was wrong and returned "<unavailable>" for every real
    call, which is a forensic field that silently records nothing. Walk out of
    this file instead of counting frames.
    """
    try:
        here = os.path.abspath(__file__)
        for fr in inspect.stack()[1:]:
            if os.path.abspath(fr.filename) != here:
                return f"{os.path.basename(fr.filename)}:{fr.lineno} in {fr.function}"
        return "<no frame outside this module>"
    except Exception as e:
        return f"<caller unavailable: {e!r}>"


class GovernedActuator:
    """Base class for any physical actuator. Concrete drivers override
    `_actuate`, and `actuate()` is the only entry point that mints its way past
    the grant check.

    CLAIM direct-actuate-is-refused-and-recorded: calling `_actuate` directly
    raises and appends to `ungoverned_attempts`, rather than actuating.

    WHAT THIS DOES NOT DO — the previous docstring said drivers "cannot expose
    an ungoverned actuation path", and that was false in two ways, both
    confirmed by execution on 2026-09-01:

      * `_actuate` was a single underscore. `a._actuate("fire")` moved the
        actuator with no grant at all. Now refused and recorded, including for
        subclass overrides, which are wrapped automatically by
        `__init_subclass__` so a driver author cannot opt out by forgetting.

      * `GrantAuthority` lives in this process and the actuator holds the SAME
        secret it verifies against. Anything that can reach it calls `mint()`
        and gets a valid grant for any actuator and command. That is not
        fixable here — a shared secret in a shared address space is a shared
        secret. `authority_is_in_process` exposes it so a deployment check can
        assert on it, and the architectural fix is the one already recorded in
        this project: put the safety wall in a separate OS process under a
        different user, reachable only over a socket.

    So: this class raises the cost of an accidental bypass and makes a
    deliberate one leave evidence. It does not contain a determined caller
    inside the same interpreter, and nothing written in Python can."""

    def __init__(self, actuator_id: str, grant_authority: GrantAuthority):
        self.actuator_id = actuator_id
        self._authority  = grant_authority
        self.performed   = []   # log of executed commands (for inspection/tests)
        # Direct-call attempts on _actuate. Assertable by a deployment check,
        # like unverified_releases and kernel_halt_wired elsewhere.
        self.ungoverned_attempts: list = []
        # Per-thread, per-actuator. See _governed_depth.
        self._governed_tls = threading.local()

    def actuate(self, command: str, grant: object) -> bool:
        if not self._authority.verify(grant, self.actuator_id, command):
            raise PermissionError(
                f"Actuation '{command}' on '{self.actuator_id}' refused: "
                f"no valid coordinator-issued grant. An agent cannot self-authorize."
            )
        # The window is opened only here, after the grant verified, and closed
        # in `finally` so a raising driver cannot leave it open for the next
        # direct call to walk through.
        tls = self._governed_tls
        tls.depth = getattr(tls, "depth", 0) + 1
        try:
            return self._actuate(command)
        finally:
            tls.depth -= 1

    def __init_subclass__(cls, **kwargs):
        """Wrap a driver's own `_actuate` so it cannot be reached ungoverned.

        Done here rather than by asking driver authors to call a helper, because
        a protection a subclass can forget is a protection that will be
        forgotten. Wrapping is idempotent — re-wrapping an inherited, already
        wrapped method is skipped.
        """
        super().__init_subclass__(**kwargs)
        raw = cls.__dict__.get("_actuate")
        if raw is not None and not getattr(raw, "_grant_gated", False):
            wrapped = _grant_gated(raw)
            wrapped._grant_gated = True
            cls._actuate = wrapped

    @property
    def authority_is_in_process(self) -> bool:
        """CLAIM in-process-authority-is-assertable: True when the GrantAuthority
        this actuator verifies against lives in the same interpreter.

        When it does, the actuator holds the secret it checks signatures with, so
        anything that can reach it calls `mint()` and gets a valid grant for any
        actuator and command. The grant check is then a check against a key the
        caller also has. Nothing in this file can change that.

        It is exposed rather than hidden so a deployment can assert on it — the
        same reason `kernel_halt_wired` and `release_integrity_ok` exist. A gap
        that a deployment check can name is a gap; one that only a docstring
        mentions is a surprise.
        """
        return self._authority is not None

    def _actuate(self, command: str) -> bool:
        """Override in real drivers (drive a motor, etc.). Default records it."""
        self.performed.append(command)
        return True

    # The base class's own _actuate needs the same gate; __init_subclass__ only
    # fires for subclasses, so wrapping it there would leave GovernedActuator
    # itself as the one class with an open path.
    _actuate = _grant_gated(_actuate)
    _actuate._grant_gated = True
