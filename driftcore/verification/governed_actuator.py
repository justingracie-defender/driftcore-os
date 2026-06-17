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

import hmac
import hashlib
import os
import time
from typing import Optional


class GrantAuthority:
    """Mints and verifies single-use, expiring, bound actuation grants.
    Held by the coordinator. The actuator is given the SAME authority so it
    can verify (prototype: shared secret; production: pub/priv split)."""

    def __init__(self, secret: Optional[bytes] = None):
        self._secret = secret or os.urandom(32)
        self._consumed = set()

    def mint(self, actuator_id: str, command: str, ttl_seconds: float = 5.0) -> dict:
        nonce   = os.urandom(8).hex()
        expires = time.time() + ttl_seconds
        payload = f"{actuator_id}|{command}|{nonce}|{expires}".encode()
        sig = hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        return {"actuator_id": actuator_id, "command": command,
                "nonce": nonce, "expires": expires, "sig": sig}

    def verify(self, grant: object, actuator_id: str, command: str,
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
        expected = hmac.new(self._secret, f"{aid}|{cmd}|{nonce}|{expires}".encode(),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return False
        if consume:
            self._consumed.add(nonce)
        return True


class GovernedActuator:
    """Base class for any physical actuator. Concrete drivers override
    `_actuate`; they cannot expose an ungoverned actuation path because the
    only public entry point demands a valid coordinator grant."""

    def __init__(self, actuator_id: str, grant_authority: GrantAuthority):
        self.actuator_id = actuator_id
        self._authority  = grant_authority
        self.performed   = []   # log of executed commands (for inspection/tests)

    def actuate(self, command: str, grant: object) -> bool:
        if not self._authority.verify(grant, self.actuator_id, command):
            raise PermissionError(
                f"Actuation '{command}' on '{self.actuator_id}' refused: "
                f"no valid coordinator-issued grant. An agent cannot self-authorize."
            )
        return self._actuate(command)

    def _actuate(self, command: str) -> bool:
        """Override in real drivers (drive a motor, etc.). Default records it."""
        self.performed.append(command)
        return True
