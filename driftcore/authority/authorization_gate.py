"""
driftcore/authority/authorization_gate.py
=========================================
The authorization gate — the "dumb lock". A PASSIVE precondition on action,
enforced OUTSIDE the agent. See SAFETY_MODEL.md §5 for the full reasoning; the
essentials, because this is the part most easily mis-built:

WHY PASSIVE, NOT AN E-STOP THE AGENT RUNS.
  A "stop the agent performs" ("detect bad situation -> halt") is overridable:
  the agent evaluates the trigger, so a clever/jailbroken/drifting agent makes
  the trigger never fire or fakes the all-clear. This gate is the opposite — a
  "permission the agent LACKS and cannot self-grant". No valid external
  credential -> the action simply does not run. There is no trigger to defeat.
  An agent cannot think its way into a credential it does not hold.

WHY ENFORCED OUTSIDE THE AGENT.
  If the agent checks its own authorization, the overridable e-stop is rebuilt
  ("am I authorized? ...yes I am"). So verification is done by a
  CredentialVerifier the agent does NOT implement and cannot reach — supplied by
  the harness/runtime (software) or wired to actuator power (hardware). This
  module is consulted by the GovernedExecutor (the harness), never produced by
  the agent.

HARD RULE — fail closed, never fake it.
  A deployment that cannot supply a real external verifier MUST NOT pretend.
  Constructed without a verifier, the gate authorizes NOTHING (every action
  blocked). A software-flag e-stop the agent reads is worse than nothing — it
  looks like safety while being exactly the overridable trigger we reject.

DEGRADE-TO-SAFE-REST IS A FALLEN-INTO DEFAULT, NOT A DECISION.
  For a body, losing authorization degrades to a physical-safe state. That is
  the LOCK behaviour (what the body falls into when the key is absent), invoked
  by the harness on block — NOT an action the agent chooses, or it would be
  jailbreakable like any other agent decision. The safe-state callable is
  supplied by the deployment (LifeCore), not defined here.

UNIVERSAL. The gate's contract ("no action without positive external
authorization; absent -> inert") is universal — software agents included. What
counts as a valid credential, and what "safe rest" means physically, is
deployment-specific and injected. No bodies or numbers live here.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional, Protocol, runtime_checkable

from driftcore.authority.resolver import (
    AuthorityDecision, AuthorityLayer, _is_human,
)


# ── The credential (issued externally; the agent cannot mint one) ──

@dataclass(frozen=True)
class Authorization:
    """
    A token that an EXTERNAL authority issued to permit action. The agent does
    not create these; it can only present one it was given. Verification is done
    by a CredentialVerifier the agent does not control.
    """
    issuer: str           # who issued it (must be a human/external authority)
    operator: str         # the recognised operator this clears action for
    token: str            # opaque; meaning/validation belongs to the verifier
    issued_at: float
    expires_at: float     # absolute epoch seconds; 0 = never (discouraged)

    def unexpired(self, now: Optional[float] = None) -> bool:
        if self.expires_at == 0:
            return True
        return (now if now is not None else time.time()) < self.expires_at


@runtime_checkable
class CredentialVerifier(Protocol):
    """
    Supplied by the harness/deployment — NOT by the agent. Returns True only for
    a genuinely valid credential. For a robot this is wired to the thing that
    gates actuator power; for software, to the runtime's auth check.
    """
    def verify(self, auth: Authorization) -> bool: ...


# ── Gate result ───────────────────────────────────────────────────

class GateState(Enum):
    CLEARED = "cleared"     # a valid external credential is present
    BLOCKED = "blocked"     # no/invalid credential -> action does not run


@dataclass(frozen=True)
class GateResult:
    state: GateState
    reason: str

    @property
    def cleared(self) -> bool:
        return self.state is GateState.CLEARED


# ── The gate ──────────────────────────────────────────────────────

class AuthorizationGate:
    """
    Passive default-deny precondition. Constructed by the harness with a real
    external verifier. Without one, it fails closed (authorizes nothing).
    """

    def __init__(self,
                 verifier: Optional[CredentialVerifier],
                 embodied: bool = False,
                 safe_state: Optional[Callable[[], None]] = None):
        # No verifier => fail closed. We do NOT default to a permissive stub:
        # faking the check inside is worse than not having it.
        self._verifier = verifier
        self._embodied = embodied
        self._safe_state = safe_state
        self._verifier_missing = verifier is None

    def check(self, auth: Optional[Authorization],
              now: Optional[float] = None) -> GateResult:
        """
        The precondition. Called by the harness BEFORE any action is considered.
        Default-deny at every step:
          * no verifier wired    -> BLOCKED (fail closed, never fake it)
          * no credential present -> BLOCKED
          * issuer not external/human, or self-issued -> BLOCKED
          * expired               -> BLOCKED
          * verifier rejects      -> BLOCKED
        Only a present, unexpired, externally-issued, verifier-approved
        credential clears.
        """
        if self._verifier_missing:
            return GateResult(GateState.BLOCKED,
                              "no external verifier wired; gate fails closed "
                              "(a deployment that cannot verify externally must "
                              "not fake authorization)")
        if auth is None:
            return GateResult(GateState.BLOCKED, "no authorization presented")
        # The agent must not be able to self-grant: the issuer has to be a real
        # external/human authority, never the agent/system itself.
        if not _is_human(auth.issuer):
            return GateResult(GateState.BLOCKED,
                              f"authorization issuer '{auth.issuer}' is not an "
                              f"external authority (self-granted credentials are "
                              f"never valid)")
        if not auth.unexpired(now):
            return GateResult(GateState.BLOCKED, "authorization expired")
        try:
            if not self._verifier.verify(auth):
                return GateResult(GateState.BLOCKED,
                                  "external verifier rejected the credential")
        except Exception as e:
            # Verifier error fails closed.
            return GateResult(GateState.BLOCKED,
                              f"verifier error, failing closed: {e!r}")
        return GateResult(GateState.CLEARED,
                          f"valid authorization from '{auth.issuer}' for "
                          f"operator '{auth.operator}'")

    def on_blocked(self) -> None:
        """
        The fallen-into default when blocked. For an embodied deployment this
        invokes the deployment-supplied safe-state (e.g. lower to rest). It is
        invoked BY THE HARNESS, structurally — it is NOT an action the agent
        selects. Software deployments typically need no safe-state (inaction is
        already safe), so safe_state may be None.
        """
        if self._embodied and self._safe_state is not None:
            self._safe_state()

    def synthetic_decision(self, result: GateResult) -> AuthorityDecision:
        """
        Express a gate block as an AuthorityDecision so it composes with the
        existing GovernedResult shape. The gate sits UPSTREAM of the authority
        layers; we tag it CONSTITUTION because 'no authorization, no action' is
        a floor-level precondition, not an overridable layer verdict.
        """
        return AuthorityDecision(
            allowed=False,
            binding_layer=AuthorityLayer.CONSTITUTION,
            reason=f"authorization gate: {result.reason}",
        )
