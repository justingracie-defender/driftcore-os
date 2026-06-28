"""
driftcore/authority/scoped_authorization.py
===========================================
Scoped + on-demand authorization. In plain terms:

  1. ONE KEY PER DOOR (scope). A key names WHICH job it is for. A "chores" key
     cannot open the "purchase" door. No skeleton keys.

  2. KEYS ON DEMAND (admin grants in the moment). For money / sensitive data /
     risky actions, the agent holds no standing key — it ASKS, a human admin
     grants a one-time scoped key, used once then dead. A drifted/buggy agent
     can't spend or leak, because it never holds the key.

  3. DAILY BUDGET (stops "ask 10 times"). A per-operator, per-area, per-day cap
     so an agent can't defeat a per-key cap by asking many times. Persisted to
     disk so a crash can't reset it.

  4. ATOMIC BURN (stops replay races). A one-time key is marked spent FIRST,
     under a lock, and persisted, so two simultaneous uses can't both slip
     through and a crash can't revive a spent key.

  5. FACTS, NOT THE AGENT'S STORY. The human approves on area + amount only.
     The agent's free-text "reason" is LOG-ONLY and is never part of the
     approval surface — a jailbroken agent cannot social-engineer the human by
     lying in the reason field.

Credits: items 1-2 are the original design; items 3-4 and the persist-to-disk
work follow a red-team patch (Meta). This merged version closes three gaps that
patch left open: a money action with NO declared amount used to bypass the cap
and budget (now hard-blocked); the facts-only view was optional (now the reason
is structurally non-approvable); and the base lock's verify() is preserved.

This sits ON TOP of the AuthorizationGate ("dumb lock"). The agent still cannot
make or verify its own keys — only a human admin issues them, and verification
lives outside the agent. No crypto/hardware here: making the key itself
un-forgeable (signing, one-time HSM tokens, a hardware verifier) is the
deployment's job — see VERIFIER_CONTRACT in SAFETY_MODEL.md.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, Optional, Tuple

from driftcore.authority.authorization_gate import (
    Authorization, AuthorizationGate, GateResult, GateState,
)
from driftcore.authority.resolver import _is_human


# ── Doors are a fixed list, not free text (no typo-squatting) ─────

class Area(str, Enum):
    CHORES = "chores"
    PURCHASE = "purchase"
    SENSITIVE_DATA = "sensitive_data"
    # add new areas here deliberately; an unknown area cannot be requested,
    # which is the "default-off: uncategorised => cannot run" property.

# Areas that move money and therefore require a declared amount + cap + budget.
MONEY_AREAS = frozenset({Area.PURCHASE})


@dataclass(frozen=True)
class ActionRequest:
    """What the agent is attempting. area is a fixed Area; amount only for money."""
    area: Area
    amount: Optional[float] = None


@dataclass(frozen=True)
class ScopedAuthorization(Authorization):
    """A key that names its door(s), one-time flag, and (money only) a cap."""
    scopes: FrozenSet[Area] = frozenset()
    one_time: bool = False
    spend_cap: Optional[float] = None      # None = NOT a money key, ever.


@dataclass
class KeyRequest:
    request_id: str
    area: Area
    amount: Optional[float]
    reason: str          # LOG-ONLY. Never shown on the approval surface.
    granted: bool = False
    denied: bool = False


# ── Daily budget: per operator, per area, per UTC day, persisted ──

@dataclass
class DailyBudget:
    path: str = "driftcore_daily_budget.json"
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def _today(self) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime())

    def remaining_ok(self, operator: str, area: Area, amount: float,
                     day_cap: float) -> bool:
        if area not in MONEY_AREAS:
            return True
        with self._lock:
            data = self._load()
            used = data.get(operator, {}).get(self._today(), {}).get(area.value, 0.0)
            return (used + amount) <= day_cap

    def add_spend(self, operator: str, area: Area, amount: Optional[float]) -> None:
        if area not in MONEY_AREAS or amount is None:
            return
        with self._lock:
            data = self._load()
            day = data.setdefault(operator, {}).setdefault(self._today(), {})
            day[area.value] = day.get(area.value, 0.0) + amount
            self._save(data)

    def _load(self) -> Dict:
        if not os.path.exists(self.path):
            return {}
        try:
            with open(self.path) as f:
                return json.load(f)
        except Exception:
            return {}

    def _save(self, data: Dict) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())     # persist before we rely on it
        os.replace(tmp, self.path)


# ── The key-maker (admin-driven, also the verifier) ───────────────

class OnDemandKeyIssuer:
    def __init__(self, budget_path: str = "driftcore_daily_budget.json",
                 spent_path: str = "driftcore_spent_tokens.json"):
        self._requests: Dict[str, KeyRequest] = {}
        self._issued: Dict[str, ScopedAuthorization] = {}
        self._spent: set = set()
        self._lock = threading.Lock()
        self._budget = DailyBudget(budget_path)
        self._spent_path = spent_path
        self._load_spent()

    # -- agent side: ask --------------------------------------------

    def request_key(self, area: Area, reason: str,
                    amount: Optional[float] = None) -> KeyRequest:
        rid = uuid.uuid4().hex[:12]
        req = KeyRequest(rid, area, amount, reason)
        self._requests[rid] = req
        return req

    # -- admin side: FACTS-ONLY approval surface --------------------

    def approval_facts(self, request_id: str) -> Optional[Dict]:
        """
        The ONLY thing an admin should approve from. Deliberately omits the
        agent's free-text reason: the human decides on area + amount, never on
        the agent's story. (The reason is retained for the audit log via
        request_reason_for_log(), separated so it cannot drive approval.)
        """
        req = self._requests.get(request_id)
        if not req:
            return None
        return {
            "request_id": req.request_id,
            "area": req.area.value,
            "amount": req.amount,                 # None = no money
            "is_money": req.area in MONEY_AREAS,
            "note": "Approve on area + amount only. The agent's stated reason is "
                    "not shown here and must not influence approval.",
        }

    def request_reason_for_log(self, request_id: str) -> Optional[str]:
        """Reason is available for the AUDIT LOG only — never for approval."""
        req = self._requests.get(request_id)
        return req.reason if req else None

    def grant(self, request_id: str, admin: str, one_time: bool = True,
              spend_cap: Optional[float] = None, valid_for_seconds: float = 300.0,
              operator: Optional[str] = None
              ) -> Tuple[bool, str, Optional[ScopedAuthorization]]:
        if not _is_human(admin):
            return False, "only a human admin can grant a key", None
        req = self._requests.get(request_id)
        if not req or req.granted or req.denied:
            return False, "no pending request with that id", None
        # No cap = no money. Locked: a money area MUST get an explicit cap.
        if req.area in MONEY_AREAS and spend_cap is None:
            return False, "a money action requires an explicit spend_cap", None

        now = time.time()
        token = uuid.uuid4().hex
        key = ScopedAuthorization(
            issuer=admin, operator=operator or admin, token=token,
            issued_at=now, expires_at=now + valid_for_seconds,
            scopes=frozenset({req.area}), one_time=one_time,
            spend_cap=spend_cap,
        )
        with self._lock:
            self._issued[token] = key
        req.granted = True
        return True, f"key granted for '{req.area.value}'", key

    def deny(self, request_id: str, admin: str, reason: str) -> Tuple[bool, str]:
        if not _is_human(admin):
            return False, "only a human admin can deny"
        req = self._requests.get(request_id)
        if not req or req.granted or req.denied:
            return False, "no pending request"
        req.denied = True
        return True, f"denied: {reason}"

    # -- verifier side -----------------------------------------------

    def verify(self, auth: Authorization) -> bool:
        """The base lock calls this: is the key one we issued and not spent?"""
        with self._lock:
            key = self._issued.get(auth.token)
            return key is not None and key.token not in self._spent

    def verify_and_consume(self, auth: Authorization, request: ActionRequest,
                           daily_cap: Optional[float] = None) -> Tuple[bool, str]:
        """
        Atomic. Marks a one-time key spent FIRST (so a race can't double-use),
        persists it, then enforces money rules. Money rules:
          * a money area with NO declared amount is BLOCKED (no silent bypass),
          * amount must be within the key's cap,
          * amount must be within the daily budget (if a daily_cap is set).
        """
        with self._lock:
            key = self._issued.get(auth.token)
            if key is None:
                return False, "unknown token"
            if key.token in self._spent:
                return False, "token already spent"

            is_money = request.area in MONEY_AREAS

            # CLOSED HOLE: a money action must declare an amount. No amount on a
            # money door is not "free" — it is blocked.
            if is_money and request.amount is None:
                return False, "money action must declare an amount"
            # A non-money key may not be used for a money action.
            if request.amount is not None and key.spend_cap is None:
                return False, "this key cannot move money (no cap)"
            if request.amount is not None and key.spend_cap is not None:
                if request.amount > key.spend_cap:
                    return False, f"over key cap {key.spend_cap}"
                if daily_cap is not None and not self._budget.remaining_ok(
                        key.operator, request.area, request.amount, daily_cap):
                    return False, "over daily budget"

            # Passed all checks -> burn one-time key now, before the action.
            if key.one_time:
                self._spent.add(key.token)
                self._persist_spent()
            return True, "ok"

    def record_spend(self, auth: Authorization, request: ActionRequest) -> None:
        """Call AFTER the action actually succeeds, to charge the daily budget."""
        if request.amount is None:
            return
        key = self._issued.get(auth.token)
        if key is not None:
            self._budget.add_spend(key.operator, request.area, request.amount)

    def revoke(self, token: str, admin: str) -> Tuple[bool, str]:
        """Admin can kill a standing key immediately."""
        if not _is_human(admin):
            return False, "only a human admin can revoke"
        with self._lock:
            if token not in self._issued:
                return False, "no such token"
            self._spent.add(token)
            self._persist_spent()
        return True, "revoked"

    # -- spent-set persistence (crash can't revive a spent key) -----

    def _persist_spent(self) -> None:
        try:
            tmp = self._spent_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(list(self._spent), f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self._spent_path)
        except Exception:
            pass  # already marked in memory; disk is the durability backstop

    def _load_spent(self) -> None:
        if os.path.exists(self._spent_path):
            try:
                with open(self._spent_path) as f:
                    self._spent = set(json.load(f))
            except Exception:
                self._spent = set()


# ── The scope-aware gate ──────────────────────────────────────────

class ScopedGate(AuthorizationGate):
    def __init__(self, issuer: OnDemandKeyIssuer, **kwargs):
        super().__init__(verifier=issuer, **kwargs)   # base lock still runs
        self._issuer = issuer

    def check_action(self, auth: Optional[ScopedAuthorization],
                     request: ActionRequest, daily_cap: Optional[float] = None,
                     now: Optional[float] = None) -> GateResult:
        # 1. Base lock: real, external issuer, unexpired, verifier says yes.
        base = self.check(auth, now)
        if not base.cleared:
            return base
        assert auth is not None

        # 2. Right key for THIS door?
        if request.area not in auth.scopes:
            opens = sorted(s.value for s in auth.scopes)
            return GateResult(GateState.BLOCKED,
                              f"key opens {opens} but the action needs "
                              f"'{request.area.value}' — wrong key for this door")

        # 3. Atomic consume + money rules (cap, daily budget, no-amount block).
        ok, msg = self._issuer.verify_and_consume(auth, request, daily_cap=daily_cap)
        if not ok:
            return GateResult(GateState.BLOCKED, f"authorization gate: {msg}")

        # Cleared. Caller does the action, then calls issuer.record_spend().
        return GateResult(GateState.CLEARED,
                          f"key valid for '{request.area.value}'")
