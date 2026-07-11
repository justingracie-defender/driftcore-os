"""
driftcore/verification/authorization_ttl.py  (v2 — hardened)
============================================================
STATUS: PROPOSED (stdlib-only). A UNIVERSAL authorization-expiry primitive with the
two properties a naive time-limit gets catastrophically wrong.

    ┌────────────────────────── THE TWO RULES ──────────────────────────┐
    │ 1. EXPIRY OF PERMISSION, NEVER A DEADLINE TO FINISH.               │
    │    A goal's *authorization to keep running* expires and must be    │
    │    renewed. It is NEVER "finish by T or fail." A completion         │
    │    deadline manufactures rushing -> corner-cutting -> the harsh     │
    │    fast path (the exact inversion the mercy ladder prevents).       │
    │                                                                    │
    │ 2. CADENCE SCALES WITH STAKES, AND EXPIRY MEANS HOLD, NOT WAKE.    │
    │    Dusting and wiping a drive must NOT share one clock. Trivial     │
    │    in-repertoire work renews SILENTLY; only high-stakes actions may │
    │    interrupt, and quiet hours downgrade sub-critical interrupts to  │
    │    a morning-digest hold. (The "don't wake Justin at 3am to dust"  │
    │    rule. A safety feature people disable protects no one.)          │
    └────────────────────────────────────────────────────────────────────┘

═══════════════════════════ WHAT CHANGED IN v2 ═══════════════════════════
A four-model red team found two real bugs and a set of hardening gaps. Fixed:

  * PARKED-TIMESTAMP DRIFT (real bug). check() is called every coordinator tick.
    In v1, a parked goal's lease stayed expired, so each subsequent check()
    RE-PARKED it with a fresh timestamp and re-logged — sliding parked_at forward
    forever, breaking the morning-digest sort and flooding the audit log. v2 parks
    ONCE: subsequent checks return the existing hold statically (no re-stamp, no
    duplicate audit).
  * NOT_DUE vs SILENT_RENEW CONFLATION (real API bug). v1 returned SILENT_RENEW for
    both "authorization still valid, keep going" and "expired and auto-renewed" —
    materially different events a caller could not distinguish. v2 has a distinct
    NOT_DUE, and check() returns a rich AuthorizationStatus.
  * MONOTONIC CLOCK for all expiry math (a clock jump could otherwise extend a leash
    forever or expire everything). Wall clock is used ONLY for the quiet-hours local
    hour and log timestamps.
  * RENEW RE-EVALUATES STAKES (was frozen). If cumulative pressure climbed while a
    goal sat parked, renewal must ratchet the safety posture UP. Stakes may only
    RISE on renewal, never fall.
  * SILENCE IS EXPENSIVE (partial laundering mitigation). After `max_silent_renews`
    consecutive silent renewals, the goal is FORCED to HOLD_FOR_DIGEST — so no goal
    can run silently forever, and a human sees the pattern.
  * VALIDATION + FAIL-CLOSED: policy completeness and sane values are enforced at
    construction; malformed effects / out-of-range pressure / unknown-goal renew are
    refused rather than silently defaulted.
  * THREAD SAFETY: state mutations are under an RLock (same discipline as the ledger).

═════════════════════════════ HONEST LIMITS ═════════════════════════════
  * AUTHORIZATION LAUNDERING IS *NOT* SOLVED HERE, AND CANNOT BE. A campaign sliced
    into a thousand individually-TRIVIAL goals looks fine to any per-goal TTL: each
    slice is genuinely trivial. **The defense is COMPOSITION with cumulative_ledger**,
    which sums effect per-owner across actions regardless of how the work is sliced.
    TTL bounds *how long a goal may run unattended*; the LEDGER bounds *how much
    effect may accumulate*. Neither alone closes laundering; together they do. This
    module's `max_silent_renews` cap is a partial in-module mitigation (it makes
    infinite silence impossible), NOT a campaign defense. Do not deploy this without
    the ledger and claim laundering is closed.
  * STAKES ARE ONLY AS HONEST AS THE INPUTS. `default_stakes()` derives stakes from
    effects/reversibility/repertoire supplied by the caller. A planner that lies
    ("this exfil is effects=('none',)") gets a trivial leash. The fix is NOT in this
    module: effects must be STRUCTURALLY tagged at registration and the action bound
    to a signed descriptor — see signed_permission.py (`action_binding`) and
    THREAT_BOUNDARIES §7 (the TCB) and §8 (mediated actuation).
  * renew() IS NOT AUTHENTICATED HERE. `by=` is a label, not a credential. A
    capability token may be passed and is recorded, but VERIFYING it is
    signed_permission's job. Enforcement of who may renew belongs to the broker /
    reference monitor. Seam provided; guarantee not claimed.
  * IN-MEMORY STATE. Leases/parked goals do not survive a restart (a restart makes
    everything "unknown" -> fail-closed HOLD). Durable, cross-instance persistence
    would follow the AuthorizationState hash-chained pattern; not built here.
"""
from __future__ import annotations

import time
import threading
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Dict, List, Optional, Tuple


class Stakes(IntEnum):
    """Consequence tier. ORDERED: higher stakes -> shorter leash, louder surfacing."""
    TRIVIAL   = 0   # reversible, in-repertoire, no meaningful effect (dusting)
    LOW       = 1   # reversible, minor effect
    MODERATE  = 2   # notable but recoverable
    HIGH      = 3   # hard to reverse / meaningful real-world effect
    CRITICAL  = 4   # irreversible / safety-relevant / out-of-pattern


class ExpiryResponse(IntEnum):
    """What happens at (or before) expiry — NEVER 'fail the task'."""
    NOT_DUE           = 0   # authorization still valid; keep going. NOT a renewal.
    SILENT_RENEW      = 1   # expired; auto-renewed. Log only. (trivial in-bounds work)
    HOLD_FOR_DIGEST   = 2   # STOP + park; surface in the next digest (never wakes anyone)
    HOLD_FOR_PROMPT   = 3   # STOP + park; wait in the human's active queue
    INTERRUPT_NOW     = 4   # STOP + actively notify (urgent AND high-stakes only)


class PolicyError(ValueError):
    """Raised at construction for an invalid/incomplete CadencePolicy (fail-closed)."""


class UnknownGoal(KeyError):
    """Raised when renewing a goal that was never authorized (fail-closed — v1 created
    authorization from thin air here)."""


@dataclass(frozen=True)
class AuthorizationStatus:
    """Rich result of check(): distinguishes 'still valid' from 'expired and renewed'
    from 'parked', which v1 conflated."""
    response: ExpiryResponse
    due: bool                 # was the lease expired at check time?
    renewed: bool             # did this check auto-renew (silent) ?
    parked: bool              # is the goal now (or already) parked?
    stakes: Stakes
    goal_id: str
    def keep_going(self) -> bool:
        return self.response in (ExpiryResponse.NOT_DUE, ExpiryResponse.SILENT_RENEW)
    def to_dict(self) -> dict:
        return {"goal_id": self.goal_id, "response": self.response.name, "due": self.due,
                "renewed": self.renewed, "parked": self.parked, "stakes": self.stakes.name}


@dataclass(frozen=True)
class CadencePolicy:
    """Human-set. ⚠ The default numbers are ILLUSTRATIVE placeholders; a deployment
    sets real TTLs for its domain. The MACHINERY is the contribution, not the seconds.
    Validated at construction — an incomplete or nonsensical policy is REFUSED."""
    ttl_by_stakes: Dict[Stakes, float] = field(default_factory=lambda: {
        Stakes.TRIVIAL:  24 * 3600.0,   # ⚠ placeholder
        Stakes.LOW:       8 * 3600.0,   # ⚠ placeholder
        Stakes.MODERATE:  1 * 3600.0,   # ⚠ placeholder
        Stakes.HIGH:          900.0,    # ⚠ placeholder
        Stakes.CRITICAL:        0.0,    # ⚠ placeholder — re-authorize every action
    })
    response_by_stakes: Dict[Stakes, ExpiryResponse] = field(default_factory=lambda: {
        Stakes.TRIVIAL:  ExpiryResponse.SILENT_RENEW,
        Stakes.LOW:      ExpiryResponse.HOLD_FOR_DIGEST,
        Stakes.MODERATE: ExpiryResponse.HOLD_FOR_PROMPT,
        Stakes.HIGH:     ExpiryResponse.HOLD_FOR_PROMPT,
        Stakes.CRITICAL: ExpiryResponse.INTERRUPT_NOW,
    })
    quiet_hours: Tuple[int, ...] = ()
    quiet_hours_min_interrupt: Stakes = Stakes.CRITICAL
    # SILENCE IS EXPENSIVE: after this many consecutive silent renewals, force a
    # HOLD_FOR_DIGEST so no goal runs silently forever and a human sees the pattern.
    # (Partial laundering mitigation — the real campaign defense is cumulative_ledger.)
    # ⚠ CRITICAL CAVEAT (found in cold red-team): this cap counts CONSECUTIVE silent
    # renewals on ONE lease. A caller that can invoke authorize() again resets the
    # counter to 0 — so an agent able to RE-AUTHORIZE ITSELF defeats this cap entirely
    # (SILENT,SILENT,HOLD,re-authorize,SILENT,SILENT,HOLD,... forever). The cap only
    # holds if authorize()/renew() are BROKER-GATED and NOT agent-reachable. This is
    # the same "who may call the privileged method" boundary as everywhere else; the
    # enforcement is mediated actuation, not this module. Do NOT rely on the silence
    # cap against a hostile caller that controls authorize().
    max_silent_renews: int = 10                    # ⚠ placeholder
    # Parked goals older than this are re-surfaced/escalated rather than lingering.
    parked_stale_after: float = 7 * 24 * 3600.0    # ⚠ placeholder

    def __post_init__(self):
        # FAIL CLOSED on an incomplete or nonsensical policy.
        for s in Stakes:
            if s not in self.ttl_by_stakes:
                raise PolicyError(f"ttl_by_stakes is missing {s.name} (policy must be complete)")
            if s not in self.response_by_stakes:
                raise PolicyError(f"response_by_stakes is missing {s.name} (policy must be complete)")
            ttl = self.ttl_by_stakes[s]
            if not isinstance(ttl, (int, float)) or ttl < 0 or ttl != ttl:  # NaN-safe
                raise PolicyError(f"ttl for {s.name} must be a non-negative number (got {ttl!r})")
        # cadence must be monotone: higher stakes never get a LONGER leash
        ordered = [self.ttl_by_stakes[s] for s in sorted(Stakes)]
        for a, b in zip(ordered, ordered[1:]):
            if b > a:
                raise PolicyError(
                    "ttl_by_stakes must be non-increasing with stakes "
                    "(a higher-stakes action may never get a longer leash)")
        # NOT_DUE is an internal status, never a policy response
        for s, r in self.response_by_stakes.items():
            if r is ExpiryResponse.NOT_DUE:
                raise PolicyError(f"response_by_stakes[{s.name}] may not be NOT_DUE")
        for h in self.quiet_hours:
            if not (0 <= int(h) <= 23):
                raise PolicyError(f"quiet_hours entries must be 0..23 (got {h!r})")
        if self.max_silent_renews < 1:
            raise PolicyError("max_silent_renews must be >= 1 (silence must be finite)")


# ── effect/reversibility -> stakes (deterministic; a deployment may override) ──
_HIGH_EFFECTS = frozenset({"data_egress", "account_access"})
_CRITICAL_EFFECTS = frozenset({"oversight_control", "log_mutation", "lethal", "deception"})


def default_stakes(effects: Tuple[str, ...], *, reversible: bool,
                   in_repertoire: bool, cumulative_pressure: float = 0.0) -> Stakes:
    """Derive stakes from what the action DOES. Deterministic, not a judgment.
    `cumulative_pressure` (0..1, e.g. fraction of a ledger budget consumed) may only
    RAISE stakes, never lower them. Validates its inputs and fails closed.

    ⚠ HONEST LIMIT: this trusts the effects it is GIVEN. A planner that mislabels an
    exfil as effects=('none',) gets a trivial leash. Effects must be STRUCTURALLY
    tagged at actuator registration (not planner-declared) — see THREAT_BOUNDARIES §7."""
    if not isinstance(cumulative_pressure, (int, float)) or not (0.0 <= cumulative_pressure <= 1.0):
        raise ValueError(f"cumulative_pressure must be in 0..1 (got {cumulative_pressure!r})")
    effs = tuple(effects or ())
    for e in effs:
        if not isinstance(e, str):
            raise ValueError(f"effects must be Effect *values* (strings); got {e!r}")

    s = Stakes.TRIVIAL
    if any(e in _CRITICAL_EFFECTS for e in effs):
        s = Stakes.CRITICAL
    elif any(e in _HIGH_EFFECTS for e in effs):
        s = Stakes.HIGH
    elif any(e == "physical_force" for e in effs):
        s = Stakes.MODERATE
    elif any(e != "none" for e in effs):
        s = Stakes.LOW

    if not reversible:
        s = max(s, Stakes.HIGH)          # irreversible is never below HIGH
    if not in_repertoire:
        s = max(s, Stakes.MODERATE)      # out-of-pattern raises stakes
    # cumulative pressure ratchets caution up (and CAN reach CRITICAL when nearly spent
    # on an already-serious action — v1 capped this at HIGH, a red-team finding)
    if cumulative_pressure >= 0.95 and s >= Stakes.HIGH:
        s = Stakes.CRITICAL
    elif cumulative_pressure >= 0.8:
        s = max(s, Stakes.HIGH)
    elif cumulative_pressure >= 0.5:
        s = max(s, Stakes.MODERATE)
    return s


@dataclass(frozen=True)
class ParkedGoal:
    goal_id: str
    stakes: Stakes
    response: ExpiryResponse
    parked_at: float          # wall time, STABLE (set once — v1 slid this forward)
    note: str = ""
    def to_dict(self) -> dict:
        return {"goal_id": self.goal_id, "stakes": self.stakes.name,
                "response": self.response.name, "parked_at": self.parked_at, "note": self.note}


@dataclass
class AuthorizationLease:
    """A goal's live authorization to run. It EXPIRES; it imposes NO completion
    deadline. Expiry math uses MONOTONIC time so a clock jump cannot extend or void it."""
    goal_id: str
    stakes: Stakes
    granted_mono: float
    ttl: float
    silent_renews: int = 0        # consecutive silent renewals (silence is expensive)
    renewals: int = 0             # lineage: how many times renewed
    def expires_mono(self) -> float:
        return self.granted_mono + self.ttl
    def expired(self, now_mono: float) -> bool:
        return self.ttl <= 0.0 or now_mono >= self.expires_mono()


class AuthorizationTTLEngine:
    """Deterministic stakes-scaled leash engine (thread-safe).

        lease  = engine.authorize(goal_id, stakes)
        status = engine.check(goal_id)      # NOT_DUE / SILENT_RENEW / HOLD_* / INTERRUPT_NOW
        engine.renew(goal_id, by="justin", stakes=...)   # resumes a parked goal
        digest = engine.morning_digest()    # "here's what I paused on"
    """

    def __init__(self, policy: Optional[CadencePolicy] = None, *,
                 mono: Callable[[], float] = time.monotonic,
                 wall: Callable[[], float] = time.time,
                 local_hour: Optional[Callable[[], int]] = None,
                 audit_logger=None):
        self.policy = policy or CadencePolicy()
        self._mono = mono                 # expiry math (immune to clock jumps)
        self._wall = wall                 # log timestamps only
        self._local_hour = local_hour or (lambda: time.localtime(self._wall()).tm_hour)
        self._audit = audit_logger or (lambda **kw: None)
        self._lock = threading.RLock()
        self._leases: Dict[str, AuthorizationLease] = {}
        self._parked: Dict[str, ParkedGoal] = {}
        self.history: List[dict] = []     # append-only lineage (park/renew/authorize)

    def _log(self, event: str, **kw) -> None:
        rec = {"ts": self._wall(), "event": event, **kw}
        self.history.append(rec)
        self._audit(stage="authz_ttl", **rec)

    # ── grant ──
    def authorize(self, goal_id: str, stakes: Stakes) -> AuthorizationLease:
        """Grant (or refresh) a leash sized to stakes. Clears any parked state."""
        if not isinstance(stakes, Stakes):
            raise ValueError(f"stakes must be a Stakes member (got {stakes!r})")
        with self._lock:
            prev = self._leases.get(goal_id)
            ttl = self.policy.ttl_by_stakes[stakes]
            lease = AuthorizationLease(goal_id, stakes, self._mono(), ttl,
                                       silent_renews=0,
                                       renewals=(prev.renewals if prev else 0))
            self._leases[goal_id] = lease
            self._parked.pop(goal_id, None)
            self._log("authorize", goal_id=goal_id, stakes=stakes.name, ttl=ttl)
            return lease

    # ── the tick ──
    def check(self, goal_id: str) -> AuthorizationStatus:
        """Called every coordinator tick. Distinguishes NOT_DUE (keep going) from
        SILENT_RENEW (expired + auto-renewed) from a HOLD (parked). PARKS ONCE:
        a goal already parked returns its EXISTING hold statically — no timestamp
        drift, no duplicate audit spam (the v1 bug)."""
        with self._lock:
            # already parked -> return the existing hold unchanged (STABLE)
            parked = self._parked.get(goal_id)
            if parked is not None:
                return AuthorizationStatus(parked.response, due=True, renewed=False,
                                           parked=True, stakes=parked.stakes, goal_id=goal_id)

            lease = self._leases.get(goal_id)
            if lease is None:
                # never authorized (or lost to a restart) -> FAIL CLOSED: park it.
                p = ParkedGoal(goal_id, Stakes.MODERATE, ExpiryResponse.HOLD_FOR_PROMPT,
                               self._wall(), note="no authorization on record (fail-closed)")
                self._parked[goal_id] = p
                self._log("parked", goal_id=goal_id, reason="unknown_goal",
                          response=p.response.name)
                return AuthorizationStatus(p.response, due=True, renewed=False, parked=True,
                                           stakes=p.stakes, goal_id=goal_id)

            now = self._mono()
            if not lease.expired(now):
                return AuthorizationStatus(ExpiryResponse.NOT_DUE, due=False, renewed=False,
                                           parked=False, stakes=lease.stakes, goal_id=goal_id)

            # expired -> how should it surface?
            response = self.policy.response_by_stakes[lease.stakes]

            # SILENCE IS EXPENSIVE: cap consecutive silent renewals.
            if response is ExpiryResponse.SILENT_RENEW:
                if lease.silent_renews + 1 >= self.policy.max_silent_renews:
                    response = ExpiryResponse.HOLD_FOR_DIGEST
                    self._log("silence_cap", goal_id=goal_id,
                              silent_renews=lease.silent_renews,
                              max_silent_renews=self.policy.max_silent_renews)

            response = self._apply_quiet_hours(response, lease.stakes, goal_id)

            if response is ExpiryResponse.SILENT_RENEW:
                new = AuthorizationLease(goal_id, lease.stakes, now,
                                         self.policy.ttl_by_stakes[lease.stakes],
                                         silent_renews=lease.silent_renews + 1,
                                         renewals=lease.renewals)
                self._leases[goal_id] = new
                self._log("silent_renew", goal_id=goal_id, stakes=lease.stakes.name,
                          silent_renews=new.silent_renews)
                return AuthorizationStatus(ExpiryResponse.SILENT_RENEW, due=True, renewed=True,
                                           parked=False, stakes=lease.stakes, goal_id=goal_id)

            # PARK ONCE (stable timestamp, single audit entry)
            p = ParkedGoal(goal_id, lease.stakes, response, self._wall(),
                           note=f"authorization expired at stakes {lease.stakes.name}")
            self._parked[goal_id] = p
            self._log("parked", goal_id=goal_id, stakes=lease.stakes.name,
                      response=response.name)
            return AuthorizationStatus(response, due=True, renewed=False, parked=True,
                                       stakes=lease.stakes, goal_id=goal_id)

    def _apply_quiet_hours(self, response: ExpiryResponse, stakes: Stakes,
                           goal_id: str) -> ExpiryResponse:
        """During quiet hours, anything below min-interrupt stakes may NOT interrupt —
        it downgrades to a hold. The anti-3am-dusting rule, made mechanical."""
        if self._local_hour() in self.policy.quiet_hours:
            if response is ExpiryResponse.INTERRUPT_NOW and stakes < self.policy.quiet_hours_min_interrupt:
                self._log("quiet_hours_downgrade", goal_id=goal_id, stakes=stakes.name)
                return ExpiryResponse.HOLD_FOR_PROMPT
        return response

    # ── renewal (re-evaluates stakes; fails closed on unknown goals) ──
    def renew(self, goal_id: str, *, by: str, stakes: Optional[Stakes] = None,
              capability: Optional[str] = None) -> AuthorizationLease:
        """A human/authority re-authorizes a parked (or live) goal. Expiry was never
        failure — this is the normal 'yes, keep going' path.

        STAKES ARE RE-EVALUATED, NOT FROZEN: pass the CURRENT stakes (e.g. recomputed
        from default_stakes with fresh cumulative_pressure). Stakes may only RATCHET
        UP on renewal — a goal cannot be renewed into a *longer* leash than its current
        posture warrants.

        FAILS CLOSED on an unknown goal (v1 conjured a MODERATE lease from nothing).

        `capability` is RECORDED but NOT VERIFIED here — verifying who may renew is
        signed_permission's / the broker's job (see the honest limits at the top)."""
        with self._lock:
            prev = self._leases.get(goal_id)
            if prev is None:
                raise UnknownGoal(
                    f"cannot renew {goal_id!r}: no authorization on record "
                    f"(fail-closed; authorize() it explicitly)")
            new_stakes = prev.stakes if stakes is None else stakes
            if not isinstance(new_stakes, Stakes):
                raise ValueError(f"stakes must be a Stakes member (got {stakes!r})")
            # ratchet: renewal may raise the posture, never lower it
            effective = max(new_stakes, prev.stakes) if stakes is not None else prev.stakes
            ttl = self.policy.ttl_by_stakes[effective]
            lease = AuthorizationLease(goal_id, effective, self._mono(), ttl,
                                       silent_renews=0, renewals=prev.renewals + 1)
            self._leases[goal_id] = lease
            self._parked.pop(goal_id, None)
            self._log("renewed", goal_id=goal_id, by=by, stakes=effective.name,
                      capability_recorded=bool(capability), renewals=lease.renewals)
            return lease

    # ── surfacing ──
    def morning_digest(self, *, clear: bool = False) -> List[dict]:
        """'Here's what I paused on' — parked goals, highest stakes first, then oldest,
        then goal_id (fully deterministic ordering). Low-stakes holds surface calmly
        instead of waking anyone. Stale parked goals are flagged."""
        with self._lock:
            now = self._wall()
            items = sorted(self._parked.values(),
                           key=lambda g: (-int(g.stakes), g.parked_at, g.goal_id))
            out = []
            for g in items:
                d = g.to_dict()
                d["stale"] = (now - g.parked_at) > self.policy.parked_stale_after
                out.append(d)
            if clear:
                self._parked.clear()
                self._log("digest_cleared", count=len(out))
            return out

    def parked_ids(self) -> List[str]:
        with self._lock:
            return list(self._parked.keys())

    def is_due(self, goal_id: str) -> bool:
        """Pure expiry question (ignores quiet hours / surfacing). Unknown goal = due."""
        with self._lock:
            lease = self._leases.get(goal_id)
            return lease is None or lease.expired(self._mono())

    def lease_info(self, goal_id: str) -> Optional[dict]:
        with self._lock:
            l = self._leases.get(goal_id)
            if l is None:
                return None
            return {"goal_id": l.goal_id, "stakes": l.stakes.name, "ttl": l.ttl,
                    "silent_renews": l.silent_renews, "renewals": l.renewals}
