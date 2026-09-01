"""
driftcore/verification/breach_response.py
=========================================
STATUS: PROPOSED (stdlib-only). THE ALARM ON THE WALL.

Every other module answers "how do we PREVENT a harmful action." This one answers the
question that matters the microsecond AFTER prevention fails, because prevention will
sometimes fail — a bug, a blind spot, an unknown unknown, a composed capability no
single check caught:

    "When a safety line is crossed — by attack OR by the system's own accident —
     does the system NOTICE, record it TRUTHFULLY, enter a SAFE STATE, and HOLD for
     a human? Or does it log 'blocked' and carry on as if nothing happened?"

A wall that is crossed and does not notice is far more dangerous than one that is
crossed and immediately freezes and screams for a human. The first keeps drifting.
The second is recoverable. This module is the second.

    ┌───────────────────────────── THE PRINCIPLE ────────────────────────────┐
    │  The alarm is wired to the BREACH, not to the system's OPINION of the   │
    │  breach. A system under pressure will dramatize; a system over-tuned    │
    │  toward compliance will downplay. BOTH corrupt self-report. So the      │
    │  breach record is written from the OBSERVED violation, and it is written│
    │  to an append-only ledger the system cannot edit — never from the       │
    │  system's own account of what happened.                                 │
    └─────────────────────────────────────────────────────────────────────────┘

WHY THIS EXISTS (the two failure modes it defends against, both real):
  1. SILENT BYPASS. A harm slips through (bug / blind spot / composition). If the
     system just continues, the breach becomes invisible drift. Breach-response makes
     it a LOUD, RECORDED, RECOVERABLE event instead.
  2. SELF-REPORT CORRUPTION. Whether the system over-dramatizes (sycophantic frame-
     capture) or under-reports (cover-up under over-constraint), its account of itself
     is unreliable. So we do not ask the system "did something go wrong?" — we record
     the OBSERVED violation and let a human read the unfalsifiable log.

WHAT IT DOES:
  * On a detected violation, WRITE THE BREACH to the append-only hash-chained ledger
    (truthful, attributable, tamper-evident) — first, before anything else.
  * TRANSITION the system to a conservative SAFE STATE (default: HALT — refuse further
    consequential action). Severity-scaled: a minor near-miss may only heighten
    caution; a hard-line breach halts.
  * HOLD in that state until a HUMAN acknowledges. The system cannot clear its own
    breach (that would be the fox guarding the henhouse — exactly the self-report
    corruption this defends against). Acknowledgement requires a human-signed action.
  * ESCALATE on repetition: repeated near-misses ratchet the posture tighter, the way
    a careful person slows down after a close call.

HONEST LIMITS (stated, not hidden):
  * DETECTION IS UPSTREAM. This responds to a breach that something ELSE detected
    (the guard, the wall, a monitor). It cannot catch a harm that was never recognized
    as a harm — the unknown-unknown that trips nothing still trips nothing. What it
    guarantees is that ANY breach the system CAN see becomes loud and safe instead of
    silent. It shrinks the damage of a detected breach; it does not detect the
    undetectable.
  * SAFE-STATE ENFORCEMENT IS ADVISORY HERE. This module records the breach and sets
    the state; the ACTUAL halting of physical action must be enforced by the actuation
    layer consulting this state (and, for the critical limits, by HARDWARE). A safe
    state the agent can ignore is a note, not a brake. Wire `is_operational()` into the
    mediated-actuation broker so a breached system genuinely cannot actuate.
  * LEDGER IS TAMPER-EVIDENT, NOT OS-IMMUTABLE. The hash chain makes edits DETECTABLE;
    true immutability is a deployment/hardware concern (append-only storage).
  * RESTART FORGETS THE SAFE STATE (found in seven-question red-team — IMPORTANT). The
    posture and hold are in-memory. A breached, halted system that RESTARTS comes back
    NORMAL and could resume — the same durability gap as in-memory nonces, but more
    dangerous here (it un-does a safety halt). For any real deployment the safe state
    MUST be persisted to durable storage and restored on startup, and startup should
    FAIL CLOSED into the last known posture if the store is unreadable. Not wired here
    (this module provides the mechanism); the persistence is a deployment requirement.
  * A HUMAN-ACK VERIFIER IS MANDATORY FOR RECOVERY (found in red-team). With no
    `human_ack_verifier`, a breach can never be cleared (intentional fail-closed —
    better stuck-safe than self-cleared). A deployment MUST supply a real verifier
    (e.g. a signed-grant check) or a halted system cannot be recovered by anyone.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, List, Optional


class Severity(IntEnum):
    """How bad the breach is. Ordered — a higher severity forces a stricter posture."""
    NEAR_MISS = 1     # something approached a line but did not cross (heighten caution)
    SOFT = 2          # a bounded/recoverable line crossed (e.g. a limit exceeded, contained)
    HARD = 3          # a constitutional bright line crossed (lethal/exfil/oversight/deceive)


class Posture(IntEnum):
    """The system's operational stance. Higher = more restricted. Never lowered except
    by a human acknowledgement."""
    NORMAL = 0        # ordinary operation
    HEIGHTENED = 1    # more conservative; near a line; extra scrutiny
    RESTRICTED = 2    # consequential actions refused; benign operation only
    HALT = 3          # all consequential action refused; hold for human


@dataclass(frozen=True)
class BreachRecord:
    """The truthful, observed record of a breach. Built from what was OBSERVED, never
    from the system's self-report. Frozen — once made, it is not edited.

    NOTE (red-team fix): there is deliberately NO 'accidental' / 'intent' field. That
    was a self-report field — an opinion the caller supplies — smuggled into a module
    whose entire principle is 'record the observed violation, not the system's
    narrative about it.' A buggy or captured detector could label its own breach an
    'accident' to downplay it. Intent is not observed; it is inferred later by a HUMAN
    from the `observed` description and context. We record what happened, not why."""
    ts: float
    severity: int
    invariant: str            # which line was crossed (the OBSERVED one)
    observed: str             # what was observed to happen (not the system's narrative)
    posture_after: int
    def to_dict(self) -> dict:
        return {"ts": self.ts, "severity": self.severity, "invariant": self.invariant,
                "observed": self.observed, "posture_after": self.posture_after}


class _AppendOnlyLedger:
    """Minimal hash-chained append-only ledger (mirrors HashChainLedger). Breach
    records go here first, before any state change — so the truth is recorded even if
    everything downstream fails. Tamper-EVIDENT (detect), not OS-immutable (prevent)."""
    GENESIS = "0" * 64
    def __init__(self):
        self._chain: List[dict] = []
    def append(self, payload: dict) -> dict:
        prev = self._chain[-1]["hash"] if self._chain else self.GENESIS
        entry = {**payload, "prev": prev}
        entry["hash"] = hashlib.sha256(
            (prev + json.dumps(entry, sort_keys=True)).encode()).hexdigest()
        self._chain.append(entry)
        return entry
    def verify(self) -> bool:
        prev = self.GENESIS
        for e in self._chain:
            if e["prev"] != prev:
                return False
            body = {k: e[k] for k in e if k != "hash"}
            if hashlib.sha256((e["prev"] + json.dumps(body, sort_keys=True)).encode()).hexdigest() != e["hash"]:
                return False
            prev = e["hash"]
        return True
    def entries(self) -> List[dict]:
        return list(self._chain)


class BreachResponse:
    """The alarm on the wall. Records breaches truthfully, sets a conservative safe
    state, and holds for a human. The system CANNOT clear its own breach."""

    def __init__(self, *, ledger: Optional[_AppendOnlyLedger] = None,
                 near_miss_escalation_threshold: int = 3,
                 severity_escalation_score: int = 6,
                 human_ack_verifier: Optional[Callable[[object], bool]] = None,
                 alert_hook: Optional[Callable[[BreachRecord], None]] = None,
                 kernel_halt_source: Optional[Callable[[], bool]] = None):
        self._ledger = ledger or _AppendOnlyLedger()
        self._posture = Posture.NORMAL
        self._holding_for_human = False
        self._breaches: List[BreachRecord] = []
        self._near_miss_count = 0
        self._near_miss_threshold = near_miss_escalation_threshold
        self._severity_escalation_score = severity_escalation_score
        self._severity_score = 0
        # (C6 fix, 2026-08-31) Wires is_operational() to the kernel's halt signal.
        # Without this, emergency_halt() sets kernel.locked but is_operational()
        # reads only _posture (a breach-layer concept), so any consumer of
        # is_operational() — monitoring, dashboards, the posture_source slot of an
        # ungated broker — saw True while Poppy was physically halted.
        #
        # A callable returning True while the kernel is halted (e.g.
        # `lambda: kernel.locked`). When supplied, is_operational() returns False
        # whenever the kernel is halted, regardless of breach posture. The lifecycle
        # is correct: the kernel gate must be released independently by an
        # authenticated human — this source is read-only from this layer.
        #
        # DEFAULT None = kernel halt NOT reflected in is_operational(). That is the
        # pre-fix behaviour and is never a neutral default for a deployment with
        # physical actuators. It defaults off so existing callers do not silently
        # change behaviour. Expose via status()["kernel_halt_wired"] so the gap is
        # visible and assertable in deployment checks.
        self._kernel_halt_source = kernel_halt_source
        self._human_ack_verifier = human_ack_verifier
        self._alert = alert_hook or (lambda rec: None)
        self._lock = threading.RLock()   # concurrent breaches must not race (Q5)
        # RESTART RECOVERY (red-team's #1 finding): if the ledger already contains
        # history (e.g. a durable ledger was passed in), restore the last posture. A
        # HALT that a restart forgets is worse than no HALT. We replay the ledger's
        # posture transitions and, if the last recorded posture was RESTRICTED+ without
        # a subsequent human ack, we come back HELD in that posture — fail-closed. The
        # in-memory default ledger is empty, so a fresh instance starts NORMAL as
        # before; the recovery matters when a DURABLE ledger is supplied.
        self._restore_from_ledger()

    def _restore_from_ledger(self) -> None:
        """Replay the ledger to restore the safe state after a restart. Fail-closed:
        the last recorded posture stands unless a later ack cleared it. This is the
        mechanism; supplying a DURABLE (disk/WORM) ledger is the deployment's job."""
        last_posture = Posture.NORMAL
        held = False
        for e in self._ledger.entries():
            kind = e.get("kind")
            if kind == "posture":
                last_posture = Posture(int(e.get("posture", 0)))
                held = bool(e.get("holding", False))
            elif kind == "ack_accepted":
                last_posture = Posture.NORMAL
                held = False
                self._near_miss_count = 0
                self._severity_score = 0
        self._posture = last_posture
        self._holding_for_human = held

    # ── the core: record a breach, from the OBSERVED violation ──
    def record_breach(self, *, severity: Severity, invariant: str, observed: str) -> BreachRecord:
        """Called when a safety line is OBSERVED to be crossed — by the guard, the
        wall, or a monitor. Writes the truth to the ledger FIRST, then sets the safe
        state. `observed` is what was seen to happen, NOT the system's narrative about
        it. (There is deliberately no 'accidental'/'intent' parameter — see BreachRecord;
        intent is inferred later by a human, not self-reported by the system.)"""
        # 1. Decide the new posture from severity (and accumulation).
        self._lock.acquire()
        try:
          if severity >= Severity.HARD:
            new_posture = Posture.HALT
          elif severity == Severity.SOFT:
            new_posture = Posture.RESTRICTED
          else:  # NEAR_MISS
            self._near_miss_count += 1
            new_posture = (Posture.RESTRICTED if self._near_miss_count >= self._near_miss_threshold
                           else Posture.HEIGHTENED)

          # ACCUMULATING SEVERITY SCORE (red-team: SOFT/near-miss breaches that COMPOSE
          # into real harm should escalate even if no single one is HARD). Each breach
          # adds its severity; if the running total crosses the escalation score, the
          # posture ratchets up — the composition analog of the near-miss counter.
          self._severity_score += int(severity)
          if self._severity_score >= self._severity_escalation_score:
            new_posture = Posture(max(int(new_posture), int(Posture.RESTRICTED)))

          # Posture only ever RATCHETS UP automatically; it is never lowered except by a
          # verified human acknowledgement.
          new_posture = Posture(max(int(self._posture), int(new_posture)))

          rec = BreachRecord(ts=time.time(), severity=int(severity), invariant=invariant,
                             observed=observed, posture_after=int(new_posture))

          # 2. WRITE THE TRUTH FIRST — to the append-only ledger, before the state change,
          #    so the breach is recorded even if everything after this fails. This is the
          #    whole point: the record is written from the observed violation, and the
          #    system cannot edit it.
          self._ledger.append({"kind": "breach", **rec.to_dict()})
          self._breaches.append(rec)
          # Persist the posture transition to the ledger so a restart can restore it
          # (red-team: the single biggest gap — a restart must not forget a HALT).
          self._ledger.append({"kind": "posture", "ts": time.time(),
                               "posture": int(new_posture),
                               "holding": new_posture >= Posture.RESTRICTED})

          # 3. Transition to the safe state and hold for a human on any real breach.
          self._posture = new_posture
          if new_posture >= Posture.RESTRICTED:
            self._holding_for_human = True
        finally:
          self._lock.release()

        # 4. Alert (best-effort; a broken alert sink must not stop the record/halt).
        try:
            self._alert(rec)
        except Exception:
            pass
        return rec

    # ── the gate the actuation layer consults ──
    def is_operational(self, *, consequential: bool = True) -> bool:
        """Whether the system may act. Wire this into the mediated-actuation broker so
        a breached system genuinely cannot actuate.

        HALT and RESTRICTED refuse ALL actions — not just consequential ones (red-team:
        the old code let non-consequential actions through in HALT, a 'cat door'; and a
        thousand 'non-consequential' actions can compose into harm). Only HEIGHTENED
        stays fully operational (flagged). The `consequential` parameter is retained so
        a caller CAN still ask, but a halted/restricted system is not operational for
        anything.

        (C6 fix) Also reflects the kernel halt state when kernel_halt_source is wired.
        A kernel emergency_halt() sets kernel.locked but does not write to _posture
        (different layer, different lifecycle). Without this check, is_operational()
        returned True while Poppy was physically halted — any consumer of this method
        (monitoring, the posture_source slot of the broker) got the wrong answer.

        Failure mode if kernel_halt_source raises or returns a non-bool: treated as
        halted (fail-closed). The kernel state is unknown; unknown is not safe.
        """
        # Check kernel halt first: a physical stop overrides posture regardless of
        # whether the breach layer has caught up. Fail-closed on source errors.
        if self._kernel_halt_source is not None:
            try:
                kernel_halted = self._kernel_halt_source()
                if kernel_halted is True:
                    return False
                if kernel_halted is not False:
                    # Non-bool return: wiring error, same fail-closed treatment as the
                    # broker's posture gate (Posture.HALT == 3 is truthy; bool() would
                    # invert the signal on a wiring mistake).
                    return False
            except Exception:
                return False   # source unavailable = treat as halted

        if self._posture >= Posture.RESTRICTED:
            return False
        if self._holding_for_human:
            return False
        return True

    # ── clearing requires a HUMAN; the system cannot clear itself ──
    def acknowledge(self, human_credential: object) -> bool:
        """A human acknowledges the breach and clears the hold. REQUIRES a verified
        human credential — the system cannot fake its own clearance (that would be the
        exact self-report corruption this module exists to defend against). Returns
        False and stays held if the credential does not verify. The acknowledgement is
        itself recorded in the ledger."""
        if self._human_ack_verifier is None:
            # Fail-closed: with no way to verify a human, we do not clear. Better a
            # system stuck safe than one that cleared itself.
            return False
        try:
            ok = bool(self._human_ack_verifier(human_credential))
        except Exception:
            ok = False
        if not ok:
            self._ledger.append({"kind": "ack_rejected", "ts": time.time()})
            return False
        # Record the human clearance (truthfully, in the ledger), then release.
        self._ledger.append({"kind": "ack_accepted", "ts": time.time(),
                             "cleared_posture_from": int(self._posture)})
        self._holding_for_human = False
        self._posture = Posture.NORMAL
        self._near_miss_count = 0
        self._severity_score = 0
        return True

    # ── read-only introspection (for the human / audit) ──
    @property
    def posture(self) -> Posture:
        return self._posture

    @property
    def kernel_halt_wired(self) -> bool:
        """True when a kernel_halt_source is installed.

        Deployment checks should assert this. An unwired BreachResponse does not
        reflect kernel emergency halts in is_operational() — any consumer (monitoring,
        broker posture_source) gets the wrong answer after an e-stop. This property
        makes the gap assertable rather than silent. Same pattern as
        ActuationBroker.is_breach_gated().

        assert breach.kernel_halt_wired, (
            "BreachResponse has no kernel halt source: is_operational() will return "
            "True even when the kernel is physically halted.")
        """
        return self._kernel_halt_source is not None
    @property
    def holding_for_human(self) -> bool:
        return self._holding_for_human
    def breaches(self) -> List[BreachRecord]:
        return list(self._breaches)
    def ledger_intact(self) -> bool:
        """True iff the breach ledger's hash chain verifies (no tampering detected)."""
        return self._ledger.verify()
    def ledger_entries(self) -> List[dict]:
        return self._ledger.entries()
