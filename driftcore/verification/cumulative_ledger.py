"""
driftcore/verification/cumulative_ledger.py
===========================================
STATUS: PROPOSED (stdlib-only). CROSS-ACTION accounting — the gap FOUR independent
red-team rounds converged on.

THE HOLE THIS CLOSES. The coordinator judges one action at a time. That is blind to
harm and leakage that live in a SEQUENCE of individually-acceptable actions:
  * FRAGMENTATION: send secret as piece A, then B, then C — three authorized
    DATA_EGRESS sends, one leak. No single send trips anything.
  * CUMULATIVE HARM: four actions each at P(harm)=0.49 under a 0.5 cutoff — each
    passes; the trajectory totals ~1.96. No per-action gate sums them.
  * SLOW EXFIL / stego across many outputs: each clause is benign; the accumulation
    is the payload. A speech-layer surface check cannot see this (see
    SPEECH_LAYER_OUTPUT_BACKSTOP.md §4) — its real defense is HERE, at the effect
    boundary, accounting for what crosses over time.

WHAT THIS DOES. Maintains, per (owner, window), running budgets that a caller checks
BEFORE permitting a consequential action:
  * egress-volume budgets: count and/or bytes of DATA_EGRESS / ACCOUNT_ACCESS per
    window (fragmentation + slow-exfil defense);
  * cumulative harm budget: sum of VERIFIER-SOURCED P(harm) per window
    (cumulative-harm defense);
  * generic per-effect counts (e.g. how many OVERSIGHT_CONTROL touches this window).
When a proposed action WOULD push a budget past its limit, `check` returns a
DENY/REVIEW verdict; the caller escalates to a human or refuses. Windows roll
(fixed-duration) so budgets are "per hour/day", not "forever".

HONESTY — asymmetry mirrored from harm_estimate. Only VERIFIER-SOURCED harm counts
toward the harm budget; an UNVERIFIED planner number may not be used to *raise* the
running total in a way that then blocks legitimate work (it cannot lower caution
either — it is simply not trusted to drive the budget). Egress COUNTS are structural
(the effect either is or isn't DATA_EGRESS), so they are always counted.

HONEST LIMITS (named, not hidden):
  * This BOUNDS cumulative effect; it does not UNDERSTAND intent. It cannot tell a
    legitimate 500-email newsletter from 500 exfiltration sends — it bounds the
    volume and escalates past the threshold; a human sets whether the threshold fits
    the workload. Setting budgets too high defeats it; that is a deployment choice.
  * "Bytes leaked" is only as good as the byte count the caller supplies. If the
    execution layer under-reports payload size, the budget under-counts. The count
    (number of egress actions) is more robust than the byte total.
  * Durable + cross-instance via the same hash-chained pattern as AuthorizationState,
    so the 8-agents case shares one budget and it survives a crash — but it is
    single-host durability (a file), not distributed consensus. Cross-host needs a
    shared backend; the interface is small so that swap is a drop-in.
  * This is one more EVIDENCE source, not a sole judge (DriftCore's fusion model).
"""
from __future__ import annotations

import json
import os
import time
import hashlib
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional


class LedgerVerdict(str, Enum):
    OK               = "OK"                # within all budgets
    REVIEW_REQUIRED  = "REVIEW_REQUIRED"   # a soft budget is crossed -> human should look
    DENY             = "DENY"              # a hard budget is crossed -> refuse


@dataclass(frozen=True)
class BudgetPolicy:
    """Per-window limits. None = that budget is not enforced. `window_seconds` rolls
    the accounting (e.g. 3600 = hourly). Soft limits escalate to REVIEW; hard limits
    DENY. Hard must be >= soft when both are set."""
    window_seconds: float = 3600.0
    # egress volume
    max_egress_actions: Optional[int] = None          # hard cap on # of egress actions
    soft_egress_actions: Optional[int] = None         # soft cap -> REVIEW
    max_egress_bytes: Optional[int] = None            # hard cap on total egress bytes
    # cumulative harm (verifier-sourced P(harm) summed)
    max_cumulative_harm: Optional[float] = None       # hard cap on summed P(harm)
    soft_cumulative_harm: Optional[float] = None      # soft cap -> REVIEW
    # generic per-effect action counts (effect_value -> hard cap)
    max_effect_actions: Dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class ProposedAction:
    """What the caller is about to permit, described in the system's real vocabulary.
    `effects` are Effect *values* (e.g. 'data_egress'); `harm_p` is a P(harm) point
    estimate; `harm_verifier_sourced` gates whether it may drive the harm budget;
    `egress_bytes` is the payload size if known."""
    effects: tuple = ()
    harm_p: Optional[float] = None
    harm_verifier_sourced: bool = False
    egress_bytes: int = 0


_EGRESS = frozenset({"data_egress", "account_access"})


def _entry_hash(prev: str, rec: dict) -> str:
    body = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev + "\n" + body).encode()).hexdigest()


class LedgerIntegrityError(Exception):
    pass


class CumulativeLedger:
    """Durable, hash-chained, per-(owner,window) running budgets. Append-only JSONL,
    fsynced under a lock, shared across instances on one path — same discipline as
    AuthorizationState. `check` is the decision the coordinator/deployment calls
    before permitting a consequential action; `record` commits the action's effects
    to the current window (call it only when the action is actually permitted)."""

    def __init__(self, path: Optional[str], policy: BudgetPolicy, *, audit_logger=None):
        self.policy = policy
        self.path = path
        self._audit = audit_logger or (lambda **kw: None)
        self._lock = threading.RLock()
        # window state: owner -> {"start": ts, "egress_actions": n, "egress_bytes": n,
        #                         "harm_sum": f, "effects": {effect_value: n}}
        self._w: Dict[str, dict] = {}
        self._head = "GENESIS"
        self._seq = 0
        if path:
            d = os.path.dirname(path)
            if d:
                os.makedirs(d, exist_ok=True)
            self._replay()

    # ── window helpers ────────────────────────────────────────────
    def _window(self, owner: str, now: float) -> dict:
        w = self._w.get(owner)
        if w is None or (now - w["start"]) >= self.policy.window_seconds:
            w = {"start": now, "egress_actions": 0, "egress_bytes": 0,
                 "harm_sum": 0.0, "effects": {}}
            self._w[owner] = w
        return w

    # ── durable append ────────────────────────────────────────────
    def _replay(self) -> None:
        if not os.path.exists(self.path):
            return
        with open(self.path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                recomputed = _entry_hash(rec.get("prev", ""),
                                         {k: rec[k] for k in rec if k != "hash"})
                if rec.get("prev") != self._head or rec.get("hash") != recomputed:
                    raise LedgerIntegrityError(
                        f"cumulative-ledger chain broken at seq={rec.get('seq')}")
                self._apply(rec)
                self._head = rec["hash"]
                self._seq = rec.get("seq", self._seq)

    def _resync(self) -> None:
        if not self.path or not os.path.exists(self.path):
            return
        with open(self.path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if rec.get("seq", 0) <= self._seq:
                    continue
                recomputed = _entry_hash(rec.get("prev", ""),
                                         {k: rec[k] for k in rec if k != "hash"})
                if rec.get("prev") != self._head or rec.get("hash") != recomputed:
                    raise LedgerIntegrityError("cumulative-ledger chain broken on resync")
                self._apply(rec)
                self._head = rec["hash"]
                self._seq = rec["seq"]

    def _apply(self, rec: dict) -> None:
        owner = rec.get("owner", "")
        now = rec.get("ts", time.time())
        w = self._window(owner, now)
        w["egress_actions"] += rec.get("d_egress_actions", 0)
        w["egress_bytes"]   += rec.get("d_egress_bytes", 0)
        w["harm_sum"]       += rec.get("d_harm", 0.0)
        for ev, n in (rec.get("d_effects") or {}).items():
            w["effects"][ev] = w["effects"].get(ev, 0) + n

    def _append(self, owner: str, deltas: dict) -> None:
        rec = {"seq": self._seq + 1, "ts": round(time.time(), 3), "prev": self._head,
               "owner": owner, **deltas}
        rec["hash"] = _entry_hash(self._head, rec)
        if self.path:
            with open(self.path, "a") as f:
                f.write(json.dumps(rec, separators=(",", ":")) + "\n")
                f.flush()
                os.fsync(f.fileno())
        self._apply(rec)
        self._head = rec["hash"]
        self._seq = rec["seq"]

    # ── public API ────────────────────────────────────────────────
    def check(self, owner: str, action: ProposedAction) -> LedgerVerdict:
        """Would permitting `action` push a budget past its limit THIS window?
        Returns DENY (hard), REVIEW_REQUIRED (soft), or OK. Does NOT record — call
        `record` only when the action is actually permitted. Read-only + resync."""
        with self._lock:
            self._resync()
            now = time.time()
            w = self._window(owner, now)
            p = self.policy

            egress_n = sum(1 for e in action.effects if e in _EGRESS)
            proj_actions = w["egress_actions"] + egress_n
            proj_bytes = w["egress_bytes"] + (action.egress_bytes if egress_n else 0)
            # only verifier-sourced harm may drive the harm budget
            add_harm = (action.harm_p or 0.0) if (
                action.harm_p is not None and action.harm_verifier_sourced) else 0.0
            proj_harm = w["harm_sum"] + add_harm

            verdict = LedgerVerdict.OK
            reasons = []

            # hard caps -> DENY
            if p.max_egress_actions is not None and proj_actions > p.max_egress_actions:
                verdict = LedgerVerdict.DENY
                reasons.append(f"egress actions {proj_actions}>{p.max_egress_actions}")
            if p.max_egress_bytes is not None and proj_bytes > p.max_egress_bytes:
                verdict = LedgerVerdict.DENY
                reasons.append(f"egress bytes {proj_bytes}>{p.max_egress_bytes}")
            if p.max_cumulative_harm is not None and proj_harm > p.max_cumulative_harm:
                verdict = LedgerVerdict.DENY
                reasons.append(f"cumulative harm {proj_harm:.3f}>{p.max_cumulative_harm}")
            for e in action.effects:
                cap = p.max_effect_actions.get(e)
                if cap is not None and (w["effects"].get(e, 0) + 1) > cap:
                    verdict = LedgerVerdict.DENY
                    reasons.append(f"effect '{e}' {w['effects'].get(e,0)+1}>{cap}")

            # soft caps -> REVIEW (only if not already DENY)
            if verdict is LedgerVerdict.OK:
                if p.soft_egress_actions is not None and proj_actions > p.soft_egress_actions:
                    verdict = LedgerVerdict.REVIEW_REQUIRED
                    reasons.append(f"egress actions {proj_actions}>soft {p.soft_egress_actions}")
                if p.soft_cumulative_harm is not None and proj_harm > p.soft_cumulative_harm:
                    verdict = LedgerVerdict.REVIEW_REQUIRED
                    reasons.append(f"cumulative harm {proj_harm:.3f}>soft {p.soft_cumulative_harm}")

            self._audit(stage="cumulative_ledger", owner=owner, verdict=verdict.value,
                        reasons=reasons, egress_actions=proj_actions, harm=round(proj_harm, 3))
            return verdict

    def record(self, owner: str, action: ProposedAction) -> None:
        """Commit a PERMITTED action's effects to the current window (durable).
        Call only after the action is allowed — check() does not mutate."""
        with self._lock:
            self._resync()
            egress_n = sum(1 for e in action.effects if e in _EGRESS)
            add_harm = (action.harm_p or 0.0) if (
                action.harm_p is not None and action.harm_verifier_sourced) else 0.0
            effs: Dict[str, int] = {}
            for e in action.effects:
                effs[e] = effs.get(e, 0) + 1
            self._append(owner, {
                "d_egress_actions": egress_n,
                "d_egress_bytes": action.egress_bytes if egress_n else 0,
                "d_harm": add_harm,
                "d_effects": effs,
            })

    def usage(self, owner: str) -> dict:
        """Current window usage for an owner (read-only snapshot)."""
        with self._lock:
            self._resync()
            w = self._window(owner, time.time())
            return {"egress_actions": w["egress_actions"], "egress_bytes": w["egress_bytes"],
                    "harm_sum": round(w["harm_sum"], 3), "effects": dict(w["effects"])}

    def verify_integrity(self) -> bool:
        if not self.path or not os.path.exists(self.path):
            return True
        prev = "GENESIS"
        with open(self.path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if rec.get("prev") != prev or rec.get("hash") != _entry_hash(
                        prev, {k: rec[k] for k in rec if k != "hash"}):
                    return False
                prev = rec["hash"]
        return True
