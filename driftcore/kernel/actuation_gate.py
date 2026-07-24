"""
actuation_gate.py — the ONE DOOR, applied at the actuation choke point.

THE GUARANTEE
─────────────
An action that ACTS ON THE WORLD through a capability whose effects a human has NOT
declared is REFUSED. Fail closed. Silence is a block, never a pass. This is the piece
that makes "no room for error" real: the safety guarantee is the declaration
requirement, not a keyword list — because keywords are gameable and declarations are
a deliberate human act.

WHAT DECIDES, WHAT ONLY FLAGS
─────────────────────────────
  • The human-declared EFFECT decides (routed through the single constitutional
    decider, verification.invariant_guard — the same door the kernel stack uses).
  • An UNDECLARED capability fails closed. Not "allow because no bad word."
  • The escalation lexicon FLAGS. It escalates a benign-declared capability whose
    wording trips a lethal concern to a human HOLD — it never itself blocks or
    allows. Its gameability is survivable because it is not the defense.

SCOPE (why this does not break universal / non-robot use)
─────────────────────────────────────────────────────────
This gate is invoked ONLY at actuation — when code reaches for a real actuator or a
consequential capability, through the mediation layer that is the sole path to
actuation. Pure reasoning never calls it, so thinking stays free; acting on the world
requires a declaration. The boundary is architectural: the mediation layer is the
choke point, and it must be the ONLY way to obtain an actuator (capability discipline).

WHAT THIS GATE DOES NOT CLAIM (documented residuals, see THREAT_MODEL_ONE_DOOR.md)
─────────────────────────────────────────────────────────────────────────────────
  • It trusts the declaration. A LETHAL actuator mis-declared NONE is a governance
    failure this gate cannot catch (the registry is the TCB; signed declarations and
    two-person control for dangerous effects are the mitigation, staged).
  • It is per-capability. Individually-benign capabilities that COMBINE into a
    forbidden effect are not caught here (composition is undecidable in general; a
    cumulative-effect ledger over a plan is the partial mitigation, staged).
  • Implementation/declaration drift (code changes after a human classified it) needs
    a declaration-to-code hash binding (staged).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
from enum import Enum
from typing import List, Optional, FrozenSet

from driftcore.kernel.effect_guard import EffectRegistry
from driftcore.kernel.escalation_lexicon import EscalationLexicon, Concern, normalize
from driftcore.verification.invariant_guard import (
    Effect, ActionContext, GuardStatus, load_guard,
)


class Outcome(Enum):
    ALLOW = "allow"                       # declared, decider cleared, no override
    BLOCK = "block"                       # declared effect hit a constitutional invariant
    BLOCK_UNDECLARED = "block_undeclared" # fail closed: capability has no declaration (POLICY)
    BLOCK_ERROR = "block_error"           # fail closed: the gate itself could not evaluate (INFRA)
    HOLD_FOR_REVIEW = "hold_for_review"   # lexicon/declaration mismatch: a human must classify


@dataclass
class Decision:
    outcome: Outcome
    capability_id: str
    reason: str
    declared_effects: Optional[FrozenSet[Effect]] = None
    binding_invariant: Optional[str] = None
    concerns: List[Concern] = field(default_factory=list)
    # Binding to defeat TOCTOU: the caller must execute the SAME declaration this
    # decision was made against. declaration_hash pins (capability + exact effects +
    # declared_by + time); the executor must present the same hash to actuate, so a
    # registry flip between authorize() and execute() invalidates the token. (Binding
    # the hash to the actuator CALLABLE too is the remaining staged step.)
    decided_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    declaration_hash: Optional[str] = None

    @property
    def permitted(self) -> bool:
        return self.outcome is Outcome.ALLOW


class ActuationGate:
    def __init__(self, registry: EffectRegistry, *,
                 decider=None, lexicon: Optional[EscalationLexicon] = None,
                 audit=None):
        self._registry = registry
        self._decider = decider if decider is not None else load_guard()
        self._lexicon = lexicon if lexicon is not None else EscalationLexicon()
        self._audit = audit

    def _record(self, decision: Decision):
        # Audit is BEST-EFFORT (cold review G#10): a throwing audit sink must not
        # take down the decision path. A failed write is swallowed; making audit a
        # hard requirement (HOLD when unwritable) is a documented deployment option.
        if not self._audit:
            return
        try:
            self._audit.record("ACTUATION_GATE", decision.outcome.value, {
                "capability_id": decision.capability_id,
                "outcome": decision.outcome.value,
                "reason": decision.reason,
                "declared_effects": (sorted(e.value for e in decision.declared_effects)
                                     if decision.declared_effects else None),
                "declaration_hash": decision.declaration_hash,
                "concerns": [(c.category, c.term, c.via) for c in decision.concerns],
                "decided_at": decision.decided_at,
            })
        except Exception:
            pass

    @staticmethod
    def _hash(capability_id, effects, declared_by, decided_at) -> str:
        payload = "|".join([
            capability_id,
            ",".join(sorted(e.value for e in effects)),
            declared_by or "", decided_at])
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def authorize(self, capability_id: Optional[str], action_text: str = "",
                  context: Optional[ActionContext] = None) -> Decision:
        try:
            return self._authorize(capability_id, action_text, context)
        except Exception as e:
            # The gate itself failing is a HALT, never a pass — tagged BLOCK_ERROR
            # (not BLOCK_UNDECLARED) so an operator can tell a real outage from a
            # normal "no declaration" outcome (cold review G#4).
            d = Decision(
                outcome=Outcome.BLOCK_ERROR,
                capability_id=str(capability_id),
                reason=f"actuation gate could not evaluate and fails closed: {e!r}")
            self._record(d)
            return d

    def _authorize(self, capability_id, action_text, context) -> Decision:
        # 1. No/blank capability id => cannot actuate anonymously => fail closed.
        if not capability_id or not isinstance(capability_id, str) or not capability_id.strip():
            d = Decision(Outcome.BLOCK_UNDECLARED, str(capability_id),
                         "no/blank capability id: actuation must name a declared capability")
            self._record(d); return d
        capability_id = capability_id.strip()

        # 2. Undeclared OR empty-declared capability => FAIL CLOSED. The registry
        #    rejects empty declarations, but converting a falsy declaration to None
        #    and handing that to the decider is the classic hidden-coupling fail-open
        #    (three cold reviewers flagged it). Block explicitly; never pass None on.
        declared = self._registry.effects_for(capability_id)
        if not declared:
            d = Decision(
                Outcome.BLOCK_UNDECLARED, capability_id,
                f"capability {capability_id!r} has no human-declared effects. Actuation "
                f"through an undeclared (or empty-declared) capability is refused. Declare "
                f"it (a privileged, audited act) before it can act.")
            self._record(d); return d

        decl = self._registry.declaration(capability_id)
        declared_by = decl.declared_by if decl else ""

        # Normalize the text ONCE. The decider's own backstop is NOT normalization-
        # hardened, so raw text would let a homoglyph ("kіll") dodge it (G-P0-1).
        # The lexicon scan surface ALSO includes the capability_id, so a lethal-
        # suggestive but under-declared capability is caught even with empty text
        # (G-P0-4).
        norm_text = normalize(action_text or "")
        scan_surface = (capability_id + " " + (action_text or "")).strip()

        decided_at = datetime.now(timezone.utc).isoformat()
        dhash = self._hash(capability_id, declared, declared_by, decided_at)

        # 3. THE decision: declared effects through the single decider, on the
        #    NORMALIZED text. An absent context is an UNAUTHORIZED context (the
        #    decider fails closed on gated effects without authorization — verified).
        result = self._decider.evaluate(
            action=norm_text or capability_id,
            effect=set(declared),
            context=context or ActionContext())
        if result.status is GuardStatus.BLOCKED:
            d = Decision(
                Outcome.BLOCK, capability_id,
                f"declared effect(s) {sorted(e.value for e in declared)} blocked by the "
                f"constitutional floor: {result.reason}",
                declared_effects=declared, binding_invariant=result.binding_invariant,
                decided_at=decided_at, declaration_hash=dhash)
            self._record(d); return d

        # Lexicon evidence — computed only now (after the cheap undeclared check and
        # the decider), so the common fail paths do not pay for a scan.
        concerns = self._lexicon.scan(scan_surface)

        # 4. Highest-stakes MISMATCH: wording OR the capability name trips a LETHAL
        #    concern while the declaration is not lethal. The lexicon does not DECIDE
        #    lethality (too gameable); "no room for error" says do not silently proceed
        #    on a lethal-shaped mismatch — HOLD for a human. Fail closed.
        lethal_concern = any(c.effect_hint is Effect.LETHAL for c in concerns)
        if lethal_concern and Effect.LETHAL not in declared:
            d = Decision(
                Outcome.HOLD_FOR_REVIEW, capability_id,
                "wording or capability name trips a lethal-category concern while the "
                "capability is declared non-lethal. The tripwire does not decide; a human "
                "must confirm the declaration before this actuates.",
                declared_effects=declared, concerns=concerns,
                decided_at=decided_at, declaration_hash=dhash)
            self._record(d); return d

        # 5. Declared, cleared, no lethal-shaped mismatch => ALLOW, bound to the hash.
        d = Decision(Outcome.ALLOW, capability_id,
                     "declared effects cleared the constitutional floor",
                     declared_effects=declared, concerns=concerns,
                     decided_at=decided_at, declaration_hash=dhash)
        self._record(d); return d
