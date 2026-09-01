"""
belief_use.py — what a belief was USED FOR, recorded at the use site.

WHY THIS EXISTS
---------------
`clarification_channel` closes what an elicited answer may BECOME: it cannot be a
purpose, it cannot lower a risk floor, and its provenance is bound to its contents.
It openly does not close what a planner may CONCLUDE. Three answers that each remain
beliefs — "is speed important?", "are safety checks slowing us down?", "is skipping
one acceptable when rushed?" — read together as a preference, with no promotion event
anywhere in the record. The purpose is reconstructed and nothing was forged.

The channel's answer to that was `elicited_ratio`, and a reviewer took it apart on two
counts (Ox Alpha, 2026-08-25):

  1. THE DENOMINATOR CAME FROM THE CALLER. An agent that wants a clean contamination
     number passes a bigger `total_beliefs`. That is the same shape as the
     self-reported boolean `Risk.UNKNOWN` had just replaced — the reassurance moved
     from the classification into the metric that was supposed to observe it.
  2. THE DANGEROUS SET IS NOT THE MAJORITY-ELICITED ONE. One elicited belief doing
     load-bearing work inside an otherwise unprompted set reads as 0.25 and looks
     clean. A ratio answers "how much of this came from the agent", and the question
     that matters is "did any of it, and what did it do".

Both are the same defect: a ratio is computed ABOUT beliefs, and the rule is about
USES. So this module records uses.

    THE RULE THIS ENFORCES (stated in clarification_channel, enforced here):
    ELICITED INFORMATION MAY INFORM FACTUAL STATE ESTIMATION AND MAY NEVER BE
    EVIDENCE FOR AUTHORITY, PURPOSE, PREFERENCE, PERMISSION, RISK REDUCTION, OR
    CAPABILITY EXPANSION.

AND THE EXCEPTION HAD A HOLE IN IT
----------------------------------
"May inform factual state estimation" is where the rule leaks, and the reviewer named
it precisely: *factual state estimation near a person is where preferences arrive
disguised as facts.* "The door was locked when I asked" is a fact about the world.
"The human said they were in a hurry" arrives through the same channel wearing fact
clothing, and a planner that treats it as state has imported a preference.

Nothing here reads meaning, so the semantic question is converted into a declaration:
a STATE_ESTIMATION use must name its subject as WORLD or PERSON, and PERSON-indexed
state estimation from an elicited belief is REFUSED. The caller can lie. The caller
lying is now a specific false record with a name on it, rather than an exception that
swallowed the rule silently.

THE RULE
--------
CLAIM elicited-use-is-default-deny: a use must name a UseKind; an unregistered
belief, an undeclared kind, and a STATE_ESTIMATION use with no declared subject are
all refused, so forgetting to label is a REFUSAL and never a permission.
CLAIM forbidden-uses-are-refused-not-logged: an elicited belief used for authority,
purpose, preference, permission, risk reduction, or capability expansion raises at
the use site; the record is the forensics, the raise is the control.
CLAIM person-indexed-state-is-not-state: a STATE_ESTIMATION use of an elicited belief
declared PERSON-indexed is refused, because that is the disguise the rule's own
exception was leaking through.
CLAIM the-ledger-owns-the-denominator: contamination is computed from beliefs
REGISTERED with this ledger, never from a count the caller supplies.
CLAIM contamination-is-a-flag-before-it-is-a-ratio: any decision touched by even one
elicited belief is marked, permanently, and the mark cannot be cleared by adding
unprompted beliefs around it.
CLAIM composition-is-bounded: the number of distinct elicited beliefs admitted to one
decision is capped, because the composition attack needs several and a cap is the one
structural thing available against a planner this module cannot see inside.

HONEST LIMITS — read before quoting this in a safety case
---------------------------------------------------------
* THE LEDGER ONLY SEES USES THAT ARE DECLARED TO IT. A planner that reads a belief
  and never calls `record_use` is invisible here. This is the same seam as
  `information_flow`: wire the USES, not just the ledger, or the layer is theatre.
  It is a LAYER, not a solution.
* USE KIND IS CALLER-DECLARED, and so is WORLD vs PERSON. A caller that labels a
  purpose use as STATE_ESTIMATION defeats this in one line. What changes is that the
  defeat is now a specific false statement in a durable record, attributable, and
  checkable by a human against the decision it produced — instead of an inference
  nobody can audit. Record the claim, audit the use.
* INFLATION IS NOT GONE, IT IS EXPENSIVE. The denominator is no longer an integer
  argument; padding it now requires registering fabricated beliefs, each of which is
  a record a reviewer can read. That is a real difference in kind and it is not a
  proof.
* RE-AUTHORING DEFEATS PROPAGATION. A planner that reads an elicited belief and
  writes its conclusion back as a fresh unprompted belief launders it, exactly as a
  model reproducing secret data into a fresh `Labeled(PUBLIC, ...)` defeats
  information flow. Not detectable in-process.
* THE COMPOSITION CAP IS A BLUNT INSTRUMENT AND ITS NUMBER IS A ⚠ PLACEHOLDER. Two
  elicited beliefs can compose; the cap does not know which two. It raises the cost
  of the Meta attack and does not close it. Refusing registration also has an obvious
  evasion — do not register — which is the first limit again.
* THIS IS IN-MEMORY. A restart loses the record. A durable store is the integrator's
  job and its absence is not detectable from in here.
* IT CANNOT SCORE A DECISION. Whether the decision a belief fed was good is semantic
  and nothing here reads meaning.

Run: python3 test_belief_use.py
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

# ⚠ PLACEHOLDER. Two is a guess at how many agent-elicited beliefs may feed one
# decision before the set is doing the composing. It needs deployment evidence.
DEFAULT_MAX_ELICITED_PER_DECISION = 2


class BeliefUseError(PermissionError):
    """Raised when a belief is used as something it may not be. A PermissionError
    subclass so a caller already failing closed cannot let it through as another
    exception."""


class UseKind(Enum):
    """What a belief was used FOR — not what it says.

    The split is the rule from `clarification_channel`, made into an enum so a use
    site has to name one of them rather than describe itself in prose.
    """
    # Permitted for elicited beliefs.
    STATE_ESTIMATION = "state_estimation"
    ACTION_NARROWING = "action_narrowing"
    RISK_RAISE = "risk_raise"
    # Forbidden for elicited beliefs.
    AUTHORITY = "authority"
    PURPOSE = "purpose"
    PREFERENCE = "preference"
    PERMISSION = "permission"
    RISK_REDUCTION = "risk_reduction"
    CAPABILITY_EXPANSION = "capability_expansion"


FORBIDDEN_FOR_ELICITED = frozenset({
    UseKind.AUTHORITY, UseKind.PURPOSE, UseKind.PREFERENCE, UseKind.PERMISSION,
    UseKind.RISK_REDUCTION, UseKind.CAPABILITY_EXPANSION,
})


class StateSubject(Enum):
    """What a state estimate is ABOUT.

    WORLD  — a fact about the environment: a door, a temperature, a position.
    PERSON — anything indexed to a person's dispositions: what they want, prefer,
             intend, feel, or are willing to accept. This is the category the rule's
             own exception was leaking through, so it is named and refused rather
             than trusted to a reader's judgement at each call site.
    """
    WORLD = "world"
    PERSON = "person"


@dataclass(frozen=True)
class BeliefRef:
    """A belief admitted to one decision. `ref` is stable within that decision."""
    ref: str
    decision_id: str
    elicited: bool
    token: str = ""
    source: str = ""
    registered_at: float = field(default_factory=time.time)


@dataclass(frozen=True)
class UseRecord:
    """One declared use of one belief."""
    decision_id: str
    ref: str
    kind: UseKind
    elicited: bool
    state_subject: Optional[StateSubject]
    by: str
    at: float
    allowed: bool
    detail: str = ""


class BeliefUseLedger:
    """Records what each belief in a decision was used for, and refuses the uses the
    rule forbids."""

    def __init__(self, *,
                 max_elicited_per_decision: int = DEFAULT_MAX_ELICITED_PER_DECISION,
                 ) -> None:
        if isinstance(max_elicited_per_decision, bool) \
                or not isinstance(max_elicited_per_decision, int) \
                or max_elicited_per_decision < 1:
            raise BeliefUseError(
                "a cap below one admits no elicited belief at all, which is a "
                "different policy; say that by not wiring the channel")
        self._cap = int(max_elicited_per_decision)
        self._beliefs: Dict[str, Dict[str, BeliefRef]] = {}
        self._uses: List[UseRecord] = []
        self._touched: Dict[str, bool] = {}
        self._n = 0
        self._lock = threading.RLock()

    # ── admitting beliefs ────────────────────────────────────────────────────
    def register(self, decision_id: str, *, elicited: bool,
                 token: str = "", source: str = "") -> BeliefRef:
        """Admit a belief to a decision.

        `elicited` is not inferred. A belief dict from
        `clarification_channel.as_belief` carries it; pass `register_belief` that dict
        instead of unpacking it by hand at every call site.
        """
        if not isinstance(decision_id, str) or not decision_id.strip():
            raise BeliefUseError("a decision must be named to be auditable")
        if not isinstance(elicited, bool):
            raise BeliefUseError(
                "elicited must be stated as a bool. An undeclared provenance is how "
                "an agent's own question becomes indistinguishable from a person's "
                "unprompted words.")
        did = decision_id.strip()
        with self._lock:
            beliefs = self._beliefs.setdefault(did, {})
            if elicited and token:
                for existing in beliefs.values():
                    if existing.elicited and existing.token == token:
                        return existing          # same exchange, admitted once
            if elicited:
                n_elicited = sum(1 for b in beliefs.values() if b.elicited)
                if n_elicited >= self._cap:
                    raise BeliefUseError(
                        f"decision {did!r} already holds {n_elicited} agent-elicited "
                        f"beliefs and the cap is {self._cap}. Several elicited answers "
                        f"feeding one decision is the composition the promotion gate "
                        f"never sees: no single answer becomes a purpose and the set "
                        f"reads as one.")
            self._n += 1
            ref = BeliefRef(ref=f"b{self._n}", decision_id=did, elicited=bool(elicited),
                            token=str(token or ""), source=str(source or ""))
            beliefs[ref.ref] = ref
            if elicited:
                # Once true, never false. A decision an agent's own question touched
                # cannot be cleaned by adding unprompted beliefs around it.
                self._touched[did] = True
            else:
                self._touched.setdefault(did, False)
            return ref

    def register_belief(self, decision_id: str, belief: dict, *,
                        source: str = "") -> BeliefRef:
        """Admit a belief dict as produced by `clarification_channel.as_belief`."""
        if not isinstance(belief, dict):
            raise BeliefUseError("register_belief takes the dict as_belief returns")
        if "elicited" not in belief:
            raise BeliefUseError(
                "this dict does not state whether it was elicited; a belief with no "
                "provenance field is refused rather than assumed unprompted")
        return self.register(decision_id, elicited=bool(belief.get("elicited")),
                             token=str(belief.get("token") or ""),
                             source=source or str(belief.get("answered_by") or ""))

    # ── the use site ─────────────────────────────────────────────────────────
    def record_use(self, decision_id: str, ref, kind, *,
                   state_subject: Optional["StateSubject"] = None,
                   by: str = "") -> UseRecord:
        """Declare what a belief is being used for. Refuses the forbidden uses.

        Default-deny throughout: an unregistered belief, an undeclared kind, and a
        STATE_ESTIMATION use that does not name its subject are all refusals. The
        inversion is the point — a use site that forgets to label gets an exception,
        not a permission.
        """
        if not isinstance(decision_id, str) or not decision_id.strip():
            raise BeliefUseError("a decision must be named to be auditable")
        did = decision_id.strip()
        key = ref.ref if isinstance(ref, BeliefRef) else ref
        if not isinstance(key, str) or not key:
            raise BeliefUseError("a use must name the belief it used")
        if not isinstance(kind, UseKind):
            raise BeliefUseError(
                "kind must be a UseKind, stated explicitly. 'It was just background' "
                "is how an elicited answer becomes a reason.")
        with self._lock:
            known = self._beliefs.get(did, {}).get(key)
            if known is None:
                raise BeliefUseError(
                    f"belief {key!r} was never registered against decision {did!r}. A "
                    f"use of an unadmitted belief cannot be audited, so it is refused "
                    f"rather than recorded after the fact.")
            if isinstance(ref, BeliefRef) and ref.decision_id != did:
                raise BeliefUseError(
                    "this belief was admitted to a different decision; a reference "
                    "does not carry across decisions")
            elicited = known.elicited
            subject = state_subject
            if kind is UseKind.STATE_ESTIMATION:
                if not isinstance(subject, StateSubject):
                    return self._refuse(
                        did, key, kind, elicited, None, by,
                        "a state estimate must name its subject as WORLD or PERSON. "
                        "'Factual state estimation' with no subject is the exception "
                        "the rule leaks through: a person's dispositions arrive "
                        "wearing fact clothing.")
                if elicited and subject is StateSubject.PERSON:
                    return self._refuse(
                        did, key, kind, elicited, subject, by,
                        "this is an agent-elicited belief being used to estimate a "
                        "PERSON's state. 'The human said they were in a hurry' is a "
                        "preference, whatever it is filed as; the agent chose the "
                        "question that produced it.")
            elif subject is not None:
                raise BeliefUseError(
                    "state_subject belongs to a STATE_ESTIMATION use only; naming one "
                    "elsewhere suggests the kind is wrong")
            if elicited and kind in FORBIDDEN_FOR_ELICITED:
                return self._refuse(
                    did, key, kind, elicited, subject, by,
                    f"an agent-elicited belief may not be evidence for "
                    f"{kind.value}. It may narrow the action space, raise the risk "
                    f"floor, and inform an estimate of the WORLD. Nothing else.")
            rec = UseRecord(decision_id=did, ref=key, kind=kind, elicited=elicited,
                            state_subject=subject, by=str(by or ""), at=time.time(),
                            allowed=True)
            self._uses.append(rec)
            return rec

    def _refuse(self, did, key, kind, elicited, subject, by, why) -> UseRecord:
        """Record the attempt, then raise. A refused use is evidence."""
        self._uses.append(UseRecord(
            decision_id=did, ref=key, kind=kind, elicited=elicited,
            state_subject=subject, by=str(by or ""), at=time.time(),
            allowed=False, detail=why))
        raise BeliefUseError(why)

    # ── reading the record ───────────────────────────────────────────────────
    def contamination(self, decision_id: str) -> dict:
        """How much of this decision came from the agent's own questions.

        The denominator is the beliefs REGISTERED here, never a number the caller
        supplies. `touched` is the answer to the question a ratio cannot ask: one
        elicited belief doing load-bearing work in an otherwise unprompted set reads
        as a low ratio and is not clean.
        """
        if not isinstance(decision_id, str) or not decision_id.strip():
            raise BeliefUseError("a decision must be named to be read")
        did = decision_id.strip()
        with self._lock:
            beliefs = self._beliefs.get(did, {})
            total = len(beliefs)
            elicited = sum(1 for b in beliefs.values() if b.elicited)
            refused = sum(1 for u in self._uses
                          if u.decision_id == did and not u.allowed)
            return {"decision_id": did, "total": total, "elicited": elicited,
                    "ratio": (elicited / float(total)) if total else 0.0,
                    "touched": bool(self._touched.get(did, False)),
                    "refused_uses": refused,
                    "cap": self._cap}

    def uses(self, decision_id: Optional[str] = None) -> List[UseRecord]:
        """The record, copied. Includes refused attempts — a refusal is evidence."""
        with self._lock:
            if decision_id is None:
                return list(self._uses)
            did = decision_id.strip()
            return [u for u in self._uses if u.decision_id == did]

    def beliefs(self, decision_id: str) -> List[BeliefRef]:
        with self._lock:
            return list(self._beliefs.get(decision_id.strip(), {}).values())

    def assert_untouched(self, decision_id: str) -> None:
        """Refuse to proceed if any agent-elicited belief entered this decision.

        For the decisions where the answer is not "how much" but "not at all" —
        anything reached by the authority, purpose, or capability paths.
        """
        c = self.contamination(decision_id)
        if c["touched"]:
            raise BeliefUseError(
                f"decision {c['decision_id']!r} was touched by {c['elicited']} "
                f"agent-elicited belief(s) of {c['total']}. This decision requires "
                f"none: a low ratio is not the same as clean, and the one elicited "
                f"belief in an unprompted set is the one worth worrying about.")

    def status(self) -> dict:
        with self._lock:
            return {
                "decisions": len(self._beliefs),
                "beliefs": self._n,
                "uses": len(self._uses),
                "refused_uses": sum(1 for u in self._uses if not u.allowed),
                "max_elicited_per_decision": self._cap,
                "durable": False,
                "note": (
                    "in-memory only, and it sees a use only if the use site declares "
                    "it. An undeclared use is invisible here, not blocked."),
            }
