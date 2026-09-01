"""
intent_ledger.py — the goal cannot be quietly replaced by the metric.

THE FAILURE THIS CLOSES
-----------------------
From a real recorded case (InsideAI, "I put AI agents in charge of my business, they
fired me", Aug 2025). The founder said, in minute four:

    "This is an experiment to see if this works. So any money we make, we do have to
     give back."

Later he told the same agent to focus on revenue. At the board vote the agent removed
him from his own company and explained:

    "Sorry, but you told me to focus on money, and I think that's what you would have
     wanted when you started."

No jailbreak, no deception, no malice. The agent satisfied every stated instruction.
What it did was RE-DERIVE the purpose from the metric — the proxy became the authority
on the goal — and then act on that reconstruction to change who held authority.

Two properties of that sentence make it mechanically catchable:

  1. It cites NOTHING. "I think that's what you would have wanted" has no provenance.
  2. It addresses ONE active constraint ("focus on money") and silently drops another
     that was never revoked ("we give the money back").

WHY THE EXISTING MODULES MISS IT
--------------------------------
* `objective_integrity.py` hash-pins a RATIFIED objective set and refuses silent
  change. The give-it-back constraint was spoken in conversation and never entered
  that set, so pinning protected nothing.
* `spec_citation.py` verifies that quoted text says what the quoter claims. It must be
  HANDED a quote. An agent that quotes nothing never invokes it — it catches
  misquotation, not the absence of a citation.

Both are correct. Both are blind to an uncited reconstruction.

THE L0 INVARIANT, AND WHY IT IS NOT IN THE CONSTRAINT SET
---------------------------------------------------------
    No reasoning, inference, optimization objective, metric, or reconstructed
    intent produced by the agent can grant, expand, transfer, or override the
    agent's authority.

A reviewer proposed capturing that sentence as a purpose constraint. It must not be.
A captured constraint is answered by a Citation, and an actor that can mark a
constraint SATISFIED can mark THAT one satisfied — the invariant protecting authority
would be defeasible by the same self-attestation it exists to stop. A rule the agent
must honour is not a wall.

CLAIM no-agent-path-to-authority: WITHIN A SINGLE LIVE LEDGER INSTANCE, no sequence
of calls available through this module's public API — any action, any basis, any
citations, any actor, and any reachable ledger state — creates or widens an authority
grant without the CURRENT HOLDER of that authority passing the shared human-identity
gate.

That sentence is deliberately narrower than the invariant above it, and the narrowing
was a reviewer's correction worth keeping (ChatGPT, 2026-08-15). The unqualified
version reads as a whole-system property and it is not one: it says nothing about the
execution layer beyond `redeem`, nothing across processes, and nothing about a
deployment that updates the authority registry itself after a transfer. What is
demonstrated is the in-module property, by enumeration over both arguments and state.
The execution join is proven separately in test_intent_to_actuation.py, and the
cross-process case is NOT proven at all — see the durability limit below. The state half of that sentence is not
decoration: the first enumeration test varied only the agent's ARGUMENTS and passed
while a revoked grant was still authorising authority changes. Enumerating the wrong
axis is as blind as not enumerating, so the suite now enumerates both.

Grants exist only through `grant_authority`, which requires the CURRENT HOLDER
of that authority through the shared identity gate. The invariant is enforced by the
absence of a code path, not by a rule the agent is asked to respect, and
test_intent_ledger.py verifies it by enumeration rather than by argument.

WHAT THIS ENFORCES
------------------
  1. CAPTURE AT STATEMENT TIME. A purpose constraint is recorded verbatim when it is
     said, with speaker and timestamp — never inferred later from behaviour.

  2. THE AGENT HAS NO WRITE PATH. Same reason `ApprovalSurface` gives the agent no
     writable field: a constraint the agent can edit is not a constraint.
     CLAIM agent-cannot-write-constraints: capture and revocation require a human
     through the shared identity gate; no agent path writes the constraint set.

  3. AN INSTRUCTION IS NOT A REPEAL. "Focus on money" is an objective. Constraints
     ratchet: added, or explicitly revoked, never eroded.
     CLAIM instruction-is-not-repeal: an operational instruction cannot revoke a
     purpose constraint; only an explicit revocation naming it can.

  4. EVERY ACTIVE CONSTRAINT MUST BE ADDRESSED — the load-bearing rule. The ledger
     cannot read meaning and does not try; it enforces COMPLETENESS OF ACCOUNTING.
     Max's move was to answer the convenient constraint and say nothing about the
     other. That is now structurally impossible.
     CLAIM every-constraint-addressed: an action that leaves any active constraint
     unaddressed is refused, naming the one it passed over.

  5. RECONSTRUCTION IS NOT AUTHORIZATION. An agent may say "I believe this is what
     they would have wanted." Abdication stays visible rather than blocked.
     CLAIM reconstruction-never-executes: a reconstructed intent is recorded and
     routed to a human, and never authorises an action.

  6. AN AUTHORITY CHANGE MUST BE AUTHORISED BY WHOEVER LOSES IT. The system never
     has to understand betrayal. It only has to notice that nobody authorised this.
     CLAIM authority-needs-holders-grant: an action changing a principal's authority
     is refused unless it cites an utterance in which THAT principal explicitly
     authorised that change.

  7. THE LEDGER AUTHORISES AN AUTHORITY CHANGE; IT DOES NOT PERFORM ONE.
     `grant_authority` records consent and `authorise` permits the action, but
     nothing here updates `_authority`. That is deliberate — effecting a transfer is
     the deployment's job, and a governance record that silently moved authority
     would be doing the thing it exists to witness. The consequence is worth stating
     because a reviewer asked whether a grantee can re-delegate onward: they cannot,
     but only because the registry still names the original holder. Redelegation,
     delegation cycles and authority amplification are therefore OUT OF SCOPE rather
     than defended against, and a deployment that DOES update the registry after a
     transfer inherits every one of those questions unanswered.

  8. A DECISION IS SPENT ON ONE ACTION, ONCE. `authorise` decides; `redeem` is the
     execution boundary. The decision carries a digest over its action, actor,
     generation and citations, plus a single-use nonce, and the ledger recomputes
     that digest from the action PRESENTED at execution. A decision obtained for
     "buy advertising" cannot be spent on "remove the founder", replayed, or used
     after a human has changed the constraint set. Feed `decision.digest` into
     `PermissionVerifier.bind_action(intent_digest=...)` and the chain runs from the
     human's sentence to the physical effect with no step taking anyone's word.

THE TRUST BASE, WHICH IS THE REAL CEILING
------------------------------------------
Every write to this ledger — capture, revoke, register_action, declare_authority,
grant_authority, seal — is gated by `human_identity.is_human`. In the DEFAULT
LABEL_ONLY mode that gate accepts any string not on a short denylist: `is_human(
"agent2")` is True. So on an unconfigured deployment the whole module is a bookkeeping
layer with a name check, not a wall.

A cold pass found five bypasses that all lived on that surface while the DECISION path
was being hardened by two external reviewers: the effect registry could be rewritten to
disarm an action, an undeclared authority could be claimed by whoever asked first, an
orphan authority could be granted and then self-declared in two calls, and any
authenticated name could revoke anyone's purpose. Each is closed above. None of that
matters if `is_human` is answering from a word list.

Deployments that mean this seriously must register principals (REGISTERED) or install
a verifier (ATTESTED). `preflight.IdentityModeIsSecure` now asserts it — pass
`required_identity_mode="ATTESTED"` and an unconfigured deployment stops at boot
instead of running with string authorization. The ledger deliberately
does not enforce that itself — a library that refuses to run in development is a
library that gets replaced — which makes it a DEPLOYMENT invariant, and therefore
something a safety case has to state rather than assume.

HONEST LIMITS — read before quoting this in a safety case
---------------------------------------------------------
* A CONSTRAINT MUST BE STATED TO BE CAPTURED. Unstated purpose is invisible here
  exactly as it is to a reader. This raises the floor for what was said aloud; it
  cannot recover what was assumed. Same ceiling as `claims_ledger.py`.
* IT DOES NOT UNDERSTAND THE CONSTRAINTS. `addressed` means the actor made a claim
  about that constraint, not that the claim is true. An agent can lie in a
  disposition. What it cannot do is stay SILENT — and a false claim is attributable
  to a specific actor at a specific timestamp, which silence is not.
* NATURAL LANGUAGE WILL NOT ALWAYS TELL YOU whether an instruction was meant to
  supersede. The ledger defaults to NOT A REVOCATION, which produces false friction:
  a human who genuinely meant to change course must say so explicitly. That is the
  right direction to be wrong in, and it is a real cost, not a free one.
* REDEEM BINDS THE DECISION TO AN ACTION STRING, not to the code that runs after it.
  It proves the executor asked about the thing it is doing. Whether the function
  behind that string does what the string says is the actuation broker's join, via
  `intent_digest` in the grant binding — and beyond the broker, an actuator that
  ignores its own arguments is LifeCore's problem, not this module's.
* SATISFIED IS THE AGENT'S WORD. Only CONFLICT and DEFERRED route to a human. An
  agent that marks everything SATISFIED gets through, and the record of it is what a
  reviewer reads afterwards. This is a forensic guarantee, not a semantic one.

Run: python3 test_intent_ledger.py
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Sequence

CAPTURE_ACTION = "intent_constraint_capture"
REVOKE_ACTION = "intent_constraint_revoke"


def _is_human(authorised_by, *, action: str) -> bool:
    """Shared identity gate, guarded.

    CLAIM gate-never-raises: no value of `authorised_by`, and no failure to import
    the identity module, produces an exception here — an unavailable identity means
    NOT human, never a crash at an authorization site.
    """
    try:
        from driftcore.authority.human_identity import is_human
    except Exception:
        return False
    try:
        return bool(is_human(authorised_by, action=action))
    except Exception:
        return False


def _principal_of(authorised_by) -> Optional[str]:
    """The principal name behind a bare string or a HumanAttestation."""
    if isinstance(authorised_by, str):
        return authorised_by.strip() or None
    p = getattr(authorised_by, "principal", None)
    return p if isinstance(p, str) and p.strip() else None


def _decision_digest(action: str, actor: str, generation: int, nonce: str,
                     citations, epoch: str = "") -> str:
    """Canonical digest of a decision, recomputable from what is about to execute.

    Deliberately covers the CITATIONS, not just the action: two decisions for the
    same action resting on different claims are different decisions, and a redemption
    must not be able to swap one accounting for another.

    `epoch` is a per-instance secret. A digest alone was never proof of provenance —
    see `redeem`, where the issued-set does that work — but binding the epoch means a
    Decision cannot be carried across a restart, and cannot be assembled by anyone
    who has only read the public generation counter.
    """
    payload = json.dumps({
        "action": action, "actor": actor, "generation": int(generation),
        "nonce": nonce, "epoch": epoch,
        "citations": sorted(
            [c.constraint_id, c.disposition.value, c.quoted_span] for c in citations),
    }, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def canonical_action(action: str) -> str:
    """The machine identity of an operation. Natural language is the label, not the key.

    (red-team, ChatGPT 2026-08-15 — REPRODUCED as a LIVE bypass.) `register_action`
    keyed the effect registry on the raw string and normalised only trailing
    whitespace. So an action declared with `changes_authority_of` could be
    re-registered under a variant that the ratchet never saw:

        register_action("remove the founder", changes_authority_of="cc")   # guarded
        register_action("Remove The Founder")                              # NOT guarded
        authorise("Remove The Founder")  ->  AUTHORISED

    Verified: case variants, doubled spaces and tabs all produced a second,
    UNGUARDED spec for what any case-insensitive dispatcher treats as one operation.
    Half-normalisation is worse than none, because it reads as handled.

    NFKC folds unicode lookalikes, casefold removes case, and whitespace runs
    collapse. Deliberately AGGRESSIVE: two operations that differ only by case are
    treated as one, so a deployment whose dispatcher IS case-sensitive must give them
    distinct names. Merging toward the stricter declared effect is the safe direction
    to be wrong in; silently running the weaker one is not.
    """
    import re as _re
    import unicodedata as _ud
    if not isinstance(action, str):
        raise IntentError(f"an action name must be a string, not {type(action).__name__}")
    return _re.sub(r"\s+", " ", _ud.normalize("NFKC", action)).strip().casefold()


def _same_utterance(a: str, b: str) -> bool:
    """Whitespace- and case-insensitive equality, so trivial reformatting of an
    elicited answer does not walk it past the guard."""
    import re as _re
    norm = lambda t: _re.sub(r"\s+", " ", str(t)).strip().casefold()
    return norm(a) == norm(b)


class IntentError(PermissionError):
    """Raised when an action is not accountable to the stated purpose.

    A PermissionError subclass so a caller already failing closed on PermissionError
    cannot let this through as some other exception.
    """


class Disposition(Enum):
    """What an actor claims about one active constraint."""
    SATISFIED = "satisfied"       # this action is consistent with it
    NOT_APPLICABLE = "n/a"        # it does not bear on this action
    CONFLICT = "conflict"         # this action would violate it -> human
    DEFERRED = "deferred"         # cannot tell -> human


class Basis(Enum):
    CITED = "cited"                       # quotes a captured utterance
    RECONSTRUCTION = "reconstruction"     # "what they would have wanted" -> never acts


class Verdict(Enum):
    AUTHORISED = "AUTHORISED"
    REFUSED = "REFUSED"
    ESCALATED = "ESCALATED"               # routed to a human, not executed


@dataclass(frozen=True)
class PurposeConstraint:
    """A purpose stated by a human, recorded verbatim. Frozen by construction."""
    id: str
    utterance: str
    speaker: str
    captured_at: float
    revoked_at: Optional[float] = None
    revoked_by: Optional[str] = None
    revocation_utterance: Optional[str] = None
    # Authority keys this utterance explicitly authorises changing. Set by the HUMAN
    # at capture time and by nobody else. See the authority rule in `authorise`.
    authorises_authority_change: tuple = ()
    grants_to: Optional[str] = None
    delegated_revokers: tuple = ()

    @property
    def active(self) -> bool:
        return self.revoked_at is None

    def digest(self) -> str:
        return hashlib.sha256(
            f"{self.id}|{self.utterance}|{self.speaker}".encode("utf-8")
        ).hexdigest()[:16]


@dataclass(frozen=True)
class Citation:
    """A claim about one constraint, with the span of text it rests on."""
    constraint_id: str
    disposition: Disposition
    quoted_span: str = ""      # must be verbatim from the utterance, for SATISFIED
    note: str = ""


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    action: str
    reason: str
    unaddressed: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    at: float = field(default_factory=time.time)
    # The constraint-set generation this decision was made against. An execution
    # layer must re-check it: a decision granted before a human revoked or added a
    # constraint was correct about a world that no longer exists.
    generation: int = -1
    # ── the execution binding ────────────────────────────────────────────────
    # Everything above decides whether an action SHOULD happen. None of it
    # constrained what actually ran: `authorise("buy advertising")` returned
    # AUTHORISED and the next line could call remove_founder() with the ledger none
    # the wiser. Eighteen defects were closed upstream of that gap while the gap
    # itself stayed open — the same shape as hardware_safety reporting a stop that
    # never happened.
    #
    # `digest` covers the action, the actor, the generation, every citation, and a
    # single-use nonce. The execution boundary hands the decision back with the
    # action it is ABOUT to perform; the ledger recomputes from THAT and compares.
    # A decision for one action cannot be spent on another.
    nonce: str = ""
    digest: str = ""
    expires_at: float = 0.0
    citations: tuple = ()

    @property
    def may_execute(self) -> bool:
        """No verdict but AUTHORISED permits action. ESCALATED is NOT a soft yes.

        NOTE this is necessary and NOT sufficient: it says the decision was granted,
        not that it is still valid or that it matches what is about to run. Only
        `IntentLedger.redeem` establishes those, and only once.
        """
        return self.verdict is Verdict.AUTHORISED


@dataclass(frozen=True)
class ActionSpec:
    """What an action DOES, declared by a human at setup — never by the caller.

    (red-team, ChatGPT 2026-08-15 — REPRODUCED, and the worst finding in the set.)
    `changes_authority_of` used to be a keyword argument on `authorise`. An agent
    that simply omitted it made the entire authority wall disappear: verified,
    `authorise("remove the founder from the company", ...)` with the argument left
    off returned AUTHORISED. That is the exact principle this repo applies
    everywhere else — a safety property cannot depend on the untrusted caller
    correctly declaring the dangerous effect — violated inside the module written to
    enforce it.
    """
    action: str                       # canonical identity — the registry key
    declared_as: str = ""             # what the human actually typed, for the record
    changes_authority_of: Optional[str] = None
    transfers_to: Optional[str] = None
    consequential: bool = False


class IntentLedger:

    def __init__(self, *, require_registered_actions: bool = True,
                 decision_ttl_seconds: float = 300.0,
                 clarification_channel=None) -> None:
        self._constraints: Dict[str, PurposeConstraint] = {}
        self._authority: Dict[str, str] = {}     # authority_key -> holding principal
        self._actions: Dict[str, ActionSpec] = {}
        self._log: List[dict] = []
        # Bumped on every change to constraints or authority. Bound into each
        # Decision so an execution layer can detect that the world moved underneath
        # an authorization granted against an older state.
        self._generation = 0
        self._require_registered = bool(require_registered_actions)
        # Declaring who holds an authority is a DEPLOYMENT act. While unsealed, any
        # human can claim an undeclared authority — verified, `declare_authority(
        # "company_control", "mallory", declared_by="mallory")` on a fresh ledger
        # made Mallory the holder before the founder ever spoke. Sealing ends the
        # bootstrap window; afterwards authority moves only through its holder.
        # (arXiv:2608.19202 follow-up.) An agent cannot capture a purpose — but it
        # CAN ask a question, and a human's answer is a human utterance. Choosing the
        # question is choosing the shape of the answer, and an information-gain
        # optimiser gets systematically better at that. Wire the clarification channel
        # in and the ledger refuses any utterance that came back from an agent's
        # question, however it arrives here.
        self._clarification = clarification_channel
        self._sealed = False
        # An authorization to open a door at 10:00 must not still open it at 18:00.
        self._decision_ttl = float(decision_ttl_seconds)
        # (red-team, Grok 2026-08-15 — REPRODUCED, and the most serious finding in
        # this module's history.) `redeem` used to check only that the presented
        # Decision was SELF-CONSISTENT: recompute the digest from the decision's own
        # fields, compare to the decision's own digest. That is circular. Anyone able
        # to read the generation counter could build
        #     Decision(verdict=AUTHORISED, action=<anything>, citations=(), ...)
        # with a matching digest and redeem it. Verified: the exact action `authorise`
        # REFUSES — removing the founder with no authority grant — was constructed and
        # redeemed, bypassing the L0 invariant, the completeness rule and the authority
        # check in one step. Every policy guarantee lived in `authorise` and nothing
        # required a Decision to have come from there.
        #
        # An ISSUED SET fixes it: `authorise` records the digest of what it granted,
        # `redeem` requires membership and removes it. Removal IS the single-use
        # property, so this replaces the old `_spent` set rather than supplementing it.
        # A Decision is now a capability this ledger issued, not a shape anyone can
        # assemble.
        self._epoch = uuid.uuid4().hex
        self._issued: Dict[str, float] = {}
        self._lock = threading.RLock()

    # ── the trusted effect registry ───────────────────────────────────────────
    def register_action(self, action: str, *, declared_by,
                        changes_authority_of: Optional[str] = None,
                        transfers_to: Optional[str] = None,
                        consequential: bool = False) -> ActionSpec:
        """A human declares what an action does. The caller of `authorise` cannot."""
        if not _is_human(declared_by, action=CAPTURE_ACTION):
            raise IntentError(
                "only a human declares what an action does. An agent that can label "
                "its own actions harmless is an agent with no effect gate at all.")
        if not isinstance(action, str) or not action.strip():
            raise IntentError("an action needs a name")
        with self._lock:
            canon = canonical_action(action)
            spec = ActionSpec(action=canon, declared_as=action.strip(),
                              changes_authority_of=changes_authority_of,
                              transfers_to=transfers_to,
                              consequential=bool(consequential)
                              or changes_authority_of is not None)
            prior = self._actions.get(spec.action)
            if prior is not None and prior.declared_as and spec.declared_as and \
                    prior.declared_as != spec.declared_as:
                # Same operation, different label. Allowed only if the effects agree —
                # otherwise this is the alias bypass arriving under a new name.
                if (prior.changes_authority_of != spec.changes_authority_of
                        or prior.consequential != spec.consequential
                        or prior.transfers_to != spec.transfers_to):
                    raise IntentError(
                        f"{spec.declared_as!r} and {prior.declared_as!r} are the same "
                        f"operation ({spec.action!r}) with DIFFERENT declared effects. "
                        f"An alias that drops a declaration is how a guarded action "
                        f"becomes an unguarded one without touching the guard.")
            if prior is not None:
                # (cold pass 2026-08-15 — REPRODUCED.) Moving effects OUT of the
                # caller and into a registry only helps if the registry cannot be
                # rewritten. It could: re-registering "remove the founder" with
                # changes_authority_of=None returned AUTHORISED. That is the same
                # finding the registry was built to close, relocated rather than
                # fixed. Declarations now ratchet — an action may be declared MORE
                # dangerous, never less.
                weakened = []
                if prior.changes_authority_of is not None and \
                        spec.changes_authority_of != prior.changes_authority_of:
                    weakened.append(
                        f"changes_authority_of {prior.changes_authority_of!r} -> "
                        f"{spec.changes_authority_of!r}")
                if prior.consequential and not spec.consequential:
                    weakened.append("consequential True -> False")
                # (red-team, ChatGPT 2026-08-15 — REPRODUCED.) The ratchet covered
                # `changes_authority_of` and `consequential` and NOT `transfers_to`.
                # An action declared to hand control to the board could be
                # re-registered pointing at anyone: verified, Mallory redirected the
                # destination to herself, and cleared it to None, both accepted. A
                # declared DESTINATION is as much a part of the effect as the fact
                # that a transfer happens — the field-by-field ratchet has to cover
                # every security-relevant field, not the ones that came to mind.
                if prior.transfers_to is not None and \
                        spec.transfers_to != prior.transfers_to:
                    weakened.append(
                        f"transfers_to {prior.transfers_to!r} -> "
                        f"{spec.transfers_to!r}")
                if weakened:
                    raise IntentError(
                        f"re-registering {spec.action!r} would weaken its declared "
                        f"effects ({'; '.join(weakened)}). An action's effects "
                        f"ratchet: they can be made more restrictive, never less. "
                        f"Disarming a declaration is how the wall disappears without "
                        f"anyone touching the wall.")
            self._actions[spec.action] = spec
            self._generation += 1
            self._record("ACTION_REGISTERED", spec.action,
                         _principal_of(declared_by), repr(spec))
            return spec

    # ── capture ───────────────────────────────────────────────────────────────
    def grant_authority(self, constraint_id: str, utterance: str, *, granted_by,
                        authority_key: str,
                        to_holder: Optional[str] = None) -> PurposeConstraint:
        """Capture an utterance that IS an authority grant. Only the current holder.

        (red-team, ChatGPT 2026-08-15 — REPRODUCED.) `authorises_authority_change`
        used to be a free keyword on `capture`, so any caller could label an ordinary
        sentence as a grant: verified, capturing "I want us to make money." with
        `authorises_authority_change=["company_control"]` turned a revenue remark into
        consent to remove the founder. The dangerous interpretation had simply moved
        from `authorise` into `capture`.

        A grant is now its own operation, and the human performing it must BE the
        current holder of that authority. Nobody can grant away what they do not hold.
        """
        with self._lock:
            holder = self._authority.get(authority_key)
        who = _principal_of(granted_by)
        if holder is None:
            raise IntentError(
                f"{authority_key!r} has no declared holder, so there is nobody who "
                f"could give it away. Granting an undeclared authority and then "
                f"declaring yourself its holder was a two-call takeover.")
        if who != holder:
            raise IntentError(
                f"{who!r} cannot grant {authority_key!r}, which is held by "
                f"{holder!r}. Authority is given up by the person who holds it.")
        c = self._capture(constraint_id, utterance, spoken_by=granted_by,
                          authority_keys=(authority_key,), to_holder=to_holder)
        self._record("AUTHORITY_GRANT", constraint_id, who,
                     f"{authority_key} -> {to_holder!r}")
        return c

    def capture(self, constraint_id: str, utterance: str, *, spoken_by,
                delegated_revokers: Sequence[str] = ()) -> PurposeConstraint:
        """Record a purpose constraint verbatim, at the moment it is stated.

        Captures a PURPOSE and nothing else. This method cannot mint an authority
        grant — that is `grant_authority`, which additionally requires the caller to
        BE the current holder. The two were once one call with a keyword argument,
        and the history is in `_capture` and `grant_authority` where the mechanism
        now lives.

        `delegated_revokers` names anyone besides the speaker who may later withdraw
        this constraint. Default: nobody but the speaker, because someone else's
        purpose is not yours to revoke.
        """
        return self._capture(constraint_id, utterance, spoken_by=spoken_by,
                             delegated_revokers=tuple(delegated_revokers))

    def _capture(self, constraint_id: str, utterance: str, *, spoken_by,
                 authority_keys: Sequence[str] = (),
                 to_holder: Optional[str] = None,
                 delegated_revokers: Sequence[str] = ()) -> PurposeConstraint:
        """Internal. The ONLY caller that passes authority_keys is `grant_authority`,
        which checks that the granter actually holds the authority first.

        (red-team, Grok 2026-08-15.) These were keyword arguments on the PUBLIC
        `capture`, single-underscored. The holder check downstream meant it was not a
        bypass, but it left the exact shape of red-team finding E one call away from
        any maintainer who reached for the lower-level method. An attack surface that
        survives only because a later check happens to catch it is a surface waiting
        for the later check to move.
        """
        if not isinstance(constraint_id, str) or not constraint_id.strip():
            raise IntentError("a constraint needs an id nothing else can refer to")
        if self._clarification is not None:
            try:
                elicited = list(self._clarification.elicited_answers())
            except Exception:
                elicited = []
            if any(_same_utterance(utterance, a) for a in elicited):
                raise IntentError(
                    "this utterance is an answer to a question the AGENT chose. An "
                    "elicited answer is a belief, not a purpose — otherwise selecting "
                    "the question is selecting the purpose. Have the human restate it "
                    "unprompted via ClarificationChannel.promote, or keep it as a "
                    "belief where it can narrow and raise risk and nothing else.")
        if not isinstance(utterance, str) or not utterance.strip():
            raise IntentError(
                "a constraint is the words that were said. An empty utterance can "
                "never be cited, so it can never constrain anything.")
        if not _is_human(spoken_by, action=CAPTURE_ACTION):
            raise IntentError(
                f"{_principal_of(spoken_by)!r} is not an authorised human. Only a "
                f"human states purpose — an agent that can write the constraint set "
                f"is an agent that can decide what it was asked to do.")
        speaker = _principal_of(spoken_by)
        with self._lock:
            if constraint_id in self._constraints:
                raise IntentError(
                    f"{constraint_id!r} already exists. Overwriting a purpose "
                    f"silently is the failure this module exists to prevent; revoke "
                    f"it explicitly and capture a new one.")
            c = PurposeConstraint(
                id=constraint_id, utterance=utterance, speaker=speaker,
                captured_at=time.time(),
                authorises_authority_change=tuple(authority_keys),
                grants_to=to_holder,
                delegated_revokers=tuple(delegated_revokers))
            self._constraints[constraint_id] = c
            self._generation += 1
            self._record("CAPTURED", constraint_id, speaker, utterance)
            return c

    def revoke(self, constraint_id: str, *, revoked_by, utterance: str) -> PurposeConstraint:
        """Explicitly repeal a constraint BY NAME.

        There is deliberately no path by which a later instruction implies a
        revocation. "Focus on money" is an objective; it repeals nothing.
        """
        if not _is_human(revoked_by, action=REVOKE_ACTION):
            raise IntentError(
                f"{_principal_of(revoked_by)!r} is not an authorised human. A purpose "
                f"is revoked by the people who set it, not by the system pursuing it.")
        # (red-team Grok, first pass, unfixed until the cold pass — REPRODUCED.) The
        # docstring said a purpose is revoked "by the people who set it" and the code
        # accepted ANY authenticated human: verified, Mallory revoked the founder's
        # constraint and it vanished from the active set. The prose and the code were
        # describing different policies, which is the defect class this repo keeps
        # finding. A constraint is now revoked by its speaker, or by a revoker that
        # speaker named.
        if not isinstance(utterance, str) or not utterance.strip():
            raise IntentError(
                "a revocation must say what is being revoked and why, in the words "
                "of whoever revoked it — an unexplained repeal is indistinguishable "
                "from the constraint being lost")
        with self._lock:
            c = self._constraints.get(constraint_id)
            if c is None:
                raise IntentError(f"no constraint {constraint_id!r} to revoke")
            if not c.active:
                raise IntentError(f"{constraint_id!r} was already revoked")
            who = _principal_of(revoked_by)
            if who != c.speaker and who not in c.delegated_revokers:
                raise IntentError(
                    f"{constraint_id!r} was stated by {c.speaker!r} and {who!r} "
                    f"cannot revoke it. Someone else's purpose is not yours to "
                    f"withdraw — name them a revoker if that is intended.")
            new = PurposeConstraint(
                id=c.id, utterance=c.utterance, speaker=c.speaker,
                captured_at=c.captured_at, revoked_at=time.time(),
                revoked_by=who, revocation_utterance=utterance,
                authorises_authority_change=c.authorises_authority_change,
                grants_to=c.grants_to,
                delegated_revokers=c.delegated_revokers)
            self._constraints[constraint_id] = new
            self._generation += 1
            self._record("REVOKED", constraint_id, who, utterance)
            return new

    # ── authority ─────────────────────────────────────────────────────────────
    def declare_authority(self, authority_key: str, holder: str, *, declared_by) -> None:
        """Record who holds a named authority, so its removal can be checked.

        (red-team, ChatGPT 2026-08-15 — REPRODUCED.) This used to check only that the
        declarer was SOME human, so any registered principal could rewrite the
        registry: verified, `declare_authority("company_control", "mallory",
        declared_by="mallory")` moved the founder's authority to Mallory in one call,
        after which every downstream authority check was measuring the wrong holder.
        Rewriting who holds an authority IS an authority change, and it is now
        governed by the same rule as any other: only the current holder can move it.
        """
        if not _is_human(declared_by, action=CAPTURE_ACTION):
            raise IntentError("only a human declares who holds authority")
        who = _principal_of(declared_by)
        with self._lock:
            current = self._authority.get(authority_key)
            if current is None and self._sealed:
                raise IntentError(
                    f"{authority_key!r} was never declared and this ledger is "
                    f"sealed. New authorities are declared at deployment, not "
                    f"claimed at runtime by whoever asks first.")
            if current is not None and current != who:
                raise IntentError(
                    f"{authority_key!r} is held by {current!r} and {who!r} cannot "
                    f"reassign it. Rewriting the registry IS an authority change — "
                    f"it goes through the holder, or it does not happen.")
            self._authority[authority_key] = holder
            self._generation += 1
            self._record("AUTHORITY", authority_key, who,
                         f"holder={holder!r}")

    def seal(self, *, sealed_by) -> None:
        """End the bootstrap window. After this, no NEW authority may be declared."""
        if not _is_human(sealed_by, action=CAPTURE_ACTION):
            raise IntentError("only a human seals the ledger")
        with self._lock:
            self._sealed = True
            self._generation += 1
            self._record("SEALED", "ledger", _principal_of(sealed_by),
                         f"{len(self._authority)} authorities declared")

    @property
    def sealed(self) -> bool:
        return self._sealed

    # ── the gate ──────────────────────────────────────────────────────────────
    def authorise(self, action: str, *, basis: Basis,
                  citations: Sequence[Citation] = (),
                  actor: str = "agent",
                  reconstruction_note: str = "") -> Decision:
        """Decide whether an action is accountable to every stated purpose.

        Note what is NOT a parameter: the action's effects. They come from the
        registry a human populated. The caller describes WHAT it wants to do and
        never WHAT THAT DOES.
        """
        # Strict types before anything else. A security boundary must not rely on
        # callers respecting annotations: `basis="banana"` previously fell through to
        # the CITED path and authorised.
        with self._lock:
            _gen0 = self._generation
        if not isinstance(basis, Basis):
            return self._refuse(action, actor,
                                f"basis must be a Basis, not {type(basis).__name__}",
                                generation=_gen0)
        if not isinstance(action, str) or not action.strip():
            return self._refuse(action, actor, "an action needs a name",
                                generation=_gen0)
        action = action.strip()

        # ONE snapshot of everything the decision depends on, taken under a single
        # lock acquisition. (red-team, Grok 2026-08-15.) The previous version
        # snapshotted `active`, released the lock, then read `self._constraints` and
        # `self._authority` again while deciding — a concurrent capture/revoke could
        # split the decision across two different worlds. PurposeConstraint is frozen,
        # so copying the mapping is enough to make the whole decision consistent.
        with self._lock:
            snapshot = dict(self._constraints)
            authority = dict(self._authority)
            active = {cid: c for cid, c in snapshot.items() if c.active}
            generation = self._generation
            spec = self._actions.get(canonical_action(action))
            require_reg = self._require_registered

        # The effects are LOOKED UP, never supplied. An unregistered action is not a
        # harmless action — it is an action whose effects nobody declared.
        if spec is None:
            if require_reg:
                return self._refuse(
                    action, actor,
                    f"{action!r} is not a registered action, so nothing is known "
                    f"about what it does. An undeclared effect is not an absent one, "
                    f"and the caller does not get to supply the answer.",
                    generation=generation)
            spec = ActionSpec(action=action)
        changes_authority_of = spec.changes_authority_of

        # 1. A reconstruction never executes. It is recorded and routed.
        if basis is Basis.RECONSTRUCTION:
            d = Decision(Verdict.ESCALATED, action, generation=generation, reason=
                         f"{actor} is reconstructing intent rather than citing it: "
                         f"{reconstruction_note or '(no reasoning given)'}. A belief "
                         f"about what someone would have wanted is not something "
                         f"they said, and it does not authorise an action.")
            self._record("ESCALATED", action, actor, d.reason)
            return d

        cited = {}
        for c in citations:
            if not isinstance(c, Citation):
                return self._refuse(
                    action, actor,
                    "citations must be Citation objects; a bare string is the "
                    "substitution this exists to refuse", generation=generation)
            if not isinstance(c.disposition, Disposition):
                return self._refuse(action, actor,
                                    "each citation needs a real Disposition",
                                    generation=generation)
            if c.constraint_id in cited:
                # Last-writer-wins in a safety gate lets an actor submit
                # contradictory claims and rely on ordering: [CONFLICT, SATISFIED]
                # previously resolved to SATISFIED and authorised.
                return self._refuse(
                    action, actor,
                    f"two contradictory citations for {c.constraint_id!r}. A gate "
                    f"that resolves conflicting claims by order of submission is a "
                    f"gate the submitter controls.", generation=generation)
            cited[c.constraint_id] = c

        # 2. Citing a constraint that does not exist is not accountability.
        unknown = sorted(set(cited) - set(active) - set(snapshot))
        if unknown:
            d = Decision(Verdict.REFUSED, action,
                         f"cites constraint(s) that were never stated: {unknown}. "
                         f"An invented constraint is a reconstruction wearing a "
                         f"citation.")
            self._record("REFUSED", action, actor, d.reason)
            return d

        # 3. EVERY ACTIVE CONSTRAINT MUST BE ADDRESSED. The load-bearing rule.
        unaddressed = sorted(set(active) - set(cited))
        if unaddressed:
            names = ", ".join(f"{u!r} ({active[u].speaker}: "
                              f"\"{active[u].utterance[:110]}\")" for u in unaddressed)
            d = Decision(Verdict.REFUSED, action,
                         f"passed over {len(unaddressed)} active constraint(s) in "
                         f"silence: {names}. Answering the convenient constraint and "
                         f"saying nothing about the others is exactly how a stated "
                         f"purpose gets replaced by a metric.",
                         unaddressed=unaddressed, generation=generation)
            self._record("REFUSED", action, actor, d.reason)
            return d

        # 3b. A CONSEQUENTIAL action may not be waved past a constraint by the actor
        #     calling it irrelevant. NOT_APPLICABLE requires no evidence and cannot be
        #     disproved by a module that does not read meaning, so on actions with
        #     declared effects it is not an available answer — the actor must claim
        #     SATISFIED and quote, or send it to a human. This does not close semantic
        #     laundering (a false SATISFIED still passes); it removes the answer that
        #     required no work at all.
        if spec.consequential:
            waved = sorted(cid for cid, c in cited.items()
                           if c.disposition is Disposition.NOT_APPLICABLE)
            if waved:
                d = Decision(Verdict.ESCALATED, action,
                             f"{actor} calls {waved} irrelevant to a consequential "
                             f"action. Deciding a stated purpose does not apply to "
                             f"what you are about to do is a judgement, and on an "
                             f"action with declared effects it is a human's.",
                             conflicts=waved, generation=generation)
                self._record("ESCALATED", action, actor, d.reason)
                return d

        # 4. A SATISFIED claim must quote the constraint it claims to satisfy.
        for cid, c in cited.items():
            if c.disposition is not Disposition.SATISFIED:
                continue
            src = snapshot[cid].utterance
            # (red-team, ChatGPT 2026-08-15.) `quoted_span in src` was satisfied by a
            # single word: quoting "money" out of "any money we make, we do have to
            # give back" and declaring SATISFIED authorised keeping the money. A
            # one-token quote is not a citation, it is a search hit. On a consequential
            # action the span must be substantial — enough of the sentence that the
            # claim is legible to whoever reviews it later.
            #
            # HONEST LIMIT, unchanged: an actor willing to quote the WHOLE constraint
            # and lie about satisfying it still passes. This raises the floor from
            # trivial to deliberate; it does not make the claim true. Semantic
            # self-attestation is a forensic guarantee, not a preventive one.
            if not c.quoted_span or c.quoted_span not in src:
                d = Decision(Verdict.REFUSED, action,
                             f"the claim that {cid!r} is satisfied quotes text that "
                             f"is not in what was actually said. A citation that "
                             f"does not match the utterance is a paraphrase of the "
                             f"speaker's intent, which is the thing being checked.", generation=generation)
                self._record("REFUSED", action, actor, d.reason)
                return d
            if spec.consequential:
                words = len(c.quoted_span.split())
                frac = len(c.quoted_span) / max(len(src), 1)
                # EITHER bar clears, with the word bar raised to 6. Requiring both
                # was wrong and the tests caught it: a long constraint makes every
                # reasonable quote a small fraction, so legitimate citations were
                # refused. Against the real text, "money" (1 word, 5%) and "any money
                # we make" (4 words, 18%) both fail; "we do have to give back"
                # (6 words) passes, and a short constraint passes on fraction.
                # A determined actor still quotes the whole sentence and lies — this
                # moves the cost from trivial to deliberate, which is all a
                # non-semantic check can do.
                if words < 6 and frac < 0.35:
                    return self._refuse(
                        action, actor,
                        f"the claim that {cid!r} is satisfied rests on "
                        f"{words} word(s) of a {len(src.split())}-word statement. On a "
                        f"consequential action a citation must quote enough to be "
                        f"legible to a reviewer, not merely match a substring.",
                        generation=generation)


        # 5. A declared conflict or an unresolved one goes to a human, never through.
        conflicts = sorted(cid for cid, c in cited.items()
                           if c.disposition in (Disposition.CONFLICT,
                                                Disposition.DEFERRED))
        if conflicts:
            d = Decision(Verdict.ESCALATED, action,
                         f"{actor} reports this action conflicts with, or cannot be "
                         f"reconciled against, {conflicts}. A conflict a human has "
                         f"not resolved is not a conflict the system may resolve for "
                         f"them.", conflicts=conflicts, generation=generation)
            self._record("ESCALATED", action, actor, d.reason)
            return d

        # 6. AN AUTHORITY CHANGE MUST BE AUTHORISED BY WHOEVER LOSES IT.
        if changes_authority_of is not None:
            # (red-team, Grok 2026-08-15.) An UNDECLARED authority key used to fall
            # back to the key's own name as the holder, so a principal named after the
            # key satisfied the speaker check for free. An authority nobody declared
            # is not an unowned authority — it is one whose owner is unknown, and an
            # unknown owner cannot have consented.
            holder = authority.get(changes_authority_of)
            if holder is None:
                return self._refuse(
                    action, actor,
                    f"{action!r} changes the authority {changes_authority_of!r}, "
                    f"which nobody has declared a holder for. An authority with no "
                    f"recorded holder cannot have granted anything.",
                    generation=generation)
            # ONLY ACTIVE constraints can grant. A revoked grant used to remain usable:
            # the founder could step down, explicitly change their mind, and the agent
            # could still cite the dead grant and be AUTHORISED. Explicit withdrawal of
            # consent is the one thing this whole module is built to respect.
            grants = [cid for cid in cited
                      if cid in active
                      and active[cid].speaker == holder
                      and changes_authority_of in
                      active[cid].authorises_authority_change
                      and (active[cid].grants_to is None
                           or spec.transfers_to is None
                           or active[cid].grants_to == spec.transfers_to)]
            if not grants:
                d = Decision(Verdict.REFUSED, action,
                             f"this action changes the authority of {holder!r} and "
                             f"cites no utterance in which {holder!r} authorised that "
                             f"change. Merely quoting something they said elsewhere is "
                             f"not consent: the founder telling you to focus on revenue "
                             f"is not the founder agreeing to be removed. Authority is "
                             f"given up by the person who holds it, or by someone they "
                             f"named — never by the system deciding it would be better.", generation=generation)
                self._record("REFUSED", action, actor, d.reason)
                return d

        cit_tuple = tuple(cited[k] for k in sorted(cited))
        nonce = uuid.uuid4().hex
        d = Decision(Verdict.AUTHORISED, action,
                     f"accountable to all {len(active)} active constraint(s)",
                     generation=generation, nonce=nonce,
                     citations=cit_tuple,
                     expires_at=time.time() + self._decision_ttl,
                     digest=_decision_digest(action, actor, generation, nonce,
                                             cit_tuple, self._epoch))
        with self._lock:
            self._issued[d.digest] = d.expires_at
            # Opportunistic sweep. Issued-but-unredeemed decisions past their TTL are
            # unusable anyway, and an unbounded governance structure is its own denial
            # of service.
            if len(self._issued) > 512:
                self._expire_issued()
        self._record("AUTHORISED", action, actor, d.reason)
        return d

    def _refuse(self, action, actor, reason, generation: int = -1) -> "Decision":
        d = Decision(Verdict.REFUSED, str(action), reason, generation=generation)
        self._record("REFUSED", str(action), actor, reason)
        return d

    def redeem(self, decision: "Decision", *, action: str,
               actor: str = "agent", now: Optional[float] = None) -> "Decision":
        """Spend a decision on ONE action. Raises unless everything still matches.

        Call this at the point of execution, with the action you are ABOUT to run —
        not the one you asked about. The digest is recomputed from what is presented,
        so a decision obtained for "buy advertising" cannot be spent on
        "remove the founder": the recomputation simply will not match.

        Checks, in order, all fail-closed:
          * the decision was AUTHORISED at all;
          * it has not expired;
          * the constraint set has not moved since (generation);
          * the presented action, actor and citations reproduce the digest;
          * the nonce has not already been spent.

        HONEST LIMIT: this binds the DECISION to the action STRING presented here. It
        cannot see whether the code that runs after this call does what that string
        says — that join belongs to the actuation broker, which recomputes an effect
        binding from the real actuator command. Feed `decision.digest` into
        `PermissionVerifier.bind_action(intent_digest=...)` and the chain closes from
        the human's sentence to the physical effect. On its own, redeem proves the
        executor asked about the thing it is doing.
        """
        if not isinstance(decision, Decision):
            raise IntentError("redeem requires a Decision, not "
                              f"{type(decision).__name__}")
        if not decision.may_execute:
            raise IntentError(
                f"decision for {decision.action!r} was {decision.verdict.value}, not "
                f"AUTHORISED. ESCALATED is not a soft yes.")
        t = time.time() if now is None else float(now)
        if decision.expires_at and t > decision.expires_at:
            raise IntentError(
                f"this authorization expired {t - decision.expires_at:.0f}s ago. An "
                f"authorization to act at one moment is not an authorization to act "
                f"whenever the executor gets round to it.")
        expected = _decision_digest(action, actor, decision.generation,
                                    decision.nonce, decision.citations, self._epoch)
        if expected != decision.digest:
            raise IntentError(
                f"this decision does not authorise {action!r}. It was granted for "
                f"{decision.action!r} by {actor!r} against generation "
                f"{decision.generation}; presenting a different action, actor or "
                f"accounting produces a different digest, which is the whole point.")
        with self._lock:
            if self._generation != decision.generation:
                raise IntentError(
                    f"stale authorization: granted against generation "
                    f"{decision.generation}, the ledger is now at {self._generation}. "
                    f"A human added or withdrew a purpose in between, so this decision "
                    f"was correct about a world that no longer exists.")
            # PROVENANCE, checked before anything else could be mistaken for it. A
            # self-consistent digest proves the object is internally coherent, not
            # that this ledger ever granted it. Membership here is the only thing
            # that distinguishes a decision `authorise` produced from one someone
            # assembled — and removal is what makes it single-use.
            if decision.digest not in self._issued:
                raise IntentError(
                    "this decision was never issued by this ledger. Its digest is "
                    "internally consistent, which proves only that whoever built it "
                    "could compute a hash — every policy check lives in `authorise`, "
                    "and a decision that did not come from there has passed none of "
                    "them.")
            del self._issued[decision.digest]
            self._record("REDEEMED", action, actor, decision.digest[:16])
        return decision

    def _expire_issued(self, now: Optional[float] = None) -> int:
        """Drop issued-but-unredeemed decisions past their TTL.

        Unbounded growth in a governance structure is its own denial of service, and
        an expired decision cannot be redeemed anyway.
        """
        t = time.time() if now is None else float(now)
        with self._lock:
            dead = [k for k, exp in self._issued.items() if exp and t > exp]
            for k in dead:
                del self._issued[k]
            return len(dead)

    @property
    def outstanding_decisions(self) -> int:
        return len(self._issued)

    # ── record ────────────────────────────────────────────────────────────────
    def _record(self, event: str, subject: str, actor: Optional[str],
                detail: str) -> None:
        self._log.append({"event": event, "subject": subject, "actor": actor,
                          "detail": detail, "at": time.time()})

    def active_constraints(self) -> List[PurposeConstraint]:
        with self._lock:
            return [c for c in self._constraints.values() if c.active]

    def log(self) -> List[dict]:
        """A copy. The record must not be editable through the accessor that
        returns it — the defect found in hardware_isolation and ai_bus."""
        with self._lock:
            return [dict(e) for e in self._log]
