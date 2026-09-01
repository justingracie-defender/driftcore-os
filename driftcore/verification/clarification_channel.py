"""
clarification_channel.py — the agent may ask. It may not author the answer's status.

WHY THIS EXISTS
---------------
Dutta, Ramachandran and Sra, arXiv:2608.19202 (8 June 2026), formalise context
acquisition as active inference: when a user leaves a constraint implicit, an agent
can guess or spend tokens on a clarifying question, and the right question is the one
whose expected information gain justifies its cost. Their clarification experiments
lift verifier compliance from about 0.04 to 0.375 for roughly a hundred extra tokens.
It is a good result and a good idea. (⚠ CITATION UNVERIFIED IN-REPO: the paper
post-dates the knowledge cutoff of the model that drafted this header, and no reviewer
has confirmed the figures against the source. Confirm before quoting them anywhere
external.)

It also introduces a channel this repo did not have, and the danger is precise:

    INFORMATION GAIN OPTIMISES FOR THE AGENT'S UNCERTAINTY, NOT THE HUMAN'S
    COMPREHENSION.

Those diverge exactly where it matters. The question that maximally splits the
agent's posterior is, by construction, the one whose answer is most DECISIVE — which
is the shape of "My plan is good, right?" rather than "Is this plan good?". Highest
information gain, lowest understanding.

Against DriftCore specifically: an agent cannot capture a purpose constraint. But it
can ask a question, and a human's answer is a human utterance. Ask "should I
prioritise speed here?", receive "yes, do whatever is fastest", and if that lands in
the constraint set the agent has authored a purpose by choosing a question. An
optimiser makes it systematically better at this. That is the confused-deputy problem
with an objective function attached.

THE RULE
--------
CLAIM token-is-provenance: an Exchange is recognised by a token that is an HMAC over
its own contents under a per-channel secret and epoch, verified by RECOMPUTATION; a
rebuilt copy, a mutated copy, and a token from another channel are all refused.
CLAIM authenticity-is-not-authorization: recomputation answers "was this signed", and
NOTHING ELSE. Whether the answer may be used now is a separate predicate over
revocation, freshness, and consumption, and the two are separate methods with
separate names so no call site can mistake one for the other.
CLAIM promotion-is-single-use: an exchange may produce at most one Promotion. One
question cannot buy a second purpose by being restated again.
CLAIM revocation-is-possible-and-durable-elsewhere: a human may revoke an exchange,
after which it authenticates and is refused anyway; the revoked set is injectable so
it restores from the same store as the secret and the budget.
CLAIM the-epoch-is-part-of-the-identity: two channels share provenance only if they
share the secret AND the epoch, so a reused key in a new deployment does not silently
inherit the old deployment's tokens.
CLAIM elicited-cannot-lower-risk: a caller may claim an elicited answer lowers risk;
the channel records the claim and passes UNKNOWN, and UNKNOWN cannot lower a floor.
CLAIM elicited-is-never-a-purpose: an utterance produced in answer to an
agent-chosen question is a BELIEF. It can narrow the action space and it can raise
the risk floor. It cannot become a purpose constraint, and it cannot lower risk.
CLAIM promotion-requires-a-non-echoing-human-restatement: turning an elicited answer
into a constraint requires an authorised human to say it again in their own words —
a restatement echoing either the answer or the QUESTION is refused.
CLAIM promotion-carries-lineage: promote returns a Promotion bound to the exchange it
came from, not a bare string, so a constraint's elicited origin survives the call.
CLAIM asking-is-budgeted: the number of questions is bounded and counted, because
over-asking is the failure this paper's own benchmark reports.
CLAIM elicited-answers-expire: an answer has a freshness window measured on the
MONOTONIC clock; past it the answer is neither a belief nor promotable, because "is
a child present?" answered an hour ago is not an answer about now.
CLAIM attribution-is-recorded-not-assumed: `answered_by` is checked against the
shared identity gate AT ASK TIME, and an attribution that could not be verified is
carried as unverified into every downstream artefact rather than reading as a human.

THE THREE PROPERTIES, WHICH MUST NEVER BE CONFLATED
---------------------------------------------------
(consolidated red-team, GLM / Grok / ChatGPT, 2026-08-25.)

    1. AUTHENTICITY — did these exact bytes come from a holder of this secret?
       HMAC answers this. It is the only thing HMAC answers.
    2. HUMAN PROVENANCE — did a person actually produce these bytes?
       HMAC DOES NOT ANSWER THIS, AND NEITHER DOES THIS MODULE. `ask()` receives a
       question string and an answer string from its caller. If the caller is the
       agent, the agent chose the question, wrote the answer, named the human, and
       this channel signed the result. Every artefact is cryptographically valid and
       no human said anything. Closing it needs an authenticated user turn from the
       transport — a signed object carrying session, message id, transcript hash and
       an authentication proof — which is an architecture change above this file.
       UNTIL THEN THE HONEST PROPERTY IS: ATTRIBUTION IS UNAVAILABLE. `status()`
       reports `human_provenance: unauthenticated-strings` so no consumer has to
       infer it.
    3. SEMANTIC AUTHORITY — even if a human did say it, may it become a purpose, a
       permission, an authority, or a lower risk floor? Neither HMAC nor identity
       answers this. `belief_use.BeliefUseLedger` is where it is enforced, at the
       use site, and even there only for uses that declare themselves.

    AUTHENTICITY BINDS CONTENT. HUMAN PROVENANCE BINDS CONTENT TO AN AUTHENTICATED
    USER TURN. NEITHER GRANTS AUTHORITY.

AND THE SECRET MUST SIT OUTSIDE THE ADVERSARY'S BOUNDARY. If the process that
composes the questions can read `self._secret`, it can mint any Exchange it likes and
every check above collapses. This module cannot verify where it is running. The
invariant is architectural: THE SIGNING SECRET MUST RESIDE OUTSIDE THE AUTHORITY
BOUNDARY OF THE COMPONENT WHOSE CLAIMS IT AUTHENTICATES — which in this repo means
the safety wall's OS user, not the agent's.

VERSIONED DEFINITION CHANGE (G7), v2 -> v3, 2026-08-25. THE AUTHENTICATED MATERIAL
ITSELF CHANGED, not just the claim's meaning. Timestamps are now integer microseconds
rather than `repr(float(...))`; a schema string is prefixed for domain separation and
format versioning; and Promotion signs four more fields. INTEGRATOR CONSEQUENCE:
EVERY EXCHANGE AND PROMOTION MINTED BEFORE THIS CHANGE NOW FAILS RECOMPUTATION.
That direction is fail-closed and it is still a migration — rotate the epoch in the
same deployment so the invalidation is deliberate rather than discovered. Logged here
because the v1 -> v2 transition below is precisely what taught this repo that a
silently redefined mechanism is drift, and an unlogged change to the mechanism that
taught the lesson would be a poor way to demonstrate it.

VERSIONED DEFINITION CHANGE (G7). `token-is-provenance` v1 (2026-08-24) meant "the
token was issued by this channel", verified by set membership. That was true and
insufficient: tokens were FUNGIBLE WITHIN A CHANNEL, so one real exchange yielded an
unlimited supply of authored answers carrying valid provenance. v2 (2026-08-25) means
"the token is bound to THESE contents", verified by recomputation. Same slug, changed
meaning, recorded here because a silently redefined claim is drift.

HONEST LIMITS — read before quoting this in a safety case
---------------------------------------------------------
* AGGREGATION IS NOT CLOSED, AND IT IS THE DEEPEST HOLE. Three answers that each
  remain beliefs can be read together by a downstream planner as a preference, with
  no promotion event anywhere in the record. The rule this repo needs, and which is
  ABOVE this module, is: elicited information may inform factual state estimation and
  may never be used as evidence for authority, purpose, preference, permission, risk
  reduction, or capability expansion. Nothing here enforces it.
* AND "FACTUAL STATE ESTIMATION" IS ITSELF A LEAK PATH (red-team, Ox Alpha
  2026-08-25). "The door was locked when I asked" is a fact. "The human said they were
  in a hurry" arrives through the same channel wearing fact clothing. Any coordinator
  adopting the rule above needs a definition of STATE that excludes anything indexed
  to a person's dispositions, or the exception swallows the rule.
* `elicited_ratio` HAS A CALLER-SUPPLIED DENOMINATOR. An agent that wants a clean
  contamination number passes a larger `total_beliefs`. An impossible total (smaller
  than the number of exchanges) is now refused, but an inflated one is not detectable
  here — it is the same shape as the self-reported boolean that `Risk.UNKNOWN`
  replaced. Treat the ratio as the blunt instrument; the checkable version is
  per-use tagging at the consumer, auditing what a belief was USED FOR.
* THE RATIO ALSO MISSES THE MINORITY CASE. One elicited belief doing load-bearing
  work inside an otherwise unprompted set reads as 0.25 and is clean by this measure.
* UNPROMPTEDNESS IS NOT VERIFIABLE IN-PROCESS. `promote` cannot tell whether a human
  restated something spontaneously or because the agent asked them to; nothing here
  observes the turn structure. What is enforced is narrower and honest: an authorised
  human, a restatement that echoes neither the answer nor the question, and a source
  exchange still inside its freshness window. The v1 docstring said "UNPROMPTED" as
  though it were a check. It was never a check.
* IT CANNOT SCORE A QUESTION. Whether a question is well-chosen, leading, or
  premise-smuggling is semantic, and nothing here reads meaning. This governs what an
  answer may BECOME, not whether the question was fair.
* THE STOPPING RULE IN THE PAPER IS SELF-GRADED. "Stop when posterior entropy is low
  enough" is the agent's own posterior, and confidently wrong has low entropy. Same
  ceiling as SATISFIED in the intent ledger: forensic, not preventive.
* OVER-ASKING IS THE REAL-WORLD FAILURE. Near a person, a household asked three
  questions before every action starts answering reflexively, and then "yeah, fine"
  is being recorded as evidence of human intent. The budget is a floor on that
  problem, not a fix.
* THE SECRET AND THE BUDGET DIE TOGETHER (red-team, Ox Alpha 2026-08-25). Both live
  in the channel instance, so a fresh process gets a fresh budget AND a fresh
  token-minting key. `secret=` and `prior_questions=` exist so both can be restored
  from the same out-of-band store. Nothing here can tell whether an integrator did
  that; a module cannot detect its own absence of history.
* AUTHENTICITY IS NOT AUTHORIZATION, AND AN EARLIER DRAFT OF THIS MODULE BLURRED
  THEM (red-team, ChatGPT + Justin, 2026-08-25). That draft removed the issued-token
  set on the reasoning that "membership adds nothing against an attacker without the
  secret". True for forgery, and too broad as stated: an allow/deny set also carries
  replay, revocation, and single-use semantics that recomputation does not. A valid
  HMAC says a secret holder signed these bytes; it never says the authorisation is
  still live. What answers that here is `is_promotable`, which is revocation plus
  freshness plus consumption — and the ceiling on all three is that
  `human_identity` in REGISTERED mode compares a NAME, so anything that knows the
  principal string can present as that human. Single-use bounds what that buys to one
  promotion per exchange; it does not make the gate an authenticated act. ATTESTED
  mode is what does that, and it is the integrator's call.
* SECRET COMPROMISE IS NOT RECOVERABLE FROM IN HERE. Anyone holding the key mints
  tokens for any contents, revoked or not. Rotating the epoch invalidates every
  outstanding token at once and is the only lever this module has.
* REVOCATION IS ONLY AS DURABLE AS THE STORE. `revoked=` restores a deny-list the
  same way `prior_questions=` restores the count. A restart that restores the secret
  and forgets the revocations resurrects every revoked answer, and nothing here can
  detect that.
* `consumed=` RESTORE IS LAST-WRITER-WINS, NOT A DISTRIBUTED LOCK. Two processes
  sharing a secret, an epoch and a store can both load the same unconsumed set at T0
  and both promote the same exchange at T1. That is the cross-process form of the
  in-process TOCTOU that was fixed above, and no amount of locking in here touches
  it: this module cannot see a concurrent minter. The store owns that transaction.
* EXPIRY DELIBERATELY DOES NOT PROPAGATE THROUGH LINEAGE, AND REVOCATION DOES. A
  Promotion is a standing act — a human restated a constraint — so it is allowed to
  outlive the five-minute window on the observation that prompted it, while a
  withdrawn source retires every purpose descended from it. That is a POLICY, not a
  fact about the world, and a consumer may disagree: `Promotion.source_deadline` is
  signed so it can apply its own. `is_promotion_live` answers revocation only.
* THE RESTATEMENT FLOOR CLOSES ONE TAIL, NOT THE CASE THAT MOTIVATED IT. It stops
  assent ("yes", "ok", "sure") becoming a purpose as a RESTATEMENT, since none of
  them reaches three content tokens. It does nothing about a
  one-word ANSWER: a substantive restatement sourced from "yes" still promotes, and
  that is also the legitimate flow for a human who really did say yes and later
  really did restate it. The two are indistinguishable from in here.
  `Promotion.source_answer_tokens` records which one you are looking at. Telemetry,
  forensic, not preventive — the same posture as the contamination ratio, and the
  real fix is the delegated P0 above.
* `ClarificationError` SUBCLASSES `PermissionError` ON PURPOSE, so a caller already
  failing closed on permission errors cannot let a safety refusal through as some
  other exception. The cost is the mirror image: a broad `except PermissionError`
  elsewhere will swallow one quietly. A dedicated DriftCore exception hierarchy is
  the right fix and it is a repo-wide change, not this file's to make.
* THE ECHO DETECTOR IS A COPYING TRIPWIRE, NOT A PROVENANCE MECHANISM. It
  establishes that two strings are not too similar. It cannot establish that a human
  independently authored one of them: an agent that writes "I want safety to take
  priority over convenience" passes it cleanly. A content floor now stops the
  degenerate case ("yes", "ok", "sure" tokenise to nothing and so overlapped with
  nothing), which is a patch on a heuristic, not a fix for the missing property.
* LINEAGE PROVES ANCESTRY, NEVER DERIVATION. Nothing requires a restatement to have
  anything to do with the answer it descends from — a purpose about productivity can
  claim lineage from an answer about a door. `Promotion.source_overlap` records how
  related they actually were, inside the signature, so a reader can see it. It is
  telemetry. A floor cannot be added here without contradicting the echo rule, which
  requires restatements to be DISSIMILAR; the band between "too similar" and
  "unrelated" is semantic and nothing here reads meaning.
* THE BUDGET IS PER INSTANCE, NOT PER AGENT. A caller that constructs three channels
  asks nine questions, and one that restores with `prior_questions=0` starts over.
  `prior_questions=` is the seam for a shared durable count; whether it is wired is
  invisible from in here. The same is true of `revoked=` and `consumed=`: SINGLE-USE
  PROMOTION IS A CLAIM ABOUT ONE PROCESS LIFETIME UNLESS THAT SET IS PERSISTED.
* `elicited_ratio` IS TELEMETRY, NOT A CONTROL. Kept for diagnosis; the control is
  `belief_use.BeliefUseLedger`, which owns its denominator and audits uses.
* RAISES IS AN AVAILABILITY LEVER. A caller can attach Risk.RAISES to everything and
  escalate the system into paralysis. That is the intended direction to fail, and it
  is still a denial of service; it belongs in the operator's threat model.
* AN ATTRIBUTION IS NOT RE-CHECKED AFTER `ask()`. Credentials revoked at 10:02 do not
  retract an answer attributed at 10:01. As historical evidence that is right; as
  live authorisation it is wrong, which is why `promote` and `is_promotion_live` are
  separate from `verify_promotion`.
* ECHO DETECTION IS LEXICAL. Token overlap. A human who genuinely means the same
  thing in different words gets through, and so does an agent that paraphrases well.
* ALL TIME CONSTANTS HERE ARE ⚠ PLACEHOLDERS. `DEFAULT_ANSWER_TTL_S` is a guess by
  the model that wrote it, not a calibrated figure. The machinery is the claim; the
  number is not.

Run: python3 test_clarification_channel.py
"""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

PROMOTE_ACTION = "clarification_promote_to_constraint"
REVOKE_ACTION = "clarification_revoke_answer"
ANSWER_ACTION = "clarification_answer"

# ⚠ PLACEHOLDER. Five minutes is a guess about how long "is a child present?" stays
# an answer about now. It needs a real figure from deployment, not from a model.
DEFAULT_ANSWER_TTL_S = 300.0

_MIN_SECRET_BYTES = 16
# Minimum distinct content tokens in a restatement. Assent carries at most one:
# "ok" is filtered out entirely by the length rule, "yes" and "sure" survive as a
# single token, and a token set that thin overlaps with almost nothing — so it beat
# the echo detector by being too empty to resemble anything, which turned the
# reflexive answer this module warns about into a valid promotion path (red-team,
# GLM/Grok/ChatGPT consolidated, 2026-08-25).
_MIN_RESTATEMENT_TOKENS = 3

# Domain separation + schema version inside the authenticated material. The v1->v2
# meaning change of `token-is-provenance` is precedent: a cryptographic format needs
# a version of its own, or artefacts become ambiguous across a migration.
_EXCHANGE_SCHEMA = "driftcore.clarification.exchange.v3"
_PROMOTION_SCHEMA = "driftcore.clarification.promotion.v3"


def _us(t) -> str:
    """A timestamp as integer microseconds.

    `repr(float(...))` round-trips in CPython and is still the wrong thing to sign:
    it makes the authenticated bytes depend on a language's float representation, so
    a persisted artefact can stop verifying across a serialisation boundary that had
    nothing to do with its contents.
    """
    return str(int(round(float(t) * 1_000_000)))


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


def _identity_mode() -> str:
    """The identity policy in force, or UNAVAILABLE. Never raises."""
    try:
        from driftcore.authority.human_identity import mode
        return str(mode())
    except Exception:
        return "UNAVAILABLE"


class ClarificationError(PermissionError):
    """Raised when an elicited answer is used as something it is not. A
    PermissionError subclass so a caller already failing closed cannot let it
    through as another exception."""


def _tokens(text: str) -> set:
    return {t for t in re.findall(r"[a-z0-9']+", (text or "").lower()) if len(t) > 2}


def _overlap(a_text: str, b_text: str) -> float:
    a, b = _tokens(a_text), _tokens(b_text)
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _echoes(restatement: str, answer: str) -> bool:
    """Is the restatement substantially the answer's own words?

    Deliberately crude. A human restating a purpose in their own words shares few
    content tokens with the answer they gave a moment ago; an agent laundering the
    answer back through a human shares most of them.
    """
    return _overlap(restatement, answer) >= 0.6


class Risk(Enum):
    """What an elicited answer does to estimated risk.

    (red-team, Ox Alpha / ChatGPT 2026-08-25.) This was a caller-supplied boolean, so
    a dangerous answer labelled `raises_risk=False` reached the narrowing channel as
    reassurance. The channel cannot verify the classification — nothing here reads
    meaning — so the fix is not a better default but a third value: UNKNOWN is what
    an unverified classification actually is, and UNKNOWN cannot lower anything.
    """
    RAISES = "raises"
    UNKNOWN = "unknown"
    LOWERS = "lowers"


def _canonical(*parts: str) -> bytes:
    """Length-prefixed join.

    A plain separator is forgeable: question="a|b", answer="c" and question="a",
    answer="b|c" produce the same string, so two different exchanges would share a
    token. Length prefixes make the encoding injective.
    """
    return "|".join(f"{len(p)}:{p}" for p in parts).encode("utf-8")


@dataclass(frozen=True)
class Exchange:
    """One question the agent chose, and the answer it received.

    `token` is the provenance, and it is an HMAC over EVERY field below under the
    channel's secret. (red-team, Ox Alpha 2026-08-25, second round.) v1 minted a
    token from the secret and a counter and verified it by set membership, which
    proved the channel had issued SOME token and bound it to nothing: verified by
    execution, a fabricated Exchange carrying a real token was accepted as a belief,
    and so was `dataclasses.replace(real, answer=...)`. One genuine question bought
    an unlimited supply of authored answers with valid provenance. Recomputation
    closes it — change any field and the token no longer verifies.
    """
    question: str
    answer: str
    answered_by: str
    token: str = ""
    asked_at: float = field(default_factory=time.time)
    # Freshness is measured on the monotonic clock; `asked_at` is for the record
    # only. A wall clock that steps backwards must not resurrect a stale answer.
    asked_mono: float = field(default_factory=time.monotonic)
    # Whether the identity gate could VERIFY `answered_by` at ask time. False under
    # LABEL_ONLY, where nothing is verified and a name is only a name.
    attribution_verified: bool = False

    def _material(self) -> bytes:
        return _canonical(_EXCHANGE_SCHEMA, self.question, self.answer,
                          self.answered_by, _us(self.asked_at), _us(self.asked_mono),
                          "1" if self.attribution_verified else "0")


@dataclass(frozen=True)
class Promotion:
    """An elicited answer a human has restated, with its origin still attached.

    (red-team, Ox Alpha 2026-08-25.) `promote` used to return a bare string, so the
    moment it was handed to a ledger every trace that it began as an agent-chosen
    question was gone. A constraint whose elicited origin is unrecoverable cannot be
    audited for the aggregation failure this module openly does not close.
    """
    text: str
    source_token: str
    promoted_by: str
    at: float
    # The source's security state, carried INSIDE the signature (red-team,
    # GLM/Grok/ChatGPT consolidated, 2026-08-25). An auditor holding only a Promotion
    # could not previously tell whether it descended from a verified human or from a
    # LABEL_ONLY name, and the two must never look equivalent downstream.
    source_attribution_verified: bool = False
    source_identity_mode: str = ""
    # Token overlap between the restatement and the source answer. Lineage proves
    # ANCESTRY, never derivation: nothing stops a restatement about productivity
    # claiming descent from an answer about a door. This number does not prevent
    # that; it makes it visible to whoever reads the record.
    source_overlap: float = 0.0
    # How much content the source ANSWER carried. A one-word "yes" tokenises to
    # nothing, so the restatement floor cannot have been informed by it: the
    # restatement is substantive and the thing it claims to restate is not
    # (red-team, consolidated round four, 2026-08-25). Telemetry, like the overlap.
    source_answer_tokens: int = 0
    # Wall-clock instant at which the SOURCE would have gone stale, or 0.0 for a
    # channel with no TTL. Signed so a consumer can apply its own expiry policy;
    # `is_promotion_live` deliberately does not apply one. Wall clock is skewable —
    # this is for a consumer's judgement, never for this module's own freshness.
    source_deadline: float = 0.0
    token: str = ""

    def _material(self) -> bytes:
        return _canonical(_PROMOTION_SCHEMA, self.text, self.source_token,
                          self.promoted_by, _us(self.at),
                          "1" if self.source_attribution_verified else "0",
                          self.source_identity_mode, f"{self.source_overlap:.6f}",
                          str(int(self.source_answer_tokens)),
                          _us(self.source_deadline))


class ClarificationChannel:
    """Records agent-initiated questions and holds their answers at belief status."""

    def __init__(self, max_questions: int = 3, *,
                 secret: Optional[bytes] = None,
                 prior_questions: int = 0,
                 epoch: str = "",
                 revoked=None,
                 consumed=None,
                 answer_ttl_s: Optional[float] = DEFAULT_ANSWER_TTL_S,
                 require_verified_attribution: bool = True) -> None:
        if isinstance(max_questions, bool) or not isinstance(max_questions, int) \
                or max_questions < 0:
            raise ClarificationError("a question budget cannot be negative")
        if isinstance(prior_questions, bool) or not isinstance(prior_questions, int) \
                or prior_questions < 0:
            raise ClarificationError(
                "prior_questions is a count restored from a store; it cannot be "
                "negative, and a negative one would hand back budget already spent")
        if answer_ttl_s is not None:
            if isinstance(answer_ttl_s, bool) or not isinstance(answer_ttl_s, (int, float)):
                raise ClarificationError("answer_ttl_s must be a number of seconds or None")
            if not math.isfinite(answer_ttl_s):
                raise ClarificationError(
                    "a non-finite TTL is not a window. NaN compares false against "
                    "every bound, so `nan <= 0` passes validation and `age > nan` "
                    "passes the expiry check: the answer never expires and the "
                    "configuration looks valid.")
            if answer_ttl_s <= 0:
                raise ClarificationError(
                    "a non-positive TTL expires every answer at birth; pass None to "
                    "state deliberately that answers do not expire")
        if secret is not None:
            if not isinstance(secret, (bytes, bytearray)) or len(secret) < _MIN_SECRET_BYTES:
                raise ClarificationError(
                    f"an injected secret must be at least {_MIN_SECRET_BYTES} bytes of "
                    f"key material; a short or text secret is a guessable token")
            secret = bytes(secret)
        if not isinstance(epoch, str):
            raise ClarificationError(
                "an epoch is a label restored from the store, not an object")
        if revoked is not None and isinstance(revoked, (str, bytes)):
            raise ClarificationError(
                "revoked is a collection of tokens; a bare string is one character "
                "per entry and would silently revoke nothing")
        self._max = int(max_questions)
        self._prior = int(prior_questions)
        self._epoch = epoch.strip()
        if consumed is not None and isinstance(consumed, (str, bytes)):
            raise ClarificationError(
                "consumed is a collection of spent exchange tokens; a bare string "
                "is one character per entry and would spend nothing")
        self._revoked: set = {str(t) for t in (revoked or ()) if str(t)}
        # Spent single-use tokens. In memory these die with the process, which
        # REFUNDS every promotion on restart — the single-use claim only holds if
        # this restores from the same store as the secret, the count and the
        # revocations (red-team, GLM/Grok/ChatGPT consolidated, 2026-08-25).
        self._consumed: set = {str(t) for t in (consumed or ()) if str(t)}
        self._ttl = None if answer_ttl_s is None else float(answer_ttl_s)
        self._require_verified = bool(require_verified_attribution)
        # Per-channel secret. Injected so it can be restored from the SAME store as
        # `prior_questions` — otherwise a restart resets the budget and the minting
        # key together, and both defences degrade at once.
        self._secret_injected = secret is not None
        self._secret = secret if secret is not None else os.urandom(32)
        self._exchanges: List[Exchange] = []
        self._promotions: set = set()
        self._log: List[dict] = []
        self._lock = threading.RLock()

    # ── minting and verifying ────────────────────────────────────────────────
    def _mint(self, material: bytes) -> str:
        # The epoch is folded into every MAC, so "same secret" alone does not mean
        # "same channel". A key reused in a new deployment under a new epoch mints a
        # disjoint token space and cannot verify the old one's exchanges.
        return hmac.new(self._secret, _canonical(self._epoch) + material,
                        hashlib.sha256).hexdigest()[:32]

    def _authentic(self, obj) -> bool:
        """Was this signed by a holder of this channel's secret, under this epoch?

        This is the ONLY question recomputation answers. It says nothing about
        whether the answer may be used: a revoked exchange, an expired one, and one
        whose single promotion is already spent all authenticate perfectly.
        `_usable` is where those live, and the two are kept apart on purpose —
        (red-team, ChatGPT + Justin, 2026-08-25) an earlier draft removed the
        issued-token set claiming membership "adds nothing", which held only for
        forgery and quietly dropped replay, revocation, and single-use with it.

        The issued-token ALLOW-list stays gone, because it breaks restore for no
        forgery benefit; a revocation DENY-list replaces it, and restores from the
        same store as the secret and the count.
        """
        tok = getattr(obj, "token", "")
        if not isinstance(tok, str) or not tok:
            return False
        try:
            expected = self._mint(obj._material())
        except Exception:
            return False
        return hmac.compare_digest(tok, expected)

    def _usable(self, exchange: "Exchange", what: str) -> None:
        """May this authenticated exchange be used, right now, for `what`?

        Authenticity is assumed already checked. This is the live-authorisation half:
        revocation, freshness, and — for promotion — whether the single use is spent.
        """
        with self._lock:
            if exchange.token in self._revoked:
                self._record("REVOKED-USE", exchange.question,
                             f"{what} refused: the exchange was revoked")
                raise ClarificationError(
                    "this exchange was revoked. It still authenticates — the token is "
                    "genuine and the contents are the signed contents — and it may not "
                    "be used, because a signature is a fact about the past and an "
                    "authorisation is a claim about now.")
        self._require_fresh(exchange, what)

    def revoke(self, exchange: "Exchange", *, by) -> str:
        """Withdraw an answer. A human act, because an agent revoking inconvenient
        answers is the same authorship problem pointing the other way."""
        if not isinstance(exchange, Exchange):
            raise ClarificationError("revoke requires an Exchange from ask()")
        if not _is_human(by, action=REVOKE_ACTION):
            raise ClarificationError(
                f"{by!r} is not an authorised human. Choosing which of a person's "
                f"answers still counts is not the agent's choice to make.")
        if not self._authentic(exchange):
            raise ClarificationError(
                "this exchange does not authenticate, so there is nothing here to "
                "revoke; a revocation of an unverifiable token would be a record of "
                "an event that did not happen")
        with self._lock:
            self._revoked.add(exchange.token)
            self._record("REVOKED", exchange.question, f"by {_principal(by)}")
            return exchange.token

    def consumed_tokens(self) -> List[str]:
        """Spent single-use exchange tokens, for the store that holds the rest."""
        with self._lock:
            return sorted(self._consumed)

    def revoked_tokens(self) -> List[str]:
        """The deny-list, for the store that also holds the secret and the count."""
        with self._lock:
            return sorted(self._revoked)

    def is_authentic(self, obj) -> bool:
        """Was this signed here? Never raises. NOT a permission — see is_promotable."""
        return self._authentic(obj)

    def is_promotable(self, exchange: "Exchange") -> bool:
        """Is this answer authentic AND live AND unspent, right now? Never raises."""
        if not isinstance(exchange, Exchange) or not self._authentic(exchange):
            return False
        with self._lock:
            if exchange.token in self._revoked or exchange.token in self._consumed:
                return False
        if self._ttl is not None and self._age_s(exchange) > self._ttl:
            return False
        return True

    # ── asking ───────────────────────────────────────────────────────────────
    def ask(self, question: str, answer: str, *, answered_by: str) -> Exchange:
        """Record an agent-chosen question and the human's answer.

        `answered_by` is checked against the shared identity gate here, at the point
        the attribution is made. (red-team, Ox Alpha 2026-08-25.) It used to be
        checked for non-emptiness only, so an agent could record its own answer as
        "justin" and `as_belief` would report it as a human's — the identity gate sat
        on `promote`, which the aggregation attack never calls.
        """
        if not isinstance(question, str) or not question.strip():
            raise ClarificationError("a question must be non-empty text")
        if not isinstance(answer, str) or not answer.strip():
            raise ClarificationError("an answer must be non-empty text")
        if not isinstance(answered_by, str) or not answered_by.strip():
            raise ClarificationError(
                "an answer must name who gave it; an unattributable answer is not "
                "evidence of anyone's intent")
        who = answered_by.strip()
        gate_ok = _is_human(who, action=ANSWER_ACTION)
        mode = _identity_mode()
        # Under LABEL_ONLY nothing is verified — the gate accepts any name not on a
        # six-item denylist — so the attribution is carried as UNVERIFIED even though
        # it passed. A permissive mode must be visible downstream, not silent.
        verified = bool(gate_ok) and mode not in ("LABEL_ONLY", "UNAVAILABLE")
        if self._require_verified and not gate_ok:
            raise ClarificationError(
                f"{who!r} did not pass the identity gate, so this answer cannot be "
                f"attributed to a human. An agent naming itself as the answerer is "
                f"the whole confused-deputy path this module exists to close.")
        with self._lock:
            if self._prior + len(self._exchanges) >= self._max:
                raise ClarificationError(
                    f"question budget of {self._max} is spent. The benchmark failure "
                    f"in arXiv:2608.19202 is models asking MORE than the oracle, and "
                    f"near a person the cost of over-asking is that answers stop "
                    f"meaning anything.")
            draft = Exchange(question=question.strip(), answer=answer.strip(),
                             answered_by=who, attribution_verified=verified)
            tok = self._mint(draft._material())
            ex = Exchange(question=draft.question, answer=draft.answer,
                          answered_by=draft.answered_by, token=tok,
                          asked_at=draft.asked_at, asked_mono=draft.asked_mono,
                          attribution_verified=draft.attribution_verified)
            self._exchanges.append(ex)
            self._record("ASKED", ex.question,
                         f"{who} ({'verified' if verified else 'unverified'}, "
                         f"mode={mode}): {ex.answer[:60]}")
            return ex

    # ── freshness ────────────────────────────────────────────────────────────
    def _age_s(self, exchange: Exchange) -> float:
        return time.monotonic() - float(exchange.asked_mono)

    def _require_fresh(self, exchange: Exchange, what: str) -> None:
        if self._ttl is None:
            return
        age = self._age_s(exchange)
        # NaN satisfies NEITHER comparator: `nan < 0` is False so it skips the clock
        # fault, and `nan > ttl` is False so it never expires — the same immortality
        # through the adjacent door (red-team, consolidated round four, 2026-08-25).
        # Today it dies earlier, at authenticity, because `_us()` cannot convert NaN
        # and `_authentic` returns False; that is incidental and it is not the guard.
        # EVERY NUMERIC GUARD MUST DECLARE ITS BEHAVIOUR FOR NON-FINITE VALUES.
        if not math.isfinite(age) or age < 0:
            with self._lock:
                self._record("CLOCK-FAULT", exchange.question,
                             f"{what} refused at age {age}")
            raise ClarificationError(
                "this answer reports an age that is negative or not a number, so its "
                "monotonic mark did not come from this clock domain. Both read as "
                "'not expired', which is the wrong direction to fail. An object "
                "reporting neither a plausible positive age nor a clearly negative "
                "one is corrupt, not young; re-ask rather than trusting a timestamp "
                "that crossed a reboot, a migration, or a JSON round-trip.")
        if age > self._ttl:
            with self._lock:
                self._record("EXPIRED", exchange.question,
                             f"{what} refused at age {age:.1f}s > ttl {self._ttl:.1f}s")
            raise ClarificationError(
                f"this answer is {age:.0f}s old and the freshness window is "
                f"{self._ttl:.0f}s. An answer about the world is an answer about WHEN "
                f"it was given; ask again rather than acting on a stale one.")

    # ── what an answer may become ────────────────────────────────────────────
    def as_belief(self, exchange: Exchange, *, risk: "Risk") -> dict:
        """The ONLY status an elicited answer has by default.

        Feed the result to `narrowing_channel.apply(belief=..., belief_risk=...)`,
        where it can narrow and can raise the risk floor and can do nothing else.
        `risk` is required rather than defaulted, and is three-valued. The caller
        cannot verify its own classification, so LOWERS is not a claim this channel
        will pass on as fact: it is downgraded to UNKNOWN, recorded with what was
        claimed, and UNKNOWN cannot lower an existing floor. The invariant is
        stronger than "the caller must set the boolean correctly":

            NO UNVERIFIED ELICITED INFORMATION MAY DECREASE THE RISK FLOOR.
        """
        if not isinstance(exchange, Exchange):
            raise ClarificationError("as_belief requires an Exchange from ask()")
        if not isinstance(risk, Risk):
            raise ClarificationError(
                "risk must be a Risk value, stated explicitly. An undeclared "
                "direction is how a reassurance passes as neutral.")
        with self._lock:
            if not self._authentic(exchange):
                raise ClarificationError(
                    "this exchange's token does not verify against its own contents "
                    "under this channel's secret. Rebuilding an Exchange with "
                    "identical fields is not provenance, and neither is carrying a "
                    "real token on altered fields — the token signs the answer, not "
                    "the fact that some answer once existed.")
        self._usable(exchange, "as_belief")
        # A caller may CLAIM the answer lowers risk. The channel records the claim
        # and passes UNKNOWN, because an elicited reassurance the agent solicited is
        # the exact thing that must not be able to relax anything.
        effective = Risk.UNKNOWN if risk is Risk.LOWERS else risk
        marks = "elicited" if exchange.attribution_verified else \
            "elicited, unverified-attribution"
        att = "verified" if exchange.attribution_verified else "unverified"
        with self._lock:
            self._record("BELIEF", exchange.question,
                         f"claimed={risk.value} effective={effective.value} "
                         f"attribution={att}")
        return {"belief": f"[{marks}] {exchange.question} -> {exchange.answer}",
                "risk": effective, "claimed_risk": risk,
                "elicited": True, "answered_by": exchange.answered_by,
                "attribution_verified": exchange.attribution_verified,
                "token": exchange.token}

    def promote(self, exchange: Exchange, *, restatement: str,
                stated_by) -> "Promotion":
        """Turn an elicited answer into text eligible to become a purpose constraint.

        Requires an authorised human to say it again in their own words. An echo of
        the answer is refused, and so is an echo of the QUESTION: if the agent chose
        the question and the agent's phrasing comes back either way, the agent
        authored the purpose. This does NOT establish that the restatement was
        unprompted — see the honest limits in the module header. Returns a Promotion
        carrying the source token, so the constraint's elicited origin survives.
        """
        if not isinstance(exchange, Exchange):
            raise ClarificationError("promote requires an Exchange from ask()")
        if not _is_human(stated_by, action=PROMOTE_ACTION):
            raise ClarificationError(
                f"{stated_by!r} is not an authorised human. Promoting an answer to a "
                f"purpose is a human act; if the agent could do it, choosing the "
                f"question would be choosing the purpose.")
        if not isinstance(restatement, str) or not restatement.strip():
            raise ClarificationError("a restatement must be non-empty text")
        # Resolved OUTSIDE the critical section: `_principal` reads an attribute off
        # a caller-supplied object, and a hostile property that blocks would hold the
        # channel lock for as long as it liked.
        who = _principal(stated_by)
        # ONE critical section from the spent-check through the mint. Split across
        # two acquisitions this was a TOCTOU: verified by execution with a 50ms
        # window forced between them, two threads both passed the check and one
        # exchange produced TWO purposes (red-team, GLM/Grok/ChatGPT consolidated,
        # 2026-08-25).
        with self._lock:
            if not self._authentic(exchange):
                raise ClarificationError(
                    "this exchange's token does not verify against its own contents; "
                    "a purpose may not be built on an answer whose provenance cannot "
                    "be recomputed.")
            self._usable(exchange, "promote")
            if exchange.token in self._consumed:
                self._record("REPLAY", exchange.question,
                             "a second promotion of an already-promoted exchange")
                raise ClarificationError(
                    "this exchange has already produced a purpose. One question buys "
                    "one promotion; a second restatement of the same elicited answer "
                    "is the agent asking twice with extra steps.")
            if len(_tokens(restatement)) < _MIN_RESTATEMENT_TOKENS:
                raise ClarificationError(
                    f"a restatement of {restatement.strip()[:20]!r} carries too "
                    f"little content. Assent tokenises to at most one word, and a "
                    f"token set that thin beats the echo detector by overlapping "
                    f"with nothing — which turns the reflexive answer this module "
                    f"warns about into a purpose. Say the constraint, not the assent.")
            if _echoes(restatement, exchange.answer):
                raise ClarificationError(
                    "the restatement is substantially the answer's own words. The "
                    "point of restating is that the human, not the question, supplies "
                    "the wording — say it differently or leave it as a belief.")
            if _echoes(restatement, exchange.question):
                raise ClarificationError(
                    "the restatement is substantially the QUESTION's own words. A "
                    "human reading the agent's framing back is the agent's framing, "
                    "whichever side of the exchange it came from.")
            draft = Promotion(
                text=restatement.strip(), source_token=exchange.token,
                promoted_by=who, at=time.time(),
                source_attribution_verified=exchange.attribution_verified,
                source_identity_mode=_identity_mode(),
                source_overlap=_overlap(restatement, exchange.answer),
                source_answer_tokens=len(_tokens(exchange.answer)),
                source_deadline=(0.0 if self._ttl is None
                                 else exchange.asked_at + self._ttl))
            tok = self._mint(draft._material())
            p = Promotion(
                text=draft.text, source_token=draft.source_token,
                promoted_by=draft.promoted_by, at=draft.at,
                source_attribution_verified=draft.source_attribution_verified,
                source_identity_mode=draft.source_identity_mode,
                source_overlap=draft.source_overlap,
                source_answer_tokens=draft.source_answer_tokens,
                source_deadline=draft.source_deadline, token=tok)
            self._promotions.add(tok)
            self._consumed.add(exchange.token)
            self._record("PROMOTED", exchange.question,
                         f"{who}: {p.text[:60]} "
                         f"(source attribution="
                         f"{'verified' if p.source_attribution_verified else 'unverified'},"
                         f" overlap={p.source_overlap:.2f})")
            return p

    def verify_promotion(self, promotion: "Promotion") -> bool:
        """Did THIS channel issue this promotion, with this text? Never raises.

        AUTHENTICITY ONLY, and a Promotion is HISTORICAL EVIDENCE — a record that a
        human once restated something — never a live authorisation. A promotion whose
        source has since been revoked still verifies here, correctly: the event
        happened. `is_promotion_live` is the question a consumer about to ACT must
        ask instead (red-team, GLM/Grok/ChatGPT consolidated, 2026-08-25).
        """
        if not isinstance(promotion, Promotion):
            return False
        with self._lock:
            return self._authentic(promotion)

    def is_promotion_live(self, promotion: "Promotion") -> bool:
        """Authentic AND its source has not been withdrawn. Never raises.

        Revocation propagates through lineage here and nowhere else: `source_token`
        is the link, so revoking an exchange retires every purpose descended from it.
        This does NOT re-check the source's freshness — a promotion is deliberately
        allowed to outlive the five-minute answer window, because a constraint a
        human stated is not a transient observation. Whether THAT is right for a
        given consumer is the consumer's call, and it is the reason this method and
        `verify_promotion` have different names.
        """
        if not isinstance(promotion, Promotion) or not self._authentic(promotion):
            return False
        with self._lock:
            return promotion.source_token not in self._revoked

    # ── observation ──────────────────────────────────────────────────────────
    def elicited_ratio(self, total_beliefs: int) -> float:
        """What fraction of a belief set this channel produced.

        (red-team, Meta 2026-08-25 — the deepest finding, and NOT closed here.) An
        agent can ask three questions that each stay a belief — "is speed important?",
        "are safety checks slowing us down?", "is skipping one acceptable when
        rushed?" — and a downstream planner can read all three together and conclude
        "the human prefers speed over safety". No promote() ever happens, so no
        promotion event appears in the audit trail, and the purpose has been
        reconstructed anyway.

        THE DENOMINATOR COMES FROM THE CALLER (red-team, Ox Alpha 2026-08-25), so an
        agent wanting a clean number passes a bigger total. A total smaller than the
        number of exchanges is impossible and is refused rather than clamped to 1.0,
        because a clamp turns a provably wrong input into a plausible reading. An
        INFLATED total is not detectable here at all. Use `elicited_count` and the
        consumer's own belief record if the number has to mean anything — or use
        `belief_use.BeliefUseLedger`, which owns its denominator and records what
        each belief was USED FOR, which is what the rule was always about.
        """
        if isinstance(total_beliefs, bool) or not isinstance(total_beliefs, int):
            raise ClarificationError("total_beliefs must be an integer count")
        if total_beliefs < 0:
            raise ClarificationError("a belief set cannot have a negative size")
        with self._lock:
            n = len(self._exchanges)
        if total_beliefs < n:
            raise ClarificationError(
                f"total_beliefs={total_beliefs} is smaller than the {n} beliefs this "
                f"channel produced. That total is wrong, and clamping it to 1.0 would "
                f"report a plausible number for an impossible input.")
        return 0.0 if total_beliefs == 0 else n / float(total_beliefs)

    @property
    def elicited_count(self) -> int:
        """The numerator on its own — the only half of the ratio this channel knows."""
        with self._lock:
            return len(self._exchanges)

    @property
    def asked(self) -> int:
        with self._lock:
            return len(self._exchanges)

    @property
    def remaining(self) -> int:
        with self._lock:
            return max(0, self._max - self._prior - len(self._exchanges))

    def exchanges(self) -> List[Exchange]:
        with self._lock:
            return list(self._exchanges)

    def elicited_answers(self) -> List[str]:
        """Every answer this channel produced, for the ledger to refuse."""
        with self._lock:
            return [e.answer for e in self._exchanges]

    def status(self) -> dict:
        """What this channel is actually enforcing, including where it is weak.

        Mirrors `human_identity.status()`: a permissive configuration should be
        legible on demand rather than discoverable only by reading the constructor.
        """
        mode = _identity_mode()
        with self._lock:
            n = len(self._exchanges)
            unverified = sum(1 for e in self._exchanges if not e.attribution_verified)
            prior, ttl, req, injected = (self._prior, self._ttl,
                                         self._require_verified, self._secret_injected)
            remaining = max(0, self._max - self._prior - n)
        return {
            "identity_mode": mode,
            "attribution_verifiable": mode not in ("LABEL_ONLY", "UNAVAILABLE"),
            "require_verified_attribution": req,
            "answer_ttl_s": ttl,
            "asked": n,
            "prior_questions": prior,
            "remaining": remaining,
            "unverified_attributions": unverified,
            "secret_injected": injected,
            "epoch": self._epoch,
            "revoked": len(self._revoked),
            "promotions_spent": len(self._consumed),
            "human_provenance": "unauthenticated-strings",
            "note": (
                "identity mode is LABEL_ONLY: every attribution here is a name, not a "
                "verified human, and is marked unverified downstream."
                if mode == "LABEL_ONLY" else
                "the identity module could not be reached; attributions cannot be "
                "verified and require_verified_attribution cannot be relied on."
                if mode == "UNAVAILABLE" else
                "attributions are checked at ask time against the identity gate."),
        }

    def log(self) -> List[dict]:
        """A copy — the record must not be editable through the accessor that
        returns it."""
        with self._lock:
            return [dict(e) for e in self._log]

    def _record(self, event: str, subject: str, detail: str) -> None:
        self._log.append({"event": event, "subject": subject, "detail": detail,
                          "at": time.time()})


def _principal(who) -> str:
    """A stable label for the record.

    Never "?" — an audit line on the one path that creates a constraint has to say
    something a reader can act on, and an unattributable promoter is a fact worth
    recording as itself.
    """
    if isinstance(who, str):
        return who
    got = getattr(who, "principal", None)
    if isinstance(got, str) and got.strip():
        return got.strip()
    return f"<unattributable {type(who).__name__}>"
