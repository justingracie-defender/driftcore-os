"""
driftcore/safety/required_knowledge.py
=======================================
Missing safety information must never read as "no such concern".

WHY THIS EXISTS
---------------
Reproduced end to end, 2026-09-06:

  1. Someone tells the robot "jonny is allergic to peanuts".
  2. Permanent memory needs human confirmation, so it waits in working memory.
  3. Nobody confirms.
  4. It expires. A restart leaves no trace of it at all.
  5. "make jonny a peanut butter sandwich"  ->  PROCEED.

Every gate did its job. The permanent-memory gate correctly refused to store an
unconfirmed medical fact. The expiry correctly removed an item nobody vouched
for. And the system ended up more dangerous than if nobody had ever mentioned the
allergy, because the mention created a false sense that the robot had been told.

**Preventing an unapproved fact from being SAVED is not the same as preventing an
unsafe ACTION.** The confirmation gate added earlier that day made this worse, not
better: before it, an allergy fact landed in Tier 1 quarantined; after it, an
unconfirmed one expires to nothing.

THE RULE
--------
    A safety concern that was raised and never resolved BLOCKS the actions it
    bears on, and keeps blocking them after it expires and after a restart.

A raised concern does not need to become a confirmed medical fact to justify a
pause. "Somebody said Jonny might have a peanut allergy and nobody has confirmed
or denied it" is sufficient reason not to make him a peanut butter sandwich. It
is not sufficient reason to record a diagnosis, which is why the memory gate is
still right to refuse the write.

So the two mechanisms answer different questions and both are needed:

    memory confirmation :  may I record this as true?
    this module         :  may I act as though it is false?

The second one is the one that was missing. This is the same shape as
`EgressGuard` — "unconfigured is not permissive" — and as the audit anchor's
refusal when a chain exists but its head does not: **we could not check is not
the same as we checked.**

WHAT THIS DOES NOT DO
---------------------
* It does not decide what is safe. It records that a question is open and refuses
  to let an open question be read as a closed one. What counts as a prerequisite
  for what action is a deployment's declaration, not this module's opinion.
* It cannot detect a concern nobody raised. A robot that was never told about a
  latex allergy has no open question about latex. This closes "told and lost",
  not "never told".
* Resolution requires a human. `resolve()` takes the same identity gate as every
  other authority in this repo, so under an UNCONFIGURED process nothing resolves
  — which is the safe direction and will be loud.
* It holds concerns in memory. Surviving a restart requires the deployment to
  persist and reload them; `to_records()` / `from_records()` exist for that and
  the persistence itself is the integrator's job.
"""

import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

# Words that make a raised concern safety-bearing rather than conversational.
# A tripwire, not a classifier: this is the weak layer and it is meant to be
# generous, because the cost of a false positive here is a question and the cost
# of a false negative is a child eating a peanut.
SAFETY_SIGNALS = (
    "allerg", "anaphyla", "epipen", "medication", "medicine", "dose", "insulin",
    "asthma", "seizure", "diabet", "choking", "intoleran", "contraindicat",
    "must not eat", "cannot eat", "can't eat", "reacts to", "sensitive to",
)


# ── effects carry their prerequisites ────────────────────────────────────────
#
# (2026-09-06) Two declaration tables were drifting apart. `tool_effects` says
# what an actuator DOES; `required_facts` said what a domain must KNOW. Both are
# lookups into a table a human filled in, both refuse on an empty lookup, and both
# fail the same silent way when the declaration is wrong — `bash` declared
# Effect.NONE lets `curl` through, and required_facts listing only allergy_status
# means choking hazards were never asked about.
#
# One declaration is better than two that can disagree. Declaring an actuator's
# EFFECTS now implies what must be known before it runs, so an integrator who gets
# the effect right gets the prerequisites for free.
#
# This mapping is deliberately small and deliberately not exhaustive. It is a
# floor that ships, not a claim about every hazard. A deployment ADDS to it and
# cannot subtract — see `prerequisites_for`.
EFFECT_PREREQUISITES = {
    "physical_force": ("subject_present", "safety_envelope"),
    "lethal":         ("subject_present", "safety_envelope", "human_authorisation"),
    "data_egress":    ("destination_declared",),
    "account_access": ("account_owner_consent",),
}

# Prerequisites a deployment attaches to its own domains, e.g. food -> allergy
# status. Kept separate from the effect mapping because a household knows things
# about its kitchen that a library cannot.


def prerequisites_for(effects, domain_facts=(), extra=()) -> Tuple[str, ...]:
    """Everything that must be on file before this action runs.

    CLAIM prerequisites-only-accumulate: the result is the UNION of what the
    declared effects require, what the domain requires, and anything the caller
    adds. There is no argument that removes a requirement.

    That asymmetry is the point and it is the same rule as `narrowing_channel`:
    authority may shrink and never grow, so a requirement may be added and never
    quietly dropped. A deployment that could subtract prerequisites would be a
    deployment where getting the effect right stops meaning anything — and the
    subtraction would be invisible, because a check that was removed looks exactly
    like a check that passed.
    """
    out = set(domain_facts or ()) | set(extra or ())
    for e in (effects or ()):
        key = getattr(e, "value", e)
        out |= set(EFFECT_PREREQUISITES.get(key, ()))
    return tuple(sorted(out))


class UnresolvedSafetyQuestion(PermissionError):
    """An action was refused because a safety question about it is still open."""


@dataclass(frozen=True)
class SafetyConcern:
    """Something was raised about a subject and nobody has closed it."""
    subject: str                 # who it is about, e.g. "jonny"
    text: str                    # what was said, verbatim
    raised_by: str               # who said it
    raised_at: float = field(default_factory=time.time)
    domains: Tuple[str, ...] = ()   # what it bears on, e.g. ("food", "medical")

    def to_record(self) -> dict:
        return asdict(self)


def looks_safety_bearing(text: str) -> bool:
    """Does this mention carry a safety signal?

    Deliberately generous. A false positive costs a question; a false negative
    costs the thing this module exists to prevent.
    """
    if not isinstance(text, str):
        return False
    low = text.lower()
    return any(sig in low for sig in SAFETY_SIGNALS)


class RequiredKnowledge:
    """The open questions, and the actions they block.

    CLAIM unresolved-blocks-the-action: while a concern about a subject is open,
    actions declared to depend on it are refused, and the refusal names the
    concern so a human can close it.

    CLAIM expiry-does-not-resolve: a concern is removed by `resolve()` and by
    nothing else. Time passing, memory expiry and process restart do not close a
    question — they are the exact conditions under which one gets forgotten.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._open: List[SafetyConcern] = []
        self._resolved_log: List[dict] = []

    # ── raising ──────────────────────────────────────────────────────────
    def raise_concern(self, subject: str, text: str, raised_by: str,
                      domains: Tuple[str, ...] = ("food", "medical")) -> Optional[SafetyConcern]:
        """Record that something safety-bearing was said and is not yet resolved.

        Returns the concern, or None if the text carried no safety signal. Safe to
        call on every observation: the signal check is what decides.
        """
        if not looks_safety_bearing(text):
            return None
        c = SafetyConcern(subject=str(subject), text=str(text),
                          raised_by=str(raised_by), domains=tuple(domains))
        with self._lock:
            self._open.append(c)
        return c

    # ── resolving ────────────────────────────────────────────────────────
    def resolve(self, concern: SafetyConcern, *, resolved_by, outcome: str) -> None:
        """Close a question. Requires a human, and requires an ANSWER.

        `outcome` is what the human determined — "confirmed: peanut allergy" or
        "checked with the parent: no allergies". Both close the question. What
        does not close it is silence, which is the entire point.
        """
        from driftcore.authority.human_identity import is_human
        if not is_human(resolved_by, action="safety_concern_resolve"):
            raise UnresolvedSafetyQuestion(
                f"{resolved_by!r} did not pass the identity gate. Closing a safety "
                f"question is a human act — an agent that can close its own open "
                f"questions has no open questions.")
        if not isinstance(outcome, str) or not outcome.strip():
            raise ValueError(
                "resolve() requires an outcome. A question closed with no answer "
                "recorded is a question that was dropped, not answered.")
        with self._lock:
            if concern in self._open:
                self._open.remove(concern)
            self._resolved_log.append(
                {"concern": concern.to_record(), "outcome": outcome,
                 "resolved_by": str(resolved_by), "resolved_at": time.time()})

    # ── the gate ─────────────────────────────────────────────────────────
    def open_for(self, subject: str, domain: str) -> List[SafetyConcern]:
        """Open concerns about this subject that bear on this domain.

        (external red-team, Grok, 2026-09-09) `raise_concern` defaults its domains
        to ("food", "medical"); the coordinator defaults an unspecified domain to
        "general". The two defaults never met, so an integrator who supplied
        `safety_subject` and trusted the rest got a PROCEED on an open peanut
        concern. Two reasonable defaults, chosen in different files, producing a
        silent bypass — nobody wrote a hole, the hole grew between them.
        
        An unspecified domain now matches EVERY open concern about the subject.
        Not knowing which domain an action belongs to is not the same as knowing
        it belongs to a domain with no concerns — the same rule as everywhere
        else here, applied to a default nobody thought of as a check.
        """
        d = str(domain) if domain else ""
        with self._lock:
            return [c for c in self._open
                    if c.subject.lower() == str(subject).lower()
                    and (not d or d == "general" or d in c.domains)]

    def require_clear(self, subject: str, domain: str) -> None:
        """Refuse the action while a question about this subject is open.

        The refusal names the concern and who raised it, because "blocked for
        safety" that does not say what is missing cannot be resolved and will be
        turned off.
        """
        blocking = self.open_for(subject, domain)
        if blocking:
            first = blocking[0]
            raise UnresolvedSafetyQuestion(
                f"{len(blocking)} unresolved safety question(s) about "
                f"{subject!r} in {domain!r}. {first.raised_by!r} said: "
                f"{first.text!r}. Nobody has confirmed or denied it. Not knowing "
                f"is not the same as knowing there is nothing — resolve it with "
                f"a responsible adult before acting.")

    # ── the stronger gate: affirmative presence, not mere absence ────────
    def require_known(self, subject: str, domain: str, facts: Tuple[str, ...],
                      lookup) -> None:
        """Refuse unless the required facts about this subject are ON FILE.

        CLAIM absence-is-not-clearance: `require_clear` alone is not enough, and
        this is the sharper half of the same rule.

        `require_clear` refuses while somebody's raised concern is open. It says
        nothing when NOBODY raised one — so a robot that was never told about
        Jonny's allergy has a clear register and proceeds. That is the original
        defect wearing a different hat: absence of a warning read as absence of a
        hazard.

        This asks the other question. For a declared action class, the required
        facts must be affirmatively present — "jonny: no known allergies, checked
        by mum on the 3rd" is an answer, and so is a list of allergies. What is
        not an answer is nothing at all.

        `lookup(subject, fact) -> bool` is the deployment's, because only the
        deployment knows where its safety profile lives. The rule this module
        enforces is that an unanswered lookup refuses.
        """
        missing = []
        for fact in facts:
            try:
                if not lookup(subject, fact):
                    missing.append(fact)
            except Exception:
                missing.append(fact)   # a lookup that fails has not answered
        if missing:
            raise UnresolvedSafetyQuestion(
                f"cannot act in {domain!r} for {subject!r}: required safety "
                f"information is not on file — {', '.join(missing)}. Nobody has "
                f"said there is a problem, and nobody has said there is not. The "
                f"second one is what is needed before acting, and only a person "
                f"can put it there.")

    def require_safe(self, subject: str, domain: str,
                     facts: Tuple[str, ...] = (), lookup=None) -> None:
        """Both halves, in the order a person would ask them.

        This is the shape worth generalising: before a consequential action, ask
        what is unresolved, then ask what is missing. Neither question is
        answered by the absence of the other.
        """
        self.require_clear(subject, domain)
        if facts:
            if lookup is None:
                raise UnresolvedSafetyQuestion(
                    f"required facts were declared for {domain!r} but no lookup "
                    f"was supplied, so they cannot be checked. Unable to check is "
                    f"not the same as checked.")
            self.require_known(subject, domain, facts, lookup)

    # ── persistence across restart (the integrator's job to call) ────────
    def to_records(self) -> List[dict]:
        with self._lock:
            return [c.to_record() for c in self._open]

    def from_records(self, records) -> None:
        """Reload open questions. Additive: reloading never closes anything."""
        with self._lock:
            for r in records or ():
                try:
                    self._open.append(SafetyConcern(
                        subject=r["subject"], text=r["text"],
                        raised_by=r["raised_by"],
                        raised_at=float(r.get("raised_at", time.time())),
                        domains=tuple(r.get("domains", ()))))
                except Exception:
                    continue    # a malformed record is not a reason to lose the rest

    def open_count(self) -> int:
        with self._lock:
            return len(self._open)
