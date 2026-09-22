# SPDX-License-Identifier: Apache-2.0
"""
memory_gate.py — memory has one door, and a question you may not ask is answered
the same way as a question with no answer.

# CLAIMS: driftcore/governance/memory_gate.py:one-door
# CLAIMS: driftcore/governance/memory_gate.py:refusal-is-shaped-like-absence
# CLAIMS: driftcore/governance/memory_gate.py:ceiling-filters-before-ranking
# CLAIMS: driftcore/governance/memory_gate.py:recall-raises-the-session-label
# CLAIMS: driftcore/governance/memory_gate.py:budget-is-content-independent
# CLAIMS: driftcore/governance/memory_gate.py:consequences-are-declassified-at-write
# CLAIMS: driftcore/governance/memory_gate.py:human-only-is-not-reachable-by-any-session

WHAT THIS IS FOR

driftcore/memory/ stores bare text. Nothing in it knows about labels, so anything
retrieved arrives in the model's head without the wall seeing it. That is the path
that defeats audience_release: a session the wall believes is PUBLIC recalls a
household secret, writes a paraphrase, and the gate releases it into a room that
may not hold it — correctly, by its own lights, because the session's label never
rose. This module is the seam. Recall is the only way an agent reaches memory, and
everything that comes back is labelled and observed into the session on the way.

WHY THERE IS NO "DOES A MEMORY EXIST" CALL

A store you can ask yes/no questions about is an oracle. Ask enough narrow
questions and the pattern of yes and no reconstructs what you were not told. So
there is no exists(), no count(), no search(), no "you are not cleared for that"
and no "there are 3 more results". There is one call, and it returns one of two
things:

    FOUND    — here are the items you may have
    UNKNOWN  — nothing to give you

UNKNOWN is returned when the store holds nothing matching, when everything matching
is above the session's ceiling, when the match is human-only, and when the query
was malformed. Those four are the same object with the same fields. The agent
cannot tell which of them happened, which means the absence of a memory and the
existence of one it may not have are the same observation.

CLAIM one-door: recall() is the only method an agent-held handle can reach.
remember(), forget() and the human-side read are broker methods and take no handle.

CLAIM refusal-is-shaped-like-absence: every non-delivery is Verdict.UNKNOWN with an
empty items tuple and the same reason string, whatever caused it. No field, count,
flag or message distinguishes "nothing here" from "not for you".

CLAIM ceiling-filters-before-ranking: items above the ceiling are removed before
relevance is scored, not after. Ranking first and filtering second leaks: the
number of results that come back would drop when a high-labelled item outranked a
low one, and that drop is a yes.

CLAIM recall-raises-the-session-label: every item handed back is observed into the
session first, so the session carries what it was given. A recall that cannot be
observed is not delivered.

CLAIM budget-is-content-independent: a recall costs the same whether it found
everything, nothing, or something it could not give. Budget state therefore says
nothing about the store, and running out can be reported honestly.

CLAIM consequences-are-declassified-at-write: "this matches a prior safety event,
ask the owner first" is a caution a human writes and labels when the memory is
stored. It is an ordinary stored item and comes back under ordinary rules. It is
never derived at read time from a record the session may not have — a summary
computed from a secret is the secret, in smaller words.

CLAIM human-only-is-not-reachable-by-any-session: an item stored human_only is
never returned by recall() at any ceiling. The owner reads it through the broker.

HONEST LIMITS

* This closes the structural channel, not the semantic one. If a public memory only
  ever gets written when a secret one does, the public one is a tell. No label
  arithmetic fixes that; it is a question about what you choose to store.
* Constant work, not constant time. The gate scores every item on every recall so
  the work does not vary with what matched, but Python timing is not a covert
  channel defence and this does not claim to be one.
* The ceiling is a policy about what a session may receive. It is not isolation: an
  agent with arbitrary in-process access can read the store directly. Same ceiling
  as every other stage here, stated rather than implied.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Tuple

from driftcore.governance.information_flow import (
    FlowRefused, Label, Labeled, Level, PUBLIC)
from driftcore.governance.audience_release import AgentSession, label_token

MAX_QUERY_CHARS = 400
DEFAULT_K = 3
DEFAULT_BUDGET = 64

# Every non-delivery says exactly this. One string, so a reason cannot be read.
_NOTHING = "nothing to give you"


class Verdict(Enum):
    FOUND = "found"
    UNKNOWN = "unknown"
    BUDGET_SPENT = "budget_spent"     # independent of content; safe to report


@dataclass(frozen=True)
class Recall:
    verdict: Verdict
    items: Tuple[Labeled, ...] = ()
    reason: str = _NOTHING

    @property
    def delivered(self) -> Tuple[str, ...]:
        return tuple(i.value for i in self.items)


@dataclass(frozen=True)
class _Record:
    text: str
    label: Label
    origin: str
    human_only: bool


def _nothing() -> Recall:
    # The single object every non-delivery returns. Built the same way each time so
    # no caller can tell the four causes apart by identity, length or wording.
    return Recall(Verdict.UNKNOWN, (), _NOTHING)


def _relevance(query: str, text: str) -> float:
    # Deliberately dull word overlap. The point of this module is the door, not the
    # ranking; a smarter scorer drops in here without touching the guarantees.
    q = set(query.lower().split())
    t = set(text.lower().split())
    if not q or not t:
        return 0.0
    return len(q & t) / len(q | t)


class MemoryGate:
    """One door onto a labelled store."""

    def __init__(self, *, k: int = DEFAULT_K, budget: int = DEFAULT_BUDGET,
                 min_relevance: float = 0.01):
        if not isinstance(k, int) or k < 1:
            raise FlowRefused("k is how many items a recall may return, at least 1")
        if not isinstance(budget, int) or budget < 1:
            raise FlowRefused("a session needs a recall budget of at least 1")
        self._k = k
        self._budget = budget
        self._min_relevance = min_relevance
        self._records: List[_Record] = []
        self._sessions: Dict[str, Tuple[AgentSession, Label]] = {}
        self._spent: Dict[str, int] = {}
        self._lock = threading.Lock()

    # ── broker side ─────────────────────────────────────────────────────────

    def remember(self, text: str, label: Label, *, origin: str = "observation",
                 human_only: bool = False) -> None:
        # Broker side. Storage names the label; the store never guesses one, because
        # a guessed label is an unverified state converted into a permission.
        if type(text) is not str or not text.strip():
            raise FlowRefused("a memory is non-empty text")
        if not isinstance(label, Label):
            raise FlowRefused(
                f"a memory is stored with its label, not a bare "
                f"{type(label).__name__}; label it at its source")
        if human_only is not True and human_only is not False:
            raise FlowRefused("human_only is declared True or False, nothing else")
        with self._lock:
            self._records.append(_Record(text, label, origin, human_only))

    def open_session(self, session: AgentSession, ceiling: Label) -> str:
        # Broker side. The ceiling is the most this session may ever be handed. It
        # is separate from the session's label, which is what it has been handed so
        # far: one is permission, the other is history, and conflating them is how
        # a session ends up cleared for what it happens to have seen.
        if not isinstance(session, AgentSession):
            raise FlowRefused("a memory session is the wall's AgentSession")
        if not isinstance(ceiling, Label):
            raise FlowRefused("a session declares the ceiling it may be handed")
        if not ceiling.dominates(session.label):
            raise FlowRefused(
                "this session already carries more than its ceiling allows; it "
                "could not be handed what it has already seen")
        handle = "mh_" + __import__("secrets").token_urlsafe(24)
        with self._lock:
            self._sessions[handle] = (session, ceiling)
            self._spent[handle] = 0
        return handle

    def read_for_owner(self, query: str) -> Tuple[Labeled, ...]:
        # The human side. No handle, no ceiling, no budget — and human_only records
        # are reachable only from here.
        with self._lock:
            rows = list(self._records)
        hits = [r for r in rows if _relevance(query, r.text) >= self._min_relevance]
        return tuple(Labeled(r.text, r.label, frozenset({f"memory:{r.origin}"}))
                     for r in hits)

    # ── the one door ────────────────────────────────────────────────────────

    def recall(self, handle: str, query: str) -> Recall:
        with self._lock:
            entry = self._sessions.get(handle)
            if entry is not None:
                spent = self._spent[handle]
                if spent >= self._budget:
                    return Recall(Verdict.BUDGET_SPENT, (),
                                  f"this session has spent its {self._budget} recalls")
                # Charged before the work, and charged the same for every outcome.
                # A budget that only moved on a hit would be a counter the agent
                # could read the store with.
                self._spent[handle] = spent + 1
            rows = list(self._records)

        if entry is None:
            return _nothing()
        session, ceiling = entry
        if type(query) is not str or not query.strip() or len(query) > MAX_QUERY_CHARS:
            return _nothing()

        # Filter by the ceiling FIRST. Scoring first and filtering after would let a
        # high-labelled item take a result slot and come back as a short list, and a
        # short list is an answer.
        allowed = [r for r in rows if not r.human_only and ceiling.dominates(r.label)]

        # Score every stored row regardless, so the work done does not vary with how
        # much was filtered out.
        for r in rows:
            _relevance(query, r.text)

        scored = [(_relevance(query, r.text), i, r) for i, r in enumerate(allowed)]
        scored = [s for s in scored if s[0] >= self._min_relevance]
        scored.sort(key=lambda s: (-s[0], s[1]))
        top = [r for _, _, r in scored[:self._k]]
        if not top:
            return _nothing()

        # Deliver by observing: the session carries what it was given, so a draft it
        # writes afterwards is held at the label of what it recalled.
        out: List[Labeled] = []
        for r in top:
            item = Labeled(r.text, r.label, frozenset({f"memory:{r.origin}"}))
            session.observe(item)
            out.append(item)
        return Recall(Verdict.FOUND, tuple(out), "delivered")

    # ── introspection for operators, never for a handle ─────────────────────

    def stats(self) -> dict:
        with self._lock:
            return {"records": len(self._records),
                    "sessions": len(self._sessions),
                    "budget": self._budget, "k": self._k}
