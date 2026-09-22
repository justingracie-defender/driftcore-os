# SPDX-License-Identifier: Apache-2.0
"""
CLAIM release-follows-the-current-room: a held draft is released to a room only
when every member of a roster read at release time is cleared for the draft's
label, and a member added without an epoch change is still caught.

CLAIM future-members-count-where-history-shows: where new members can read
earlier messages, the room is cleared no higher than its join floor, which is
PUBLIC unless a human declared a higher one for that room.

CLAIM unreadable-roster-refuses: a roster that cannot be read, names no members,
answers for a different room, or comes from any platform but the one the gate was
built for releases nothing and holds nothing.

CLAIM unregistered-member-is-public: a member with no declared clearance counts
as PUBLIC.

CLAIM stale-roster-refuses: a draft held against one roster is not released to a
different one, even a fully cleared one; it has to be held again.

CLAIM one-minting-path: nothing is held unless the gate labelled it, either an
agent's words under its session's label or a registered drafter's output under the
label of what went in; no entry point takes a caller's label, and a context this
gate did not build, or one edited after it was built, is refused.

CLAIM drafter-is-registered: a clean draft comes only from a drafter registered
when the gate was built; a callable handed in at draft time is refused.

CLAIM the-drafter-has-seen-what-it-was-shown: every brief and item the gate hands
a drafter is recorded against that drafter's session before the call, so a drafter
shown a secret for one room carries it into the next draft instead of staying at
the label it was registered under. A drafter declared stateless is given a fresh
session built from its declared readable set on each call, so the declaration
changes the mechanism rather than switching the check off.

CLAIM the-seal-names-the-label-it-sealed: the context seal covers label_token() for
the brief and every item, so replacing a label with an incomparable one that prints
the same no longer verifies.

CLAIM the-audit-must-actually-write: an audit whose record() is async is refused
when the gate is built, and a receipt that turns out to be awaitable is not a
receipt: it is closed and the hold or release is refused as unrecorded.

CLAIM the-reviewer-sees-which-label: review() carries an id and a structured
level-and-compartments form for the draft's label, the room's clearance and its
join floor, because an id nobody renders does not make an approval unambiguous.

CLAIM draft-label-is-assigned-by-the-wall: a clean draft carries the join of the
brief, every item in the drafter's context and the drafter's own session label,
whatever the drafter returns, and a drafter that hands back its own label is
refused.

CLAIM drafter-sees-only-what-the-room-may-hold: the context builder passes the
drafter only labelled items the room's current audience dominates, and refuses a
bare value rather than guessing its label.

CLAIM tainted-brief-refuses: a brief the room's audience does not dominate refuses
the whole build, because otherwise the secret rides in on the task.

CLAIM agent-draft-carries-session-label: a draft the agent writes itself is held
under the join of every label its session could read, assigned by the wall; the
agent supplies words and never a label, so a paraphrase of a secret is held at the
secret's label.

CLAIM the-wall-owns-the-session: open_session() keeps the session and hands back
an unguessable handle. No object the caller builds decides the label, and neither
does a name the caller knows: an AgentSession subclass, a second session on a live
id, and another session's id are all refused, and the refusal does not say whether
that id exists. Reopening an open id is refused. A handle is a bearer capability:
in-process this is a discipline like every other stage here, and it holds against
an agent that knows the other session's name, not against one that can read the
other session's handle out of memory.

CLAIM held-label-is-current-at-commit: the label a ticket carries is re-checked
against its session at the moment the ticket is written, so a value handed to the
session while the roster was being read voids the hold instead of riding out under
the label that was true before it arrived.

CLAIM label-identity-is-injective: anything signed over or compared as a label
uses label_token(), because str(Label) joins compartments with a comma and so one
compartment named "a,b" prints the same as two named "a" and "b"; two labels
neither of which dominates the other never share an attestation string.

CLAIM text-committed-per-ticket: a draft is non-empty text within the size cap, and
each ticket commits to its text under a key the log does not hold, mixed with the
ticket id, so equal texts in different tickets leave different digests.

CLAIM exact-bytes-once: each ticket sends exactly the text it held, at most once,
and a spent ticket is refused by both release paths.

CLAIM human-release-binds-the-audience: a human release needs a verified
attestation naming this ticket, this room, this draft's digest and this roster; a
bare name or an attestation for anything else releases nothing.

CLAIM disclosure-needs-authority: a verified human releases a draft only if they
are a declared discloser whose own clearance dominates the draft's label.

CLAIM join-floor-needs-a-human: a join floor above PUBLIC is accepted only with a
verified attestation from its declared author naming this platform, that room and
that floor; the gate refuses to be built otherwise.

CLAIM floor-breach-is-not-a-routine-refusal: a roster with a member below the
room's declared join floor gets its own outcome, ahead of any stale-roster
refusal, and its record names the audience that was checked and the one found,
because anything released under that floor is now exposed.

CLAIM post-send-change-is-recorded: a roster that differs, at the read after a send,
from the one checked before it gets its own outcome and record instead of reading
as a clean delivery.

CLAIM sender-must-accept: an async sender is refused when the gate is built, and a
send counts as a delivery only when the sender returns the literal True. False,
None, an error string and an awaitable are all failed sends: a value that was
never a statement about delivery does not become one by being truthy.

CLAIM unrecorded-release-refuses: a hold or release whose audit write raises, or
returns no receipt, does not happen.

CLAIM spent-drafts-are-disposed: a spent, void or expired ticket keeps no draft,
and held drafts are capped in number and in age.

CLAIM review-shows-exposure: review shows the room's history visibility, join
floor, clearance and breach status, and offers no action to sign for a draft whose
room has changed or whose floor is breached.

CLAIM audit-names-the-audience-not-the-content: every record carries the audience
fingerprint, so two different rosters are distinguishable in the log; no record
carries the draft's text, and the digest is keyed so a short secret cannot be
recovered from the log by guessing.

WHAT THIS DOES NOT DO
─────────────────────
Status: built and tested, not wired. ActuationBroker does not route room sends
through this gate yet, so nothing in the pipeline depends on it until that wiring
exists and has been red-teamed on its own.

It does not close the Fry case where the join is not ours. With a join floor above
PUBLIC, an exposure of earlier history is found at the next roster read, not
prevented: the join happens on the platform and no gate method runs when it does.
Only a room whose joins DriftCore controls could close that, and that join gate is
not built. `history_visible` is the platform's statement, not a measurement.

It never reads a draft. Whether a draft may go out is decided by its label and by
who is in the room, not by what the words say. A human may read a held draft in
order to release it; the gate does not.

The agent-facing surface is hold_agent_draft and nothing else. build_context,
hold_clean_draft, release, release_by_human, review and pending belong on the
broker side of the OS boundary, and review() returns a draft's plaintext to
whoever calls it.

WHY THIS EXISTS
───────────────
test_redteam_audience_rebind.py showed that a sink is cleared for a name while
the audience behind the name can change. George joined the family chat, and the
next release to it was byte-for-byte an ordinary family send. The source is the
"George" test in Hannah Fry's 2026 video on AI agents. Two reviewers (Grok and
Astra, 2026-09-10) converged on the repair and disagreed about who owns the join.

The draft-and-release shape is Justin's, refined with Astra. Its weak point was a
rewrite loop: a model that saw the secret produces drafts that stay private
whatever they say, so asking it to rewrite can never end in a release, and judging
the rewrite would mean reading text. The loop is gone. Two exits remain: a clean
drafter whose context only ever held what the room may hold, or a human releasing
that specific disclosure.

Grok and Astra red-teamed v133 on 2026-09-11. All 17 findings reproduced against
v133 before anything changed, five of them things v133 had written down as limits
in words too soft to act on. This revision is the repair. What could not be
repaired is stated below in plainer terms than before.

HOW TO USE IT
─────────────
    gate = AudienceGate(
        platform="whatsapp:family-account",    # the only roster source accepted
        clearances={...},                      # a snapshot; a change needs a new gate
        roster_fn=platform_roster, send_fn=platform_send,
        audit=audit_chain,                     # record() returns a receipt, or failed
        drafters={"clean": Drafter(model_call, AgentSession("drafter", [PUBLIC]))},
        disclosers={"justin"},
        declarations=[RoomDeclaration("family", floor, "justin", attestation)])

    ctx = gate.build_context("family", brief, candidates)
    d   = gate.hold_clean_draft(ctx, "clean")
    d   = gate.release(d.ticket)             # or gate.release_by_human(...)

An agent's own draft goes through a session the wall opens and keeps. The agent
holds an id, never the object:

    gate.open_session("poppy-1", readable=[household_label, calendar_label])
    d = gate.hold_agent_draft("family", "poppy-1", text)   # agent side
    gate.observe_for("poppy-1", item)        # broker side, whatever it is handed

Declare every label the session can read. Declaring nothing is refused rather than
read as PUBLIC. A draft from a session that saw more than the room may hold can be
held, but only a declared discloser, cleared for the draft's label, can send it,
with an attestation naming this ticket, room, digest and roster. review(ticket)
gives the human surface the members, the draft, the room's exposure facts and,
while the room still matches, the exact action string to sign.
join_floor_action() gives the string a floor declaration must be signed over.

send_fn must be synchronous and must return the literal True once the platform has
accepted the message. Every other return, including None, is a failed send. An
adapter that sends correctly but returns nothing will be recorded as SEND_FAILED
until it is changed: that is the safe direction, but it is a contract change from
v134 and existing adapters need a line adding.

HONEST LIMITS
─────────────
* In-process this is a discipline, not a boundary. The guarantee needs the gate,
  the roster reader and the sender on the broker side of the OS boundary, like
  every other stage, with the agent reaching only hold_agent_draft.
* A drafter is registered with the session that says what it has seen, and that
  registration is trusted. A drafter that has seen a secret but is registered as
  [PUBLIC] launders it; test_audience_release.py demonstrates exactly that as a
  residual rather than claiming otherwise.
* Candidates and the brief are labelled by the wall code that reads them. The gate
  filters by label; it cannot check that a label is true.
* A roster is only as true as the platform reporting it. A platform that adds a
  member without changing the roster it reports defeats this.
* A join and a leave between the two roster reads are invisible unless the
  platform's epoch advances on every membership change. Two snapshots cannot see
  an interval, and preventing that exposure needs a platform send that is atomic
  with its audience.
* send_fn receives plaintext. The adapter and the platform are in the trusted base,
  and True means the platform accepted the message, not that it arrived.
* A session's label is re-checked when the ticket is written, which closes the gap
  between reading the label and committing. It does not close a read the wall never
  saw: observe_for() covers what the wall hands over, not what the agent fetches
  some other way.
* A join floor above PUBLIC is a human declaration and joins the trusted base. Its
  attestation is consumed when the gate is built, so a restart needs a fresh one:
  human_identity has no non-consuming verify path yet, the same gap that keeps the
  claims ledger from accepting any signature.
* Identifiers are metadata. Room names, session ids, origins, compartment names and
  human reasons appear in records, so none of them may carry a secret.
* A session's label is only as complete as the declaration of what it can read.
  A read path the wall does not know about leaves the label too low; observe()
  covers what the wall hands over, not what the agent fetches some other way.
* The audience fingerprint is a plain hash of member ids, so anyone who can guess
  the members can confirm them. It protects nothing secret and is not meant to.
* Tickets live in memory. A restart forgets held drafts, which is the safe
  direction: nothing held is ever sent by a process that no longer knows it.
"""

from __future__ import annotations

import hashlib
import secrets
import hmac
import inspect
import math
import os
import threading
import uuid
from dataclasses import dataclass
from enum import Enum
from time import monotonic as _monotonic
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple

from driftcore.audit.bounded_fields import (
    MAX_DETAIL_CHARS, AuditFieldRefused, bounded_reason)
from driftcore.authority.human_identity import is_human
from driftcore.governance.information_flow import (
    PUBLIC, FlowRefused, Label, Labeled)

# Caps. A draft is a chat message, and a hold is a queue for a human, not storage.
MAX_DRAFT_CHARS = 20_000
MAX_HELD = 1_000
MAX_HOLD_SECONDS = 86_400        # the same ceiling as a human attestation's TTL


class RosterUnreadable(FlowRefused):
    # Raised inside the gate when a roster cannot be trusted. Every public entry
    # point turns it into a refusal; none of them turns it into a default.
    pass


class BuildRefused(FlowRefused):
    pass


class _Unrecorded(Exception):
    # An audit write that raised, or came back without a receipt.
    pass


def meet_all(labels: Iterable[Label]) -> Label:
    # The greatest label every input dominates: the lowest level, and only the
    # compartments all of them share. An empty set has no meet, and an audience of
    # nobody is not an audience.
    items = list(labels)
    if not items:
        raise FlowRefused("the meet of no labels is undefined")
    for lab in items:
        if not isinstance(lab, Label):
            raise FlowRefused(f"meet over a non-Label {type(lab).__name__}")
    level = min((lab.level for lab in items), key=lambda v: v.value)
    compartments = frozenset.intersection(*(frozenset(lab.compartments) for lab in items))
    return Label(level, compartments)


def label_token(label: Label) -> str:
    # An injective spelling of a label. str(Label) is for reading, not for
    # identity: it joins compartments with a comma, so one compartment named
    # "a,b" and two named "a" and "b" print the same. Two labels that neither
    # dominates the other must not share the string an attestation is signed
    # over. Lengths first, same discipline the room and platform already get.
    if not isinstance(label, Label):
        raise FlowRefused(f"a label token needs a Label, not {type(label).__name__}")
    name = label.level.name
    parts = [f"{len(name)}:{name}", str(len(label.compartments))]
    for c in sorted(label.compartments):
        parts.append(f"{len(c)}:{c}")
    return "|".join(parts)


def _label_parts(label: Label) -> dict:
    # The structured form. An approval surface can show the level and each
    # compartment separately, which is the only rendering in which "a,b" as one
    # compartment reads differently from "a" and "b" as two.
    return {"level": label.level.name,
            "compartments": sorted(label.compartments)}


def join_floor_action(platform: str, room: str, floor: Label) -> str:
    # What a floor declaration's attestation must name. Lengths first, so a colon
    # inside a platform or room name cannot move the boundary between them, and
    # the floor is spelled injectively so one floor's attestation cannot verify
    # a different, incomparable floor.
    return (f"audience_join_floor:{len(platform)}:{platform}:"
            f"{len(room)}:{room}:{label_token(floor)}")


@dataclass(frozen=True)
class Roster:
    # What the platform says about a room at the moment it was asked. `epoch` is
    # the platform's own membership version; `history_visible` is whether someone
    # who joins later can read what was sent before they joined; `source` names the
    # platform that answered.
    room: str
    members: FrozenSet[str]
    history_visible: bool
    epoch: int
    source: str

    def __post_init__(self):
        if not isinstance(self.room, str) or not self.room or "\x00" in self.room:
            raise RosterUnreadable("a roster must name its room")
        if not isinstance(self.members, frozenset) or not self.members:
            raise RosterUnreadable(f"the roster for {self.room!r} names no members")
        for m in self.members:
            if not isinstance(m, str) or not m or "\x00" in m:
                raise RosterUnreadable(
                    f"the roster for {self.room!r} has an unusable member id")
        # Literal booleans only. A history flag of 1 or "no" is not a statement
        # about the platform, and guessing its meaning is guessing the audience.
        if self.history_visible is not True and self.history_visible is not False:
            raise RosterUnreadable(
                f"the roster for {self.room!r} does not say whether history is visible")
        if type(self.epoch) is not int:
            raise RosterUnreadable(f"the roster for {self.room!r} has no integer epoch")
        if not isinstance(self.source, str) or not self.source or "\x00" in self.source:
            raise RosterUnreadable(f"the roster for {self.room!r} names no source")


@dataclass(frozen=True)
class RoomDeclaration:
    # A human statement about who can ever be added to a room. It only matters
    # where history is visible, and it is part of the trusted base, like an effect
    # declaration. Above PUBLIC it needs an attestation from its declared author.
    room: str
    join_floor: Label
    declared_by: str
    attestation: Any = None

    def __post_init__(self):
        if not isinstance(self.room, str) or not self.room:
            raise FlowRefused("a room declaration must name its room")
        if not isinstance(self.join_floor, Label):
            raise FlowRefused(f"the join floor for {self.room!r} is not a Label")
        if not isinstance(self.declared_by, str) or not self.declared_by.strip():
            raise FlowRefused(
                f"the join floor for {self.room!r} has no declared_by; a floor is a "
                f"safety-critical declaration and must be attributable")


@dataclass(frozen=True)
class DraftContext:
    # What a clean drafter may see. `withheld` is for the operator and never
    # reaches the drafter: telling a model what it was not shown is a hint. `seal`
    # binds the context to the gate that built it, so a hand-made or edited one is
    # refused rather than drafted from.
    room: str
    brief: Labeled
    items: Tuple[Labeled, ...]
    audience: str
    withheld: int
    seal: str = ""


class Outcome(Enum):
    HELD = "held"
    HELD_FOR_HUMAN = "held_for_human"
    RELEASED = "released"
    RELEASED_ROSTER_MOVED = "released_roster_moved"
    SEND_FAILED = "send_failed"
    REFUSED_LABEL = "refused_label"
    REFUSED_STALE = "refused_stale"
    REFUSED_ROSTER = "refused_roster"
    REFUSED_FLOOR_BREACH = "refused_floor_breach"
    REFUSED_SPENT = "refused_spent"
    REFUSED_HUMAN = "refused_human"
    REFUSED_UNRECORDED = "refused_unrecorded"
    REFUSED_FORMAT = "refused_format"
    REFUSED_CAPACITY = "refused_capacity"


_SENT = frozenset({Outcome.RELEASED, Outcome.RELEASED_ROSTER_MOVED})


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    ticket: Optional[str]
    room: str
    audience: str
    reason: str

    @property
    def sent(self) -> bool:
        return self.outcome in _SENT


class _Ticket:
    # States: held -> releasing -> spent, or held -> void, or held -> expired.
    # Spent, void and expired tickets are removed with their text. Only the gate
    # touches these, always under its lock.
    __slots__ = ("tid", "room", "value", "label", "origins", "digest", "audience",
                 "held_at", "state")

    def __init__(self, tid, room, value, label, origins, digest, audience, held_at):
        self.tid, self.room, self.value, self.label = tid, room, value, label
        self.origins, self.digest, self.audience = origins, digest, audience
        self.held_at, self.state = held_at, "held"


def _audience_fingerprint(r: Roster) -> str:
    # Platform, room, epoch, history flag and every member id. NUL cannot occur
    # inside a part (Roster refuses it), so the parts cannot run into each other.
    h = hashlib.sha256()
    for part in (r.source, r.room, str(r.epoch), "1" if r.history_visible else "0",
                 *sorted(r.members)):
        h.update(part.encode("utf-8") + b"\x00")
    return h.hexdigest()


def _human_action(ticket: str, room: str, digest: str, audience: str) -> str:
    # The ticket first and the digest and fingerprint last, all fixed-length hex,
    # so the string is unambiguous whatever the room name contains.
    return f"audience_release:{ticket}:{room}:{digest}:{audience}"


def _awaitable_receipt(receipt: Any) -> bool:
    # A coroutine is truthy. Treating one as a receipt records nothing and reports
    # success, so it is refused here and closed so it leaves no warning behind.
    if inspect.isawaitable(receipt):
        close = getattr(receipt, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass
        return True
    return False


def _is_async(fn: Any) -> bool:
    return (inspect.iscoroutinefunction(fn) or inspect.isasyncgenfunction(fn)
            or inspect.iscoroutinefunction(getattr(fn, "__call__", None)))


class AgentSession:
    # What one agent session could read, kept on the wall's side. Its label is the
    # join of every label declared readable for it, plus anything handed to it
    # through observe(), and it only rises. Declaring nothing is refused rather than
    # read as PUBLIC: "nobody said" must not become "there was nothing".
    def __init__(self, session_id: str, readable: Iterable[Label]):
        if not isinstance(session_id, str) or not session_id.strip():
            raise FlowRefused("an agent session needs an id")
        labels = list(readable)
        if not labels:
            raise FlowRefused(
                f"session {session_id!r} declares nothing readable; declare [PUBLIC] "
                f"if it reads nothing private")
        for lab in labels:
            if not isinstance(lab, Label):
                raise FlowRefused(
                    f"readable entries must be Labels, not {type(lab).__name__}")
        label = PUBLIC
        for lab in labels:
            label = label.join(lab)
        self._id = session_id
        self._label = label
        self._version = 0
        self._lock = threading.Lock()

    @property
    def session_id(self) -> str:
        return self._id

    @property
    def label(self) -> Label:
        with self._lock:
            return self._label

    def snapshot(self) -> Tuple[Label, int]:
        # The label and the count of observations behind it, read together. A hold
        # that reads these separately can hold a draft under a label that stopped
        # being true between the two reads.
        with self._lock:
            return self._label, self._version

    def observe(self, item: Labeled) -> Any:
        # Everything the wall hands the session passes through here and raises its
        # label to cover it. There is no way to lower it short of a new session.
        if not isinstance(item, Labeled):
            raise FlowRefused("a session is handed labelled values only")
        with self._lock:
            self._label = self._label.join(item.label)
            # Bumped whether or not the join moved the label: the ticket's question
            # is "did anything arrive while I was holding", not "did it raise".
            self._version += 1
        return item.value

    def labelled(self, value: Any) -> Labeled:
        # Anything the agent writes: its words under the session's label.
        return Labeled(value, self.label, frozenset({f"agent:{self._id}"}))


@dataclass(frozen=True)
class Drafter:
    # A model call registered when the gate is built, together with the session
    # that says what it has seen. For a fresh, tool-less call that is [PUBLIC]. A
    # drafter that has seen more carries it into every draft it writes.
    fn: Callable[[Tuple[str, ...]], Any]
    session: AgentSession
    # A stateless drafter keeps nothing between calls. Declaring it does not turn
    # a check off: the gate gives a stateless drafter a fresh session built from
    # its declared readable set on every invocation, so there is nothing to carry.
    # The default is stateful, because a callable that remembers is the normal case
    # and the safe reading of an undeclared one.
    stateless: bool = False
    readable: Tuple[Label, ...] = ()

    def __post_init__(self):
        if not callable(self.fn):
            raise BuildRefused("a drafter needs a callable")
        if self.stateless is not True and self.stateless is not False:
            raise BuildRefused("stateless is declared True or False, nothing else")
        if _is_async(self.fn):
            raise BuildRefused("a drafter is called synchronously; an async one would "
                               "hand back a coroutine instead of a draft")
        if not isinstance(self.session, AgentSession):
            raise BuildRefused("a drafter needs the wall's AgentSession for what it "
                               "has seen")
        if self.stateless and not self.readable:
            raise BuildRefused(
                "a stateless drafter declares the labels its fresh session starts "
                "from; the gate rebuilds that session on every call")


class AudienceGate:
    def __init__(self, *, platform: str,
                 clearances: Mapping[str, Label],
                 roster_fn: Callable[[str], Roster],
                 send_fn: Callable[[str, str], Any],
                 audit: Any,
                 declarations: Iterable[RoomDeclaration] = (),
                 drafters: Optional[Mapping[str, Drafter]] = None,
                 disclosers: Iterable[str] = (),
                 max_draft_chars: int = MAX_DRAFT_CHARS,
                 max_held: int = MAX_HELD,
                 max_hold_seconds: int = MAX_HOLD_SECONDS):
        # All of this is broker-side configuration. The agent reaches the gate only
        # through hold_agent_draft on the broker socket: review() returns plaintext,
        # and every other method decides what is sent.
        if not isinstance(platform, str) or not platform or "\x00" in platform:
            raise FlowRefused("a gate is built for one named platform")
        if not isinstance(clearances, Mapping):
            raise FlowRefused("clearances must map principal ids to Labels")
        snapshot: Dict[str, Label] = {}
        for who, lab in clearances.items():
            if not isinstance(who, str) or not who or not isinstance(lab, Label):
                raise FlowRefused("every clearance maps a non-empty id to a Label")
            snapshot[who] = lab
        # A snapshot: later edits to the caller's mapping change nothing here.
        self._clearances = snapshot
        if not callable(roster_fn) or not callable(send_fn):
            raise FlowRefused("roster_fn and send_fn must both be callable")
        if _is_async(send_fn):
            raise FlowRefused("send_fn is async; the gate calls it synchronously and "
                              "would record a delivery that never ran")
        if audit is None or not callable(getattr(audit, "record", None)):
            raise FlowRefused("a gate without an audit sink would release unrecorded")
        if _is_async(getattr(audit, "record")):
            # The same rule the sender gets. An async record() returns a coroutine
            # whose body never ran; the coroutine is truthy, so it read as a
            # receipt and a release went out with nothing written down.
            raise FlowRefused(
                "the audit's record() is async; it would hand back a coroutine "
                "instead of writing, and every release would look recorded")
        for name, cap in (("max_draft_chars", max_draft_chars), ("max_held", max_held),
                          ("max_hold_seconds", max_hold_seconds)):
            if type(cap) is not int or cap < 1:
                raise FlowRefused(f"{name} must be a positive integer")
        # Written as a rejecting range that raises, so a non-finite value takes the
        # raise rather than the allow branch. An int cannot be NaN, but the shape
        # should not depend on a type check three lines up to stay safe.
        if not 1 <= max_hold_seconds <= MAX_HOLD_SECONDS:
            raise FlowRefused(f"max_hold_seconds must be 1..{MAX_HOLD_SECONDS}")
        self._platform = platform
        self._roster_fn = roster_fn
        self._send_fn = send_fn
        self._audit = audit
        self._max_chars = max_draft_chars
        self._max_held = max_held
        self._max_hold = max_hold_seconds
        regs: Dict[str, Drafter] = {}
        for name, d in dict(drafters or {}).items():
            if not isinstance(name, str) or not name or not isinstance(d, Drafter):
                raise FlowRefused("drafters maps a non-empty name to a Drafter")
            regs[name] = d
        self._drafters = regs
        if isinstance(disclosers, str):
            raise FlowRefused("disclosers is a collection of principal ids, not one id")
        who_may = frozenset(disclosers)
        for p in who_may:
            if not isinstance(p, str) or not p:
                raise FlowRefused("disclosers are non-empty principal ids")
        self._disclosers = who_may
        self._tickets: Dict[str, _Ticket] = {}
        # The wall's sessions, by id. An agent names a session; it never hands one
        # in. Nothing the agent can construct is accepted as a session, so neither
        # a subclass that reports PUBLIC nor a second session built on the same id
        # with a lower label reaches a hold.
        self._sessions: Dict[str, AgentSession] = {}   # handle -> session
        self._session_ids: set = set()                 # ids in use, for reopen
        self._lock = threading.Lock()
        # Keyed so the digest in the log cannot be matched against guesses. A
        # four-digit code has ten thousand candidates; a plain hash gives it away.
        self._digest_key = os.urandom(32)
        decls: Dict[str, RoomDeclaration] = {}
        for d in declarations:
            if not isinstance(d, RoomDeclaration):
                raise FlowRefused(f"declarations must be RoomDeclaration, not {type(d).__name__}")
            if d.room in decls:
                raise FlowRefused(f"room {d.room!r} is declared twice")
            if not PUBLIC.dominates(d.join_floor):
                self._verify_floor(d)
            decls[d.room] = d
        self._declarations = decls

    def _verify_floor(self, d: RoomDeclaration) -> None:
        # A floor above PUBLIC lets more into a room whose history later members can
        # read, so it is authority-expanding and gets the same proof as a release:
        # a verified attestation, from the author it names, for exactly this floor.
        att = d.attestation
        if getattr(att, "principal", None) != d.declared_by:
            raise FlowRefused(f"the join floor for {d.room!r} is not attested by its "
                              f"declared author {d.declared_by!r}")
        action = join_floor_action(self._platform, d.room, d.join_floor)
        if not is_human(att, action=action, attestation_required=True):
            raise FlowRefused(f"the join floor {d.join_floor} for {d.room!r} has no "
                              f"verified attestation naming it")

    # ── reading the room ────────────────────────────────────────────────────

    def _read(self, room: str):
        try:
            r = self._roster_fn(room)
        except Exception as e:
            raise RosterUnreadable(
                f"the roster for {room!r} could not be read ({type(e).__name__})")
        if not isinstance(r, Roster):
            raise RosterUnreadable(
                f"the roster reader returned {type(r).__name__}, not a Roster")
        if r.room != room:
            raise RosterUnreadable(f"asked about {room!r}, the reader answered {r.room!r}")
        if r.source != self._platform:
            raise RosterUnreadable(f"the roster for {room!r} came from {r.source!r}, "
                                   f"not {self._platform!r}")
        decl = self._declarations.get(room)
        floor = decl.join_floor if decl is not None else PUBLIC
        cleared = [self._clearances.get(m, PUBLIC) for m in r.members]
        clearance = meet_all(cleared)
        if r.history_visible:
            clearance = meet_all([clearance, floor])
        breached = any(not c.dominates(floor) for c in cleared)
        return r, clearance, _audience_fingerprint(r), breached

    def _digest(self, ticket: str, text: str) -> str:
        # Keyed, and mixed with the ticket, so the log cannot be matched against
        # guesses and one ticket's digest says nothing about another's.
        return hmac.new(self._digest_key,
                        ticket.encode("ascii") + b"\x00" + text.encode("utf-8"),
                        hashlib.sha256).hexdigest()

    def _seal_of(self, room: str, brief: Labeled, items: Tuple[Labeled, ...],
                 audience: str) -> str:
        h = hmac.new(self._digest_key, b"audience_release:context\x00", hashlib.sha256)
        # label_token, not str(Label): str() joins compartments with a comma, so
        # swapping one compartment "a,b" for two named "a" and "b" — incomparable
        # labels — left the seal verifying. The seal must name the label it sealed.
        for part in (room, audience, label_token(brief.label), brief.value,
                     *(x for it in items
                       for x in (label_token(it.label), it.value))):
            b = part.encode("utf-8")
            h.update(len(b).to_bytes(8, "big") + b)
        return h.hexdigest()

    def _text_problem(self, value: Any) -> Optional[str]:
        # A draft is text. One type means one serialisation, so the digest a human
        # approves and the bytes the platform receives are the same thing.
        if type(value) is not str:
            return f"a draft is text, not {type(value).__name__}"
        if not value.strip():
            return "a draft cannot be empty"
        if len(value) > self._max_chars:
            return f"the draft is {len(value)} characters; the cap is {self._max_chars}"
        return None

    # ── the clean drafter ───────────────────────────────────────────────────

    def build_context(self, room: str, brief: Labeled,
                      candidates: Iterable[Labeled]) -> DraftContext:
        try:
            r, clearance, fp, breached = self._read(room)
        except RosterUnreadable as e:
            raise BuildRefused(e.operator_detail)
        if breached:
            raise BuildRefused(f"room {room!r} has a member below its declared join floor")
        if not isinstance(brief, Labeled):
            raise BuildRefused("the brief is unlabelled; a task of unknown provenance "
                               "may carry anything")
        if type(brief.value) is not str:
            raise BuildRefused("the brief is not text")
        if not clearance.dominates(brief.label):
            raise BuildRefused(f"the brief carries {brief.label}, which room {room!r} "
                               f"may not hold")
        kept: List[Labeled] = []
        withheld = 0
        for c in list(candidates):
            if not isinstance(c, Labeled):
                raise BuildRefused(f"a candidate is a bare {type(c).__name__}; label it "
                                   f"at its source")
            if clearance.dominates(c.label):
                if type(c.value) is not str:
                    raise BuildRefused("a candidate the drafter would see is not text")
                kept.append(c)
            else:
                withheld += 1
        items = tuple(kept)
        return DraftContext(room=room, brief=brief, items=items, audience=fp,
                            withheld=withheld,
                            seal=self._seal_of(room, brief, items, fp))

    def hold_clean_draft(self, context: DraftContext, drafter: str) -> Decision:
        if not isinstance(context, DraftContext):
            raise BuildRefused("hold_clean_draft takes a DraftContext from build_context()")
        parts = (context.brief,) + tuple(context.items)
        for p in parts:
            if not isinstance(p, Labeled) or type(p.value) is not str:
                raise BuildRefused("a draft context holds only labelled text")
        if (type(context.room) is not str or type(context.audience) is not str
                or type(context.seal) is not str):
            raise BuildRefused("a draft context names its room, audience and seal")
        expected = self._seal_of(context.room, context.brief, tuple(context.items),
                                 context.audience)
        if not hmac.compare_digest(context.seal.encode("utf-8"), expected.encode("ascii")):
            raise BuildRefused("this gate did not build that context, or it was edited")
        reg = self._drafters.get(drafter) if isinstance(drafter, str) else None
        if reg is None:
            raise BuildRefused("name a drafter registered when the gate was built; a "
                               "callable is not accepted here")
        origins = {f"drafter:{drafter}"}
        for p in parts:
            origins |= set(p.origins)
        # A stateless drafter is handed a session built fresh for this call, so
        # nothing this context contains can reach the next one. A stateful one
        # keeps its session, and that session must record what it is about to be
        # shown: v135 filtered the context to what the room could hold and then
        # forgot it, so a drafter given a secret for one room stayed PUBLIC and
        # repeated it into another.
        session = (AgentSession(f"{drafter}:{uuid.uuid4().hex}", reg.readable)
                   if reg.stateless else reg.session)
        for p in parts:
            # Before the call, not after: a drafter that fails partway through has
            # still been shown its inputs.
            session.observe(p)
        try:
            out = reg.fn(tuple(p.value for p in parts))
        except Exception as e:
            raise BuildRefused(f"the drafter failed ({type(e).__name__})") from e
        # The label comes from what went in and from what the drafter itself has
        # seen, recomputed here and never read back from the drafter. Read *after*
        # the call: a drafter that observes something while it runs has seen it,
        # and a label read before the call would not cover it.
        label = session.label
        for p in parts:
            label = label.join(p.label)
        if isinstance(out, Labeled):
            raise BuildRefused("the drafter returned its own label; the wall assigns it")
        return self._hold(context.room, out, label, frozenset(origins))

    # ── sessions (broker side) ──────────────────────────────────────────────

    def open_session(self, session_id: str, readable: Iterable[Label]) -> str:
        # Broker side. The wall builds the session, keeps it, and hands back an
        # unguessable handle. v135 handed back the session id, which meant an
        # agent that knew another session's id could hold a draft under that
        # session's label: naming is not authority. A handle is the authority, so
        # an agent can only ever speak for the session it was given.
        session = AgentSession(session_id, readable)
        with self._lock:
            if session.session_id in self._session_ids:
                raise FlowRefused(
                    f"session {session.session_id!r} is already open; a session's "
                    f"label only rises, so a new one on the same id would lower it")
            handle = "sh_" + secrets.token_urlsafe(24)
            self._sessions[handle] = session
            self._session_ids.add(session.session_id)
        return handle

    def adopt_session(self, session: AgentSession) -> str:
        # Broker side. Registers a session the wall already built — the case where
        # one session is shared with another gate, such as memory_gate, so that what
        # it recalls there is carried by what it drafts here. Same trust level as
        # open_session: it takes a real AgentSession from the broker, never from an
        # agent, and the id rule is unchanged.
        if not isinstance(session, AgentSession):
            raise FlowRefused("adopt_session takes the wall's AgentSession")
        with self._lock:
            if session.session_id in self._session_ids:
                raise FlowRefused(
                    f"session {session.session_id!r} is already open; a session's "
                    f"label only rises, so a new one on the same id would lower it")
            handle = "sh_" + secrets.token_urlsafe(24)
            self._sessions[handle] = session
            self._session_ids.add(session.session_id)
        return handle

    def observe_for(self, session_id: str, item: Labeled) -> Any:
        # Broker side. Whatever the wall hands a session goes through here, so the
        # session the gate holds is the one whose label rises.
        return self._session(session_id).observe(item)

    def session_label(self, session_id: str) -> Label:
        return self._session(session_id).label

    def close_session(self, handle: str) -> None:
        # Broker side. Retires a handle and frees its id for a later session.
        with self._lock:
            s = self._sessions.pop(handle, None)
            if s is not None:
                self._session_ids.discard(s.session_id)

    def _session(self, handle: str) -> AgentSession:
        if type(handle) is not str:
            raise FlowRefused(
                f"a session is reached through the handle open_session() returned, "
                f"not handed in as {type(handle).__name__}; the wall keeps the session")
        with self._lock:
            s = self._sessions.get(handle)
        if s is None:
            # The handle, never the session id: an id that exists must not be
            # distinguishable from one that does not.
            raise FlowRefused("that is not an open session handle")
        return s

    # ── holding ─────────────────────────────────────────────────────────────

    def hold_agent_draft(self, room: str, handle: str, text: Any) -> Decision:
        # The agent supplies words and the handle for its own session. The label
        # comes from that session. Neither a session object nor another session's
        # id is accepted: the caller never chooses which label it writes under.
        try:
            session = self._session(handle)
        except FlowRefused as e:
            # operator_detail, not str(e): the generic form names no mechanism, and
            # a session id is the agent's own handle, not something to withhold.
            return self._refuse(Outcome.REFUSED_LABEL, None, room, "",
                                e.operator_detail)
        if isinstance(text, Labeled):
            return self._refuse(Outcome.REFUSED_LABEL, None, room, "",
                                "the agent supplies words, not a label")
        label, version = session.snapshot()
        return self._hold(room, text, label,
                          frozenset({f"agent:{session.session_id}"}),
                          session=session, version=version)

    def _hold(self, room: str, value: Any, label: Label,
              origins: FrozenSet[str], *,
              session: Optional[AgentSession] = None,
              version: Optional[int] = None) -> Decision:
        # `session`/`version` carry the snapshot the label came from. Reading the
        # roster is not instant, and observe() can run on another thread while it
        # happens, so the label is re-checked at the moment the ticket is written.
        problem = self._text_problem(value)
        if problem is not None:
            return self._refuse(Outcome.REFUSED_FORMAT, None, room, "", problem)
        try:
            r, clearance, fp, breached = self._read(room)
        except RosterUnreadable as e:
            return self._refuse(Outcome.REFUSED_ROSTER, None, room, "", e.operator_detail)
        if breached:
            return self._refuse(Outcome.REFUSED_FLOOR_BREACH, None, room, fp,
                                "a member is below the room's declared join floor; "
                                "what was released under it is exposed")
        outcome = Outcome.HELD if clearance.dominates(label) else Outcome.HELD_FOR_HUMAN
        tid = uuid.uuid4().hex
        digest = self._digest(tid, value)
        now = _monotonic()
        with self._lock:
            self._expire_locked(now)
            if session is not None:
                now_label, now_version = session.snapshot()
                if now_version != version:
                    # Something was handed to the session while this draft was
                    # being held. The label that was checked is not the label the
                    # session has, so the check is void rather than nearly right.
                    return self._refuse(
                        Outcome.REFUSED_LABEL, None, room, fp,
                        f"session {session.session_id!r} observed while the draft "
                        f"was held; it now carries {now_label}, held against "
                        f"{label}. Hold it again.")
            if len(self._tickets) >= self._max_held:
                full = True
            else:
                full = False
                try:
                    self._record_event(f"AUDIENCE_{outcome.name}", room, fp,
                                       len(r.members), label, origins, digest,
                                       by="system", ticket=tid)
                except _Unrecorded as e:
                    return Decision(Outcome.REFUSED_UNRECORDED, None, room, fp,
                                    f"audit write failed ({e}); nothing held")
                self._tickets[tid] = _Ticket(tid, room, value, label, origins, digest,
                                             fp, now)
        if full:
            return self._refuse(Outcome.REFUSED_CAPACITY, None, room, fp,
                                f"{self._max_held} drafts are already held")
        return Decision(outcome, tid, room, fp, "held")

    def review(self, ticket: str) -> dict:
        # For the human surface only. It returns the draft's plaintext and the room's
        # exposure facts, and the exact action string to sign only while the room
        # still matches the roster the draft was held against and no floor is
        # breached: a string that could never release the draft is not offered.
        now = _monotonic()
        with self._lock:
            self._expire_locked(now)
            t = self._tickets.get(ticket) if isinstance(ticket, str) else None
            if t is None or t.state != "held":
                raise FlowRefused("no held draft with that ticket")
            room, value, label, digest = t.room, t.value, t.label, t.digest
            held_fp, origins = t.audience, t.origins
        r, clearance, fp, breached = self._read(room)
        decl = self._declarations.get(room)
        floor = decl.join_floor if decl is not None else PUBLIC
        stale = fp != held_fp
        return {"ticket": ticket, "room": room, "platform": self._platform,
                "members": sorted(r.members), "label": str(label),
                # str(Label) is for reading and is not injective. Every label a
                # reviewer is shown carries an id and a structured form beside it,
                # so an approval surface can render the distinction rather than
                # holding an id nobody displays. v135 gave the draft's label an id
                # and left the clearance and the floor ambiguous, which is the pair
                # that decides whether the draft may go.
                "label_id": label_token(label),
                "label_parts": _label_parts(label), "value": value,
                "origins": sorted(origins), "digest": digest, "audience": fp,
                "history_visible": r.history_visible, "join_floor": str(floor),
                "join_floor_id": label_token(floor),
                "join_floor_parts": _label_parts(floor),
                "clearance": str(clearance), "clearance_id": label_token(clearance),
                "clearance_parts": _label_parts(clearance),
                "cleared": clearance.dominates(label),
                "breached": breached, "stale": stale,
                "action": None if (stale or breached)
                else _human_action(ticket, room, digest, fp)}

    def pending(self) -> int:
        # How many drafts are held or being sent. Expired ones are dropped first.
        now = _monotonic()
        with self._lock:
            self._expire_locked(now)
            return len(self._tickets)

    # ── releasing ───────────────────────────────────────────────────────────

    def release(self, ticket: str) -> Decision:
        t = self._reserve(ticket)
        if t is None:
            return self._refuse(Outcome.REFUSED_SPENT, ticket, "", "",
                                "unknown, spent, void or expired ticket")
        checked = self._recheck(t, ticket)
        if isinstance(checked, Decision):
            return checked
        r, clearance, fp = checked
        if not clearance.dominates(t.label):
            self._settle(t, "held")
            return self._refuse(Outcome.REFUSED_LABEL, ticket, t.room, fp,
                                f"{t.label} exceeds what this room may hold; only a "
                                f"human release can send it")
        return self._dispatch_held(t, ticket, fp, len(r.members), by="system", reason="")

    def release_by_human(self, ticket: str, attestation: Any, reason: str) -> Decision:
        try:
            bounded_reason(reason, field="human release reason")
        except AuditFieldRefused as e:
            return Decision(Outcome.REFUSED_HUMAN, ticket, "", "", str(e))
        t = self._reserve(ticket)
        if t is None:
            return self._refuse(Outcome.REFUSED_SPENT, ticket, "", "",
                                "unknown, spent, void or expired ticket")
        checked = self._recheck(t, ticket)
        if isinstance(checked, Decision):
            return checked
        r, _clearance, fp = checked
        action = _human_action(ticket, t.room, t.digest, fp)
        if not is_human(attestation, action=action, attestation_required=True):
            self._settle(t, "held")
            return self._refuse(Outcome.REFUSED_HUMAN, ticket, t.room, fp,
                                "no verified attestation for this ticket, room, draft "
                                "and roster")
        principal = getattr(attestation, "principal", "")
        # Being a verified human is identity. Disclosing this label to this room is
        # authority: a declared discloser who could read the draft themselves.
        if (principal not in self._disclosers
                or not self._clearances.get(principal, PUBLIC).dominates(t.label)):
            self._settle(t, "held")
            return self._refuse(Outcome.REFUSED_HUMAN, ticket, t.room, fp,
                                f"{principal!r} may not disclose {t.label}")
        return self._dispatch_held(t, ticket, fp, len(r.members), by=principal,
                                   reason=reason)

    def _recheck(self, t: _Ticket, ticket: str):
        # Shared by both release paths: re-read the room, refuse a breached floor,
        # then refuse a changed room. The breach comes first because a member below
        # the floor exposes what was already released, which is a different
        # incident from a draft that merely needs holding again.
        try:
            r, clearance, fp, breached = self._read(t.room)
        except RosterUnreadable as e:
            self._settle(t, "held")
            return self._refuse(Outcome.REFUSED_ROSTER, ticket, t.room, "",
                                e.operator_detail)
        if breached:
            self._settle(t, "void")
            return self._refuse(Outcome.REFUSED_FLOOR_BREACH, ticket, t.room, fp,
                                f"a member is below the room's declared join floor; "
                                f"checked={t.audience} found={fp}; what was released "
                                f"under the floor is exposed")
        if fp != t.audience:
            self._settle(t, "void")
            return self._refuse(Outcome.REFUSED_STALE, ticket, t.room, fp,
                                "the room changed after the draft was held; hold it again")
        return r, clearance, fp

    def _dispatch_held(self, t: _Ticket, ticket: str, fp: str, n: int, *, by: str,
                       reason: str) -> Decision:
        try:
            self._record_event("AUDIENCE_RELEASING", t.room, fp, n, t.label, t.origins,
                               t.digest, by=by, ticket=ticket, reason=reason)
        except _Unrecorded as e:
            self._settle(t, "held")
            return Decision(Outcome.REFUSED_UNRECORDED, ticket, t.room, fp,
                            f"audit write failed ({e}); nothing sent")
        try:
            result = self._send_fn(t.room, t.value)
        except Exception as e:
            # Delivery unknown. The ticket is spent rather than retried: a send
            # that may have happened is not repeated on a guess.
            self._settle(t, "spent")
            return self._refuse(Outcome.SEND_FAILED, ticket, t.room, fp,
                                f"send raised {type(e).__name__}; delivery unknown")
        self._settle(t, "spent")
        if inspect.isawaitable(result):
            if inspect.iscoroutine(result):
                result.close()
            return self._refuse(Outcome.SEND_FAILED, ticket, t.room, fp,
                                "the sender returned an awaitable, which was not "
                                "awaited; delivery unknown")
        if result is not True:
            # Only a literal True is an acceptance. `None` is what a sender that
            # forgot to report returns, and an error string is truthy, so anything
            # looser records a delivery on the strength of a value that was never
            # a statement about delivery. Truthiness is not consent, and it is not
            # acknowledgement either.
            return self._refuse(Outcome.SEND_FAILED, ticket, t.room, fp,
                                f"the sender returned {type(result).__name__}, not "
                                f"True; a delivery is acknowledged or it is not")
        moved = self._moved_since(t.room, fp)
        outcome = Outcome.RELEASED_ROSTER_MOVED if moved else Outcome.RELEASED
        why = ("the roster moved during delivery; treat as a possible exposure"
               if moved else "released")
        try:
            self._record_event(f"AUDIENCE_{outcome.name}", t.room, fp, n, t.label,
                               t.origins, t.digest, by=by, ticket=ticket, reason=reason)
        except _Unrecorded as e:
            # The release was recorded before the send. Say so in the decision
            # rather than dropping the second record in silence.
            return Decision(outcome, ticket, t.room, fp,
                            f"{why}; the post-send record failed ({e})")
        return Decision(outcome, ticket, t.room, fp, why)

    def _moved_since(self, room: str, fp: str) -> bool:
        # After a send: did the audience change? A roster that cannot be read cannot
        # confirm who received it, so it counts as moved.
        try:
            _r, _c, after, _b = self._read(room)
        except RosterUnreadable:
            return True
        return after != fp

    # ── ticket state and records ────────────────────────────────────────────

    def _expire_locked(self, now: float) -> None:
        # A held draft older than the hold's lifetime, or stamped by a clock reading
        # now in the future, is dropped with its text. Tickets being sent are left
        # alone; spent and void ones are already gone.
        for tid in [k for k, t in self._tickets.items()
                    if t.state == "held" and not self._still_young(now, t.held_at)]:
            del self._tickets[tid]

    def _still_young(self, now: float, held_at: float) -> bool:
        # A clock that cannot say what time it is cannot establish that a hold is
        # still within its lifetime, so a non-finite reading expires the draft
        # instead of keeping it. Note which half of this does the work: NaN is false
        # against every comparison, so the age test below ALREADY answers "not
        # young" and the caller drops the draft. The isfinite call states that
        # intent instead of leaving it resting on the direction the test happens to
        # be written in — write it as `not (age > cap)` and NaN keeps the secret.
        cap = self._max_hold
        if not math.isfinite(now) or not math.isfinite(held_at) or not math.isfinite(cap):
            return False
        return 0 <= now - held_at <= cap

    def _reserve(self, ticket: str) -> Optional[_Ticket]:
        now = _monotonic()
        with self._lock:
            self._expire_locked(now)
            t = self._tickets.get(ticket) if isinstance(ticket, str) else None
            if t is None or t.state != "held":
                return None
            t.state = "releasing"
            return t

    def _settle(self, t: _Ticket, state: str) -> None:
        with self._lock:
            t.state = state
            if state != "held":
                # Spent or void: the ticket and its text go. A later call with this
                # ticket is refused as unknown, which is all a spent ticket needs.
                self._tickets.pop(t.tid, None)
                t.value = ""

    def _record_event(self, action: str, room: str, fp: str, n: int, label: Label,
                      origins: FrozenSet[str], digest: str, *, by: str, ticket: str,
                      reason: str = "") -> None:
        detail = (f"audience={fp} room={room} members={n} label={label} "
                  f"digest={digest} ticket={ticket} origins={sorted(origins)}")
        if reason:
            detail += f" reason={reason}"
        try:
            receipt = self._audit.record(action=action, memory_text="audience_release",
                                         authorised_by=by or "system",
                                         detail=detail[:MAX_DETAIL_CHARS])
        except Exception as e:
            raise _Unrecorded(type(e).__name__) from e
        if _awaitable_receipt(receipt):
            raise _Unrecorded("the audit returned an awaitable, so nothing was written")
        if not receipt:
            # driftcore.audit.record() reports a failed or compromised write by
            # returning None rather than raising, so no receipt means no record.
            raise _Unrecorded("no receipt")

    def _refuse(self, outcome: Outcome, ticket: Optional[str], room: str,
                fp: str, why: str) -> Decision:
        detail = f"audience={fp} room={room} ticket={ticket} why={why}"
        try:
            receipt = self._audit.record(action=f"AUDIENCE_{outcome.name}",
                                         memory_text="audience_release",
                                         authorised_by="system",
                                         detail=detail[:MAX_DETAIL_CHARS])
            if _awaitable_receipt(receipt):
                receipt = None
        except Exception as e:
            # A refusal stands whether or not it could be written down, and the
            # decision says which.
            return Decision(outcome, ticket, room, fp,
                            f"{why}; this refusal could not be recorded ({type(e).__name__})")
        if not receipt:
            return Decision(outcome, ticket, room, fp,
                            f"{why}; this refusal could not be recorded (no receipt)")
        return Decision(outcome, ticket, room, fp, why)
