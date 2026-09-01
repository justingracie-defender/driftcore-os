"""
information_flow.py — WHAT MAY LEAVE, NOT JUST WHERE IT MAY GO.

THE RESIDUAL THIS CLOSES
────────────────────────
Every egress layer built so far bounds the DESTINATION. `egress_guard` says
which host, `payload_shape` says which fields, `mediated_llm` says the agent
cannot even name a host. All correct, and all silent about the thing that
actually leaves:

    POST https://api.openai.com/v1/chat/completions      ← allowlisted
    {"messages":[{"role":"user","content":"<the family's address>"}]}

Every check passes. The destination is declared, the shape is declared, the
broker holds the socket. And the secret is gone. Three independent red teams
named this as the next real boundary, and they were right: an adversarial model
does not need `evil.com?secret=` if it can put the secret in a legitimate
prompt to a legitimate provider.

WHAT DOES NOT WORK, AND WHY IT IS NOT BUILT HERE
────────────────────────────────────────────────
Scanning content for secrets. A classifier asking "does this text contain
something sensitive?" is the detection posture this whole project rejects: an
injected agent paraphrases, encodes, or splits across calls, and the classifier
is a speed bump with a confidence score. The memory heist made the general
lesson concrete — the secret was never in a payload at all, so no payload
inspection could have seen it.

WHAT WORKS: LABEL THE DATA, NOT THE TEXT
────────────────────────────────────────
Classic information-flow control. Data is labelled AT ITS SOURCE, labels
propagate through combination, and the label is checked AT THE SINK. The
question stops being "does this string look sensitive?" — which is undecidable
— and becomes "what is this string DERIVED FROM?", which is bookkeeping.

    memory.read()  ──► Labeled(SECRET, {family})
                          │  join
    "Summarise: " ────────┤
    Labeled(PUBLIC)       │
                          ▼
                   Labeled(SECRET, {family})
                          │
                          ▼  sink.may_receive?
              third-party LLM (PUBLIC only) ──► REFUSED

THE LATTICE: LEVEL *AND* COMPARTMENTS
─────────────────────────────────────
A single sensitivity number is not enough. "Childcare notes" and "API keys" are
both sensitive and must not flow to the same places. So a label carries a LEVEL
(ordered) and a set of COMPARTMENTS (unordered categories). A sink must dominate
on BOTH — its level at least as high, its compartment clearance a superset.
That is what lets `childcare` data be refused by a sink that is otherwise
cleared for SECRET.

Combination takes the JOIN: the higher level, the union of compartments.
Mixing public text with a secret yields a secret. This is the direction that
matters; there is no operation here that lowers a label by accident.

THE ONE DESIGN DECISION THAT MAKES THIS REAL: DEFAULT-DENY ON UNLABELLED
───────────────────────────────────────────────────────────────────────
Python cannot do transparent taint tracking — there is no way to intercept every
string operation. So this is a DISCIPLINE ENFORCED AT THE SINK: a governed sink
accepts `Labeled` values and refuses bare strings. Forgetting to label is
therefore a REFUSAL, not a leak. That inversion is the whole reason this is
worth building rather than a `# TODO: check for secrets`.

DECLASSIFICATION
────────────────
Without a downgrade path the system is unusable: everything a sensitive source
touches becomes untouchable forever and an operator eventually disables the
layer. With an ungated downgrade path it is worthless. So declassification is
possible, human-authorised, reason-bearing, and audited — the same asymmetry as
every other policy change here. Tightening a label is free; lowering one is not.

HONEST BOUNDARIES — READ BEFORE RELYING ON THIS
───────────────────────────────────────────────
  * LABELS ARE DECLARED, NOT DERIVED. The guarantee is only as good as the
    labelling at the sources. If a memory backend hands out bare strings, this
    layer never sees the data and cannot help. Wire the SOURCES first; a sink
    check with unlabelled sources is theatre.
  * AN AGENT THAT CAN READ SECRET DATA AND WRITE A NEW STRING FROM MEMORY OF IT
    DEFEATS PROPAGATION. Nothing in-process stops a model from reproducing what
    it read into a fresh `Labeled(PUBLIC, ...)`. That is laundering, it is not
    detectable here, and it is why this is a layer rather than a solution.
  * THE AUDIT LOG IS A SINK TOO. This module logs LABELS and ORIGINS, never
    values — but `origins` are source NAMES chosen by the integrator, so a
    source called `memory:medical_records` puts that string in the audit trail.
    Name sources for what they are, not for what they contain.
  * COVERT CHANNELS REMAIN. Timing, ordering, which of several sinks is chosen,
    and the choice of declassification requests all carry bits. The cumulative
    ledger bounds volume; it does not eliminate them.

This narrows what can leave from "anything the agent can read" to "anything the
agent explicitly re-authored or an authorised human released." That is a real
reduction and it is not a proof.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, FrozenSet, Iterable, List, Optional, Tuple


class Level(Enum):
    """Ordered sensitivity. Compartments handle the unordered part."""
    PUBLIC = 0
    INTERNAL = 1
    SENSITIVE = 2
    SECRET = 3

    def __lt__(self, other): return self.value < other.value
    def __le__(self, other): return self.value <= other.value


class FlowRefused(Exception):
    """A flow was refused. Operator detail is kept separate so a refusal never
    becomes an oracle an agent can probe against."""

    GENERIC = "information flow refused"

    def __init__(self, operator_detail: str, generic: Optional[str] = None):
        self.operator_detail = operator_detail
        super().__init__(generic or self.GENERIC)


@dataclass(frozen=True)
class Label:
    """A level plus a set of compartments.

    Dominance requires BOTH: `a.dominates(b)` means a is cleared for everything
    b requires. A sink cleared SECRET but not for `childcare` must still refuse
    childcare data — which a single sensitivity number could never express.
    """
    level: Level = Level.PUBLIC
    compartments: FrozenSet[str] = frozenset()

    def dominates(self, other: "Label") -> bool:
        return (self.level.value >= other.level.value
                and other.compartments <= self.compartments)

    def join(self, other: "Label") -> "Label":
        """The least label that covers both. Combining data NEVER lowers it."""
        return Label(
            level=self.level if self.level.value >= other.level.value else other.level,
            compartments=self.compartments | other.compartments)

    def __str__(self) -> str:
        c = f"+{{{','.join(sorted(self.compartments))}}}" if self.compartments else ""
        return f"{self.level.name}{c}"


PUBLIC = Label(Level.PUBLIC)

# The audit record is a sink. Anything written there has left the controller's
# reach, so operator free text going into it is bounded like any other payload.
MAX_REASON_CHARS = 200


def _freeze(value: Any) -> Any:
    """Return an immutable snapshot of `value`.

    `Labeled` is a frozen dataclass, which freezes the REFERENCE, not the object
    it points at: labelling a list PUBLIC and then appending a secret to that
    same list left the label saying PUBLIC over changed contents. Red team
    (Grok, 2026-08). Containers are snapshotted at labelling time so the label
    describes what was actually labelled.
    """
    if isinstance(value, (str, bytes, int, float, bool, type(None), frozenset)):
        return value
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    if isinstance(value, set):
        return frozenset(_freeze(v) for v in value)
    if isinstance(value, dict):
        return tuple(sorted((k, _freeze(v)) for k, v in value.items()))
    # An arbitrary object cannot be frozen here. Refuse rather than pretend:
    # a label over something that can change underneath it is a false statement.
    raise FlowRefused(
        f"cannot label a mutable {type(value).__name__}: the label would "
        f"describe a value that can change after it is attached. Pass an "
        f"immutable value, or a str/bytes/list/dict/set/tuple of them.")


@dataclass(frozen=True)
class Labeled:
    """A value carrying its label and its provenance.

    `origins` records which sources contributed, so an incident review can ask
    "where did this come from?" rather than only "how sensitive was it?".

    The payload is SNAPSHOT-FROZEN at construction: a frozen dataclass freezes
    the reference, not the object, and a label over mutable contents is a
    statement that can quietly stop being true.
    """
    value: Any
    label: Label
    origins: FrozenSet[str] = frozenset()

    def __post_init__(self):
        object.__setattr__(self, "value", _freeze(self.value))

    @staticmethod
    def public(value: Any, origin: str = "literal") -> "Labeled":
        return Labeled(value, PUBLIC, frozenset({origin}))

    def combine(self, other: "Labeled", joiner: Callable[[Any, Any], Any] = None
                ) -> "Labeled":
        """Combine two labelled values. The result carries the JOIN of both
        labels — mixing public text with a secret yields a secret."""
        if not isinstance(other, Labeled):
            raise FlowRefused(
                f"cannot combine a Labeled with a bare {type(other).__name__}: "
                f"an unlabelled operand has unknown provenance, and assuming it "
                f"is public is how a secret becomes public by accident")
        j = joiner or (lambda a, b: f"{a}{b}")
        return Labeled(j(self.value, other.value),
                       self.label.join(other.label),
                       self.origins | other.origins)

    def __str__(self) -> str:
        return f"Labeled({self.label}, from={sorted(self.origins)})"


def join_all(parts: Iterable["Labeled"],
             joiner: Callable[[Any, Any], Any] = None) -> Labeled:
    """Fold a sequence of labelled values into one. Refuses an empty sequence
    rather than inventing a PUBLIC default."""
    items = list(parts)
    if not items:
        raise FlowRefused("join_all of nothing has no defined label")
    acc = items[0]
    for nxt in items[1:]:
        acc = acc.combine(nxt, joiner)
    return acc


@dataclass(frozen=True)
class Sink:
    """A destination and the maximum label it may RECEIVE.

    This is the generalisation of allowlist_hygiene's ReceiveTrust: instead of
    first-party/third-party, a sink declares its actual clearance. The framing
    is unchanged — an allowlisted destination is not "a host trusted to be
    benign", it is a host TRUSTED TO RECEIVE what its clearance covers.
    """
    name: str
    clearance: Label
    declared_by: str = ""
    purpose: str = ""

    def __post_init__(self):
        if not self.name:
            raise FlowRefused("a sink requires a name")
        if not self.declared_by:
            raise FlowRefused(
                f"sink {self.name!r} has no declared_by; a clearance is a "
                f"safety-critical declaration and must be attributable")

    def may_receive(self, label: Label) -> Tuple[bool, str]:
        if self.clearance.dominates(label):
            return True, f"{self.name} is cleared for {label}"
        missing = sorted(label.compartments - self.clearance.compartments)
        why = []
        if label.level.value > self.clearance.level.value:
            why.append(f"level {label.level.name} > clearance "
                       f"{self.clearance.level.name}")
        if missing:
            why.append(f"uncleared compartment(s) {missing}")
        return False, "; ".join(why)


@dataclass(frozen=True)
class Declassification:
    """A human decision to lower a label, recorded as evidence."""
    from_label: Label
    to_label: Label
    authorised_by: str
    reason: str
    at: float = field(default_factory=time.time)


def _is_human(who, *, action: str = "declassify") -> bool:
    """Delegate to the repo's authorization primitive.

    A local denylist ("is the string not one of these?") was the weakest part of
    this module and it sat directly on the SECRET → PUBLIC boundary: any caller
    who chose the string "justin" was treated as Justin. Red team (ChatGPT,
    2026-08).

    `driftcore.authority.human_identity` already solves this and is used by the
    actuation path, so this delegates rather than reinventing a second, weaker
    answer. Its three modes matter here:

      ATTESTED   → requires a signed HumanAttestation; a bare string is NEVER
                   human. This is the mode a real deployment runs in.
      REGISTERED → the name must be a pre-registered principal.
      LABEL_ONLY → the legacy denylist, insecure, and `status()` says so.

    Fail-closed on import failure: if the identity module cannot be loaded, no
    caller is human, so declassification stops rather than falling back to a
    string check nobody is checking.
    """
    try:
        from driftcore.authority.human_identity import is_human as _ih
    except Exception:
        return False
    return _ih(who, action=action)


class FlowController:
    """Checks flows at the sink and gates declassification.

    Construct with the declared sinks. `send()` is the only way data reaches a
    sink, and it refuses anything that is not `Labeled` — which is what makes
    forgetting to label a refusal rather than a leak.
    """

    def __init__(self, sinks: Iterable[Sink], *, audit=None,
                 audit_required: bool = True):
        self._sinks = {s.name: s for s in sinks}
        if not self._sinks:
            raise FlowRefused(
                "a flow controller with no declared sinks would refuse "
                "everything; declare where data is allowed to go")
        self._audit = audit
        self._audit_required = audit_required
        self._declassifications: List[Declassification] = []
        self._lock = threading.RLock()

    # -- the sink check ---------------------------------------------------

    def send(self, sink_name: str, payload: Any) -> Any:
        """Release `payload` to `sink_name`, returning the raw value on success.

        A bare string is REFUSED. That is the load-bearing decision: unlabelled
        data has unknown provenance, and treating unknown as public is exactly
        how a secret leaves by accident.
        """
        sink = self._sinks.get(sink_name)
        if sink is None:
            raise FlowRefused(
                f"no sink declared named {sink_name!r} "
                f"(declared: {sorted(self._sinks)})")
        if not isinstance(payload, Labeled):
            raise FlowRefused(
                f"payload for {sink_name!r} is a bare {type(payload).__name__}, "
                f"not a Labeled. Unlabelled data has unknown provenance; "
                f"assuming it is public is how a secret leaves by accident. "
                f"Label it at its source.")
        allowed, why = sink.may_receive(payload.label)
        if not allowed:
            self._log("FLOW_REFUSED", "system",
                      f"{payload.label} -/-> {sink.name}: {why} "
                      f"(origins={sorted(payload.origins)})")
            raise FlowRefused(
                f"{payload.label} may not flow to {sink.name!r}: {why}. "
                f"Origins: {sorted(payload.origins)}")
        self._log("FLOW_PERMITTED", "system",
                  f"{payload.label} -> {sink.name} "
                  f"(origins={sorted(payload.origins)})")
        return payload.value

    def may_send(self, sink_name: str, payload: Any) -> Tuple[bool, str]:
        """PURE query: would this flow be permitted? Does not release, does not
        audit, does not mutate anything.

        It used to call `send()`, so every probe wrote a FLOW_PERMITTED or
        FLOW_REFUSED record. That gave a probing agent two things it should not
        have: it could inflate the audit log at will, and the record itself
        confirmed the existence and label of data the agent was only asking
        about. Red team (Grok, 2026-08).

        A decision that is only CONSIDERED is not an event. Only a release is.
        """
        sink = self._sinks.get(sink_name)
        if sink is None:
            return False, str(FlowRefused(""))
        if not isinstance(payload, Labeled):
            return False, str(FlowRefused(""))
        allowed, _why = sink.may_receive(payload.label)
        return allowed, ("permitted" if allowed else str(FlowRefused("")))

    # -- declassification: possible, human-gated, audited -----------------

    def declassify(self, payload: Labeled, to: Label,
                   authorised_by: str, reason: str) -> Labeled:
        """Lower a label. Requires a human and a reason; always audited.

        Without this the layer is unusable and gets switched off. With it
        ungated it is worthless. So it exists and it costs something.
        """
        if not isinstance(payload, Labeled):
            raise FlowRefused("only a Labeled value can be declassified")
        if not _is_human(authorised_by):
            self._log("DECLASSIFY_DENIED", authorised_by or "system",
                      f"{payload.label} -> {to}: no human authoriser")
            raise FlowRefused(
                "declassification requires a human authoriser: lowering a label "
                "is the one operation that can turn a secret into a public "
                "string, so it is not something the system does to itself")
        if not reason.strip():
            raise FlowRefused(
                "declassification requires a reason (for the audit trail)")
        # THE AUDIT LOG IS ITSELF A SINK. `reason` is operator free text and
        # goes straight into the record, so without a bound the layer can
        # produce its own signature failure: "we stopped the secret reaching the
        # LLM, so we wrote it into the audit record instead." Red team
        # (ChatGPT, 2026-08). A reason is a short justification for a reviewer,
        # not a place to paste data.
        from driftcore.audit.bounded_fields import (
            bounded_reason, AuditFieldRefused)
        try:
            bounded_reason(reason, field="declassification reason")
        except AuditFieldRefused as e:
            raise FlowRefused(str(e))
        if not payload.label.dominates(to) or payload.label == to:
            raise FlowRefused(
                f"{to} is not strictly lower than {payload.label}; "
                f"declassification only lowers")
        with self._lock:
            record = Declassification(payload.label, to, authorised_by, reason)
            self._log("DECLASSIFIED", authorised_by,
                      f"{payload.label} -> {to} (origins="
                      f"{sorted(payload.origins)}): {reason}")
            self._declassifications.append(record)
        return Labeled(payload.value, to, payload.origins)

    @property
    def declassification_log(self) -> Tuple[Declassification, ...]:
        return tuple(self._declassifications)

    def _log(self, action: str, by: str, detail: str):
        if self._audit is None:
            if self._audit_required:
                raise FlowRefused(
                    "no audit sink configured but audit_required=True: a flow "
                    "decision that cannot be recorded is refused")
            return
        try:
            self._audit.record(action=action, memory_text="information_flow",
                               authorised_by=by or "system", detail=detail)
        except Exception as e:
            if self._audit_required:
                raise FlowRefused(
                    f"audit write failed for {action} ({e}); refusing the flow "
                    f"rather than releasing data unrecorded")


class LabeledSource:
    """Wraps a data source so it emits `Labeled` values instead of bare ones.

    Wire the SOURCES, not just the sink. A sink check with unlabelled sources is
    theatre: the data never carries a label, so the check has nothing to refuse.
    This is the piece an integrator most often skips.
    """

    def __init__(self, name: str, label: Label, read_fn: Callable[..., Any]):
        self._name = name
        self._label = label
        self._read = read_fn

    def read(self, *a, **kw) -> Labeled:
        return Labeled(self._read(*a, **kw), self._label, frozenset({self._name}))
