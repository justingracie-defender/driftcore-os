"""
payload_shape.py — A THIRD_PARTY DESTINATION GETS DECLARED FIELDS, NOT FREE TEXT.

THE REMAINING HALF OF "IS IT GOING HOME?"
─────────────────────────────────────────
egress_guard answers WHERE data may go. allowlist_hygiene answers WHICH hosts are
trusted to RECEIVE it. Neither answers WHAT rides along, and that is the last open
channel in the exfiltration threat model:

    https://api.weather.com/v1/forecast?q=Kingston                    intended
    https://api.weather.com/v1/forecast?q=Kingston&ref=<secret>       exfiltration

Both are ALLOW at the destination layer, because both go to a host the human
declared. The secret leaves inside a request that is, by every check so far,
completely legitimate. Volume caps do not help: one request carries a name.

So for a THIRD_PARTY destination the rule is inverted from "block what looks bad"
to "permit only what was declared":

    * the path must match a declared template,
    * every query parameter must be declared,
    * every value must satisfy its declared TYPE,
    * anything undeclared is REFUSED — not stripped, not sanitized.

REFUSED, NOT STRIPPED — WHY THAT MATTERS
────────────────────────────────────────
Silently dropping an undeclared parameter would let an injected agent keep trying
encodings until something survives, and the operator would see only successful
requests. A refusal is loud, attributable, and appears in the audit trail. The
same reasoning as MalformedDestination: a request the layer cannot fully account
for is a request it must not send.

WHAT A "TYPE" IS HERE
─────────────────────
Deliberately narrow. A field type is a shape a HUMAN declared, and the point is
that the shape must be too small to carry a secret:

    ENUM      one of a fixed set                  (units=metric|imperial)
    INTEGER   digits, with optional bounds        (limit=1..100)
    TOKEN     short [A-Za-z0-9._-], length-capped (a city name, an id)
    UUID      canonical 8-4-4-4-12
    ISO_DATE  YYYY-MM-DD

There is no FREE_TEXT type, and that omission is the design. A free-text field on
a third-party destination is an exfiltration channel with a nice name. If a real
API genuinely needs prose, that call belongs behind a first-party service that
forwards only the fields you intend.

ENTROPY BUDGET — VALUES *AND* STRUCTURE
───────────────────────────────────────
Even declared fields leak if you declare enough of them: eight TOKEN fields of 32
chars is a comfortable channel. So each template carries a total capacity budget,
computed from the declared fields, and building a template that exceeds it fails
at DECLARATION time — the same "lint the declaration before it can be enforced
against" discipline as allowlist_hygiene.

Field values are not the only channel. Red team (ChatGPT, 2026-08) observed that
the SHAPE of a request carries bits independently of what is in it:

  * TEMPLATE IDENTITY — six declared paths is log2(6) = 2.6 bits per request,
    chosen freely by an injected agent no matter how tight each template is.
  * OPTIONAL-FIELD PRESENCE — each optional field is one bit (sent / not sent)
    before its value contributes anything.
  * LARGE ENUMS — a 300-value country list is 8.2 bits of real entropy that
    byte-rounding flattens to 2.

So capacity is accounted in BITS, and ShapePolicy lints the WHOLE policy rather
than each template alone: worst-case per-request capacity is the widest template,
plus its optional-presence bits, plus the template-choice bits. A policy that is
safe template-by-template can still be a channel in aggregate — which is exactly
the composition hazard this module exists to name.

BOUNDARIES — READ BEFORE RELYING ON THIS
────────────────────────────────────────
This constrains the request LINE (path + query) ONLY. It is one layer of a
composition, and ALONE it does not close the residual in the threat model:

  * BODIES AND HEADERS ARE UNCONSTRAINED. A POST body, an Authorization or
    Cookie or X-Request-Id header, is a wide-open channel to any host that logs
    it. Declaring a POST template here constrains its query string and nothing
    else. Body/header control is REQUIRED COMPANION WORK, not a nicety.
  * SCHEME AND PORT ARE NOT CHECKED HERE. This guard keys on host alone, so
    http:// and non-standard ports match the same policy. It assumes EgressGuard
    sits strictly in front enforcing the exact (scheme, host, port) triple. If
    that composition is not guaranteed, this layer is weaker than it looks.
  * A DESTINATION MUST STILL PASS allowlist_hygiene. A permissive shape on a
    pastebin or analytics host is still an exfiltration channel; shape control
    does not substitute for receive-trust classification.
  * DECLARATION-TIME LINTS BIND ONLY HONEST DECLARERS. A human can raise
    capacity_budget or declare many small fields. The lint catches drift, not a
    determined operator.

The residual after all of that is low-rate but REAL and larger than "one enum
byte": which template is chosen, presence/absence of optional fields, ordering,
timing, and value combinations across a short sequence. Short secrets are still
reachable given enough requests, which is exactly why the cumulative ledger
(action count + burst) is a required complement rather than an optional extra.
This narrows the channel by orders of magnitude; it does not eliminate it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit, parse_qsl


class FieldType(str, Enum):
    ENUM = "ENUM"
    INTEGER = "INTEGER"
    TOKEN = "TOKEN"
    UUID = "UUID"
    ISO_DATE = "ISO_DATE"


_TOKEN_RE = re.compile(r"\A[A-Za-z0-9._-]+\Z")
# An integer on the wire is a STRING the attacker chooses, not an abstract value.
# Canonical form only: optional '-', then either a single '0' or a non-zero leading
# digit. This is what stops "000...0001" from being a 1-byte field carrying 300
# characters. Red team, 2026-08: a bounded 1..14 field accepted 300 leading zeros.
_CANONICAL_INT_RE = re.compile(r"\A-?(0|[1-9][0-9]*)\Z")
# Even canonical, a digit string is a channel if it is long enough. 2^64 is 20
# digits; 24 covers any legitimate identifier with room to spare.
INTEGER_HARD_CAP = 24

# `purpose` is metadata for a human reviewer. Cap and constrain it so it cannot
# quietly become a data channel that survives review.
MAX_PURPOSE_CHARS = 120
_PURPOSE_RE = re.compile(r"\A[A-Za-z0-9 .,'\-/()]+\Z")
_UUID_RE = re.compile(
    r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
_ISO_DATE_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}\Z")

# A TOKEN longer than this is prose wearing a token's clothes.
TOKEN_HARD_CAP = 64

# Default per-request capacity ceiling, in bytes of attacker-controllable data.
# A short name is ~6 bytes; a postal code ~6; an email ~24. 48 bytes is roomy for
# legitimate parameters and tight enough that a template drifting toward a general
# channel fails loudly at declaration time.
DEFAULT_CAPACITY_BUDGET = 48

# Policy-wide ceiling. Per-request capacity across a whole host policy: the
# widest template plus the bits from choosing among templates. Slightly larger
# than a single template's budget because a legitimate API has several endpoints.
DEFAULT_POLICY_BUDGET = 64

# Independent knobs per template. A real API endpoint takes a handful of
# parameters; dozens of small fields is a channel that stays under a byte budget
# by being wide instead of deep (64 one-bit ENUMs = 16 bytes, all "declared").
MAX_FIELDS_PER_TEMPLATE = 8


class PayloadRefused(ValueError):
    """Raised when a request cannot be fully accounted for by its template.

    Carries TWO messages, deliberately:

      * `operator_detail` — specific, may quote the offending value. For the
        audit log and the human debugging a policy.
      * `str(exc)` — generic. What an agent or a caller sees.

    Refusal text that echoes attacker input is a feedback oracle: an injected
    agent probes `ref=a`, `ref=b`, ... and reads the guard's own error to learn
    what got through. The failure must be legible to the operator and silent to
    the prober. Red team (Meta, 2026-08), P1.
    """

    GENERIC = "request violates the declared shape"

    def __init__(self, operator_detail: str, generic: Optional[str] = None):
        self.operator_detail = operator_detail
        super().__init__(generic or self.GENERIC)


class UndeclarableTemplate(ValueError):
    """Raised at declaration time for a template that is itself a channel."""


@dataclass(frozen=True)
class FieldSpec:
    """One declared parameter. `capacity_bytes` is how much attacker-chosen data
    this field could carry if an injected agent controlled it completely."""
    name: str
    type: FieldType
    required: bool = False
    choices: FrozenSet[str] = frozenset()
    min_value: Optional[int] = None
    max_value: Optional[int] = None
    max_length: int = 32

    def __post_init__(self):
        if self.max_length < 1:
            raise UndeclarableTemplate(
                f"field {self.name!r} declares max_length={self.max_length}; a "
                f"field that can never validate is a misconfiguration, not a control")
        if self.type is FieldType.ENUM and not self.choices:
            raise UndeclarableTemplate(
                f"field {self.name!r} is ENUM but declares no choices; an ENUM "
                f"without a fixed set is free text")
        if self.type is FieldType.TOKEN and self.max_length > TOKEN_HARD_CAP:
            raise UndeclarableTemplate(
                f"field {self.name!r} declares max_length={self.max_length}; "
                f"TOKEN is capped at {TOKEN_HARD_CAP} because anything longer is "
                f"prose, and prose is a channel")
        if self.type is FieldType.INTEGER:
            # An unbounded INTEGER advertises 8 bytes and accepts unlimited digits.
            # Red team, 2026-08: `"1"*400` validated against a field the budget
            # counted as 8. Bounds are mandatory so capacity is computable.
            if self.min_value is None or self.max_value is None:
                raise UndeclarableTemplate(
                    f"field {self.name!r} is INTEGER without both min_value and "
                    f"max_value; an unbounded integer is an arbitrary-length digit "
                    f"channel that the capacity budget cannot account for")
            if self.min_value > self.max_value:
                raise UndeclarableTemplate(
                    f"field {self.name!r} declares min_value {self.min_value} > "
                    f"max_value {self.max_value}; it can never validate")
            widest = max(len(str(self.min_value)), len(str(self.max_value)))
            if widest > INTEGER_HARD_CAP:
                raise UndeclarableTemplate(
                    f"field {self.name!r} permits a {widest}-digit value; INTEGER "
                    f"is capped at {INTEGER_HARD_CAP} digits because a long digit "
                    f"string is a channel regardless of its numeric range")

    @property
    def capacity_bits(self) -> int:
        """Attacker-controllable capacity in BITS, from the wire format.

        Bits rather than bytes because byte-rounding hides real entropy: a
        300-value ENUM is 8.2 bits, which rounds to 2 bytes and looks the same
        as a 257-value one. Across a policy those differences accumulate.
        """
        if self.type is FieldType.ENUM:
            n = max(len(self.choices), 1)
            return max(1, (n - 1).bit_length())
        if self.type is FieldType.UUID:
            return 128
        if self.type is FieldType.ISO_DATE:
            return 16
        if self.type is FieldType.INTEGER:
            span = max(self.max_value - self.min_value, 1)
            span_bits = span.bit_length()
            # The attacker types digits; charge for whichever is wider.
            widest_digits = max(len(str(self.min_value)), len(str(self.max_value)))
            return max(span_bits, widest_digits * 8)
        return self.max_length * 8  # TOKEN: every character is attacker-chosen

    @property
    def capacity_bytes(self) -> int:
        """Capacity in whole bytes, rounded up. Kept for readability; the lint
        works in bits so rounding cannot quietly grant headroom."""
        return max(1, (self.capacity_bits + 7) // 8)

    def validate(self, raw: str) -> None:
        if self.type is FieldType.ENUM:
            if raw not in self.choices:
                raise PayloadRefused(
                    f"{self.name}={raw!r} is not one of the declared choices "
                    f"{sorted(self.choices)}")
            return
        if self.type is FieldType.INTEGER:
            # Length first: never call int() on an unbounded attacker string.
            if len(raw) > INTEGER_HARD_CAP:
                raise PayloadRefused(
                    f"{self.name} is a {len(raw)}-character digit string, capped at "
                    f"{INTEGER_HARD_CAP}; length is attacker-chosen capacity "
                    f"regardless of the numeric value")
            if not _CANONICAL_INT_RE.match(raw):
                raise PayloadRefused(
                    f"{self.name}={raw!r} is not a canonical integer (no leading "
                    f"zeros, no '+', no whitespace); non-canonical forms let a "
                    f"1-byte field carry arbitrary-length data")
            v = int(raw)
            if self.min_value is not None and v < self.min_value:
                raise PayloadRefused(f"{self.name}={v} below declared minimum "
                                     f"{self.min_value}")
            if self.max_value is not None and v > self.max_value:
                raise PayloadRefused(f"{self.name}={v} above declared maximum "
                                     f"{self.max_value}")
            return
        if self.type is FieldType.UUID:
            if not _UUID_RE.match(raw):
                raise PayloadRefused(f"{self.name}={raw!r} is not a canonical UUID")
            return
        if self.type is FieldType.ISO_DATE:
            if not _ISO_DATE_RE.match(raw):
                raise PayloadRefused(f"{self.name}={raw!r} is not an ISO date "
                                     f"(YYYY-MM-DD)")
            return
        # TOKEN
        if len(raw) > self.max_length:
            raise PayloadRefused(
                f"{self.name} is {len(raw)} chars, declared max {self.max_length}")
        if not _TOKEN_RE.match(raw):
            raise PayloadRefused(
                f"{self.name}={raw!r} contains characters outside the declared "
                f"token set [A-Za-z0-9._-]")


@dataclass(frozen=True)
class PathTemplate:
    """A declared request line: a fixed path plus a closed set of query fields.

    The path is EXACT — no wildcards, no segment variables. A variable path
    segment is a token field by another name, and one that is easy to forget is
    attacker-controlled. If an API needs an id in the path, declare several exact
    templates or put the id in a declared query field.
    """
    method: str
    path: str
    fields: Tuple[FieldSpec, ...] = ()
    purpose: str = ""
    capacity_budget: int = DEFAULT_CAPACITY_BUDGET

    def __post_init__(self):
        if not self.path.startswith("/"):
            raise UndeclarableTemplate(f"path {self.path!r} must start with '/'")
        if "*" in self.path or "{" in self.path:
            raise UndeclarableTemplate(
                f"path {self.path!r} contains a wildcard or variable; paths are "
                f"exact so that no segment is silently attacker-controlled")
        if not self.purpose.strip():
            raise UndeclarableTemplate(
                "a template requires a purpose: in six months nobody will "
                "remember why this call shape was trusted")
        # `purpose` is metadata for a human reviewer, not a payload. Free-form
        # text across many templates is itself a way to smuggle data past review
        # (a thousand base64 "purposes" look like a thousand legitimate APIs).
        # Red team (Meta, 2026-08), P2.7.
        if len(self.purpose) > MAX_PURPOSE_CHARS:
            raise UndeclarableTemplate(
                f"purpose is {len(self.purpose)} chars, capped at "
                f"{MAX_PURPOSE_CHARS}: it is metadata for a reviewer, not a field")
        if not _PURPOSE_RE.match(self.purpose):
            raise UndeclarableTemplate(
                "purpose must be plain prose (letters, digits, spaces and "
                ". , ' - / ( ) ): encoded blobs are data, not an explanation")
        names = [f.name for f in self.fields]
        if len(names) != len(set(names)):
            raise UndeclarableTemplate("duplicate field names in template")
        # Many small fields are a channel even when the byte total looks modest:
        # 64 one-bit ENUMs is 16 bytes of independently-chosen data, comfortably
        # under a 48-byte budget. Tightening the byte budget is the wrong fix — a
        # legitimate 24-char city token is 24 bytes on its own — so cap the number
        # of independent knobs instead. A real API call has a handful of
        # parameters; a template needing dozens is a channel wearing an API's
        # clothes. Red team (Meta, 2026-08), P2.8.
        if len(self.fields) > MAX_FIELDS_PER_TEMPLATE:
            raise UndeclarableTemplate(
                f"template {self.method} {self.path} declares {len(self.fields)} "
                f"fields, over the {MAX_FIELDS_PER_TEMPLATE}-field cap. Each field "
                f"is an independently-chosen value: many small fields carry as much "
                f"as one large one while staying under the byte budget. Split the "
                f"endpoint or justify a raised cap deliberately.")
        total = self.total_capacity_bits
        budget_bits = self.capacity_budget * 8
        if total > budget_bits:
            raise UndeclarableTemplate(
                f"template {self.method} {self.path} can carry {total} bits "
                f"({self.total_capacity} bytes) of attacker-chosen data — including "
                f"{self.presence_bits} bit(s) from optional-field presence — over the "
                f"{self.capacity_budget}-byte budget. Declared fields still leak if "
                f"you declare enough of them; narrow the types, drop fields, make "
                f"fields required, or raise the budget deliberately.")

    @property
    def presence_bits(self) -> int:
        """Each optional field is one bit before its value says anything:
        sent or not sent is a choice the attacker makes."""
        return sum(1 for f in self.fields if not f.required)

    @property
    def total_capacity_bits(self) -> int:
        """Values plus optional-field presence."""
        return sum(f.capacity_bits for f in self.fields) + self.presence_bits

    @property
    def total_capacity(self) -> int:
        """Whole bytes, rounded up. Reported for readability."""
        return (self.total_capacity_bits + 7) // 8

    @property
    def field_map(self) -> Dict[str, FieldSpec]:
        return {f.name: f for f in self.fields}


@dataclass(frozen=True)
class ShapePolicy:
    """The declared request shapes for one destination host."""
    host: str
    templates: Tuple[PathTemplate, ...]
    declared_by: str = ""
    policy_budget: int = DEFAULT_POLICY_BUDGET

    @staticmethod
    def build(host: str, templates: Sequence[PathTemplate], declared_by: str,
              policy_budget: int = DEFAULT_POLICY_BUDGET) -> "ShapePolicy":
        if not declared_by:
            raise UndeclarableTemplate(
                "declared_by is required: a payload shape is a safety-critical "
                "declaration and must be attributable")
        if not templates:
            raise UndeclarableTemplate(
                f"no templates declared for {host}: an empty shape policy would "
                f"refuse everything, which is a misconfiguration, not a control")
        # Overlapping (method, path) previously resolved to silent first-wins, so a
        # second, laxer template could sit in the policy looking enforced while
        # never being consulted. A shadowed declaration is a lie about the policy.
        seen = set()
        for t in templates:
            key = (t.method.upper(), t.path)
            if key in seen:
                raise UndeclarableTemplate(
                    f"duplicate template {key[0]} {key[1]} for {host}; overlapping "
                    f"declarations would silently shadow one another")
            seen.add(key)
        policy = ShapePolicy(host=host, templates=tuple(templates),
                             declared_by=declared_by,
                             policy_budget=policy_budget)
        # Policy-wide lint. A set of templates that are each individually within
        # budget can still be a channel together, because WHICH template the agent
        # picks is itself attacker-chosen. Red team (ChatGPT, 2026-08): six paths
        # is 2.6 bits per request that no per-template check ever sees.
        worst = policy.worst_case_bits
        budget_bits = policy_budget * 8
        if worst > budget_bits:
            raise UndeclarableTemplate(
                f"policy for {host} can carry {worst} bits per request "
                f"({policy.template_choice_bits} from choosing among "
                f"{len(templates)} templates, {worst - policy.template_choice_bits} "
                f"from the widest template), over the {policy_budget}-byte policy "
                f"budget. Reduce the number of declared shapes, narrow the widest "
                f"template, or raise the policy budget deliberately.")
        return policy

    @property
    def template_choice_bits(self) -> int:
        """Which declared shape the agent picks is itself a channel."""
        n = max(len(self.templates), 1)
        return (n - 1).bit_length()

    @property
    def worst_case_bits(self) -> int:
        """Per-request capacity: the widest template plus the choice of template."""
        widest = max((t.total_capacity_bits for t in self.templates), default=0)
        return widest + self.template_choice_bits


class PayloadShapeGuard:
    """Checks a request line against the declared shapes for its host.

    Fail-closed at every branch: an unparseable URL, an unknown host, an
    undeclared path, an undeclared parameter, a value failing its type, a missing
    required field, and a repeated parameter are all REFUSALS.
    """

    def __init__(self, policies: Sequence[ShapePolicy]):
        self._by_host: Dict[str, ShapePolicy] = {}
        for p in policies:
            self._by_host[p.host.lower()] = p

    def check(self, url: str, method: str = "GET") -> None:
        """Return None if the request is fully accounted for; raise otherwise."""
        try:
            parts = urlsplit(url)
        except Exception as e:
            raise PayloadRefused(f"request line could not be parsed: {e}")

        host = (parts.hostname or "").lower()
        if not host:
            raise PayloadRefused("request has no host")

        policy = self._by_host.get(host)
        if policy is None:
            raise PayloadRefused(
                f"no declared payload shape for {host}; a THIRD_PARTY destination "
                f"may only receive declared request shapes")

        if parts.fragment:
            raise PayloadRefused(
                "request carries a URL fragment; fragments are not part of a "
                "declared shape and can carry arbitrary data")

        path = parts.path or "/"
        candidates = [t for t in policy.templates
                      if t.path == path and t.method.upper() == method.upper()]
        if not candidates:
            raise PayloadRefused(
                f"{method} {path} is not a declared request shape for {host}")
        template = candidates[0]

        # Parameter names must appear on the wire EXACTLY as declared. parse_qsl
        # percent-decodes names, so "%71=x" arrives as "q" and validates — while a
        # receiver that does not decode names sees a different parameter entirely.
        # That is a parser differential: the guard and the server disagree about
        # what was sent. Self-red-team 2026-08.
        raw_pairs = parts.query.split("&") if parts.query else []
        for raw in raw_pairs:
            if not raw:
                continue
            raw_name = raw.split("=", 1)[0]
            if "%" in raw_name or "+" in raw_name:
                raise PayloadRefused(
                    f"parameter name {raw_name!r} is percent- or plus-encoded; names "
                    f"must appear literally as declared. Encoded names decode to a "
                    f"declared name here while a receiver that does not decode sees "
                    f"a different parameter — a parser differential, not a shape.")

        # keep_blank_values: an empty value is still a declared-or-not decision.
        pairs = parse_qsl(parts.query, keep_blank_values=True,
                          strict_parsing=False)
        seen: Dict[str, int] = {}
        specs = template.field_map

        for name, value in pairs:
            if name not in specs:
                raise PayloadRefused(
                    f"undeclared parameter {name!r} on {method} {path}. Refused, "
                    f"not stripped: a request that cannot be fully accounted for "
                    f"must not be sent.")
            seen[name] = seen.get(name, 0) + 1
            if seen[name] > 1:
                raise PayloadRefused(
                    f"parameter {name!r} repeated; repetition multiplies a "
                    f"declared field's capacity and is not a declared shape")
            specs[name].validate(value)

        for spec in template.fields:
            if spec.required and spec.name not in seen:
                raise PayloadRefused(
                    f"required parameter {spec.name!r} missing on {method} {path}")

    def permits(self, url: str, method: str = "GET",
                operator_detail: bool = False) -> Tuple[bool, str]:
        """Non-raising form. Returns the GENERIC reason by default.

        `operator_detail=True` returns the specific reason and must only be used
        where the output goes to a human or an audit sink — never back to the
        agent, or the refusal becomes an oracle it can probe against.
        """
        try:
            self.check(url, method)
            return True, "request line matches a declared shape"
        except PayloadRefused as e:
            return False, (e.operator_detail if operator_detail else str(e))


class ShapedRequest:
    """Safe-by-construction wrapper: the bytes VALIDATED are the bytes SENT.

    `PayloadShapeGuard.check()` is advisory — it inspects a string and returns.
    Nothing stops a caller from validating one URL and then sending another, or
    appending a parameter afterwards:

        guard.permits(url)                       # ALLOW
        transport(url + "&leak=SECRET")          # never seen by the guard

    That is a time-of-check/time-of-use gap, and it is the same mistake as a
    monitor that can be bypassed by not calling it. `GuardedEgress` solved this
    for destinations by owning the transport; this does the same for shape.

    Use this at the boundary. Reach for the bare guard only when something else
    already owns the transport and re-validates the final bytes.
    """

    def __init__(self, guard: PayloadShapeGuard, transport, schema=None):
        """`schema` is an optional RequestSchemaGuard. Without one, bodies and
        headers are refused outright — a blanket refusal is the correct default,
        because an undeclared body is an unconstrained channel. With one, they
        are declared and validated like everything else."""
        self._guard = guard
        self._transport = transport
        self._schema = schema

    def request(self, url: str, method: str = "GET", **kwargs):
        # Formats this layer cannot account for are refused regardless of schema.
        for unsupported in ("files", "params"):
            if kwargs.get(unsupported) is not None:
                raise PayloadRefused(
                    f"{unsupported!r} is not permitted on a shaped request: this "
                    f"layer constrains only declared shapes, so multipart uploads "
                    f"and client-side param building are unconstrained channels")

        body = kwargs.pop("json", None)
        for alias in ("data", "body"):
            if kwargs.get(alias) is not None:
                if body is not None:
                    raise PayloadRefused("multiple body arguments supplied")
                body = kwargs.pop(alias)
        headers = kwargs.get("headers") or {}

        if body is not None or headers:
            if self._schema is None:
                raise PayloadRefused(
                    "a body or custom headers were supplied but no request schema "
                    "is declared: they would be an unconstrained channel alongside "
                    "a 'declared' URL. Declare a RequestSchemaGuard or send neither")
            if headers:
                kwargs["headers"] = self._schema.check_headers(headers)
            if body is not None:
                # Transmit the CANONICAL bytes: validated object and sent object
                # are the same, and the key-order channel is removed rather than
                # budgeted for.
                kwargs["data"] = self._schema.canonical_body(body)

        # A validated URL that the transport is then free to FOLLOW elsewhere is
        # not a control. A 302 to attacker.com carries the whole query string with
        # it, outside both this guard and the destination allowlist. Redirects are
        # refused here rather than re-validated: GuardedEgress already owns hop-by-
        # hop re-checking, and two layers silently disagreeing about who follows
        # redirects is worse than one layer that never does.
        # Red team (Meta, 2026-08), P0.
        if kwargs.get("allow_redirects"):
            raise PayloadRefused(
                "allow_redirects=True is not permitted on a shaped request: a "
                "redirect carries the validated query string to a destination "
                "neither this guard nor the egress allowlist approved")
        kwargs["allow_redirects"] = False

        self._guard.check(url, method)          # raises on refusal
        response = self._transport(url, method=method, **kwargs)  # the SAME url

        # If the transport reports a redirect anyway, surface it as a refusal
        # rather than letting a caller quietly follow it.
        status = getattr(response, "status_code", None)
        if status is None and isinstance(response, tuple) and response:
            status = response[0]
        if isinstance(status, int) and 300 <= status < 400:
            raise PayloadRefused(
                f"destination answered {status} with a redirect; following it would "
                f"send the validated request line to an undeclared destination")
        return response
