"""
request_schema.py — DECLARED BODIES AND HEADERS, OR NONE AT ALL.

WHY THIS EXISTS
───────────────
`payload_shape` constrains the request LINE. That was always half a control,
and the docstring said so: a perfectly-shaped URL is worthless if a JSON body
rides alongside it.

    GET  /v1/forecast?q=Kingston          <- declared, budgeted, 25 bytes
    POST /v1/forecast?q=Kingston
         {"note": "<the entire contents of memory>"}   <- unconstrained

`ShapedRequest` handled this by refusing bodies and headers outright, which is
correct and unusable: real APIs POST. This module is the alternative to a blanket
refusal — the same discipline applied one layer down, so a body can be *declared*
rather than merely *allowed*.

THE SAME RULE, ONE LAYER DOWN
─────────────────────────────
    * every field declared, by name, with a FieldSpec type from payload_shape,
    * no undeclared keys — REFUSED, not stripped,
    * no free text (there is still no FREE_TEXT type, deliberately),
    * capacity accounted in bits, including structural entropy,
    * over-budget schemas fail at DECLARATION time.

WHAT A BODY ADDS THAT A QUERY DOES NOT
──────────────────────────────────────
A query string is flat. A JSON body is a TREE, and trees carry entropy in their
shape as well as their values:

  * NESTING. An object inside an object is another set of independently-chosen
    keys. Depth multiplies capacity; it does not add to it.
  * ARRAYS. A list of N items is N copies of a field's capacity, and N itself is
    attacker-chosen. An unbounded array is an unbounded channel wearing a
    declared type — the array equivalent of the unbounded INTEGER that the first
    red team found.
  * KEY ORDER. `{"a":1,"b":2}` and `{"b":2,"a":1}` are the same object and
    different bytes. n! orderings is log2(n!) bits that no per-field check sees.
    Bodies are therefore re-serialized canonically (sorted keys, fixed
    separators) before transmission — the ordering channel is removed rather
    than budgeted.
  * TYPE POLYMORPHISM. JSON distinguishes 1, "1", 1.0, true. A validator that
    coerces accepts several encodings of one value; each alternative is free
    bits. Types are checked strictly, on the parsed JSON type, before values.

HEADERS
───────
Headers are a query string with worse hygiene: attacker-influenceable, widely
logged, and rarely reviewed. Same treatment — declared names only, typed values,
everything else refused. A short deny-list of headers that are channels by
construction (Cookie, Authorization, anything X-) is refused even if declared,
because those are where an injected agent would reach first and no legitimate
declared-shape call needs the agent to choose them.

BOUNDARIES
──────────
Constrains JSON bodies and headers on requests this layer sends. Multipart,
protobuf, GraphQL documents, and streaming bodies are NOT covered and must be
refused rather than assumed safe. Compression is refused for the same reason the
first red team flagged: a small compressed body can represent far more
attacker-chosen data than its size suggests, so capacity accounting would lie.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Mapping, Optional, Sequence, Tuple

from driftcore.kernel.payload_shape import (
    FieldSpec, FieldType, PayloadRefused, UndeclarableTemplate,
    MAX_FIELDS_PER_TEMPLATE, DEFAULT_CAPACITY_BUDGET,
)


# A body may nest, but not deeply. Every level multiplies the declared surface,
# and a legitimate API request is not a document tree.
MAX_BODY_DEPTH = 3
# Arrays must be bounded at declaration; this is the ceiling on that bound.
MAX_ARRAY_ITEMS = 16
# Bodies get a little more room than a query line, but not much.
DEFAULT_BODY_BUDGET = 64

# Headers that are channels by construction. Refused even if someone declares
# them: no declared-shape call needs an agent choosing these.
FORBIDDEN_HEADERS: FrozenSet[str] = frozenset({
    "cookie", "set-cookie", "authorization", "proxy-authorization",
    "referer", "user-agent", "origin", "forwarded", "x-forwarded-for",
    "traceparent", "tracestate", "baggage", "via", "dnt",
})

# Content encodings that break capacity accounting.
FORBIDDEN_ENCODINGS: FrozenSet[str] = frozenset({
    "gzip", "deflate", "br", "zstd", "compress", "identity;q=0",
})


class SchemaRefused(PayloadRefused):
    """A body or header could not be fully accounted for by its schema.

    Inherits the generic/operator-detail split from PayloadRefused: the caller
    sees one flat message, the audit log keeps the specifics. A schema violation
    is exactly the kind of failure an injected agent would probe against.
    """


@dataclass(frozen=True)
class ArraySpec:
    """A bounded list of one declared item type.

    `max_items` is mandatory. An unbounded array is an unbounded channel — the
    same mistake as an INTEGER without bounds, which the first red team turned
    into a 400-character exfiltration field.
    """
    name: str
    item: FieldSpec
    max_items: int
    required: bool = False

    def __post_init__(self):
        if self.max_items < 1:
            raise UndeclarableTemplate(
                f"array {self.name!r} declares max_items={self.max_items}; an "
                f"array that can never validate is a misconfiguration")
        if self.max_items > MAX_ARRAY_ITEMS:
            raise UndeclarableTemplate(
                f"array {self.name!r} permits {self.max_items} items, over the "
                f"{MAX_ARRAY_ITEMS} cap; length is attacker-chosen, so a long "
                f"array multiplies its item type into a wide channel")

    @property
    def capacity_bits(self) -> int:
        # Worst case: a full array, plus the choice of how many items to send.
        length_bits = max(1, (self.max_items).bit_length())
        return self.item.capacity_bits * self.max_items + length_bits


@dataclass(frozen=True)
class ObjectSchema:
    """A declared JSON object: named fields, nested objects, bounded arrays."""
    fields: Tuple[FieldSpec, ...] = ()
    arrays: Tuple[ArraySpec, ...] = ()
    objects: Tuple[Tuple[str, "ObjectSchema"], ...] = ()
    required_objects: FrozenSet[str] = frozenset()

    def __post_init__(self):
        names = ([f.name for f in self.fields]
                 + [a.name for a in self.arrays]
                 + [n for n, _ in self.objects])
        if len(names) != len(set(names)):
            raise UndeclarableTemplate("duplicate key names in object schema")
        if len(names) > MAX_FIELDS_PER_TEMPLATE:
            raise UndeclarableTemplate(
                f"object declares {len(names)} keys, over the "
                f"{MAX_FIELDS_PER_TEMPLATE}-key cap; many small keys carry as "
                f"much as one large one while staying under a byte budget")
        if self.depth > MAX_BODY_DEPTH:
            raise UndeclarableTemplate(
                f"object nests {self.depth} levels, over the {MAX_BODY_DEPTH} "
                f"cap; each level multiplies the declared surface, and a request "
                f"body is not a document tree")

    @property
    def depth(self) -> int:
        return 1 + max((s.depth for _, s in self.objects), default=0)

    @property
    def presence_bits(self) -> int:
        opt_fields = sum(1 for f in self.fields if not f.required)
        opt_arrays = sum(1 for a in self.arrays if not a.required)
        opt_objects = sum(1 for n, _ in self.objects
                          if n not in self.required_objects)
        return opt_fields + opt_arrays + opt_objects

    @property
    def capacity_bits(self) -> int:
        """Values + arrays + nested objects + presence. Key ORDER is not counted
        because canonical re-serialization removes it entirely."""
        return (sum(f.capacity_bits for f in self.fields)
                + sum(a.capacity_bits for a in self.arrays)
                + sum(s.capacity_bits for _, s in self.objects)
                + self.presence_bits)

    def key_map(self):
        return ({f.name: f for f in self.fields},
                {a.name: a for a in self.arrays},
                {n: s for n, s in self.objects})


@dataclass(frozen=True)
class BodySchema:
    """A declared JSON request body."""
    root: ObjectSchema
    purpose: str = ""
    capacity_budget: int = DEFAULT_BODY_BUDGET

    @staticmethod
    def build(root: ObjectSchema, purpose: str,
              capacity_budget: int = DEFAULT_BODY_BUDGET) -> "BodySchema":
        if not purpose.strip():
            raise UndeclarableTemplate(
                "a body schema requires a purpose: it is the only record of why "
                "this structure was trusted to leave the system")
        schema = BodySchema(root=root, purpose=purpose,
                            capacity_budget=capacity_budget)
        bits = root.capacity_bits
        if bits > capacity_budget * 8:
            raise UndeclarableTemplate(
                f"body schema can carry {bits} bits ({(bits + 7) // 8} bytes) of "
                f"attacker-chosen data, over the {capacity_budget}-byte budget. "
                f"Nesting and arrays multiply capacity; narrow the item types, "
                f"shorten the arrays, or raise the budget deliberately.")
        return schema

    @property
    def capacity_bits(self) -> int:
        return self.root.capacity_bits


@dataclass(frozen=True)
class HeaderSchema:
    """Declared request headers. Names are matched case-insensitively because
    HTTP header names are case-insensitive; values are typed like any field."""
    fields: Tuple[FieldSpec, ...] = ()

    def __post_init__(self):
        for f in self.fields:
            if f.name.lower() in FORBIDDEN_HEADERS:
                raise UndeclarableTemplate(
                    f"header {f.name!r} is refused even when declared: it is a "
                    f"channel by construction (widely logged, attacker-"
                    f"influenceable) and no declared-shape call needs an agent "
                    f"choosing it")
            if f.name.lower().startswith("x-"):
                raise UndeclarableTemplate(
                    f"header {f.name!r}: X- headers are unregistered and "
                    f"unreviewed by definition, which makes them the first place "
                    f"an injected agent reaches. Use a declared body field")
        names = [f.name.lower() for f in self.fields]
        if len(names) != len(set(names)):
            raise UndeclarableTemplate(
                "duplicate header names (HTTP header names are case-insensitive)")

    @property
    def capacity_bits(self) -> int:
        return (sum(f.capacity_bits for f in self.fields)
                + sum(1 for f in self.fields if not f.required))


class RequestSchemaGuard:
    """Validates a JSON body and headers against declared schemas.

    Fail-closed at every branch. Returns the CANONICAL body bytes so the caller
    transmits exactly what was validated — the ordering channel is removed, and
    there is no gap between the object checked and the object sent.
    """

    def __init__(self, body: Optional[BodySchema] = None,
                 headers: Optional[HeaderSchema] = None):
        self._body = body
        self._headers = headers or HeaderSchema()

    # -- body ---------------------------------------------------------

    def canonical_body(self, payload: Any) -> bytes:
        """Validate `payload` and return canonical JSON bytes.

        Canonical means sorted keys and fixed separators, so `{"a":1,"b":2}` and
        `{"b":2,"a":1}` produce identical bytes. Key order is a real channel
        (log2(n!) bits for n keys); re-serializing removes it rather than
        budgeting for it.
        """
        if self._body is None:
            raise SchemaRefused(
                "a body was supplied but no body schema is declared for this "
                "request; bodies are declared or refused, never assumed")
        if not isinstance(payload, dict):
            raise SchemaRefused(
                f"body root is {type(payload).__name__}, not an object; a schema "
                f"describes named keys and cannot account for a bare value")
        self._check_object(payload, self._body.root, path="$")
        return json.dumps(payload, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")

    def _check_object(self, value: Mapping, schema: ObjectSchema, path: str):
        field_map, array_map, object_map = schema.key_map()
        for key in value:
            if not isinstance(key, str):
                raise SchemaRefused(f"{path}: non-string key {key!r}")
            if key not in field_map and key not in array_map and key not in object_map:
                raise SchemaRefused(
                    f"{path}.{key}: undeclared key. Refused, not stripped: a body "
                    f"that cannot be fully accounted for must not be sent.")

        for name, spec in field_map.items():
            if name not in value:
                if spec.required:
                    raise SchemaRefused(f"{path}.{name}: required key missing")
                continue
            self._check_scalar(value[name], spec, f"{path}.{name}")

        for name, aspec in array_map.items():
            if name not in value:
                if aspec.required:
                    raise SchemaRefused(f"{path}.{name}: required array missing")
                continue
            items = value[name]
            if not isinstance(items, list):
                raise SchemaRefused(
                    f"{path}.{name}: declared as an array, got "
                    f"{type(items).__name__}")
            if len(items) > aspec.max_items:
                raise SchemaRefused(
                    f"{path}.{name}: {len(items)} items, declared max "
                    f"{aspec.max_items}; array length is attacker-chosen capacity")
            for i, item in enumerate(items):
                self._check_scalar(item, aspec.item, f"{path}.{name}[{i}]")

        for name, sub in object_map.items():
            if name not in value:
                if name in schema.required_objects:
                    raise SchemaRefused(f"{path}.{name}: required object missing")
                continue
            child = value[name]
            if not isinstance(child, dict):
                raise SchemaRefused(
                    f"{path}.{name}: declared as an object, got "
                    f"{type(child).__name__}")
            self._check_object(child, sub, f"{path}.{name}")

    @staticmethod
    def _validate_value(spec: FieldSpec, raw: str, path: str):
        """Run a FieldSpec check and re-raise as SchemaRefused.

        FieldSpec.validate raises PayloadRefused (it belongs to the request-line
        layer). Letting that escape from here would mean a body/header violation
        is a different exception type depending on which check caught it, and a
        caller writing `except SchemaRefused` would silently miss half of them.
        One layer, one exception type.
        """
        try:
            spec.validate(raw)
        except PayloadRefused as e:
            detail = getattr(e, "operator_detail", str(e))
            raise SchemaRefused(f"{path}: {detail}")

    @classmethod
    def _check_scalar(cls, value: Any, spec: FieldSpec, path: str):
        """Strict on the JSON type before the value.

        JSON can express one value several ways (1, "1", 1.0, true). A validator
        that coerces accepts every alternative, and each alternative is free bits
        for an injected agent. So the parsed type must match the declared type
        exactly, and only then is the value checked.
        """
        if isinstance(value, bool):
            # bool is a subclass of int in Python; JSON true/false is never a
            # declared type here, so reject before the int branch sees it.
            raise SchemaRefused(
                f"{path}: boolean is not a declared type (use an ENUM with "
                f"explicit choices so the value set is visible)")
        if spec.type is FieldType.INTEGER:
            if not isinstance(value, int):
                raise SchemaRefused(
                    f"{path}: declared INTEGER, got {type(value).__name__}; "
                    f"types are not coerced, because each accepted encoding of a "
                    f"value is another way to say the same thing")
            cls._validate_value(spec, str(value), path)
            return
        if not isinstance(value, str):
            raise SchemaRefused(
                f"{path}: declared {spec.type.value}, got {type(value).__name__}")
        cls._validate_value(spec, value, path)

    # -- headers ------------------------------------------------------

    def check_headers(self, headers: Optional[Mapping[str, str]]) -> Dict[str, str]:
        """Validate headers and return them; refuses anything undeclared."""
        headers = headers or {}
        declared = {f.name.lower(): f for f in self._headers.fields}
        seen = set()
        for name, value in headers.items():
            low = name.lower()
            if low in FORBIDDEN_ENCODINGS or low == "content-encoding":
                raise SchemaRefused(
                    "content-encoding is refused: a compressed body can carry far "
                    "more attacker-chosen data than its size suggests, which makes "
                    "capacity accounting a lie")
            if low in FORBIDDEN_HEADERS:
                raise SchemaRefused(
                    f"header {name!r} is refused by construction (channel header)")
            if low not in declared:
                raise SchemaRefused(
                    f"header {name!r} is undeclared. Refused, not stripped.")
            if low in seen:
                raise SchemaRefused(f"header {name!r} repeated")
            seen.add(low)
            if not isinstance(value, str):
                raise SchemaRefused(f"header {name!r}: value must be a string")
            self._validate_value(declared[low], value, f"header {name}")
        for low, spec in declared.items():
            if spec.required and low not in seen:
                raise SchemaRefused(f"required header {spec.name!r} missing")
        return dict(headers)

    @property
    def capacity_bits(self) -> int:
        """Total declared capacity across body and headers."""
        body_bits = self._body.capacity_bits if self._body else 0
        return body_bits + self._headers.capacity_bits


def order_channel_bits(n_keys: int) -> int:
    """Bits carried purely by key ORDER for an n-key object.

    Reported so the removal is legible: canonical re-serialization takes this to
    zero. Eight keys is ~15 bits — two bytes per request, from nothing but the
    order someone wrote them in.
    """
    return int(math.floor(math.log2(math.factorial(max(n_keys, 1))))) if n_keys > 1 else 0
