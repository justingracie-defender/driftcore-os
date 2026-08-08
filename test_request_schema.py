"""Request schemas: a declared body and declared headers, or none at all.
Closes the "constrained URL, unconstrained body" gap that payload_shape named as
required companion work."""

from driftcore.kernel.request_schema import (
    ObjectSchema, ArraySpec, BodySchema, HeaderSchema, RequestSchemaGuard,
    SchemaRefused, order_channel_bits,
    MAX_BODY_DEPTH, MAX_ARRAY_ITEMS, FORBIDDEN_HEADERS,
)
from driftcore.kernel.payload_shape import (
    FieldSpec, FieldType, UndeclarableTemplate, PayloadRefused,
    PathTemplate, ShapePolicy, PayloadShapeGuard, ShapedRequest,
)

# The summary below reports passed/EXPECTED_CHECKS, not passed/passed.
# Self-red-team 2026-08: printing "{passed}/{passed}" is self-certifying — the
# two numbers are equal BY CONSTRUCTION, so a file that exits early (an early
# return, a swallowed exception, a conditional skip) reports "3/3 passed" and the
# gate sees nothing wrong. The total just gets quietly smaller, and nobody
# notices a smaller number. A declared expected count makes a shortfall visible.
EXPECTED_CHECKS = 35

passed = 0
def ok(c, label):
    global passed
    assert c, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")


body = BodySchema.build(
    ObjectSchema(fields=(
        FieldSpec("city", FieldType.TOKEN, required=True, max_length=24),
        FieldSpec("days", FieldType.INTEGER, min_value=1, max_value=14),
    )),
    purpose="forecast request body")
guard = RequestSchemaGuard(body=body)


print("== the gap: a shaped URL with an unconstrained body ==")
sp = PayloadShapeGuard([ShapePolicy.build(
    "api.x.com",
    [PathTemplate("POST", "/v1/f",
                  (FieldSpec("q", FieldType.TOKEN, required=True, max_length=8),),
                  purpose="post forecast")],
    declared_by="justin")])
sent = []
def transport(url, method="GET", **kw):
    sent.append((url, kw)); return "ok"

bare = ShapedRequest(sp, transport)          # no schema declared
try:
    bare.request("https://api.x.com/v1/f?q=a", method="POST",
                 json={"note": "ENTIRE CONTENTS OF MEMORY"})
    ok(False, "an undeclared body should be refused")
except PayloadRefused as e:
    ok("unconstrained channel" in e.operator_detail,
       "undeclared body refused when no schema is declared (safe default)")
ok(sent == [], "nothing transmitted on refusal")


print("== a declared body is permitted and canonicalized ==")
shaped = ShapedRequest(sp, transport, schema=guard)
shaped.request("https://api.x.com/v1/f?q=a", method="POST",
               json={"days": 3, "city": "Kingston"})
ok(sent[-1][1]["data"] == b'{"city":"Kingston","days":3}',
   "body is transmitted as CANONICAL bytes (sorted keys, fixed separators)")

print("== key ORDER is a channel, removed rather than budgeted ==")
sent.clear()
shaped.request("https://api.x.com/v1/f?q=a", method="POST",
               json={"city": "Kingston", "days": 3})
a = sent[-1][1]["data"]
shaped.request("https://api.x.com/v1/f?q=a", method="POST",
               json={"days": 3, "city": "Kingston"})
ok(a == sent[-1][1]["data"],
   "two key orderings produce identical bytes on the wire")
ok(order_channel_bits(8) == 15,
   f"an 8-key object carries {order_channel_bits(8)} bits in order alone "
   f"(removed by canonicalization)")

print("== undeclared keys refused, not stripped ==")
for bad, why in [({"city": "K", "leak": "s"}, "extra key"),
                 ({"city": "K", "nested": {"a": 1}}, "undeclared object")]:
    try:
        guard.canonical_body(bad); ok(False, f"{why} should be refused")
    except SchemaRefused as e:
        ok("undeclared key" in e.operator_detail, f"{why} refused")
try:
    guard.canonical_body({"days": 3}); ok(False, "missing required should refuse")
except SchemaRefused as e:
    ok("required" in e.operator_detail, "missing required key refused")

print("== JSON types are not coerced (each encoding is free bits) ==")
for value, why in [("3", "string for an INTEGER"), (3.0, "float for an INTEGER"),
                   (True, "boolean"), (None, "null"), ([1], "array for a scalar")]:
    try:
        guard.canonical_body({"city": "K", "days": value})
        ok(False, f"{why} should be refused")
    except SchemaRefused:
        ok(True, f"{why} refused (no type coercion)")
ok(guard.canonical_body({"city": "K", "days": 3}), "the declared types validate")

print("== body root must be an object ==")
for bad in (["a"], "string", 5):
    try:
        guard.canonical_body(bad); ok(False, "non-object root should refuse")
    except SchemaRefused as e:
        ok("root" in e.operator_detail or "object" in e.operator_detail,
           f"non-object root ({type(bad).__name__}) refused")

print("== arrays: bounded at declaration, length checked at runtime ==")
try:
    ArraySpec("tags", FieldSpec("t", FieldType.TOKEN, max_length=8), max_items=1000)
    ok(False, "an over-long array should be undeclarable")
except UndeclarableTemplate as e:
    ok("cap" in str(e), f"array over the {MAX_ARRAY_ITEMS}-item cap refused")

arr_guard = RequestSchemaGuard(body=BodySchema.build(
    ObjectSchema(arrays=(ArraySpec("tags",
                                   FieldSpec("t", FieldType.TOKEN, max_length=8),
                                   max_items=3),)),
    purpose="tagged request"))
ok(arr_guard.canonical_body({"tags": ["a", "b"]}), "a bounded array validates")
try:
    arr_guard.canonical_body({"tags": ["a", "b", "c", "d"]})
    ok(False, "an over-length array should be refused")
except SchemaRefused as e:
    ok("attacker-chosen capacity" in e.operator_detail,
       "array longer than declared refused (length is capacity)")

print("== nesting is capped: depth multiplies capacity ==")
try:
    ObjectSchema(objects=(("a", ObjectSchema(objects=(
        ("b", ObjectSchema(objects=(("c", ObjectSchema()),))),))),))
    ok(False, f"nesting past {MAX_BODY_DEPTH} should be refused")
except UndeclarableTemplate as e:
    ok("nests" in str(e), f"object deeper than {MAX_BODY_DEPTH} levels refused")
ok(ObjectSchema(objects=(("a", ObjectSchema(objects=(("b", ObjectSchema()),))),)).depth
   == MAX_BODY_DEPTH,
   f"nesting up to {MAX_BODY_DEPTH} levels is still allowed")

print("== capacity budget covers nesting and arrays ==")
try:
    BodySchema.build(
        ObjectSchema(arrays=(ArraySpec("a", FieldSpec("i", FieldType.TOKEN,
                                                      max_length=64),
                                       max_items=16),)),
        purpose="wide", capacity_budget=16)
    ok(False, "an over-budget body should be refused")
except UndeclarableTemplate as e:
    ok("budget" in str(e), "over-capacity body schema refused at DECLARATION time")

print("== headers: declared only, channel headers refused outright ==")
for h in ("Cookie", "Authorization", "Referer", "X-Request-Id"):
    try:
        HeaderSchema(fields=(FieldSpec(h, FieldType.TOKEN, max_length=8),))
        ok(False, f"{h} should be undeclarable")
    except UndeclarableTemplate as e:
        ok("refused" in str(e) or "X-" in str(e),
           f"{h} refused even when declared (channel by construction)")

hg = RequestSchemaGuard(headers=HeaderSchema(fields=(
    FieldSpec("Accept-Language", FieldType.ENUM,
              choices=frozenset({"en", "fr"})),)))
ok(hg.check_headers({"Accept-Language": "en"}), "a declared header validates")
ok(hg.check_headers({"accept-language": "fr"}),
   "header names match case-insensitively (as HTTP requires)")
for bad, why in [({"X-Leak": "secret"}, "undeclared X- header"),
                 ({"Accept-Language": "de"}, "value outside the declared enum"),
                 ({"Content-Encoding": "gzip"}, "content-encoding")]:
    try:
        hg.check_headers(bad); ok(False, f"{why} should be refused")
    except SchemaRefused:
        ok(True, f"{why} refused")

print("== compression breaks capacity accounting, so it is refused ==")
try:
    hg.check_headers({"Content-Encoding": "gzip"})
    ok(False, "gzip should be refused")
except SchemaRefused as e:
    ok("capacity accounting" in e.operator_detail,
       "content-encoding refused with the accounting reason stated")

print("== refusals do not echo attacker input to the caller ==")
try:
    guard.canonical_body({"city": "K", "SECRETKEY": "SECRETVALUE"})
except SchemaRefused as e:
    ok("SECRETVALUE" not in str(e) and "SECRETKEY" not in str(e),
       "caller-visible message echoes neither key nor value")
    ok("SECRETKEY" in e.operator_detail,
       "operator/audit view keeps the specific key for debugging")

print(f"\n{passed}/{EXPECTED_CHECKS} checks passed")
