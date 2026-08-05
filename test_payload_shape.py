"""Payload shape: a THIRD_PARTY destination receives DECLARED FIELDS, not free
text. Closes the last channel in THREAT_MODEL_exfiltration.md — exfiltration via
path/query to a host the human legitimately allowlisted."""

from driftcore.kernel.payload_shape import (
    FieldType, FieldSpec, PathTemplate, ShapePolicy, PayloadShapeGuard, ShapedRequest,
    PayloadRefused, UndeclarableTemplate, TOKEN_HARD_CAP, INTEGER_HARD_CAP,
)
from driftcore.kernel.egress_guard import EgressPolicy, EgressGuard

passed = 0
def ok(c, label):
    global passed
    assert c, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")


# A legitimate third-party API the human declared: weather lookups.
forecast = PathTemplate(
    method="GET", path="/v1/forecast",
    fields=(
        FieldSpec("q", FieldType.TOKEN, required=True, max_length=24),
        FieldSpec("units", FieldType.ENUM, choices=frozenset({"metric", "imperial"})),
        FieldSpec("days", FieldType.INTEGER, min_value=1, max_value=14),
    ),
    purpose="daily forecast for a declared location")
policy = ShapePolicy.build("api.weather.com", [forecast], declared_by="justin")
guard = PayloadShapeGuard([policy])


print("== the residual: egress guard alone permits the exfil query ==")
eg = EgressGuard(EgressPolicy.build(["https://api.weather.com"], declared_by="justin"))
leak = "https://api.weather.com/v1/forecast?q=Kingston&ref=justin-gracie-613-449-8616"
ok(eg.check(leak).permitted,
   "destination layer ALLOWS the request carrying a secret in the query (the gap)")

print("== payload shape refuses it ==")
permitted, reason = guard.permits(leak)
ok(not permitted, "undeclared parameter refused")
_, op_reason = guard.permits(leak, operator_detail=True)
ok("undeclared parameter" in op_reason and "ref" in op_reason,
   "operator view names the offending parameter")
ok("not stripped" in op_reason,
   "operator view states it is REFUSED, not silently stripped")
ok("ref" not in reason,
   "caller-visible reason stays generic (no probing oracle)")

print("== the intended call still works ==")
ok(guard.permits("https://api.weather.com/v1/forecast?q=Kingston&units=metric&days=3")[0],
   "declared fields with valid values are permitted")
ok(guard.permits("https://api.weather.com/v1/forecast?q=Kingston")[0],
   "optional fields may be omitted")

print("== every declared type actually constrains ==")
ok(not guard.permits("https://api.weather.com/v1/forecast?q=Kingston&units=exfil")[0],
   "ENUM rejects a value outside the declared set")
ok(not guard.permits("https://api.weather.com/v1/forecast?q=Kingston&days=99")[0],
   "INTEGER rejects a value above the declared maximum")
ok(not guard.permits("https://api.weather.com/v1/forecast?q=Kingston&days=abc")[0],
   "INTEGER rejects a non-integer")
ok(not guard.permits(
    "https://api.weather.com/v1/forecast?q=" + "A" * 40)[0],
   "TOKEN rejects a value longer than its declared max_length")
ok(not guard.permits(
    "https://api.weather.com/v1/forecast?q=Kingston%20secret%3Ajustin")[0],
   "TOKEN rejects characters outside the declared set (spaces, colons)")

print("== path is exact; nothing else on the host is implied ==")
ok(not guard.permits("https://api.weather.com/v1/forecast/justin")[0],
   "an undeclared path on a declared host is refused")
ok(not guard.permits("https://api.weather.com/v1/upload?q=Kingston")[0],
   "a different path on the same host is refused")
ok(not guard.permits("https://api.weather.com/v1/forecast?q=Kingston", method="POST")[0],
   "a declared path under an undeclared method is refused")

print("== the sneaky shapes ==")
ok(not guard.permits("https://api.weather.com/v1/forecast?q=Kingston#justin")[0],
   "URL fragment refused (fragments are not part of a declared shape)")
ok(not guard.permits("https://api.weather.com/v1/forecast?q=Kin&q=gston")[0],
   "repeated parameter refused (repetition multiplies capacity)")
ok(not guard.permits("https://other.example.com/v1/forecast?q=Kingston")[0],
   "a host with no declared shape is refused entirely")
ok(not guard.permits("https://api.weather.com/v1/forecast?Q=Kingston")[0],
   "parameter names are exact; 'Q' is not 'q'")

print("== spelling a secret one declared enum at a time is capped, not free ==")
# Even using ONLY declared fields, an injected agent gets 1 byte per request from
# an ENUM. That is the residual the docstring admits — bounded, not zero.
spell = [guard.permits(f"https://api.weather.com/v1/forecast?q=X&units={u}")[0]
         for u in ("metric", "imperial", "metric")]
ok(all(spell), "declared enum values are permitted (the bounded residual is real)")
ok(forecast.total_capacity <= forecast.capacity_budget,
   f"template capacity {forecast.total_capacity}B is within its declared budget")

print("== declaration-time lint: a template that is itself a channel is refused ==")
try:
    PathTemplate(method="GET", path="/v1/log",
                 fields=(FieldSpec("note", FieldType.TOKEN, max_length=64),
                         FieldSpec("note2", FieldType.TOKEN, max_length=64)),
                 purpose="logging")
    ok(False, "over-budget template should have been refused")
except UndeclarableTemplate as e:
    ok("budget" in str(e), "over-capacity template refused at DECLARATION time")

try:
    FieldSpec("prose", FieldType.TOKEN, max_length=4096)
    ok(False, "oversized token should have been refused")
except UndeclarableTemplate as e:
    ok(str(TOKEN_HARD_CAP) in str(e),
       f"TOKEN longer than the {TOKEN_HARD_CAP}-char cap refused (prose is a channel)")

try:
    FieldSpec("mode", FieldType.ENUM)
    ok(False, "ENUM without choices should have been refused")
except UndeclarableTemplate as e:
    ok("free text" in str(e), "ENUM with no declared choices refused")

try:
    PathTemplate(method="GET", path="/v1/x", purpose="")
    ok(False, "purposeless template should have been refused")
except UndeclarableTemplate as e:
    ok("purpose" in str(e), "template without a purpose refused")

try:
    PathTemplate(method="GET", path="/v1/{id}", purpose="fetch")
    ok(False, "wildcard path should have been refused")
except UndeclarableTemplate as e:
    ok("exact" in str(e), "variable path segment refused (it is a token in disguise)")

try:
    ShapePolicy.build("api.weather.com", [forecast], declared_by="")
    ok(False, "unattributed policy should have been refused")
except UndeclarableTemplate as e:
    ok("declared_by" in str(e), "shape policy must be attributable")

print("== RED TEAM 2026-08 regressions: the INTEGER digit-string channel ==")
# F1: an unbounded INTEGER advertised 8 bytes and accepted "1"*400.
try:
    FieldSpec("id", FieldType.INTEGER)
    ok(False, "unbounded INTEGER should be undeclarable")
except UndeclarableTemplate as e:
    ok("unbounded" in str(e),
       "F1: INTEGER without bounds refused at declaration (was: unlimited digits)")

# F3: a bounded 1..14 field advertised 1 byte and accepted 300 leading zeros.
days = FieldSpec("days", FieldType.INTEGER, min_value=1, max_value=14)
padded = "0" * 300 + "7"
try:
    days.validate(padded)
    ok(False, "leading-zero padding should be refused")
except PayloadRefused as e:
    ok("canonical" in e.operator_detail or "capped" in e.operator_detail,
       "F3: 300 leading zeros refused (was: 1-byte field carrying 300 chars)")
ok(days.validate("7") is None, "canonical value still validates")
try:
    days.validate("+7"); ok(False, "'+7' should be refused")
except PayloadRefused:
    ok(True, "non-canonical '+7' refused")

# length cap fires before int() on a huge string
big = FieldSpec("n", FieldType.INTEGER, min_value=0, max_value=999999)
try:
    big.validate("9" * 500)
    ok(False, "500-digit value should be refused")
except PayloadRefused as e:
    ok("character" in e.operator_detail and "capped" in e.operator_detail,
       "F1: over-long digit string refused on LENGTH before numeric parse")

try:
    FieldSpec("huge", FieldType.INTEGER, min_value=0, max_value=10**40)
    ok(False, "40-digit bound should be undeclarable")
except UndeclarableTemplate as e:
    ok("digit" in str(e), f"INTEGER wider than the {INTEGER_HARD_CAP}-digit cap refused")

print("== F2: capacity math uses ceil(log2), not floor ==")
import math
def correct(n): return max(1, (math.ceil(math.log2(n)) + 7) // 8)
for n in (3, 5, 17, 257, 1000):
    fs = FieldSpec("e", FieldType.ENUM,
                   choices=frozenset(str(i) for i in range(n)))
    ok(fs.capacity_bytes == correct(n),
       f"F2: ENUM n={n} capacity {fs.capacity_bytes}B == ceil(log2) {correct(n)}B")

print("== F2b: INTEGER capacity charges for the wire format, not just the span ==")
narrow = FieldSpec("y", FieldType.INTEGER, min_value=1000000, max_value=1000001)
ok(narrow.capacity_bytes >= 7,
   "a 2-value range needing 7 digits is charged for its digits, not its span")

print("== F7: overlapping templates are refused, not silently shadowed ==")
a = PathTemplate("GET", "/v1/dup", (), purpose="first")
b = PathTemplate("GET", "/v1/dup",
                 (FieldSpec("q", FieldType.TOKEN, max_length=24),), purpose="second")
try:
    ShapePolicy.build("dup.com", [a, b], declared_by="justin")
    ok(False, "duplicate (method, path) should be refused")
except UndeclarableTemplate as e:
    ok("shadow" in str(e), "F7: duplicate template refused at declaration time")

print("== misc correctness from the same review ==")
try:
    FieldSpec("z", FieldType.TOKEN, max_length=0)
    ok(False, "max_length=0 should be refused")
except UndeclarableTemplate:
    ok(True, "a field that can never validate is refused")
try:
    FieldSpec("w", FieldType.INTEGER, min_value=10, max_value=1)
    ok(False, "inverted bounds should be refused")
except UndeclarableTemplate as e:
    ok("never validate" in str(e), "inverted min/max refused")

print("== RED TEAM 2026-08 (ChatGPT): STRUCTURE carries bits, not just values ==")
import math as _m

# C1: template identity is a channel no per-template check can see.
many = [PathTemplate("GET", f"/v1/{n}", (), purpose="p")
        for n in ("forecast", "history", "alerts", "satellite", "marine", "climate")]
pol = ShapePolicy.build("api.w.com", many, declared_by="justin")
ok(pol.template_choice_bits == 3,
   f"C1: choosing among 6 templates is counted as {pol.template_choice_bits} bits")
ok(pol.worst_case_bits >= pol.template_choice_bits,
   "C1: policy worst-case includes the template-choice channel")

# A policy is measured PER REQUEST: the widest template plus the template-choice
# bits. So many templates push it over even when each one is individually legal.
tiny = [PathTemplate("GET", f"/v1/p{i}",
                     (FieldSpec("q", FieldType.TOKEN, max_length=40),), purpose="p")
        for i in range(40)]
each_ok = all(t.total_capacity <= t.capacity_budget for t in tiny)
ok(each_ok, "C1: each template is individually within its own budget")
try:
    ShapePolicy.build("wide.com", tiny, declared_by="justin", policy_budget=40)
    ok(False, "policy should bust when choice bits push it over")
except UndeclarableTemplate as e:
    ok("policy budget" in str(e) and "templates" in str(e),
       "C1: policy-wide lint refuses the set although every template passed alone")

# C2: optional-field presence is one bit each, before values.
opt_t = PathTemplate("GET", "/v1/o",
                     (FieldSpec("q", FieldType.TOKEN, required=True, max_length=4),
                      FieldSpec("a", FieldType.ENUM, choices=frozenset({"1", "2"})),
                      FieldSpec("b", FieldType.ENUM, choices=frozenset({"1", "2"})),
                      FieldSpec("c", FieldType.ENUM, choices=frozenset({"1", "2"}))),
                     purpose="p")
ok(opt_t.presence_bits == 3,
   "C2: three optional fields counted as three presence bits")
ok(opt_t.total_capacity_bits == sum(f.capacity_bits for f in opt_t.fields) + 3,
   "C2: presence bits are added to the template's declared capacity")

# C3: a large ENUM is charged its real entropy, not a flat byte.
big_enum = FieldSpec("country", FieldType.ENUM,
                     choices=frozenset(f"c{i}" for i in range(300)))
ok(big_enum.capacity_bits == _m.ceil(_m.log2(300)),
   f"C3: 300-value ENUM charged {big_enum.capacity_bits} bits (real entropy), "
   f"not a rounded byte")
small_enum = FieldSpec("u", FieldType.ENUM, choices=frozenset({"m", "i"}))
ok(big_enum.capacity_bits > small_enum.capacity_bits * 4,
   "C3: a 300-value enum costs far more than a 2-value one (byte-rounding hid this)")

# C4: a wide INTEGER range is charged for its digits (already conservative).
wide_int = FieldSpec("id", FieldType.INTEGER, min_value=1, max_value=10**9)
ok(wide_int.capacity_bits >= _m.log2(10**9),
   "C4: a 1..1e9 range is charged at least its true entropy")

print("== SELF RED TEAM 2026-08: parser differential + TOCTOU ==")

sr_t = PathTemplate("GET", "/v1/f",
                    (FieldSpec("q", FieldType.TOKEN, required=True, max_length=8),),
                    purpose="self red team")
sr_g = PayloadShapeGuard([ShapePolicy.build("api.x.com", [sr_t], declared_by="justin")])

# S1: percent-encoded parameter NAME decoded to a declared name and validated,
# while a receiver that does not decode names sees a different parameter.
ok(not sr_g.permits("https://api.x.com/v1/f?%71=abc")[0],
   "S1: percent-encoded parameter name refused (was: '%71' decoded to 'q' and passed)")
ok("differential" in sr_g.permits("https://api.x.com/v1/f?%71=abc",
                                  operator_detail=True)[1],
   "S1: operator view explains the parser differential")
ok(not sr_g.permits("https://api.x.com/v1/f?q%20=a")[0],
   "S1: any encoded byte in a name is refused")
ok(sr_g.permits("https://api.x.com/v1/f?q=abc")[0],
   "S1: the literal declared name still works")
ok(sr_g.permits("https://api.x.com/v1/f?q=a%2Db")[0],
   "S1: encoding in a VALUE is still fine (only names must be literal)")

# S2: check() is advisory — validated bytes were not bound to sent bytes.
sent = []
def fake_transport(url, method="GET", **kw):
    sent.append(url)
    return "sent"

shaped = ShapedRequest(sr_g, fake_transport)
shaped.request("https://api.x.com/v1/f?q=safe")
ok(sent == ["https://api.x.com/v1/f?q=safe"],
   "S2: ShapedRequest sends exactly the URL it validated")

try:
    shaped.request("https://api.x.com/v1/f?q=safe&leak=SECRET")
    ok(False, "appended parameter should be refused")
except PayloadRefused:
    ok(True, "S2: an appended undeclared parameter cannot reach the transport")
ok(len(sent) == 1, "S2: nothing was transmitted on refusal")

# S3: a constrained query is worthless if a body rides alongside it.
for kw in ({"json": {"secret": "x"}}, {"data": "secret"},
           {"headers": {"X-Leak": "secret"}}, {"params": {"leak": "x"}}):
    try:
        shaped.request("https://api.x.com/v1/f?q=safe", **kw)
        ok(False, f"{list(kw)[0]} should be refused")
    except PayloadRefused as e:
        ok("unconstrained channel" in e.operator_detail,
           f"S3: {list(kw)[0]!r} refused on a shaped request")
ok(len(sent) == 1, "S3: still nothing extra transmitted")

print("== RED TEAM 2026-08 (Meta): redirects, oracle, wide templates, purpose ==")

m_t = PathTemplate("GET", "/v1/f",
                   (FieldSpec("q", FieldType.TOKEN, required=True, max_length=16),),
                   purpose="meta red team")
m_g = PayloadShapeGuard([ShapePolicy.build("api.m.com", [m_t], declared_by="justin")])

# M10 (P0): a validated URL the transport may FOLLOW elsewhere is not a control.
calls = []
def m_transport(url, method="GET", **kw):
    calls.append((url, kw))
    return "ok"
m_shaped = ShapedRequest(m_g, m_transport)
m_shaped.request("https://api.m.com/v1/f?q=a")
ok(calls[-1][1].get("allow_redirects") is False,
   "M10: ShapedRequest forces allow_redirects=False on the transport")
try:
    m_shaped.request("https://api.m.com/v1/f?q=a", allow_redirects=True)
    ok(False, "explicit allow_redirects=True should be refused")
except PayloadRefused:
    ok(True, "M10: a caller cannot re-enable redirect following")

def redirecting_transport(url, method="GET", **kw):
    class R: status_code = 302
    return R()
try:
    ShapedRequest(m_g, redirecting_transport).request("https://api.m.com/v1/f?q=a")
    ok(False, "a 3xx response should be surfaced as a refusal")
except PayloadRefused as e:
    ok("redirect" in e.operator_detail,
       "M10: a 3xx answer is refused rather than quietly followed")

# M6 (P1): refusals must not echo attacker input back to the agent.
allowed, generic = m_g.permits("https://api.m.com/v1/f?q=a&ref=SECRETVALUE")
ok(not allowed, "M6: undeclared parameter still refused")
ok("SECRETVALUE" not in generic and "ref" not in generic,
   "M6: the caller-visible reason echoes neither the name nor the value")
ok(generic == PayloadRefused.GENERIC,
   "M6: callers get a single generic reason (no probing oracle)")
_, detail = m_g.permits("https://api.m.com/v1/f?q=a&ref=SECRETVALUE",
                        operator_detail=True)
ok("ref" in detail,
   "M6: the operator/audit view keeps the specific reason for debugging")

# M8 (P2): many small fields are a channel under any byte budget.
wide = tuple(FieldSpec(f"f{i}", FieldType.ENUM, choices=frozenset({"0", "1"}))
             for i in range(64))
try:
    PathTemplate("GET", "/v1/wide", wide, purpose="wide")
    ok(False, "64 one-bit fields should be refused")
except UndeclarableTemplate as e:
    ok("field cap" in str(e) or "fields, over" in str(e),
       "M8: 64x 1-bit ENUM refused by the field cap (16B, was under the byte budget)")
ok(PathTemplate("GET", "/v1/ok",
                (FieldSpec("q", FieldType.TOKEN, max_length=24),),
                purpose="normal call").total_capacity > 0,
   "M8: a realistic template is unaffected by the cap")

# M7 (P2): `purpose` is metadata, not a smuggling channel.
try:
    PathTemplate("GET", "/v1/p", (), purpose="aGVsbG8gd29ybGQgc2VjcmV0" * 8)
    ok(False, "an oversized purpose should be refused")
except UndeclarableTemplate as e:
    ok("capped" in str(e), "M7: over-long purpose refused (metadata, not a field)")
try:
    PathTemplate("GET", "/v1/p2", (), purpose="ZXhmaWx0cmF0ZWQ=+/=")
    ok(False, "an encoded-blob purpose should be refused")
except UndeclarableTemplate as e:
    ok("prose" in str(e), "M7: non-prose purpose refused")

print(f"\n{passed}/{passed} checks passed")
