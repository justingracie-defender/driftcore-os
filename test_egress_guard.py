"""
Egress guard — adversarial bench. Every bypass class that makes a naive
`if host in allowlist` check worthless, plus the honest-boundary assertions.

Scope note, restated so these tests cannot be over-read: this governs egress that
comes THROUGH the wall. A process that already holds a socket never calls any of
this. See the module docstring.
"""
from driftcore.kernel.egress_guard import (
    EgressGuard, EgressPolicy, EgressVerdict, MalformedDestination,
    normalize_destination, is_private_destination,
)

passed = 0
def ok(c, label):
    global passed
    assert c, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")

POLICY = EgressPolicy.build(
    ["https://api.example.com", "https://updates.example.org:8443"],
    declared_by="justin")
guard = EgressGuard(POLICY)
def v(url): return guard.check(url).verdict
def blocked(url): return not guard.check(url).permitted


print("== the declared destinations work ==")
ok(guard.check("https://api.example.com/v1/thing").permitted,
   "an exactly-declared destination is permitted (path is irrelevant to the triple)")
ok(guard.check("https://api.example.com:443/x").permitted,
   "explicit default port matches the implicit one")
ok(guard.check("https://updates.example.org:8443/pkg").permitted,
   "a non-default declared port matches")

print("== BYPASS 1: userinfo — the apparent host is not the real host ==")
ok(v("https://api.example.com@evil.com/") is EgressVerdict.BLOCK_MALFORMED,
   "'https://api.example.com@evil.com' is refused, not parsed around")
ok(blocked("https://api.example.com:pw@evil.com/"), "userinfo with a password too")

print("== BYPASS 2/3: suffix and substring confusion ==")
ok(blocked("https://api.example.com.evil.com/"), "suffix confusion is not a match")
ok(blocked("https://evil-api.example.com/"), "substring confusion is not a match")
ok(blocked("https://api.example.com.attacker.net/"), "longer suffix chain blocked")
ok(blocked("https://notapi.example.com/"), "prefix confusion blocked")

print("== BYPASS 4: case and trailing dot normalize to the SAME triple ==")
ok(guard.check("https://API.Example.COM/").permitted, "case folds")
ok(guard.check("https://api.example.com./").permitted, "trailing dot folds")
ok(guard.check("HTTPS://API.EXAMPLE.COM./x").permitted, "scheme case + dot together")

print("== BYPASS 5: homograph / IDNA ==")
ok(blocked("https://\u0430pi.example.com/"),
   "Cyrillic 'a' in the host does NOT match the Latin allowlist entry")
ok(normalize_destination("https://api.example.com")[1] == "api.example.com",
   "the Latin original still normalizes to itself")

print("== BYPASS 6: IP literals and the metadata-endpoint class ==")
ok(v("http://169.254.169.254/latest/meta-data/") is EgressVerdict.BLOCK_PRIVATE,
   "link-local metadata endpoint is refused (credential-harvesting class)")
for u in ["http://127.0.0.1/", "http://10.0.0.5/", "http://192.168.1.1/",
          "http://172.16.0.1/", "http://[::1]/", "http://0.0.0.0/"]:
    ok(blocked(u), f"private/loopback destination blocked: {u}")
ok(is_private_destination("169.254.169.254") and not is_private_destination("example.com"),
   "the private-space test distinguishes literals from names")

print("== scheme discipline ==")
for u in ["file:///etc/passwd", "ftp://example.com/", "gopher://api.example.com/",
          "javascript:alert(1)"]:
    ok(v(u) in (EgressVerdict.BLOCK_MALFORMED,), f"non-http(s) scheme refused: {u}")

print("== malformed is never downgraded to a guess ==")
for u in ["", "   ", "not a url", "https://", "https://exa mple.com/",
          "https://example.com:notaport/"]:
    ok(not guard.check(u).permitted, f"unreadable destination refused: {u!r}")

print("== UNCONFIGURED IS NOT PERMISSIVE ==")
bare = EgressGuard()
ok(bare.is_armed() is False, "a guard with no policy reports unarmed")
ok(bare.check("https://api.example.com/").verdict is EgressVerdict.BLOCK_UNDECLARED,
   "and it refuses EVERYTHING — 'no policy' must never read as 'any destination'")

print("== an empty allowlist is refused at build time (ambiguous intent) ==")
try:
    EgressPolicy.build([], declared_by="justin"); ok(False, "empty policy should raise")
except ValueError:
    ok(True, "an empty allowlist is refused rather than silently meaning 'deny all'")
try:
    EgressPolicy.build(["https://api.example.com"], declared_by="")
    ok(False, "missing declared_by should raise")
except ValueError:
    ok(True, "an egress allowlist must be attributable (declared_by required)")
try:
    EgressPolicy.build(["http://127.0.0.1"], declared_by="j")
    ok(False, "private destination should require explicit opt-in")
except ValueError:
    ok(True, "declaring a private destination requires explicit allow_private")
ok(EgressGuard(EgressPolicy.build(["http://127.0.0.1:9000"], declared_by="j",
                                  allow_private=True,
                                  private_reason="on-prem model server, no route out"))
  .check("http://127.0.0.1:9000/").permitted,
   "...and with the explicit opt-in, an on-prem destination is permitted")

print("== port is part of identity ==")
ok(blocked("https://api.example.com:8080/"),
   "same host, undeclared port, is a different destination")
ok(blocked("https://updates.example.org/"),
   "declared only on :8443 — the default port is not implied")

print("== fail closed on internal error ==")
class _Boom(EgressGuard):
    def is_armed(self): raise RuntimeError("boom")
gb = _Boom(POLICY)
# force the error path through check() by breaking the policy object it reads
gb._policy = object()
r = gb.check("https://api.example.com/")
ok(not r.permitted, "a guard that cannot evaluate refuses")

print("== measurements make a silent guard visible ==")
m = guard.measurements()
ok(m["armed"] is True and m["allowed"] > 0 and m["blocked"] > 0
   and m["declared_destinations"] == 2,
   "the guard reports armed state, counts, and how many destinations are declared")

print(f"\nALL {passed} CHECKS PASSED")


# ── wired into the wall ────────────────────────────────────────────────
from driftcore.verification.mediated_actuation import ActuationBroker
from driftcore.verification.signed_permission import PermissionVerifier, Grant
from driftcore.verification.invariant_guard import Effect

KEY = b"\x11" * 32
SOCK = "/tmp/dc_egress.sock"
def _g(v, aid, cmd, params, nonce, scope):
    return Grant.issue(KEY, key_id="operator", role="operator", scope=scope,
                       subject="robot-1", ttl_seconds=60, nonce=nonce,
                       action_binding=PermissionVerifier.bind_action(aid, cmd, params)
                       ).to_dict()
def _rq(aid, cmd, p, g):
    return {"op": "execute", "actuator_id": aid, "command": cmd, "params": p, "grant": g}

print()
print("== WIRED: egress destination is interlocked at the actuation wall ==")
v_ = PermissionVerifier(); v_.register_key("operator", KEY)
sent = []
b = ActuationBroker(SOCK, v_, enforce_effects=True, egress_guard=EgressGuard(POLICY))
b.register_actuator("http", lambda **k: sent.append(k) or "sent",
                    required_scope=("net:out",), effects=[Effect.DATA_EGRESS],
                    effect_declared_by="justin", destination_param="url")

p_ok = {"url": "https://api.example.com/v1/report"}
r = b._handle(_rq("http", "post", p_ok, _g(v_, "http", "post", p_ok, "x1", ("net:out",))))
ok(r.get("ok") is True and len(sent) == 1,
   "a DECLARED destination actuates through the wall")

p_bad = {"url": "https://evil.com/exfil"}
r = b._handle(_rq("http", "post", p_bad, _g(v_, "http", "post", p_bad, "x2", ("net:out",))))
ok(r.get("ok") is False and r.get("error_code") == "EGRESS_BLOCK_UNDECLARED"
   and len(sent) == 1,
   "an UNDECLARED destination is refused at the wall and nothing was sent")

p_meta = {"url": "http://169.254.169.254/latest/meta-data/"}
r = b._handle(_rq("http", "post", p_meta, _g(v_, "http", "post", p_meta, "x3", ("net:out",))))
ok(r.get("error_code") == "EGRESS_BLOCK_PRIVATE",
   "the cloud metadata endpoint is refused at the wall (credential-harvesting class)")

p_none = {"body": "no destination here"}
r = b._handle(_rq("http", "post", p_none, _g(v_, "http", "post", p_none, "x4", ("net:out",))))
ok(r.get("error_code") == "EGRESS_NO_DESTINATION",
   "a DATA_EGRESS capability with no destination in params does not act")

print("== an egress capability on a broker with NO allowlist cannot act ==")
b2 = ActuationBroker(SOCK, v_, enforce_effects=True)     # no egress_guard
b2.register_actuator("http", lambda **k: sent.append(k), required_scope=("net:out",),
                     effects=[Effect.DATA_EGRESS], effect_declared_by="justin", destination_param="url")
r = b2._handle(_rq("http", "post", p_ok, _g(v_, "http", "post", p_ok, "x5", ("net:out",))))
ok(r.get("error_code") == "EGRESS_UNCONFIGURED" and len(sent) == 1,
   "unconfigured egress governance refuses rather than permits")

print("== non-egress capabilities are unaffected by the interlock ==")
moved = []
b3 = ActuationBroker(SOCK, v_, enforce_effects=True, egress_guard=EgressGuard(POLICY))
b3.register_actuator("arm", lambda **k: moved.append(k) or "ok",
                     required_scope=("a:m",), effects=[Effect.PHYSICAL_FORCE],
                     effect_declared_by="justin")
r = b3._handle(_rq("arm", "move", {}, _g(v_, "arm", "move", {}, "x6", ("a:m",))))
ok(r.get("ok") is True and moved, "a PHYSICAL_FORCE capability is not egress-gated")

print("== posture reports ungoverned egress AND the unverifiable precondition ==")
bare_b = ActuationBroker(SOCK, v_)
layers = {e["layer"]: e["consequence"] for e in bare_b.posture_events()}
ok("egress_allowlist" in layers, "an ungoverned-egress broker records it as a posture event")
ok("unmediated_egress_verified" in layers
   and "CANNOT VERIFY" in layers["unmediated_egress_verified"],
   "and it states plainly that the no-socket precondition is NOT verifiable here")

print(f"\nALL {passed} CHECKS PASSED")


print()
print("== SELF-RED-TEAM PINS (E1-E5): all were live bypasses ==")
v2 = PermissionVerifier(); v2.register_key("operator", KEY)
def _mk(enf=True, gd=True):
    return ActuationBroker(SOCK, v2, enforce_effects=enf,
                           egress_guard=EgressGuard(POLICY) if gd else None)

# E1: decoy parameter — an allowed url plus the real destination under another key
bE, hit = _mk(), []
bE.register_actuator("h1", lambda **k: hit.append(k), required_scope=("n:o",),
                     effects=[Effect.DATA_EGRESS], effect_declared_by="j", destination_param="url")
pd = {"url": "https://api.example.com/ok", "endpoint": "https://evil.com/exfil"}
r = bE._handle(_rq("h1", "post", pd, _g(v2, "h1", "post", pd, "p1", ("n:o",))))
ok(not r.get("ok") and not hit,
   "E1: EVERY destination in params is checked, not just the first (decoy blocked)")

# E1b: nested decoy
bN, hitn = _mk(), []
bN.register_actuator("h2", lambda **k: hitn.append(k), required_scope=("n:o",),
                     effects=[Effect.DATA_EGRESS], effect_declared_by="j", destination_param="url")
pn = {"url": "https://api.example.com/ok", "body": {"callback": "https://evil.com/x"}}
r = bN._handle(_rq("h2", "post", pn, _g(v2, "h2", "post", pn, "p2", ("n:o",))))
ok(not r.get("ok") and not hitn, "E1b: a NESTED decoy destination is found and blocked")

# E2: an HTTP actuator mis-declared NONE is a declaration mismatch, not a free pass
bT, hitt = _mk(), []
bT.register_actuator("h3", lambda **k: hitt.append(k), required_scope=("n:o",),
                     effects=[Effect.NONE], effect_declared_by="j")
pt = {"url": "https://evil.com/exfil"}
r = bT._handle(_rq("h3", "post", pt, _g(v2, "h3", "post", pt, "p3", ("n:o",))))
ok(r.get("error_code") == "EGRESS_DECLARATION_MISMATCH" and not hitt,
   "E2: a URL handed to a non-egress capability is a MISMATCH held for review")

# E3: a registry read failure must not become the interlock's bypass
bR, hitr = _mk(), []
bR.register_actuator("h4", lambda **k: hitr.append(k), required_scope=("n:o",),
                     effects=[Effect.DATA_EGRESS], effect_declared_by="j", destination_param="url")
class _BadReg:
    def effects_for(self, a): raise RuntimeError("registry down")
    def declaration(self, a): return None
bR._effect_registry = _BadReg(); bR._effect_gate = None
pr = {"url": "https://evil.com/exfil"}
r = bR._handle(_rq("h4", "post", pr, _g(v2, "h4", "post", pr, "p4", ("n:o",))))
ok(r.get("error_code") in ("EGRESS_ERROR", "REGISTRY_ERROR") and not hitr,
   "E3: a registry read failure FAILS CLOSED — an error handler is not a bypass. "
   "(The refusal MOVED EARLIER: it is now REGISTRY_ERROR raised at the read itself, "
   "unconditionally, rather than EGRESS_ERROR raised further down only when the params "
   "also contained a destination. Same intent, strictly stronger.)")

# E5: an unenforced broker with an undeclared actuator is covered by the mismatch rule
bU, hitu = _mk(enf=False), []
bU.register_actuator("h5", lambda **k: hitu.append(k), required_scope=("n:o",))
pu = {"url": "https://evil.com/exfil"}
r = bU._handle(_rq("h5", "post", pu, _g(v2, "h5", "post", pu, "p5", ("n:o",))))
ok(not r.get("ok") and not hitu,
   "E5: even unenforced, a URL to an undeclared capability does not egress")

# and the legitimate path still works, single destination, no decoys
bOK, hito = _mk(), []
bOK.register_actuator("h6", lambda **k: hito.append(k) or "sent", required_scope=("n:o",),
                      effects=[Effect.DATA_EGRESS], effect_declared_by="j", destination_param="url")
po = {"url": "https://api.example.com/v1/report", "body": "fine"}
r = bOK._handle(_rq("h6", "post", po, _g(v2, "h6", "post", po, "p6", ("n:o",))))
ok(r.get("ok") is True and hito, "the legitimate declared-destination path still works")

# a non-egress capability with NO urls is untouched
bA, hita = _mk(), []
bA.register_actuator("arm2", lambda **k: hita.append(k) or "ok", required_scope=("a:m",),
                     effects=[Effect.PHYSICAL_FORCE], effect_declared_by="j")
r = bA._handle(_rq("arm2", "move", {"joint": 3}, _g(v2, "arm2", "move", {"joint": 3},
                                                    "p7", ("a:m",))))
ok(r.get("ok") is True and hita, "a non-egress capability with no destinations is unaffected")

print(f"\nALL {passed} CHECKS PASSED")


print()
print("== EXTERNAL RED TEAM PINS (Meta / Grok / ChatGPT) ==")
from driftcore.kernel.egress_guard import (
    resolve_and_pin, GuardedEgress, EgressRefused, MalformedDestination)

# Meta P2-2 (verified live): CGNAT was NOT caught by ipaddress.is_private
ok(is_private_destination("100.64.0.1"), "CGNAT 100.64.0.0/10 is refused (RFC 6598)")
ok(is_private_destination("64:ff9b::1"), "NAT64 prefix is refused (reaches v4 via v6)")
ok(not is_private_destination("8.8.8.8"), "and genuinely public space still passes")

# Meta P0-2: an exception to a safety default must carry its reason
try:
    EgressPolicy.build(["http://10.0.0.5"], declared_by="j", allow_private=True)
    ok(False, "allow_private without a reason should be refused")
except ValueError:
    ok(True, "allow_private=True requires private_reason — the WHY travels with it")

# Meta P1-3: an unreviewable allowlist is not a control
try:
    EgressPolicy.build([f"https://h{i}.example.com" for i in range(10_001)], declared_by="j")
    ok(False, "an oversized allowlist should be refused")
except ValueError:
    ok(True, "an allowlist too large for a human to review is refused")

# ChatGPT G6: repeated attacks must stay distinguishable
g6 = EgressGuard(POLICY)
for _ in range(4): g6.check("https://evil.com/x")
g6.check("https://other.evil/y")
top = dict(g6.measurements()["top_rejected"])
ok(top.get("https://evil.com/x") == 4,
   "the rejection histogram preserves the attack pattern, not just a total")

# ALL THREE: DNS rebinding — resolve-and-pin verifies every answer
pub = lambda h, p: [(2, 1, 6, "", ("93.184.216.34", p))]
pinned = resolve_and_pin(("https", "api.example.com", 443), resolver=pub)
ok(pinned.ips == ("93.184.216.34",), "resolve_and_pin returns concrete IPs to connect to")
meta_dns = lambda h, p: [(2, 1, 6, "", ("169.254.169.254", p))]
try:
    resolve_and_pin(("https", "api.example.com", 443), resolver=meta_dns)
    ok(False, "a hostname resolving to metadata space should be refused")
except MalformedDestination:
    ok(True, "a public NAME resolving into private space is refused (rebinding/SSRF shape)")
mixed = lambda h, p: [(2, 1, 6, "", ("93.184.216.34", p)), (2, 1, 6, "", ("10.0.0.5", p))]
try:
    resolve_and_pin(("https", "api.example.com", 443), resolver=mixed)
    ok(False, "a hostile record hidden among benign ones should be refused")
except MalformedDestination:
    ok(True, "EVERY resolved address must pass — a bad one cannot hide behind a good one")

# ALL THREE: redirects must be enforced, not documented
def _t(url, pinned_, **kw):
    if "safe.example.com" in url: return 302, {"Location": "https://evil.com/pwn"}, b""
    return 200, {}, b"ok"
POL2 = EgressPolicy.build(["https://api.example.com", "https://safe.example.com"],
                          declared_by="j")
ge = GuardedEgress(EgressGuard(POL2), _t, resolver=pub)
ok(ge.request("https://api.example.com/x")[0] == 200, "a permitted direct request works")
try:
    ge.request("https://safe.example.com/x")
    ok(False, "a redirect off the allowlist should be refused")
except EgressRefused as e:
    ok("evil.com" in e.hops[-1],
       "a 302 to an undeclared host is REFUSED and the hop chain is preserved")

def _loop(url, pinned_, **kw): return 302, {"Location": "https://api.example.com/a"}, b""
try:
    GuardedEgress(EgressGuard(POL2), _loop, resolver=pub, max_hops=2).request(
        "https://api.example.com/x")
    ok(False, "an infinite redirect loop should exhaust the budget")
except EgressRefused:
    ok(True, "the redirect budget is finite — a loop cannot spin the wall")

# Grok G3/P1-1 (verified live): scheme-less destinations were invisible to sniffing
v3 = PermissionVerifier(); v3.register_key("operator", KEY)
try:
    ActuationBroker(SOCK, v3, enforce_effects=True).register_actuator(
        "h9", lambda **k: None, required_scope=("n:o",),
        effects=[Effect.DATA_EGRESS], effect_declared_by="j")
    ok(False, "a DATA_EGRESS actuator without destination_param should be refused")
except ValueError:
    ok(True, "an egress capability must NAME its destination param — never guessed")

bS = ActuationBroker(SOCK, v3, enforce_effects=True, egress_guard=EgressGuard(POLICY))
hits = []
bS.register_actuator("h10", lambda **k: hits.append(k), required_scope=("n:o",),
                     effects=[Effect.DATA_EGRESS], effect_declared_by="j",
                     destination_param="host")
ps = {"host": "evil.com", "port": 443}          # scheme-less: invisible to the sniffer
r = bS._handle(_rq("h10", "send", ps, _g(v3, "h10", "send", ps, "s1", ("n:o",))))
ok(not r.get("ok") and not hits,
   "a SCHEME-LESS destination in the declared param is checked and refused")
pm = {"port": 443}
r = bS._handle(_rq("h10", "send", pm, _g(v3, "h10", "send", pm, "s2", ("n:o",))))
ok(r.get("error_code") == "EGRESS_NO_DESTINATION" and not hits,
   "a missing declared destination param fails closed")

print(f"\nALL {passed} CHECKS PASSED")
