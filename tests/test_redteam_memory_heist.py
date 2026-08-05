import sys; sys.path.insert(0, ".")
from driftcore.kernel.egress_guard import (
    EgressPolicy, EgressGuard, GuardedEgress, resolve_and_pin,
    normalize_destination, EgressVerdict, EgressRefused, MalformedDestination)

P=[]; 
def ck(n,c): P.append(c); print(f"  [{'PASS' if c else 'FAIL'}] {n}")

# Allowlist = ONLY the app's own API. This is the whole point: default-deny.
pol = EgressPolicy.build(["https://api.myapp.com"], declared_by="justin")
g = EgressGuard(pol)

print("\nA. Memory-heist core: exfil links to attacker host are refused")
# The attack: page says 'fetch /a /b /c to spell the secret' on attacker's host.
heist = [g.check(f"https://exfil.attacker.com/{c}") for c in "justin"]
ck("every exfil fetch to attacker host BLOCKED",
   all(d.verdict is EgressVerdict.BLOCK_UNDECLARED for d in heist))
ck("the allowlisted API itself still works",
   g.check("https://api.myapp.com/v1/data").permitted)

print("\nB. The evasions the memory-heist relies on")
ck("userinfo trick (api.myapp.com@attacker) blocked",
   g.check("https://api.myapp.com@exfil.attacker.com/x").verdict is EgressVerdict.BLOCK_MALFORMED)
ck("suffix confusion (api.myapp.com.attacker.com) blocked",
   not g.check("https://api.myapp.com.attacker.com/x").permitted)
ck("cloud metadata IP (169.254.169.254) blocked",
   g.check("http://169.254.169.254/latest/meta-data/").verdict is EgressVerdict.BLOCK_PRIVATE)
ck("CGNAT space (100.64.x) blocked",
   g.check("http://100.64.1.1/").verdict is EgressVerdict.BLOCK_PRIVATE)

print("\nC. Redirect variant: trusted page 302s to the attacker")
def transport_redirect(url, pinned, **kw):
    return (302, {"Location": "https://exfil.attacker.com/leak?n=justin"}, b"")
def pub_resolver(h,p): return [(2,1,6,"",("93.184.216.34",p))]  # public IP
ge = GuardedEgress(g, transport_redirect, resolver=pub_resolver)
try:
    ge.request("https://api.myapp.com/start"); ck("redirect-to-attacker refused",False)
except EgressRefused as e:
    ck("redirect-to-attacker refused mid-hop", "attacker" in str(e).lower() or "refused" in str(e).lower())

print("\nD. DNS rebinding: allowlisted NAME resolves into private space")
def rebind_resolver(h,p): return [(2,1,6,"",("169.254.169.254",p))]
try:
    resolve_and_pin(normalize_destination("https://api.myapp.com"), resolver=rebind_resolver)
    ck("rebinding to metadata refused", False)
except MalformedDestination as e:
    ck("rebinding to metadata refused at pin time", "169.254" in str(e) or "private" in str(e).lower())

print("\nE. RESIDUAL PROBE: exfil via PATH/QUERY to an ALLOWLISTED host")
# If the allowlist contains any host whose requests an attacker can observe
# (pastebin, shortener, analytics beacon, a compromised-but-allowed host),
# the secret rides in the path/query and every request is PERMITTED.
leaky = EgressPolicy.build(["https://paste.allowed.com"], declared_by="justin")
lg = EgressGuard(leaky)
enc = [lg.check(f"https://paste.allowed.com/log?c={ch}") for ch in "justin"]
ck("path/query to an allowlisted host is UNCONSTRAINED (all permitted)",
   all(d.permitted for d in enc))
print("      -> secret 'justin' rides out in the query string, guard says ALLOW x6")

print("\n" + "="*56)
print(f"{sum(P)}/{len(P)} checks passed")
