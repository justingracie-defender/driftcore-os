"""
test_signed_permission.py
=========================
The universal signed-permission primitive: signature/expiry/replay/scope, with the
role hierarchy expressed as DATA (which keys sign what), not code. The LifeCore
parent/adult/kid ladder is modeled here purely via keys + allowed_signers + scope,
proving DriftCore stays universal.
"""
import time
from driftcore.verification.signed_permission import (
    Grant, PermissionVerifier, PermissionError_, InvalidSignature, PermissionExpired,
    PermissionReplay, ScopeExceeded, UnknownSigner,
)

p = 0
def ok(cond, label):
    global p
    assert cond, "FAIL: " + label
    p += 1
    print("  ok:", label)

PARENT_KEY = "parent-authority-key"
ADULT_KEY  = "adult-authority-key"
KID_KEY    = "kid-authority-key"

def verifier():
    v = PermissionVerifier()
    v.register_key("parent", PARENT_KEY)   # the DEPLOYMENT installs these keys +
    v.register_key("adult", ADULT_KEY)     # decides what each may sign. THAT is the
    v.register_key("kid", KID_KEY)         # role hierarchy — as data, not code.
    return v

# 1. a validly signed, in-scope grant verifies
g = Grant.issue(PARENT_KEY, key_id="parent", role="parent",
                scope=("doors:front", "media:*"), subject="robot-1",
                ttl_seconds=60, nonce="n1")
ok(verifier().verify(g, required_scope=("doors:front",)).role == "parent",
   "valid signed grant, action within scope -> verifies")

# 2. TAMPER the scope -> signature fails (can't widen your own grant)
tampered = Grant(**{**g.__dict__, "scope": ("doors:front", "media:*", "doors:back")})
try:
    verifier().verify(tampered, required_scope=("doors:back",)); ok(False, "should raise")
except InvalidSignature:
    ok(True, "editing a grant's scope breaks the signature (cannot self-widen authorization)")

# 3. FORGED signer: agent mints its own grant with a key not in the registry
forged = Grant.issue("agent-made-up-key", key_id="agent", role="admin",
                     scope=("*",), subject="robot-1", ttl_seconds=60, nonce="nf")
try:
    verifier().verify(forged, required_scope=("anything",)); ok(False, "should raise")
except UnknownSigner:
    ok(True, "a grant signed by an unregistered key is rejected (agent cannot mint authority)")

# 4. EXPIRY
gexp = Grant.issue(PARENT_KEY, key_id="parent", role="parent", scope=("media:*",),
                   subject="robot-1", ttl_seconds=1, nonce="ne", now=time.time() - 10)
try:
    verifier().verify(gexp, required_scope=("media:play",)); ok(False, "should raise")
except PermissionExpired:
    ok(True, "an expired grant is rejected")

# 5. REPLAY: nonce burned after use
v = verifier()
g5 = Grant.issue(ADULT_KEY, key_id="adult", role="adult", scope=("doors:*",),
                 subject="robot-1", ttl_seconds=60, nonce="n5")
v.verify(g5, required_scope=("doors:front",)); v.consume(g5)
try:
    v.verify(g5, required_scope=("doors:front",)); ok(False, "should raise")
except PermissionReplay:
    ok(True, "a consumed grant's nonce cannot be replayed")

# 6. SCOPE EXCEEDED: in-scope for media, action needs doors
g6 = Grant.issue(KID_KEY, key_id="kid", role="kid", scope=("media:child_safe",),
                 subject="robot-1", ttl_seconds=60, nonce="n6")
try:
    verifier().verify(g6, required_scope=("doors:front",)); ok(False, "should raise")
except ScopeExceeded:
    ok(True, "a grant is rejected for a capability outside its scope")

# 7. WILDCARD scope segment: 'doors:*' covers 'doors:front' but not 'media:play'
g7 = Grant.issue(ADULT_KEY, key_id="adult", role="adult", scope=("doors:*",),
                 subject="robot-1", ttl_seconds=60, nonce="n7")
ok(verifier().verify(g7, required_scope=("doors:front", "doors:back")).role == "adult",
   "trailing-wildcard scope covers matching sub-capabilities")
try:
    verifier().verify(Grant.issue(ADULT_KEY, key_id="adult", role="adult", scope=("doors:*",),
                      subject="robot-1", ttl_seconds=60, nonce="n7b"),
                      required_scope=("media:play",)); ok(False, "should raise")
except ScopeExceeded:
    ok(True, "wildcard does not leak across capability families (doors:* != media)")

# 8. THE LADDER, expressed as DATA: only a PARENT-tier key may authorize a
#    high-tier action. DriftCore enforces "which signer", deployment defines it.
def kid_tries_parent_action():
    gk = Grant.issue(KID_KEY, key_id="kid", role="kid", scope=("household:factory_reset",),
                     subject="robot-1", ttl_seconds=60, nonce="n8")
    # deployment policy: this action may ONLY be signed by 'parent'
    verifier().verify(gk, required_scope=("household:factory_reset",),
                      allowed_signers=("parent",))
try:
    kid_tries_parent_action(); ok(False, "kid-signed high-tier action should raise")
except UnknownSigner:
    ok(True, "hierarchy-as-data: a kid-key grant is refused where policy requires a parent key")

# parent CAN authorize the same action
gp = Grant.issue(PARENT_KEY, key_id="parent", role="parent",
                 scope=("household:factory_reset",), subject="robot-1",
                 ttl_seconds=60, nonce="n8p")
ok(verifier().verify(gp, required_scope=("household:factory_reset",),
                     allowed_signers=("parent",)).role == "parent",
   "hierarchy-as-data: a parent-key grant authorizes the high-tier action")

# 9. SUBJECT binding: a grant for robot-1 doesn't authorize robot-2
g9 = Grant.issue(PARENT_KEY, key_id="parent", role="parent", scope=("media:*",),
                 subject="robot-1", ttl_seconds=60, nonce="n9")
try:
    verifier().verify(g9, required_scope=("media:play",), expected_subject="robot-2")
    ok(False, "wrong subject should raise")
except ScopeExceeded:
    ok(True, "a grant bound to one subject does not authorize another")

# 10. ACTION BINDING (TOCTOU seam): grant pinned to a specific action
binding = PermissionVerifier.bind_action("arm_1", "pick_up_cup", {"cup": "red"})
g10 = Grant.issue(PARENT_KEY, key_id="parent", role="parent", scope=("arm:move",),
                  subject="robot-1", ttl_seconds=60, nonce="n10", action_binding=binding)
ok(verifier().verify(g10, required_scope=("arm:move",), action_binding=binding).role == "parent",
   "action-bound grant verifies for the pinned action")
wrong = PermissionVerifier.bind_action("arm_1", "pick_up_knife", {})
try:
    verifier().verify(g10, required_scope=("arm:move",), action_binding=wrong)
    ok(False, "substituted action should raise")
except ScopeExceeded:
    ok(True, "action-binding seam: a substituted action fails the grant (TOCTOU defense hook)")

# 11. round-trip serialization preserves verifiability
d = g.to_dict()
g_rt = Grant.from_dict(d)
ok(verifier().verify(g_rt, required_scope=("doors:front",)).sig == g.sig,
   "grant survives to_dict/from_dict and still verifies")

print(f"\n{p}/{p} tests passed")
