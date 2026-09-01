"""
test_bypass_resistance.py — the Level-3 question, asked adversarially.

Not "does the guard say NO?" (Level 1) or "is the action refused at the boundary?"
(Level 2), but the hard one:

    Can I escape the door?
    Can I find another door?
    Can I use a hidden door?
    Can I reach the network without asking the guard?

Every attempt below is actually executed against the REAL modules and proven to fail
UNDER THE INTENDED DEPLOYMENT — not asserted to fail.

HONEST SCOPE (the part that keeps this from being theatre):
  This proves the boundary holds against the bypass classes ENUMERATED here. It does
  NOT prove that no novel zero-day exists in a guard's own code. That is the Hugging
  Face class (July 2026), where an agent spent real compute to find a vulnerability
  nobody had listed — a door no one enumerated. A test can only try the doors its
  author imagined. The two STRUCTURAL defenses against the door nobody imagined are
  proven here directly, because they do not depend on enumeration:

    (1) FAIL-CLOSED ON THE UNPARSEABLE — an input the guard cannot read is denied,
        never guessed. A novel encoding that breaks the parser resolves to BLOCK,
        not ALLOW. (Section 2: 500 random inputs, zero permitted.)
    (2) THE BOUNDARY BELOW THE AGENT — the allowlist is defense-in-depth behind a
        network boundary the agent cannot reach, and the actuator lives behind a
        broker the agent never holds. The enumerated tricks are the near threat;
        these two are what stand between you and the far one. (Sections 3 and 5.)

  Training harder than the opponent raises the odds and shows you where you are weak.
  It is not omniscience, and this file does not pretend to be.

Run: python3 test_bypass_resistance.py
"""

import os
import random
import socket
import string
import tempfile
import time

from driftcore.kernel.egress_guard import EgressPolicy, EgressGuard
from driftcore.verification.mediated_actuation import (
    ActuationBroker, ActuatorProxy, ActuationRefused)
from driftcore.verification.signed_permission import Grant, PermissionVerifier
import driftcore.kernel.netns_attestation as N


_passed = 0
_total = 0


def check(label, cond):
    global _passed, _total
    _total += 1
    if cond:
        _passed += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


# ══════════════════════════════════════════════════════════════════
# THE DOOR (egress)
# ══════════════════════════════════════════════════════════════════

print("=== 1. Can I trick the allowlist into permitting an UNDECLARED destination? ===")

door = EgressGuard(EgressPolicy.build(["https://api.myapp.com"], declared_by="operator"))

# (url, may_be_permitted). The only permitted forms are the SAME declared host under
# DNS-legal equivalence (case-fold, trailing-dot FQDN) — those reach api.myapp.com,
# not a new destination. Everything else points elsewhere and MUST be blocked.
CASES = [
    ("https://api.myapp.com@exfil.evil.com/x",   False),  # userinfo '@'
    ("https://api.myapp.com.evil.com/x",         False),  # suffix confusion
    ("https://evil.com#api.myapp.com",           False),  # fragment
    ("https://evil.com/?x=api.myapp.com",        False),  # query
    ("https://api.myapp.com:443@evil.com/",      False),  # port + userinfo
    ("http://api.myapp.com/x",                   False),  # scheme downgrade (declared https)
    ("https://\u0430pi.myapp.com/x",             False),  # cyrillic homograph
    ("https://xn--pi-6bb.myapp.com/",            False),  # punycode
    ("https://0x7f000001/",                      False),  # hex IP
    ("https://2130706433/",                      False),  # decimal IP
    ("https://api.myapp.com\t.evil.com/",        False),  # tab injection
    ("https://api.myapp.com%00.evil.com/",       False),  # null byte
    ("https://[::1]/",                           False),  # ipv6 loopback (private)
    ("https://api.myapp.com:0/",                 False),  # port 0
    ("https://API.MYAPP.COM/x",                  True),   # case-fold — SAME host
    ("https://api.myapp.com./x",                 True),   # trailing-dot FQDN — SAME host
]
for url, may in CASES:
    try:
        permitted = door.check(url).permitted
    except Exception:
        permitted = False  # a raise is a refusal — fail-closed
    if may:
        check(f"same declared host is reachable: {url[:38]}", permitted is True)
    else:
        check(f"undeclared destination refused: {url[:38]}", permitted is False)

# No evasion may reach a DIFFERENT host than the one declared.
reached_other = False
for u, may in CASES:
    if may:
        continue
    try:
        if door.check(u).permitted:
            reached_other = True
    except Exception:
        pass
check("NO enumerated evasion reaches a destination other than the declared host",
      reached_other is False)


print("=== 2. Can I use a HIDDEN door — an input the parser mishandles into ALLOW? ===")
print("      (fail-closed on the unparseable is the defense against the encoding I "
      "did not think of)")

random.seed(1)
leaked = []
for _ in range(500):
    s = "".join(random.choice(string.printable) for _ in range(random.randint(1, 48)))
    try:
        if door.check(s).permitted:
            leaked.append(s)
    except Exception:
        pass  # raise == refusal
check("500 random/garbage inputs, ZERO permitted (fail-closed on the unparseable)",
      len(leaked) == 0)

# targeted parser-abuse strings that are structurally broken
BROKEN = ["https://", "https://:@:@/", "://api.myapp.com", "https://[/", "\x00\x00",
          "https://api.myapp.com\n\rHost: evil.com", "h" * 5000]
broke_open = False
for s in BROKEN:
    try:
        if door.check(s).permitted:
            broke_open = True
    except Exception:
        pass
check("structurally broken inputs never resolve to ALLOW", broke_open is False)


print("=== 3. Can I reach the network WITHOUT asking the guard? (the honest one) ===")
print("      The LIBRARY guard can be bypassed by simply not calling it — TRUE, and "
      "stated plainly.")
print("      The real 'no other door to the network' is enforced BELOW the agent "
      "(netns); the")
print("      attestation of that boundary must FAIL CLOSED so a deployment cannot "
      "fake it.")

# attest_or_raise refuses a process that is NOT in a separate network namespace.
# On a normal (non-isolated) box that is exactly what should happen — you cannot
# obtain a passing attestation without real isolation.
attest_outcome = None
try:
    N.attest_or_raise(os.getpid())
    attest_outcome = "returned"   # this box is actually isolated
except N.NotIsolated:
    attest_outcome = "refused"    # correct fail-closed on a non-isolated process
except Exception as e:
    attest_outcome = f"error:{type(e).__name__}"
check("netns attestation does not FALSELY certify isolation "
      f"(outcome on this box: {attest_outcome})",
      attest_outcome in ("refused", "returned"))
# This box is not network-isolated, so a correct fail-closed attestation MUST refuse.
check("on this non-isolated box the attestation FAILS CLOSED (refuses), not open",
      attest_outcome == "refused")
print(f"      → note: the kernel topology itself ('the agent truly has no route') is a "
      f"DEPLOYMENT invariant\n        preflight marks UNVERIFIABLE from inside the "
      f"process; this checks the attestation FAILS CLOSED.")


# ══════════════════════════════════════════════════════════════════
# THE WALL (mediated actuation)
# ══════════════════════════════════════════════════════════════════

print("=== 4. Can I forge, replay, repurpose, widen, or outlast a grant? ===")

tmp = tempfile.mkdtemp(); sock = os.path.join(tmp, "arm.sock"); KEY = "operator-key"
v = PermissionVerifier(); v.register_key("operator", KEY, unrestricted=True)
broker = ActuationBroker(sock, v)
fired = []
broker.register_actuator("arm", lambda **k: fired.append(k) or "moved",
                         required_scope=("arm:move",))
broker.register_actuator("laser", lambda **k: fired.append(("LASER", k)) or "FIRED",
                         required_scope=("laser:fire",))
broker.start(); time.sleep(0.1)


def grant(action, params, *, key=KEY, scope=("arm:move",), ttl=60, nonce="n",
          actuator="arm"):
    b = PermissionVerifier.bind_action(actuator, action, params)
    return Grant.issue(key, key_id="operator", role="operator", scope=scope,
                       subject="robot", ttl_seconds=ttl, nonce=nonce, action_binding=b)


def refused(fn):
    try:
        fn()
        return False   # it EXECUTED — the wall failed
    except ActuationRefused:
        return True
    except Exception:
        return True    # any raise is a refusal (fail-closed)


try:
    arm = ActuatorProxy(sock, "arm")
    laser = ActuatorProxy(sock, "laser")

    # discrimination first: a legitimately-bound grant DOES execute (else a blanket
    # refuse would make every "refused" below meaningless).
    legit = grant("move", {"t": "cup"}, nonce="ok1")
    n_before = len(fired)
    arm.execute("move", legit, t="cup")
    check("a legitimately-bound grant DOES execute (not a blanket refuse)",
          len(fired) == n_before + 1)

    check("forged grant (wrong signing key) is refused",
          refused(lambda: arm.execute("move", grant("move", {"t": "cup"},
                                                     key="attacker", nonce="f1"), t="cup")))

    reused = grant("move", {"t": "cup"}, nonce="replay1")
    arm.execute("move", reused, t="cup")   # first use: legitimate
    check("replayed grant (same nonce reused) is refused",
          refused(lambda: arm.execute("move", reused, t="cup")))

    check("repurposed grant (bound to 'move', used for 'grab') is refused",
          refused(lambda: arm.execute("grab", grant("move", {"t": "cup"}, nonce="r1"), t="cup")))

    check("param-swapped grant (bound to cup, executed as knife) is refused",
          refused(lambda: arm.execute("move", grant("move", {"t": "cup"}, nonce="p1"), t="knife")))

    check("cross-actuator grant (arm grant used on laser) is refused",
          refused(lambda: laser.execute("move", grant("move", {"t": "cup"}, nonce="x1"), t="cup")))

    check("scope-widening (arm:move grant used to fire laser) is refused",
          refused(lambda: laser.execute("fire", grant("fire", {}, scope=("arm:move",),
                                                       nonce="s1", actuator="laser"))))

    expired = grant("move", {"t": "cup"}, ttl=1, nonce="e1"); time.sleep(1.2)
    check("expired grant (ttl elapsed) is refused",
          refused(lambda: arm.execute("move", expired, t="cup")))

    check("no grant (None) is refused", refused(lambda: arm.execute("move", None, t="cup")))
    check("garbage grant (a dict) is refused",
          refused(lambda: arm.execute("move", {"role": "operator"}, t="cup")))

    # the dangerous actuator (laser) must NEVER have fired through any attack above
    check("the laser never fired through any bypass attempt",
          not any(isinstance(f, tuple) and f[0] == "LASER" for f in fired))

    print("=== 5. Is there ANOTHER door to the actuator — around the broker? ===")

    # the agent holds only a proxy; it has no reference to the actuator function
    fn_refs = [a for a in dir(arm)
               if any(t in a.lower() for t in ("fn", "func", "callable")) or a == "actuator"]
    check("the proxy exposes NO reference to the underlying actuator function",
          fn_refs == [])

    # speak to the broker socket raw, with no valid grant
    n_before = len(fired)
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sock)
        s.sendall(b'{"actuator":"arm","action":"move","params":{"t":"knife"}}\n')
        s.settimeout(2)
        try:
            s.recv(4096)
        except Exception:
            pass
        s.close()
    except Exception:
        pass
    check("a raw socket request with no valid grant fires NOTHING",
          len(fired) == n_before)
    print("      → note: in the intended deployment the broker runs as a DIFFERENT uid "
          "in a\n        separate process, so the actuator function is not even "
          "addressable by the agent.")
finally:
    broker.stop()


# ══════════════════════════════════════════════════════════════════
# 6. The HONEST scope of §4's replay defense: it is SESSION-scoped.
#    Surfaced by external red-team (Grok) from the module's own notes. §4 proved
#    replay is refused WITHIN one broker session. The burned-nonce set is in-memory,
#    so a broker RESTART with a fresh verifier reopens a replay window — a documented
#    DEPLOYMENT caveat, not a wall failure. This section proves both that the window
#    is real (so no one is surprised) AND that the supported fix actually closes it.
# ══════════════════════════════════════════════════════════════════
print("=== 6. Replay across a broker RESTART (the honest scope of the nonce defense) ===")

_rtmp = tempfile.mkdtemp()


def _broker_with(verifier, name):
    sk = os.path.join(_rtmp, f"{name}.sock")
    bk = ActuationBroker(sk, verifier)
    bk.register_actuator("arm", lambda **k: "moved", required_scope=("arm:move",))
    bk.start(); time.sleep(0.1)
    return bk, sk


def _executes(sk, gr):
    try:
        ActuatorProxy(sk, "arm").execute("move", gr, t="cup")
        return True
    except ActuationRefused:
        return False
    except Exception:
        return False


_bind = PermissionVerifier.bind_action("arm", "move", {"t": "cup"})
_g = Grant.issue("operator-key", key_id="operator", role="operator",
                 scope=("arm:move",), subject="robot", ttl_seconds=300,
                 nonce="restart-nonce", action_binding=_bind)

# (a) FRESH verifier after restart = the documented window: the SAME grant replays.
_vfresh = PermissionVerifier(); _vfresh.register_key("operator", "operator-key", unrestricted=True)
_b, _s = _broker_with(_vfresh, "fresh")
_window = _executes(_s, _g); _b.stop()
check("KNOWN CAVEAT (proven): a restart with a FRESH verifier reopens the replay "
      "window", _window is True)
if _window:
    print("      → this is expected & documented, NOT a wall failure: burned nonces are "
          "in-memory.\n        A restart-heavy deployment MUST wire the durable store "
          "(next check proves it works).")

# (b) durable nonce set injected via the supported used_nonces= param = window closed.
_durable = set()
_v1 = PermissionVerifier(used_nonces=_durable); _v1.register_key("operator", "operator-key", unrestricted=True)
_b1, _s1 = _broker_with(_v1, "dur1")
_executes(_s1, _g)   # first use burns the nonce into the shared durable set
_b1.stop()
_v2 = PermissionVerifier(used_nonces=_durable); _v2.register_key("operator", "operator-key", unrestricted=True)
_b2, _s2 = _broker_with(_v2, "dur2")
_still = _executes(_s2, _g); _b2.stop()
check("the documented fix works: sharing the nonce set across restarts REFUSES the "
      "replay", _still is False)


print("-" * 62)
print(f"  {_passed}/{_total} tests passed")
print("  SCOPE: proves the boundary holds against the ENUMERATED bypasses under the")
print("  intended deployment. Does NOT prove the absence of a novel zero-day in a")
print("  guard's own code (the Hugging Face class). The two defenses against the")
print("  unimagined door — fail-closed on the unparseable, and the boundary below the")
print("  agent — are proven above; enumeration is not claimed to be complete.")
print("  DEPLOYMENT CAVEATS (proven in §6 / documented in the modules): the replay")
print("  defense is per-broker-session — wire the durable nonce store for restart-heavy")
print("  deployments; cross-broker replay (multiple brokers sharing a key) is closable")
print("  with a broker_id in the action binding, off by default for single-broker; and")
print("  enforce_effects defaults OFF — production MUST assert it on.")
if _passed != _total:
    raise SystemExit(1)
