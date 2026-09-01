"""
test_halt_release_authority.py — who may clear a safety hold.

Regression for a red-team finding verified by execution on 2026-08-31.

Law Zero item 2 ("SafetyKernel.release identity-gated, no default principal") was
recorded as DONE. It was not. The fix removed the default principal so `release()`
with no argument raised PermissionError — and left the TYPE unchanged. Under
LABEL_ONLY, the mode of any process that has not installed a verifier, the gate was
`isinstance(str) and not in ("", "system", "auto", "auto-sign", "agent",
"reflection")`. Executed against v101:

    release(authorized_by="justin")      RELEASED (locked True -> False)
    release(authorized_by="poppy")       RELEASED (locked True -> False)
    release(authorized_by="claude")      RELEASED (locked True -> False)
    release(authorized_by="LifeCore-16") RELEASED (locked True -> False)

A halt called because a child was in the path was cleared by the robot naming
itself, and the audit line recorded Poppy as the releasing human.

THE PROPERTY THIS FILE TESTS, stated so a later reader can check the test matches
the claim: clearing a safety hold requires a VERIFIED ATTESTATION, in every
deployment mode, and continues to WORK when one is presented.

The second half of that sentence is why the positive control exists. A file that
only asserted "every string is refused" would pass just as well if release() had
been broken outright, and an e-stop that can never be cleared is its own outage.
Both halves must hold.
"""
import sys

from driftcore.authority.human_identity import (
    HumanAttestation, HumanIdentityVerifier, is_human, mode,
    register_human_principal, set_verifier, reset_policy)
from driftcore.kernel.safety_kernel import SafetyKernel, RELEASE_ACTION

p = 0
def ok(cond, label):
    global p
    assert cond, "FAIL: " + label
    p += 1
    print("  ok:", label)


def halted_kernel():
    k = SafetyKernel()
    k.emergency_halt("child in the path")
    assert k.locked is True, "fixture did not halt"
    return k


def released(k, who):
    """True if `who` cleared the halt. Never raises: the two refusal paths are a
    PermissionError and a silent no-op, and both count as 'did not release'."""
    try:
        k.release(authorized_by=who)
    except PermissionError:
        return False
    return k.locked is False


# ══ 1. LABEL_ONLY — the mode the finding was found in ═══════════════════
reset_policy()
ok(mode() == "LABEL_ONLY",
   "fixture: nothing configured, so the process is in the insecure default mode "
   "— this is the state an unconfigured deployment actually ships in")

ok(is_human("poppy") is True,
   "control: LABEL_ONLY still accepts a bare label for ORDINARY sites, so this "
   "test is exercising the release pin and not a global mode change")

for who in ("justin", "poppy", "claude", "the_robot", "LifeCore-16", "operator",
            "human_operator", "mallory"):
    ok(released(halted_kernel(), who) is False,
       f"LABEL_ONLY: {who!r} cannot clear a kernel halt")

for bad in (None, 1, True, object(), ["justin"], {"principal": "justin"}):
    ok(released(halted_kernel(), bad) is False,
       f"LABEL_ONLY: {type(bad).__name__} cannot clear a kernel halt")


# ══ 2. REGISTERED — a name is still not a proof ═════════════════════════
reset_policy()
register_human_principal("justin")
ok(mode() == "REGISTERED", "fixture: one registration moves the process to REGISTERED")
ok(is_human("justin") is True,
   "control: REGISTERED accepts the registered name at ORDINARY sites")
ok(released(halted_kernel(), "justin") is False,
   "REGISTERED: the registered name alone does NOT clear a halt — a registry proves "
   "the name was configured, never that the person acted")


# ══ 3. ATTESTED — the positive control ══════════════════════════════════
# Without this section the file above would pass against a release() that refuses
# everything unconditionally, which is a different bug, not a fix.
reset_policy()
_v = HumanIdentityVerifier()
_v.register_principal("justin", "operator-key")
set_verifier(_v)

_att = HumanAttestation.issue("operator-key", principal="justin",
                              action=RELEASE_ACTION, ttl_seconds=60, nonce="n1")
k = halted_kernel()
ok(released(k, _att) is True,
   "POSITIVE CONTROL: a valid attestation for the release action DOES clear the "
   "halt — the gate refuses, it is not merely broken")
ok(any(e["decision"] == "HALT_RELEASED" for e in k.override_log),
   "the successful release is recorded as HALT_RELEASED in the override log")

# and the attacks, now against a configured process
_replay = _att
ok(released(halted_kernel(), _replay) is False,
   "ATTESTED: the same attestation cannot be replayed onto a second halt")

_wrong = HumanAttestation.issue("operator-key", principal="justin",
                                action="some_other_action", ttl_seconds=60, nonce="n2")
ok(released(halted_kernel(), _wrong) is False,
   "ATTESTED: an attestation bound to a different action does not release a halt")

_forged = HumanAttestation.issue("ATTACKER-KEY", principal="justin",
                                 action=RELEASE_ACTION, ttl_seconds=60, nonce="n3")
ok(released(halted_kernel(), _forged) is False,
   "ATTESTED: an attestation signed with the wrong key is a forgery, not a release")

_unknown = HumanAttestation.issue("operator-key", principal="poppy",
                                  action=RELEASE_ACTION, ttl_seconds=60, nonce="n4")
ok(released(halted_kernel(), _unknown) is False,
   "ATTESTED: an unregistered principal does not release a halt, even correctly signed")

ok(released(halted_kernel(), "justin") is False,
   "ATTESTED: the bare name of a registered, verified human is still not a release")


# ══ 4. the halt itself stays ungated — stopping is not authorisation ════
reset_policy()
k = SafetyKernel()
k.emergency_halt("anyone at all may pull this")
ok(k.locked is True,
   "emergency_halt takes no principal and refuses nobody: a stop that requires an "
   "authentication ceremony is not an emergency stop. Authority gates the RESTART.")

reset_policy()


# ══ 5. safe_halt: the SOFT ladder is preserved, the gap is made visible ══
# The pin tried here on 2026-08-31 was reverted (it flattened SOFT/HARD). What
# replaces it does not refuse — it refuses to LIE. Property: a release that nothing
# could verify is never recorded as a verified human release.
from driftcore.safety.safe_halt import SafeHalt

reset_policy()                                   # LABEL_ONLY, nothing configured
h = SafeHalt(); h.soft_halt()
ok(h.release("planner_agent_7") == "SYSTEM_RESUMED",
   "SOFT ladder preserved: software-only recovery still releases simply, so an "
   "operator is never left with no sanctioned path")
ok(h.status()["release_integrity_ok"] is False,
   "...but the release is flagged: nothing could verify that principal")
ok(h.status()["unverified_releases"][0]["principal"] == "planner_agent_7",
   "...and the label that was accepted is named in the record")
ok(any("UNVERIFIED" in e["event"] for e in h.log),
   "...and the log says UNVERIFIED rather than 'HALT_RELEASED by <name>'")

# DISCRIMINATION CONTROL: a genuinely verified release must NOT be flagged, or the
# flag means nothing and the check above passes for the wrong reason.
h2 = SafeHalt(verifier=lambda p: p == "alice-badge-7731"); h2.soft_halt()
ok(h2.release("alice-badge-7731") == "SYSTEM_RESUMED",
   "CONTROL: with a verifier installed the verified principal still releases")
ok(h2.status()["release_integrity_ok"] is True,
   "CONTROL: a verified release is NOT flagged — the flag discriminates")
ok(any("HALT_RELEASED by" in e["event"] for e in h2.log),
   "CONTROL: the verified release logs as a plain human release")

# the removed default principal
try:
    SafeHalt().release()
    ok(False, "release() with no principal must not be callable")
except TypeError:
    ok(True, "release() no longer has a default principal: the argument is required, "
             "so no caller silently names 'human_operator' as the releasing human")

reset_policy()
print(f"\n{p}/{p} checks passed — test_halt_release_authority.py")
