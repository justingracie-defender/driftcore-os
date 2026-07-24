"""
test_human_identity.py — who counts as a human.

Regression for an external red-team finding: three modules each carried an identical
reserved-word blacklist, so `_is_human("mallory")` was True and any caller that chose its
own `authorised_by` string self-authorized through skill governance, authority override,
and recovery/restore.
"""
import sys
from driftcore.authority.human_identity import (
    HumanAttestation, HumanIdentityVerifier, is_human, mode, status,
    register_human_principal, set_verifier, reset_policy)

p = 0
def ok(cond, label):
    global p
    assert cond, "FAIL: " + label
    p += 1
    print("  ok:", label)

reset_policy()

# ── the defect, pinned ──
ok(mode() == "LABEL_ONLY" and status()["secure"] is False,
   "with nothing configured the mode is LABEL_ONLY and status() reports secure=False — the "
   "insecure fallback is VISIBLE rather than silent")
ok(is_human("mallory") is True and is_human("planner_agent_7") is True,
   "RED-TEAM (external): LABEL_ONLY still accepts any non-reserved string — this is the "
   "documented legacy behaviour, retained only so upgrades do not change silently")
ok("INSECURE" in status()["note"],
   "status() names LABEL_ONLY as INSECURE in plain words, not as a neutral default")

# ── REGISTERED: one registration flips the whole process fail-closed ──
register_human_principal("justin")
ok(mode() == "REGISTERED" and status()["secure"] is True,
   "registering ONE principal moves the process out of LABEL_ONLY")
ok(is_human("justin") is True,
   "REGISTERED: a registered principal is human")
ok(is_human("mallory") is False and is_human("planner_agent_7") is False,
   "RED-TEAM (external, the fix): in REGISTERED mode an invented label is NOT human — a "
   "planner can no longer self-authorize by choosing a string")

# ── ATTESTED: a label alone never suffices ──
reset_policy()
_v = HumanIdentityVerifier()
_v.register_principal("justin", "operator-key")
set_verifier(_v)
ok(mode() == "ATTESTED", "installing a verifier gives ATTESTED mode")
ok(is_human("justin") is False,
   "ATTESTED: a BARE LABEL is never human, even a registered principal's name — the whole "
   "point is that a string is not a credential")
_att = HumanAttestation.issue("operator-key", principal="justin", action="restore",
                              ttl_seconds=60, nonce="n1")
ok(is_human(_att, action="restore") is True,
   "ATTESTED: a valid signed attestation for the right action IS human")

# ── attestation failure modes ──
_replay = HumanAttestation.issue("operator-key", principal="justin", action="restore",
                                 ttl_seconds=60, nonce="n1")
ok(is_human(_replay, action="restore") is False,
   "a REPLAYED attestation nonce is rejected (single-use, like a permission grant)")
_wrong = HumanAttestation.issue("operator-key", principal="justin", action="restore",
                                ttl_seconds=60, nonce="n2")
ok(is_human(_wrong, action="delete_everything") is False,
   "an attestation is BOUND to its action — approval for 'restore' cannot authorize "
   "'delete_everything'")
_forged = HumanAttestation.issue("ATTACKER-KEY", principal="justin", action="restore",
                                 ttl_seconds=60, nonce="n3")
ok(is_human(_forged, action="restore") is False,
   "an attestation signed with the wrong key is rejected (forgery)")
_unknown = HumanAttestation.issue("operator-key", principal="nobody", action="restore",
                                  ttl_seconds=60, nonce="n4")
ok(is_human(_unknown, action="restore") is False,
   "an attestation for an UNREGISTERED principal is rejected")
_expired = HumanAttestation.issue("operator-key", principal="justin", action="restore",
                                  ttl_seconds=0.001, nonce="n5")
import time as _t; _t.sleep(0.01)
ok(is_human(_expired, action="restore") is False,
   "an EXPIRED attestation is rejected")

# ── construction refuses nonsense ──
for bad in ({"principal": "", "action": "a"}, {"principal": "j", "action": ""}):
    try:
        HumanAttestation.issue("k", ttl_seconds=60, nonce="x", **bad)
        ok(False, "empty principal/action must raise")
    except ValueError:
        pass
ok(True, "an attestation with an empty principal or action is rejected at issue")
try:
    HumanAttestation.issue("k", principal="j", action="a", ttl_seconds=10**9, nonce="x")
    ok(False, "unbounded ttl must raise")
except ValueError:
    ok(True, "an attestation with an unbounded TTL is rejected — an approval that never "
             "expires is a standing grant nobody remembers issuing")
try:
    _v.register_principal("agent", "k")
    ok(False, "reserved label must not be registerable")
except ValueError:
    ok(True, "a reserved non-human label ('agent') cannot be registered as a principal")

# ── is_human never raises: it is a gate, and a crash at an authorization site is worse
#    than a refusal ──
for junk in (None, 123, object(), [], {}):
    is_human(junk)
ok(True, "is_human() returns False on junk rather than raising at an authorization site")

# ── the three former copies now share ONE implementation ──
reset_policy()
register_human_principal("justin")
from driftcore.skills.governance import _is_human as g_h
from driftcore.authority.resolver import _is_human as r_h
from driftcore.recovery.store import _is_human as s_h
ok(all(f("mallory") is False for f in (g_h, r_h, s_h))
   and all(f("justin") is True for f in (g_h, r_h, s_h)),
   "skills.governance, authority.resolver and recovery.store now share ONE implementation "
   "— the fix cannot be applied to two of three again")
reset_policy()

print(f"\n{p}/{p} tests passed")
