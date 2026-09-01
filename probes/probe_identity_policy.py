"""Probe: can the IDENTITY POLICY change mid-release, so the release commits under
rules that were evaluated before the change?

Unlike the _restart_authority instance, every mutation here is on a PUBLIC API:
`register_human_principal()` moves the process LABEL_ONLY -> REGISTERED, which flips
`status()["secure"]` from False to True.

safe_halt.release() reads the policy TWICE, at different times:
  1. `_is_human(authorized_by)`   — decides whether the release is permitted at all
  2. `_id_status()["secure"]`     — decides whether it is recorded as a VERIFIED
                                    human release or lands in `unverified_releases`

Nothing ties those two reads to the same policy.
"""
import sys, threading
sys.path.insert(0, "/home/claude/work/session/driftcore-os")

import driftcore.authority.human_identity as hi
from driftcore.safety.safe_halt import SafeHalt

PRINCIPAL = "operator_jane"

# ── controls: establish what the policy actually says, before racing anything ──
hi.reset_policy()
print("CONTROL 1 — LABEL_ONLY")
print("  mode:", hi.mode(), " secure:", hi.status()["secure"])
print(f"  is_human({PRINCIPAL!r}):", hi.is_human(PRINCIPAL, action="safe_halt_release"),
      "  <- passes: not on the six-item denylist. Nothing was checked.")

hi.register_human_principal("someone_else")
print("\nCONTROL 2 — REGISTERED (someone_else registered, jane is NOT)")
print("  mode:", hi.mode(), " secure:", hi.status()["secure"])
_denied = hi.is_human(PRINCIPAL, action="safe_halt_release")
print(f"  is_human({PRINCIPAL!r}):", _denied,
      "  <- under this policy the release would be REFUSED.")
hi.reset_policy()

# ── the race ──
print("\n" + "=" * 68)
print("RACE — policy tightens between the permission check and the audit decision")
print("=" * 68)

entered = threading.Event()
may_return = threading.Event()
_real_is_human = hi.is_human


def slow_is_human(*a, **kw):
    """Real check, then a pause. Under ATTESTED this is signature verification —
    genuinely slow work, not an artificial delay."""
    result = _real_is_human(*a, **kw)
    entered.set()
    may_return.wait(5)
    return result


hi.is_human = slow_is_human
try:
    h = SafeHalt()                      # no SafeHalt verifier: the C2 ledger path
    h.soft_halt()
    out = []
    t = threading.Thread(target=lambda: out.append(h.release(PRINCIPAL)))
    t.start()
    entered.wait(5)
    print(f"\n  thread A: is_human({PRINCIPAL!r}) evaluated under {hi.mode()} -> permitted")
    hi.register_human_principal("someone_else")   # public API, another thread
    print(f"  main:     register_human_principal() -> mode is now {hi.mode()},"
          f" secure={hi.status()['secure']}")
    print(f"  main:     under this policy is_human({PRINCIPAL!r}) ="
          f" {_real_is_human(PRINCIPAL, action='safe_halt_release')}")
    may_return.set()
    t.join(5)
finally:
    hi.is_human = _real_is_human

s = h.status()
print("\n  result:              ", out[0])
print("  halt cleared:        ", s["active"] is False)
print("  unverified_releases: ", s["unverified_releases"])
print("  release_integrity_ok:", s["release_integrity_ok"])
print("  log tail:            ", h.log[-1]["event"][:60])

print()
if (out[0] == "SYSTEM_RESUMED" and s["unverified_releases"] == []
        and s["release_integrity_ok"] is True):
    print("FINDING CONFIRMED — two failures in one release:")
    print("  (1) permitted under a policy that no longer holds; under the policy in")
    print("      force at commit time this principal would have been REFUSED.")
    print("  (2) recorded as a VERIFIED human release. unverified_releases is empty")
    print("      and release_integrity_ok is True, so the C2 signal built to say")
    print("      'nobody actually checked' reports that somebody did.")
else:
    print("no finding — the release did not commit under the stale policy")

hi.reset_policy()
