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
import os, sys, threading
# (red-team 2026-09-01) This line used to hardcode an absolute path into the author's
# container, so the probe imported DriftCore from a fixed tree no matter which tree it
# was run in — §0f's "probe that scanned the wrong repository", committed inside the
# artifact whose whole job is verification. It failed in the direction that made the
# fix look good: every tree reported "no race", including the unfixed baseline.
# Resolve from THIS FILE's location instead, so the probe always tests the tree it
# ships in.
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if not os.path.isdir(os.path.join(_root, "driftcore")):
    raise SystemExit(
        f"REFUSING TO RUN: no driftcore package at {_root!r}.\n"
        f"This probe resolves the tree from its OWN location, so it must sit in\n"
        f"<repo>/probes/. Run the copy in the repo's probes/ directory, not a\n"
        f"flattened copy elsewhere — a probe that imports the wrong tree reports\n"
        f"'no race' everywhere, which is how this exact bug hid once already.")
sys.path.insert(0, _root)

# (2026-09-09) An unconfigured process now REFUSES identity rather than accepting
# any name not on a six-word denylist. A probe is not a deployment and verifies
# nobody, so it declares that — otherwise its own CONTROLS fail and the failure
# reads as a finding. Caught exactly that way: this probe reported a "leak" that
# was its legitimate-release control being denied.
import driftcore.authority.human_identity as _identity_boot
_identity_boot.declare_label_only("probe: single process, no verifier installed")


import driftcore.authority.human_identity as hi
from driftcore.safety.safe_halt import SafeHalt

PRINCIPAL = "operator_jane"

# ── controls: establish what the policy actually says, before racing anything ──
hi.reset_policy()
_identity_boot.declare_label_only("test suite: single process, no verifier installed")
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
_identity_boot.declare_label_only("test suite: single process, no verifier installed")

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
_identity_boot.declare_label_only("test suite: single process, no verifier installed")
