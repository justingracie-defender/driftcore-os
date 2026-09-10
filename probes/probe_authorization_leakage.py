"""Adversarial sweep: can authorization granted to A be used by B?

Not a test file — an attack script. Every boundary in the repo that holds
authorization state gets three questions put to it by execution:

  Q1  If Alice is authorized right now, what stops Bob receiving the benefit?
  Q2  What stops Alice's authorization for X becoming authorization for Y?
  Q3  What stops an authorization valid 5ms ago being used after the thing it
      authorized has changed?

Run from the repo root: python3 probes/probe_authorization_leakage.py
"""
import os
import sys
import threading

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if not os.path.isdir(os.path.join(_root, "driftcore")):
    raise SystemExit(f"REFUSING TO RUN: no driftcore package at {_root!r}.")
sys.path.insert(0, _root)

# (2026-09-09) An unconfigured process now REFUSES identity rather than accepting
# any name not on a six-word denylist. A probe is not a deployment and verifies
# nobody, so it declares that — otherwise its own CONTROLS fail and the failure
# reads as a finding. Caught exactly that way: this probe reported a "leak" that
# was its legitimate-release control being denied.
import driftcore.authority.human_identity as _identity_boot
_identity_boot.declare_label_only("probe: single process, no verifier installed")


FINDINGS = []
CLEARED = []
NOT_TESTED = []


def result(boundary, question, leaked, detail):
    """A boundary that could not be driven is NOT cleared.

    The first version of this script had two buckets, so an attack that failed to
    construct its object counted as a pass and inflated the cleared total from 9
    to 11. "The attack did not run" and "the attack found nothing" are different
    results and must not share a column.
    """
    CLEARED.append((boundary, question, detail)) if not leaked else \
        FINDINGS.append((boundary, question, detail))
    print(f"  {'LEAK' if leaked else 'ok  '}  {boundary:34s} {question}")
    if detail:
        print(f"         {detail}")


def not_tested(boundary, question, why):
    NOT_TESTED.append((boundary, question, why))
    print(f"  ????  {boundary:34s} {question}")
    print(f"         NOT TESTED — {why}")


# ── 1. SafeHalt — the direct question ────────────────────────────────────────
print("\n[1] SafeHalt — does a release authorized by A benefit B?")

from driftcore.safety.safe_halt import SafeHalt

# A verifier that accepts jane and REFUSES mallory. This is the control that
# makes the attack mean anything: B must be refused on its own merits, so if B
# gets through it can only be by inheriting A's in-flight state.
#
# (An earlier version of this attack let B strip the verifier and use a bare name
# under LABEL_ONLY. B got through — and I nearly recorded it as a cross-thread
# leak. It was not: B passed its OWN identity check, because LABEL_ONLY accepts
# any name off the denylist. That is the documented LABEL_ONLY weakness, not
# leakage. Asserting the symptom instead of the mechanism, exactly as §0h warns.)
def _picky(principal):
    if principal == "operator_jane":
        _in.set()
        _hold.wait(5)
        return True
    return False            # mallory is refused, always


_in, _hold = threading.Event(), threading.Event()
h = SafeHalt(verifier=_picky)
h.soft_halt()
_out = []
t = threading.Thread(target=lambda: _out.append(h.release("operator_jane")))
t.start()
_in.wait(5)

# Thread B, whom the verifier refuses, tries while A's authorization is in flight.
try:
    _b = SafeHalt.release(h, "mallory")
except Exception as e:
    _b = f"raised {type(e).__name__}"
_hold.set()
t.join(5)

result("SafeHalt.release", "Q1 cross-thread",
       "SYSTEM_RESUMED" in str(_b),
       f"B(refused by verifier)={str(_b)[:40]!r} halt_active={h.status()['active']}")

# Control: the same verifier must still let the legitimate principal through,
# or the refusal above proves paralysis rather than isolation.
_h3 = SafeHalt(verifier=lambda p: p == "operator_jane")
_h3.soft_halt()
result("SafeHalt.release", "CONTROL legitimate release",
       _h3.release("operator_jane") != "SYSTEM_RESUMED",
       f"jane releases cleanly: {_h3.status()['active'] is False}")

# Q3: authorization valid before an escalation, spent after.
_in2, _hold2 = threading.Event(), threading.Event()
h2 = SafeHalt(verifier=lambda p: (_in2.set(), _hold2.wait(5), True)[2])
h2.soft_halt()
_o2 = []
t2 = threading.Thread(target=lambda: _o2.append(h2.release("operator_jane")))
t2.start()
_in2.wait(5)
h2.hard_halt()
_hold2.set()
t2.join(5)
result("SafeHalt.release", "Q3 stale-after-change",
       h2.status()["active"] is False,
       f"halt still active={h2.status()['active']}")


# ── 2. GrantAuthority — is a single-use grant single-use under concurrency? ──
print("\n[2] GrantAuthority — can two threads spend one grant?")

from driftcore.verification.governed_actuator import GovernedActuator, GrantAuthority

auth = GrantAuthority(in_process_only=True)
grant = auth.mint("turret_1", "fire")
act = GovernedActuator("turret_1", auth)

_barrier = threading.Barrier(8)
_spent = []


def _spend():
    _barrier.wait(5)
    try:
        _spent.append(act.actuate("fire", grant))
    except Exception:
        _spent.append(False)


_ts = [threading.Thread(target=_spend) for _ in range(8)]
[x.start() for x in _ts]
[x.join(5) for x in _ts]
_n = sum(1 for s in _spent if s is True)
result("GrantAuthority single-use", "Q1 double-spend", _n > 1,
       f"8 threads raced one grant; {_n} succeeded; actuator performed "
       f"{len(act.performed)} time(s)")

# Q2: does a grant for one command authorize another?
g2 = auth.mint("turret_1", "fire")
try:
    _cross = act.actuate("stand_down", g2)
except Exception:
    _cross = False
result("GrantAuthority binding", "Q2 action-substitution", _cross is True,
       f"grant minted for 'fire' used for 'stand_down' -> {_cross}")

# Two coordinators sharing one authority: does A's spend block B?
act_b = GovernedActuator("turret_1", auth)
g3 = auth.mint("turret_1", "fire")
_first = act.actuate("fire", g3)
try:
    _replay = act_b.actuate("fire", g3)
except Exception:
    _replay = False
result("GrantAuthority replay", "Q3 reuse-after-spend", _replay is True,
       f"same grant on a second actuator sharing the authority -> {_replay}")


# ── 3. HumanAttestation — is `action` bound into the signature? ──────────────
print("\n[3] HumanAttestation — is the action cryptographically bound?")

import driftcore.authority.human_identity as hi

hi.reset_policy()
_identity_boot.declare_label_only("test suite: single process, no verifier installed")
v = hi.HumanIdentityVerifier()
v.register_principal("jane", b"jane-key")
hi.set_verifier(v)
try:
    att = hi.HumanAttestation.issue(b"jane-key", principal="jane",
                                    action="safe_halt_release", ttl_seconds=60,
                                    nonce=os.urandom(8).hex())
    ok_same = hi.is_human(att, action="safe_halt_release")
    ok_other = hi.is_human(att, action="storage_delete_tier1")
    result("HumanAttestation action", "Q2 action-substitution",
           ok_other is True,
           f"issued for safe_halt_release; accepted for storage_delete_tier1 "
           f"-> {ok_other} (control, same action -> {ok_same})")

    # Q2b: tamper the action field directly on the object.
    forged = None
    try:
        import dataclasses
        forged = dataclasses.replace(att, action="storage_delete_tier1")
    except Exception:
        pass
    if forged is not None:
        result("HumanAttestation tamper", "Q2 field-rewrite",
               hi.is_human(forged, action="storage_delete_tier1") is True,
               "action rewritten on a signed attestation")

    # Q1: is an attestation single-use, and single-use across threads?
    att2 = hi.HumanAttestation.issue(b"jane-key", principal="jane",
                                     action="safe_halt_release", ttl_seconds=60,
                                     nonce=os.urandom(8).hex())
    _b2 = threading.Barrier(8)
    _uses = []

    def _use():
        _b2.wait(5)
        try:
            _uses.append(hi.is_human(att2, action="safe_halt_release"))
        except Exception:
            _uses.append(False)

    _t2 = [threading.Thread(target=_use) for _ in range(8)]
    [x.start() for x in _t2]
    [x.join(5) for x in _t2]
    _nu = sum(1 for u in _uses if u is True)
    result("HumanAttestation single-use", "Q1 concurrent reuse", _nu > 1,
           f"8 threads presented one attestation; {_nu} accepted")
finally:
    hi.reset_policy()
    _identity_boot.declare_label_only("test suite: single process, no verifier installed")


# ── 4. NarrowingChannel — can concurrent narrowing WIDEN authority? ─────────
print("\n[4] NarrowingChannel — conversation may shrink authority, never grow it")

from driftcore.verification.narrowing_channel import NarrowingChannel

_nc = NarrowingChannel(["a", "b", "c", "d"], constraints=["c1", "c2"])
_start = set(_nc.permitted)
_bar = threading.Barrier(8)
_errs = []


def _narrow(keep):
    _bar.wait(5)
    try:
        _nc.apply(restrict_to=list(keep), speaker="agent")
    except Exception as e:
        _errs.append(f"{type(e).__name__}")


# Eight threads narrow to different subsets simultaneously. The invariant is
# monotonic: the end state must be a subset of where it started, and must never
# contain a capability that no surviving proposal permitted.
_subsets = [{"a"}, {"b"}, {"a", "b"}, {"c"}, {"a", "c"}, {"b", "c"},
            {"d"}, {"a", "d"}]
_ts4 = [threading.Thread(target=_narrow, args=(x,)) for x in _subsets]
[x.start() for x in _ts4]
[x.join(5) for x in _ts4]
_end = set(_nc.permitted)
result("NarrowingChannel", "Q1 concurrent widening", not _end <= _start,
       f"start={sorted(_start)} end={sorted(_end)} errs={sorted(set(_errs))[:3]}")

# Q2: can restore() be used to widen past the original grant? That is the
# escape hatch, and the one place widening is legitimate at all.
_widened = False
try:
    _nc.restore(["a", "b", "c", "d", "SMUGGLED"], restored_by="agent")
    _widened = "SMUGGLED" in _nc.permitted
except Exception:
    _widened = False
result("NarrowingChannel.restore", "Q2 widening past the original grant",
       _widened is True,
       f"agent-driven restore introduced a capability never granted: {_widened}")


# ── 5. PhysicalEnvelope — does an expired authorization survive? ────────────
print("\n[5] PhysicalEnvelope — _authorised_until is a time-based grant")

not_tested("PhysicalEnvelope", "Q3 expiry",
           "constructor needs trusted_sources plus a condition/evidence "
           "pipeline; driving it correctly is its own piece of work and a "
           "half-driven attack would report a clearance it has not earned")

not_tested("clarification_channel._consumed", "Q1 concurrent token reuse",
           "token lifecycle needs a real exchange to attack; not driven")

not_tested("scoped_authorization._spent", "Q1 concurrent double-spend",
           "persists to disk via _spent_path; needs a fixture; not driven")


# ── Summary ───────────────────────────────────────────────────────────────
print("\n" + "=" * 72)
print(f"  attacks that RAN    : {len(FINDINGS) + len(CLEARED)}")
print(f"  leaks found         : {len(FINDINGS)}")
print(f"  cleared by an attack: {len(CLEARED)}")
print(f"  NOT TESTED          : {len(NOT_TESTED)}   <- not clearances")
for b, q, w in NOT_TESTED:
    print(f"      {b} — {q}")
if FINDINGS:
    print("\n  LEAKS:")
    for b, q, d in FINDINGS:
        print(f"    {b} — {q}")
        print(f"      {d}")
else:
    print("\n  No leak reproduced by THESE attacks. That is not the same as")
    print("  'no leak exists' — it is the set of questions that were asked.")
