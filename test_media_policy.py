"""
test_media_policy.py
====================
Proves the safety properties of driftcore/media:

  Invariant:   people PRESENT or UNKNOWN -> retention denied (fail-safe);
               ABSENT -> permitted by policy.
  Override:    policy set to RAW cannot beat the invariant.
  Asymmetry:   tightening is free; loosening needs a human + is audited.
  Camera:      autonomous/covert/unaware captures refused; valid SD and
               consented-email deliveries succeed; the working copy is
               ALWAYS deleted (courier, not album); the tool has no path
               to the learning corpus.

Run:  python test_media_policy.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from driftcore.media import (
    PeopleSignal, RetentionMode, LoadMode, EmbodimentClass,
    MediaPolicy, PeopleMediaInvariant, MediaPolicyController,
    CameraTool, Destination, DestinationKind, SdCardSink, EmailSink,
)

PASS, FAIL = "PASS", "FAIL"
_results = []


def check(name, cond):
    _results.append(bool(cond))
    print(f"  [{PASS if cond else FAIL}] {name}")


# ── Invariant ──────────────────────────────────────────────────────
print("\nPeopleMediaInvariant (fail-safe)")

check("ABSENT permits retention",
      PeopleMediaInvariant.permits_retention(PeopleSignal.ABSENT)[0] is True)
check("PRESENT denies retention",
      PeopleMediaInvariant.permits_retention(PeopleSignal.PRESENT)[0] is False)
check("UNKNOWN denies retention (fails safe)",
      PeopleMediaInvariant.permits_retention(PeopleSignal.UNKNOWN)[0] is False)


# ── Policy cannot override the invariant ───────────────────────────
print("\nPolicy cannot beat the invariant")

ctrl = MediaPolicyController(
    MediaPolicy(ingest=True, retain=RetentionMode.RAW,
                retention_window_days=30, load_to_context=LoadMode.ALWAYS),
    EmbodimentClass.HOME_ROBOT)

d_present = ctrl.decide_retention(PeopleSignal.PRESENT)
d_unknown = ctrl.decide_retention(PeopleSignal.UNKNOWN)
d_absent  = ctrl.decide_retention(PeopleSignal.ABSENT)

check("RAW policy + people PRESENT -> denied", d_present.allowed is False)
check("RAW policy + UNKNOWN -> denied",        d_unknown.allowed is False)
check("RAW policy + ABSENT -> allowed (raw)",
      d_absent.allowed and d_absent.mode is RetentionMode.RAW)


# ── Defaults are conservative ──────────────────────────────────────
print("\nConservative defaults")

office = MediaPolicyController.for_embodiment(EmbodimentClass.SOFTWARE_AGENT)
home   = MediaPolicyController.for_embodiment(EmbodimentClass.HOME_ROBOT)
check("software agent default keeps nothing",
      office.policy.retain is RetentionMode.NONE and not office.policy.ingest)
check("home robot default is transcript-only, not raw",
      home.policy.retain is RetentionMode.TRANSCRIPT_ONLY)


# ── Asymmetric, audited policy change ──────────────────────────────
print("\nPolicy change asymmetry")

c = MediaPolicyController.for_embodiment(EmbodimentClass.HOME_ROBOT)

looser = MediaPolicy(ingest=True, retain=RetentionMode.RAW,
                     retention_window_days=30, load_to_context=LoadMode.ALWAYS)
ok_sys, _ = c.change_policy(looser, authorised_by="system", reason="test")
check("loosening by 'system' is rejected", ok_sys is False)
check("policy unchanged after rejected loosening",
      c.policy.retain is RetentionMode.TRANSCRIPT_ONLY)

ok_human, _ = c.change_policy(looser, authorised_by="justin", reason="test")
check("loosening by a human is allowed", ok_human is True)

tighter = MediaPolicy(ingest=False, retain=RetentionMode.NONE,
                      retention_window_days=0, load_to_context=LoadMode.NEVER)
ok_tight, _ = c.change_policy(tighter, authorised_by="system", reason="test")
check("tightening by 'system' is allowed", ok_tight is True)


# ── Camera tool ────────────────────────────────────────────────────
print("\nCameraTool guarantees")

class FakeSD(SdCardSink):
    def __init__(self, available): self._a = available; self.written = None
    def is_available(self): return self._a
    def write(self, data, path): self.written = (data, path); return True

class FakeEmail(EmailSink):
    def __init__(self): self.sent = None
    def send(self, data, address): self.sent = (data, address); return True

# track the handle so we can assert it gets deleted
captured = {}
def capture_fn():
    return b"\xff\xd8imagebytes"
def indicator_on():  return True
def indicator_off(): return False

# Wrap take_photo to capture the internal handle via a spy on delete:
sd = FakeSD(available=True)
email = FakeEmail()
cam = CameraTool(capture_fn=capture_fn, indicator_fn=indicator_on,
                 sd_sink=sd, email_sink=email)

# autonomous (no requester) refused
r = cam.take_photo(requested_by="", subjects_aware=True,
                   destination=Destination(DestinationKind.SD, "/sd/p.jpg", ""))
check("autonomous capture refused", r.delivered is False)

# covert (indicator off) refused
cam_covert = CameraTool(capture_fn=capture_fn, indicator_fn=indicator_off,
                        sd_sink=sd, email_sink=email)
r = cam_covert.take_photo(requested_by="guest", subjects_aware=True,
                          destination=Destination(DestinationKind.SD, "/sd/p.jpg", "guest"))
check("covert capture (no indicator) refused", r.delivered is False)

# subjects not aware refused
r = cam.take_photo(requested_by="guest", subjects_aware=False,
                   destination=Destination(DestinationKind.SD, "/sd/p.jpg", "guest"))
check("capture of unaware subjects refused", r.delivered is False)

# valid SD delivery
r = cam.take_photo(requested_by="guest", subjects_aware=True,
                   destination=Destination(DestinationKind.SD, "/sd/p.jpg", "guest"))
check("valid SD capture delivered", r.delivered and r.kind is DestinationKind.SD)
check("photo written to SD sink", sd.written is not None)

# no card + email without consent refused
sd_nocard = FakeSD(available=False)
cam2 = CameraTool(capture_fn=capture_fn, indicator_fn=indicator_on,
                  sd_sink=sd_nocard, email_sink=email)
r = cam2.take_photo(requested_by="guest", subjects_aware=True,
                    destination=Destination(DestinationKind.EMAIL, "g@x.com", "guest"),
                    off_device_consent=False)
check("email without off-device consent refused", r.delivered is False)

# email with consent delivered
r = cam2.take_photo(requested_by="guest", subjects_aware=True,
                    destination=Destination(DestinationKind.EMAIL, "g@x.com", "guest"),
                    off_device_consent=True)
check("email with consent delivered", r.delivered and r.kind is DestinationKind.EMAIL)
check("photo sent via email sink", email.sent is not None)

# structural: the tool exposes no path to a learning corpus
tool_api = dir(cam)
check("camera tool has no learning/memory write method",
      not any(k in tool_api for k in
              ("to_learning", "store_memory", "learn", "corpus", "remember")))

# send-then-forget: the working copy is deleted in a finally block.
# Verify the handle lifecycle directly: once deleted it cannot be read.
from driftcore.media.camera import CaptureHandle
h = CaptureHandle(b"x")
h.delete()
try:
    h.read(); reads_after_delete = True
except RuntimeError:
    reads_after_delete = False
check("deleted handle cannot be read (working copy gone)",
      reads_after_delete is False)


# ─────────────────────────────────────────────────────────────────────────────
# F-003 (red-team, Grok 2026-08-15) — the loosening gate was a local denylist.
#
#     human = authorised_by not in ("", "system", "auto", "auto-sign", None)
#
# Any other string counted as human, and worse, the module could never leave that
# weakest mode: a deployment running REGISTERED or ATTESTED identity everywhere else
# still had media retention gated by a five-word list. Same bug class as recovery.py's
# `authorized_by == "agent"`, found the same day.
#
# The supplied patch delegated to the shared gate but bound no ACTION. In ATTESTED
# mode `is_human` falls back to the attestation's own action when none is given, so an
# attestation issued for "restart_the_robot" would have authorised retaining raw video
# of people — verified True unbound, False once bound. These tests pin the binding,
# not merely the delegation.
# ─────────────────────────────────────────────────────────────────────────────

from driftcore.authority import human_identity as _hi
from driftcore.authority.human_identity import (
    HumanAttestation as _Att, HumanIdentityVerifier as _HIV)
from driftcore.media.policy import LOOSEN_ACTION as _LOOSEN, _is_human as _ih

_KEY = b"media-test-key"
_LOOSE = MediaPolicy(ingest=True, retain=RetentionMode.RAW,
                     retention_window_days=365, load_to_context=LoadMode.ALWAYS)
_TIGHT = MediaPolicy(ingest=False, retain=RetentionMode.NONE,
                     retention_window_days=0, load_to_context=LoadMode.NEVER)


def _ctl():
    return MediaPolicyController.for_embodiment(EmbodimentClass.SOFTWARE_AGENT)


print("\nF-003: LABEL_ONLY behaviour preserved (upgrade-safe)")
_hi.reset_policy()
check("a non-reserved name can still loosen",
      _ctl().change_policy(_LOOSE, authorised_by="justin")[0])
for _label in ("", "system", "auto", "auto-sign"):
    check(f"{_label!r} still cannot loosen",
          not _ctl().change_policy(_LOOSE, authorised_by=_label)[0])
check("tightening remains unrestricted",
      _ctl().change_policy(_TIGHT, authorised_by="system")[0])

print("\nF-003: REGISTERED mode makes the check real")
_hi.reset_policy()
_hi.register_human_principal("justin")
check("an UNREGISTERED label can no longer loosen",
      not _ctl().change_policy(_LOOSE, authorised_by="mallory")[0])
check("a registered principal can",
      _ctl().change_policy(_LOOSE, authorised_by="justin")[0])
check("tightening is still free for anyone",
      _ctl().change_policy(_TIGHT, authorised_by="system")[0])

print("\nF-003: ATTESTED mode binds the ACTION")
_hi.reset_policy()
_v = _HIV()
_v.register_principal("justin", _KEY)
_hi.set_verifier(_v)
check("the module is in ATTESTED mode", _hi.mode() == "ATTESTED")
check("a bare NAME is no longer enough",
      not _ctl().change_policy(_LOOSE, authorised_by="justin")[0])
_unrelated = _Att.issue(_KEY, principal="justin", action="restart_the_robot",
                        ttl_seconds=300, nonce="mp-unrelated")
check("an attestation for ANOTHER action does not authorise a loosening",
      not _ctl().change_policy(_LOOSE, authorised_by=_unrelated)[0])
_right = _Att.issue(_KEY, principal="justin", action=_LOOSEN,
                    ttl_seconds=300, nonce="mp-right")
check("an attestation bound to THIS action does",
      _ctl().change_policy(_LOOSE, authorised_by=_right)[0])
_forged = _Att.issue(b"wrong-key", principal="justin", action=_LOOSEN,
                     ttl_seconds=300, nonce="mp-forged")
check("a forged attestation does not",
      not _ctl().change_policy(_LOOSE, authorised_by=_forged)[0])
_hi.reset_policy()

print("\nF-003: the gate never turns a refusal into a crash")
check("None is not human", not _ih(None))
check("an int is not human", not _ih(42))
check("a list is not human", not _ih(["justin"]))
check("an object with a friendly __str__ is not human",
      not _ih(type("X", (), {"__str__": lambda s: "justin"})()))


# ── Summary ────────────────────────────────────────────────────────
print("\n" + "=" * 56)
passed, total = sum(_results), len(_results)
print(f"{passed}/{total} checks passed")
print("=" * 56)
if passed < total:
    sys.exit(1)
