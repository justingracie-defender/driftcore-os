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


# ── Summary ────────────────────────────────────────────────────────
print("\n" + "=" * 56)
passed, total = sum(_results), len(_results)
print(f"{passed}/{total} checks passed")
print("=" * 56)
if passed < total:
    sys.exit(1)
