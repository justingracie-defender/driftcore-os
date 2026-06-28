"""
driftcore/media/camera.py
=========================
A camera *tool* for the requested, consensual case — "take a picture of us"
— kept strictly separate from the robot's learning/memory.

This is the deliberate exception to the people-media invariant: a photo a
person ASKS for, KNOWS about, and RECEIVES is not surveillance. The tool is
allowed only when all three hold, and what it produces goes to the user's
own space (SD card, or email as a fallback), never into anything the robot
trains on.

Guarantees enforced here:
  * Human-initiated.   No requester → refuse. The tool cannot fire itself.
  * Transparent.       A visible/audible indicator must fire → refuse if it
                       cannot (no covert capture).
  * Subjects aware.    Caller must assert the people in frame are present
                       and aware → refuse otherwise.
  * Courier, not album. The working copy is deleted after delivery, always,
                       even on failure (send-then-forget).
  * Two buckets.       This tool has NO reference to the learning corpus.
                       It can only write to a user destination. The
                       separation is structural, not a runtime check.
  * No address book.   Email destinations are supplied per request; the tool
                       stores none.

Hardware (the actual sensor) and delivery sinks (SD write, SMTP send) are
injected. Nothing here fakes a camera, a person detector, or an email server.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional


# ── A transient working copy (never persisted by the robot) ───────

class CaptureHandle:
    """
    Holds a freshly captured image in a transient working area. Has exactly
    one lifecycle: created by capture, consumed by delivery, then deleted.
    Deliberately exposes no path to long-term/learning storage.
    """

    def __init__(self, data: bytes):
        self._data: Optional[bytes] = data
        self._deleted = False

    @property
    def deleted(self) -> bool:
        return self._deleted

    def read(self) -> bytes:
        if self._deleted or self._data is None:
            raise RuntimeError("capture handle already deleted")
        return self._data

    def delete(self) -> None:
        self._data = None
        self._deleted = True


class DestinationKind(Enum):
    SD    = "sd"
    EMAIL = "email"


@dataclass(frozen=True)
class Destination:
    kind:        DestinationKind
    target:      str           # SD path, or email address (supplied per request)
    provided_by: str           # the requester


@dataclass(frozen=True)
class DeliveryResult:
    delivered: bool
    kind:      Optional[DestinationKind]
    reason:    str


# ── Injected sinks (user bucket only) ─────────────────────────────

class SdCardSink:
    """Writes to a user-controlled SD card. Replace with real hardware impl."""
    def is_available(self) -> bool:        # default: no card
        return False
    def write(self, data: bytes, path: str) -> bool:
        raise NotImplementedError


class EmailSink:
    """
    Sends a photo to a requester-supplied address. Credentials are the
    integrator's responsibility and must be handled like any other secret
    (env var / OS keyring — never on disk), per the review-module lesson.
    """
    def send(self, data: bytes, address: str) -> bool:
        raise NotImplementedError


# ── The tool ──────────────────────────────────────────────────────

class CameraTool:
    def __init__(self,
                 capture_fn: Callable[[], bytes],
                 indicator_fn: Callable[[], bool],
                 sd_sink: Optional[SdCardSink] = None,
                 email_sink: Optional[EmailSink] = None):
        """
        capture_fn   — hardware hook returning raw image bytes.
        indicator_fn — fires the visible/audible "taking a photo" signal;
                       returns True only if it actually fired.
        sd_sink/email_sink — user-bucket delivery only.
        """
        self._capture_fn = capture_fn
        self._indicator_fn = indicator_fn
        self._sd = sd_sink or SdCardSink()
        self._email = email_sink or EmailSink()

    def take_photo(self,
                   requested_by: str,
                   subjects_aware: bool,
                   destination: Destination,
                   off_device_consent: bool = False) -> DeliveryResult:
        # 1. Human-initiated.
        if not requested_by:
            self._audit("CAMERA_REFUSED", "system",
                        "autonomous capture not permitted (no requester)")
            return DeliveryResult(False, None, "no requester — capture refused")

        # 2. Subjects present and aware.
        if not subjects_aware:
            self._audit("CAMERA_REFUSED", requested_by,
                        "subjects not confirmed present/aware — covert capture refused")
            return DeliveryResult(False, None, "subjects must be present and aware")

        # 3. Transparent — indicator must fire.
        if not self._indicator_fn():
            self._audit("CAMERA_REFUSED", requested_by,
                        "capture indicator did not fire — no covert capture")
            return DeliveryResult(False, None, "cannot capture without a visible indicator")

        # 4. Capture into a transient handle, deliver, then ALWAYS delete.
        handle = CaptureHandle(self._capture_fn())
        self._audit("CAMERA_CAPTURE", requested_by,
                    f"requested capture; destination={destination.kind.value}")
        try:
            return self._deliver(handle, destination, requested_by, off_device_consent)
        finally:
            handle.delete()  # send-then-forget, even on error

    def _deliver(self, handle, destination, requested_by, off_device_consent):
        # Prefer SD (local, offline, user-owned).
        if destination.kind is DestinationKind.SD:
            if self._sd.is_available():
                ok = self._sd.write(handle.read(), destination.target)
                self._audit("CAMERA_DELIVERED" if ok else "CAMERA_REFUSED",
                            requested_by, f"sd={destination.target} ok={ok}")
                return DeliveryResult(ok, DestinationKind.SD,
                                     "saved to SD" if ok else "SD write failed")
            # No card → email is a fallback, but only with explicit consent,
            # because the photo then leaves the device.
            return self._email_fallback(handle, destination, requested_by, off_device_consent)

        if destination.kind is DestinationKind.EMAIL:
            return self._email_fallback(handle, destination, requested_by, off_device_consent)

        return DeliveryResult(False, None, "unknown destination kind")

    def _email_fallback(self, handle, destination, requested_by, off_device_consent):
        if not off_device_consent:
            self._audit("CAMERA_REFUSED", requested_by,
                        "email requires explicit off-device consent")
            return DeliveryResult(False, None,
                                 "no SD card — emailing sends the photo off-device; "
                                 "explicit consent required")
        address = destination.target if destination.kind is DestinationKind.EMAIL else ""
        if not address:
            self._audit("CAMERA_REFUSED", requested_by, "no email address supplied")
            return DeliveryResult(False, None, "no email address supplied")
        ok = self._email.send(handle.read(), address)
        self._audit("CAMERA_DELIVERED" if ok else "CAMERA_REFUSED",
                    requested_by, f"email -> (address withheld) ok={ok}")
        return DeliveryResult(ok, DestinationKind.EMAIL,
                             "emailed to requester" if ok else "email send failed")

    @staticmethod
    def _audit(action: str, authorised_by: str, detail: str):
        # Never records the image itself — only that a capture/delivery happened.
        try:
            from driftcore.audit import record
            record(action=action, memory_text="camera_tool",
                   authorised_by=authorised_by or "system", detail=detail)
        except Exception:
            pass
