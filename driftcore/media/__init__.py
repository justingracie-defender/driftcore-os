"""
driftcore/media
===============
Media-retention policy + the consensual camera tool.

Policy (configurable, per embodiment, audited changes) decides what rich
media the system ingests, keeps, and surfaces. One invariant sits above it:
the robot never autonomously retains media of people for its own use.

The camera tool is the deliberate, consensual exception: a photo a person
asks for, knows about, and receives — delivered to their own space (SD/email)
and structurally kept out of anything the robot learns from.
"""

from driftcore.media.policy import (
    PeopleSignal,
    RetentionMode,
    LoadMode,
    EmbodimentClass,
    MediaPolicy,
    EMBODIMENT_DEFAULTS,
    PeopleMediaInvariant,
    RetentionDecision,
    MediaPolicyController,
)
from driftcore.media.camera import (
    CameraTool,
    CaptureHandle,
    Destination,
    DestinationKind,
    DeliveryResult,
    SdCardSink,
    EmailSink,
)

__all__ = [
    "PeopleSignal", "RetentionMode", "LoadMode", "EmbodimentClass",
    "MediaPolicy", "EMBODIMENT_DEFAULTS", "PeopleMediaInvariant",
    "RetentionDecision", "MediaPolicyController",
    "CameraTool", "CaptureHandle", "Destination", "DestinationKind",
    "DeliveryResult", "SdCardSink", "EmailSink",
]
