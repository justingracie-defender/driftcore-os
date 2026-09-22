# SPDX-License-Identifier: Apache-2.0
"""Immutable, content-addressed operator policy artifacts.

This identifies the JSON artifact supplied by trusted deployment bootstrap. It
does not infer policy from Python callbacks, load untrusted files, or authenticate
the operator. Verify signed configuration before constructing a snapshot; archive
the artifact with the deployment. Restart the broker with a new snapshot when
policy changes. Keys and credentials must never be included in this public data.
"""
from dataclasses import dataclass
import hashlib
import json
import re


def validate_policy_hash(value):
    """Accept only the lowercase SHA-256 format emitted by PolicySnapshot."""
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("policy_hash must be a lowercase SHA-256 hex digest")
    return value


@dataclass(frozen=True, init=False)
class PolicySnapshot:
    """A detached copy of a nonempty, strictly JSON policy document.

    Canonicalization is versioned and Python-specific, not RFC 8785. Object key
    order is irrelevant; list order and numeric representation are significant.
    The digest identifies a declared policy artifact, not all live broker state.
    """
    _encoded: bytes

    def __init__(self, document):
        if type(document) is not dict or not document:
            raise ValueError("policy snapshot requires a nonempty JSON object")
        # Serialize first so cycles and non-finite numbers fail before traversal.
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
        pending = [document]
        while pending:
            value = pending.pop()
            if type(value) is dict:
                if any(type(key) is not str for key in value):
                    raise ValueError("policy object keys must be strings")
                pending.extend(value.values())
            elif type(value) is list:
                pending.extend(value)
            elif type(value) not in (str, int, float, bool, type(None)):
                raise ValueError("policy values must be built-in JSON types")
        object.__setattr__(self, "_encoded", encoded)

    @property
    def policy_hash(self):
        return hashlib.sha256(b"driftcore-policy-snapshot-v1\x00" + self._encoded).hexdigest()

    def to_dict(self):
        """Return a fresh copy; editing it cannot alter this snapshot."""
        return json.loads(self._encoded)
