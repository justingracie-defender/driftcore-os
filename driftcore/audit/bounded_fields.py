"""
bounded_fields.py — EVERY AUDIT FIELD A CALLER SUPPLIES IS A CHANNEL.

Red team (ChatGPT, 2026-08) found the specific case in `information_flow`: the
declassification `reason` is operator free text written straight into the audit
record, so an unbounded reason let the layer produce its own signature failure —
stop the secret reaching the LLM by writing it into the audit log instead.

That was fixed locally, and then the same reviewer made the better point: the
identical `reason -> audit.record(...)` pattern exists in `physical_envelope`
and will exist in the next module too. A lesson that has to be re-remembered at
every call site is a lesson that will be forgotten at one of them.

So the bound lives HERE, once. Governance modules call `bounded_reason()` rather
than each inventing a cap.

WHAT THIS IS NOT: a secret detector. It does not inspect content for
sensitivity, because that question is undecidable and the whole project rejects
that posture. It bounds CAPACITY — a justification for a reviewer is short, and
a field that can hold a paragraph can hold a key.
"""

from __future__ import annotations

# A justification a human reads. Long enough for a real sentence, too short to
# paste a credential, a memory dump, or a base64 blob into.
MAX_REASON_CHARS = 200
# Machine-generated detail lines (module-authored, not caller-supplied).
MAX_DETAIL_CHARS = 1000


class AuditFieldRefused(ValueError):
    """A caller-supplied audit field exceeded its bound."""


def bounded_reason(reason: str, *, field: str = "reason",
                   cap: int = MAX_REASON_CHARS) -> str:
    """Validate a caller-supplied justification. Refuses; never truncates.

    Truncation would silently keep the first `cap` characters of whatever was
    pasted, which is the same channel with a smaller mouth. A refusal is loud
    and the caller learns the field is not a payload.
    """
    if not isinstance(reason, str) or not reason.strip():
        raise AuditFieldRefused(
            f"{field} is required: an unexplained safety-relevant change is not "
            f"auditable")
    if len(reason) > cap:
        raise AuditFieldRefused(
            f"{field} is {len(reason)} chars, capped at {cap}. The audit log is "
            f"a sink like any other: a field that can hold a paragraph can hold "
            f"a secret. It is a justification for a reviewer, not a payload.")
    if any(c in reason for c in ("\r", "\n", "\x00")):
        raise AuditFieldRefused(
            f"{field} contains a control character; audit records are one line "
            f"per event and a newline forges a second record")
    return reason
