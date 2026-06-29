"""
driftcore/verification/second_reader.py
=======================================
STATUS: PROPOSED (not yet wired into the coordinator pipeline; stdlib-only so it
can be stress-tested in isolation first, per the repo's "propose, don't conflate"
rule). Where it would connect upstream is noted inline.

The anti-reverse-centaur gate for a human + AI second-reader workflow (the
radiology case: a clinician reads, an AI offers a second opinion). It exists to
make ONE thing structurally true: the AI augments the human and can never quietly
take the human's place, deskill them, or be used as an excuse to work them harder.

Built from the three design points worked out in discussion, each pinned to code:

  1. COMMIT-BEFORE-REVEAL (defeats automation bias). The human does the full read
     and COMMITS it before the AI's opinion is reachable. You cannot be anchored
     by an answer you have not seen. `reveal_ai()` refuses — loudly — if the human
     read is not yet committed, and the committed initial read is FROZEN so it can
     never be quietly edited to match the machine afterward.
     (SessionState gate + _frozen initial read)

  2. THE AI FLAG OPENS A QUESTION, IT NEVER CLOSES ONE. The AI opinion can only
     ever RAISE scrutiny, never lower it. It can never, by itself, set the
     disposition. An AI "clear" can not clear a human "suspicious"; an AI
     "suspicious" forces escalation even over a human "clear". Disagreement in
     either direction routes to a SECOND HUMAN READ and the session cannot be
     closed until a human resolves it. (resolve() + close() guard)

  3. A VOLUME FLOOR THE AI CANNOT LOWER. The workload limit is governance: it is
     owned by a human-set `WorkloadPolicy` the gate holds READ-ONLY and has no
     method to raise (same shape as the constitution's
     AI_MAY_NOT_SELF_GRANT / AGENT_MAY_NOT_MODIFY_CORE_GOVERNANCE floors). Opening
     more reads than the floor allows is refused loudly; a read committed faster
     than the floor's minimum is flagged as rushed and recorded, because the
     throughput-multiplier failure mode shows up first as time-per-read collapsing.
     (WorkloadPolicy + _opened counter + rushed flag)

What this module deliberately does NOT do (kept honest):
  - It does not store the audit trail. Every committed read, AI opinion, and
    resolution is meant to flow to the append-only audit chain and disagreements
    to the EdgeLoop as case law — enforced UPSTREAM, not claimed here.
  - It does not decide medicine. It carries dispositions a human assigns; it never
    invents one. The AI's correctness over time is for reflection.py to judge from
    logged outcomes, not for this gate to assert.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Tuple


class Disposition(str, Enum):
    CLEAR      = "CLEAR"        # nothing actionable found
    SUSPICIOUS = "SUSPICIOUS"   # something needs follow-up


class SessionState(str, Enum):
    AWAITING_HUMAN_READ = "AWAITING_HUMAN_READ"
    HUMAN_COMMITTED     = "HUMAN_COMMITTED"      # initial read locked; AI not yet revealed
    AI_REVEALED         = "AI_REVEALED"
    REQUIRES_RESOLUTION = "REQUIRES_RESOLUTION"  # human/AI disagree -> needs a 2nd human
    RESOLVED            = "RESOLVED"


class Resolution(str, Enum):
    AGREE_CLEAR             = "AGREE_CLEAR"              # both clear -> may close
    AGREE_SUSPICIOUS        = "AGREE_SUSPICIOUS"         # both suspicious -> route to follow-up
    DISAGREE_NEEDS_SECOND   = "DISAGREE_NEEDS_SECOND"    # either-direction disagreement -> 2nd human read


# ── failures are loud, never swallowed ──────────────────────────────────────
class SecondReaderError(Exception):
    """Base for contract violations this gate refuses to let pass silently."""


class AnchoringViolation(SecondReaderError):
    """Tried to see the AI opinion before the human committed their own read."""


class WorkloadFloorExceeded(SecondReaderError):
    """Tried to assign more reads than the human-set floor permits."""


class ResolutionRequired(SecondReaderError):
    """Tried to close a session while a human/AI disagreement is unresolved."""


@dataclass(frozen=True)
class WorkloadPolicy:
    """Human-set governance. The gate holds this read-only; it has NO API to raise
    these limits. Changing them is an out-of-band admin act (construct a new one),
    exactly like amending a constitutional floor."""
    max_reads_per_window: int        # hard ceiling on reads assigned to one reader per window
    min_seconds_per_read: float      # below this, a committed read is flagged 'rushed'


@dataclass(frozen=True)
class Read:
    """An immutable, attributable read. Once committed it is never edited; a change
    of mind is a NEW read, so the original uninfluenced opinion survives on record."""
    reader_id: str
    disposition: Disposition
    elapsed_seconds: float
    notes: str = ""
    rushed: bool = False


class ReadSession:
    """One case, one workflow. Enforces the commit-before-reveal ordering and the
    open-a-question-never-close-one resolution as a small state machine."""

    def __init__(self, case_id: str, reader_id: str, policy: WorkloadPolicy):
        self.case_id = case_id
        self.reader_id = reader_id
        self._policy = policy
        self.state: SessionState = SessionState.AWAITING_HUMAN_READ
        self._human_read: Optional[Read] = None      # frozen once set (principle 1)
        self._ai: Optional[Tuple[Disposition, float]] = None
        self._second_read: Optional[Read] = None
        self.resolution: Optional[Resolution] = None

    # principle 1 — the human reads first, and it is locked before the AI is seen
    def commit_human_read(self, disposition: Disposition, elapsed_seconds: float,
                          notes: str = "") -> Read:
        if self._human_read is not None:
            raise SecondReaderError("initial human read already committed; it is immutable")
        rushed = elapsed_seconds < self._policy.min_seconds_per_read
        self._human_read = Read(self.reader_id, disposition, elapsed_seconds, notes, rushed)
        self.state = SessionState.HUMAN_COMMITTED
        return self._human_read

    @property
    def human_read(self) -> Optional[Read]:
        return self._human_read

    # principle 1 — refuse to reveal the machine before the human has committed
    def reveal_ai(self, ai_disposition: Disposition, ai_confidence: float) -> Resolution:
        if self._human_read is None:
            raise AnchoringViolation(
                "AI opinion requested before the human committed a read — refused "
                "(this is the anchoring path the gate exists to block)")
        self._ai = (ai_disposition, ai_confidence)
        self.state = SessionState.AI_REVEALED
        return self._resolve(self._human_read.disposition, ai_disposition)

    # principle 2 — the AI can raise scrutiny, never lower it; only humans dispose
    def _resolve(self, human: Disposition, ai: Disposition) -> Resolution:
        if human == ai == Disposition.CLEAR:
            self.resolution = Resolution.AGREE_CLEAR
            self.state = SessionState.AI_REVEALED
        elif human == ai == Disposition.SUSPICIOUS:
            self.resolution = Resolution.AGREE_SUSPICIOUS
            self.state = SessionState.AI_REVEALED
        else:
            # disagreement in EITHER direction never auto-resolves
            self.resolution = Resolution.DISAGREE_NEEDS_SECOND
            self.state = SessionState.REQUIRES_RESOLUTION
        return self.resolution

    # principle 2 — disagreement is settled by a DIFFERENT human, not by the AI
    def second_read(self, reader_id: str, disposition: Disposition,
                    elapsed_seconds: float, notes: str = "") -> Read:
        if self.state is not SessionState.REQUIRES_RESOLUTION:
            raise SecondReaderError("second read only applies to an unresolved disagreement")
        if reader_id == self.reader_id:
            raise SecondReaderError("the arbiter must be a different human (no self-arbitration)")
        rushed = elapsed_seconds < self._policy.min_seconds_per_read
        self._second_read = Read(reader_id, disposition, elapsed_seconds, notes, rushed)
        self.state = SessionState.RESOLVED
        return self._second_read

    # principle 2 — the disposition of record is ALWAYS a human's, never the AI's
    def final_disposition(self) -> Disposition:
        if self.state is SessionState.REQUIRES_RESOLUTION:
            raise ResolutionRequired("disagreement not yet resolved by a second human read")
        if self._second_read is not None:
            return self._second_read.disposition
        assert self._human_read is not None
        return self._human_read.disposition

    def can_close(self) -> bool:
        return self.state in (SessionState.AI_REVEALED, SessionState.RESOLVED)

    def close(self) -> Disposition:
        if not self.can_close():
            raise ResolutionRequired(
                "cannot close: a human/AI disagreement is still open and needs a second read")
        self.state = SessionState.RESOLVED
        return self.final_disposition()


class SecondReaderGate:
    """Hands out sessions and enforces the workload floor (principle 3). One gate
    per reader-window; it counts what it opens and refuses past the human-set cap.
    There is intentionally no method here to raise that cap."""

    def __init__(self, policy: WorkloadPolicy):
        self._policy = policy           # read-only governance; no setter, by design
        self._opened = 0

    @property
    def reads_remaining(self) -> int:
        return max(0, self._policy.max_reads_per_window - self._opened)

    # principle 3 — the AI's existence cannot raise the quota; over the floor = refused
    def open_session(self, case_id: str, reader_id: str) -> ReadSession:
        if self._opened >= self._policy.max_reads_per_window:
            raise WorkloadFloorExceeded(
                f"reader {reader_id} is at the workload floor "
                f"({self._policy.max_reads_per_window} reads/window); refusing to assign more. "
                "Raising this is a human admin act, not something this gate can do.")
        self._opened += 1
        return ReadSession(case_id, reader_id, self._policy)
