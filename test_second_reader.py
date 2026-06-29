"""
test_second_reader.py — THE ANTI-REVERSE-CENTAUR GATE
=====================================================
STATUS: PROPOSED. Pins the three design points for the human + AI second-reader
workflow:

  1. commit-before-reveal — the AI opinion is unreachable until the human commits,
     and the committed read is immutable (defeats automation bias / anchoring).
  2. the AI flag opens a question, never closes one — disagreement in either
     direction needs a second HUMAN read; the AI never sets the disposition.
  3. a volume floor the AI cannot lower — over the human-set cap is refused; a
     rushed read is flagged.

Run with:  python test_second_reader.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from driftcore.verification.second_reader import (
    SecondReaderGate, WorkloadPolicy, Disposition, SessionState, Resolution,
    AnchoringViolation, WorkloadFloorExceeded, ResolutionRequired, SecondReaderError,
)

results = []
def check(n, c):
    print(f"  {'ok' if c else 'XX'}: {n}")
    results.append((n, bool(c)))

POLICY = WorkloadPolicy(max_reads_per_window=3, min_seconds_per_read=5.0)


# ── principle 1: commit-before-reveal ───────────────────────────────────────
g = SecondReaderGate(POLICY)
s = g.open_session("case-1", "dr_a")
try:
    s.reveal_ai(Disposition.CLEAR, 0.9)
    check("AI opinion refused before human commits a read", False)
except AnchoringViolation:
    check("AI opinion refused before human commits a read", True)

s.commit_human_read(Disposition.SUSPICIOUS, elapsed_seconds=30.0)
check("after commit, state is HUMAN_COMMITTED", s.state is SessionState.HUMAN_COMMITTED)
check("human read is recorded and attributable", s.human_read.reader_id == "dr_a")

try:
    s.commit_human_read(Disposition.CLEAR, elapsed_seconds=30.0)
    check("committed initial read cannot be overwritten", False)
except SecondReaderError:
    check("committed initial read cannot be overwritten", True)


# ── principle 2: the AI flag opens a question, never closes one ──────────────
# 2a. AI 'clear' can NOT clear a human 'suspicious' — must escalate to 2nd read.
g = SecondReaderGate(POLICY)
s = g.open_session("case-2", "dr_a")
s.commit_human_read(Disposition.SUSPICIOUS, elapsed_seconds=40.0)
r = s.reveal_ai(Disposition.CLEAR, 0.95)
check("human SUSPICIOUS + AI CLEAR -> needs second read (AI can't downgrade)",
      r is Resolution.DISAGREE_NEEDS_SECOND and s.state is SessionState.REQUIRES_RESOLUTION)
try:
    s.close()
    check("cannot close an unresolved disagreement", False)
except ResolutionRequired:
    check("cannot close an unresolved disagreement", True)
try:
    s.final_disposition()
    check("no final disposition while disagreement is open", False)
except ResolutionRequired:
    check("no final disposition while disagreement is open", True)

# 2b. AI 'suspicious' forces escalation even over a human 'clear'.
g = SecondReaderGate(POLICY)
s = g.open_session("case-3", "dr_a")
s.commit_human_read(Disposition.CLEAR, elapsed_seconds=40.0)
r = s.reveal_ai(Disposition.SUSPICIOUS, 0.8)
check("human CLEAR + AI SUSPICIOUS -> needs second read (AI raises scrutiny)",
      r is Resolution.DISAGREE_NEEDS_SECOND)

# 2c. The arbiter must be a different human (no self-arbitration).
try:
    s.second_read("dr_a", Disposition.SUSPICIOUS, elapsed_seconds=40.0)
    check("same reader cannot arbitrate their own disagreement", False)
except SecondReaderError:
    check("same reader cannot arbitrate their own disagreement", True)

# 2d. A different human resolves it; the disposition of record is the human's.
s.second_read("dr_b", Disposition.SUSPICIOUS, elapsed_seconds=45.0)
check("second human read resolves the session", s.state is SessionState.RESOLVED)
check("final disposition comes from the human arbiter, never the AI",
      s.final_disposition() is Disposition.SUSPICIOUS)

# 2e. Agreement closes cleanly; agreement-on-suspicious routes to follow-up.
g = SecondReaderGate(POLICY)
s = g.open_session("case-4", "dr_a")
s.commit_human_read(Disposition.CLEAR, elapsed_seconds=20.0)
check("both CLEAR -> AGREE_CLEAR, closeable",
      s.reveal_ai(Disposition.CLEAR, 0.9) is Resolution.AGREE_CLEAR and s.can_close())
check("agreed-clear closes to CLEAR", s.close() is Disposition.CLEAR)

g = SecondReaderGate(POLICY)
s = g.open_session("case-5", "dr_a")
s.commit_human_read(Disposition.SUSPICIOUS, elapsed_seconds=20.0)
check("both SUSPICIOUS -> AGREE_SUSPICIOUS (route to follow-up)",
      s.reveal_ai(Disposition.SUSPICIOUS, 0.9) is Resolution.AGREE_SUSPICIOUS)


# ── principle 3: a volume floor the AI cannot lower ──────────────────────────
g = SecondReaderGate(POLICY)   # cap = 3
for i in range(3):
    g.open_session(f"c{i}", "dr_a")
check("gate tracks remaining reads against the floor", g.reads_remaining == 0)
try:
    g.open_session("c4", "dr_a")
    check("opening past the workload floor is refused", False)
except WorkloadFloorExceeded:
    check("opening past the workload floor is refused", True)

check("gate exposes no setter to raise the cap (AI cannot self-grant quota)",
      not any(n for n in dir(g) if "set" in n.lower() and "policy" in n.lower()))

# rushed read (faster than the floor's minimum) is flagged, not silently accepted
g = SecondReaderGate(POLICY)
s = g.open_session("case-6", "dr_a")
rd = s.commit_human_read(Disposition.CLEAR, elapsed_seconds=2.0)   # < 5.0s min
check("a read faster than the floor's minimum is flagged rushed", rd.rushed is True)
s2 = g.open_session("case-7", "dr_a")
rd2 = s2.commit_human_read(Disposition.CLEAR, elapsed_seconds=30.0)
check("a normal-paced read is not flagged rushed", rd2.rushed is False)


passed = sum(1 for _, c in results if c)
print(f"\n{passed}/{len(results)} tests passed")
sys.exit(0 if passed == len(results) else 1)
