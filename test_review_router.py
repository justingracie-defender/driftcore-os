"""
test_review_router.py
=====================
The human end as a governed surface: escalations flow into a throttle + second-
reader gate, and the fatigue attack both red teams flagged is bounded. Red-team
this for the human-vulnerability class.
"""
from driftcore.verification.coordinator import Outcome, Decision
from driftcore.verification.review_router import ReviewRouter, ReviewTicket, ESCALATING
from driftcore.verification.approval_governance import (
    ApprovalThrottle, ApprovalPolicy, Operation, ApprovalRateExceeded, SplitEvasion,
)
from driftcore.verification.second_reader import (
    SecondReaderGate, WorkloadPolicy, WorkloadFloorExceeded, Disposition, AnchoringViolation,
)

p = 0
def ok(cond, label):
    global p
    assert cond, "FAIL: " + label
    p += 1
    print("  ok:", label)

def auth():   return Decision(Outcome.AUTHORIZATION_REQUIRED, reason="needs approval")
def review(): return Decision(Outcome.REVIEW_REQUIRED, reason="needs review")
def proceed():return Decision(Outcome.PROCEED)
def blocked():return Decision(Outcome.BLOCKED, invariant="x")

def router(cap=100, second_over=None, wl=None):
    thr = ApprovalThrottle(ApprovalPolicy(cap, second_approver_over_irreversible=second_over))
    gate = SecondReaderGate(wl) if wl else None
    return ReviewRouter(thr, second_reader_gate=gate)

# 1. PROCEED / BLOCKED never reach a human — passthrough, no budget spent
r = router(cap=1)
ok(r.route(proceed(), "op") is None, "PROCEED does not route to a human")
ok(r.route(blocked(), "op") is None, "BLOCKED does not route to a human")
# budget untouched: an escalation still works after two machine-terminal routes
ok(isinstance(r.route(auth(), "op"), ReviewTicket),
   "machine-terminal routes consume no approval budget")

# 2. escalating decisions produce a ticket
r = router()
t = r.route(auth(), "operator")
ok(t.outcome == Outcome.AUTHORIZATION_REQUIRED and t.approver == "operator",
   "escalating decision yields a review ticket for the approver")

# 3. THE FATIGUE CAP: after N approvals in a window, the human cannot be asked more
r = router(cap=3)
for _ in range(3):
    r.route(auth(), "tired_human")
try:
    r.route(auth(), "tired_human"); ok(False, "over-cap should raise")
except ApprovalRateExceeded:
    ok(True, "fatigue cap: over the content-blind per-window cap, routing is refused (fail-closed)")

# 4. content-blind: a '1 reversible' and a '12 irreversible' cost the SAME budget
r = router(cap=2)
r.route(auth(), "h", operations=[Operation("o", "read")])                 # trivial
r.route(auth(), "h", operations=[Operation(f"o{i}", "delete") for i in range(12)])  # scary
try:
    r.route(auth(), "h"); ok(False, "third should exceed cap")
except ApprovalRateExceeded:
    ok(True, "cap is content-blind: scary and trivial approvals draw down the same budget")

# 5. SPLIT EVASION: splitting one batch across the window buys nothing
r = router(cap=10)
r.route(auth(), "h", bundle_key="nightly")
try:
    r.route(auth(), "h", bundle_key="nightly"); ok(False, "split should raise")
except SplitEvasion:
    ok(True, "splitting one logical batch into separate requests is refused")

# 6. SECOND APPROVER is required by a human threshold over a VERIFIER-DERIVED count
r = router(cap=100, second_over=3)
ops_bad = [Operation(f"o{i}", "delete") for i in range(5)]   # 5 irreversible > 3
t = r.route(auth(), "h", operations=ops_bad)
ok(t.needs_second_approver is True and t.irreversible_count == 5,
   "second approver required when derived irreversible count exceeds the human threshold")

# 7. the count is DERIVED, not planner-declared: reversible ops don't trip it
r = router(cap=100, second_over=3)
ops_ok = [Operation(f"o{i}", "update") for i in range(9)]    # 0 irreversible
t = r.route(auth(), "h", operations=ops_ok)
ok(t.needs_second_approver is False and t.irreversible_count == 0,
   "irreversibility is verifier-derived from op kind, not taken from the caller")

# 8. delta is a FACT on the ticket, never a system 'this looks scary' verdict
r = router()
t = r.route(auth(), "h", operations=[Operation("o", "delete")], recent_irreversible=[0, 0, 1])
ok("irreversible: 1" in t.delta_fact and "\u0394" in t.delta_fact,
   "delta surfaces as a fact for the human, not as machine-imposed friction")

# 9. per-approver isolation: one worn-down human's cap doesn't block a fresh one
r = router(cap=1)
r.route(auth(), "human_a")
ok(isinstance(r.route(auth(), "human_b"), ReviewTicket),
   "the cap is per approver — a second human still has budget")

# 10. READ WORKFLOW (anti-anchoring) via the gate: AI cannot be seen before commit
r = router(cap=100, wl=WorkloadPolicy(max_reads_per_window=5, min_seconds_per_read=1.0))
sess = r.open_read_session("case-1", "clinician")
try:
    sess.reveal_ai(Disposition.CLEAR, 0.9); ok(False, "reveal before commit should raise")
except AnchoringViolation:
    ok(True, "read workflow: AI opinion cannot be revealed before the human commits (anti-anchoring)")

# 11. WORKLOAD FLOOR the AI cannot raise
r = router(cap=100, wl=WorkloadPolicy(max_reads_per_window=2, min_seconds_per_read=1.0))
r.open_read_session("c1", "clin"); r.open_read_session("c2", "clin")
try:
    r.open_read_session("c3", "clin"); ok(False, "over floor should raise")
except WorkloadFloorExceeded:
    ok(True, "read workflow: the AI cannot push a human past the human-set workload floor")

# 12. no gate configured -> read review refuses clearly
r = router()   # no wl policy
try:
    r.open_read_session("c", "clin"); ok(False, "should refuse without a gate")
except RuntimeError:
    ok(True, "read review refuses cleanly when no SecondReaderGate is configured")

print(f"\n{p}/{p} tests passed")
