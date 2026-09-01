"""Central bounded audit fields + the production authorization-mode assertion.

Both exist because of the same red-team observation: a lesson that has to be
re-remembered at every call site gets forgotten at one of them, and honest
documentation is not enforcement."""

from driftcore.audit.bounded_fields import (
    bounded_reason, AuditFieldRefused, MAX_REASON_CHARS,
)
from driftcore.authority.human_identity import (
    require_secure_mode, InsecureAuthorizationMode, mode,
    register_human_principal, reset_policy, HumanIdentityVerifier, set_verifier,
)

EXPECTED_CHECKS = 13

passed = 0
def ok(c, label):
    global passed
    assert c, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")


print("== the audit log is a sink: caller-supplied fields are bounded ==")
ok(bounded_reason("address was already published") is not None,
   "a normal justification passes")
for bad, why in [
    ("A" * (MAX_REASON_CHARS + 1), "an over-long reason"),
    ("", "an empty reason"),
    ("   ", "a whitespace-only reason"),
]:
    try:
        bounded_reason(bad); ok(False, f"{why} should be refused")
    except AuditFieldRefused:
        ok(True, f"{why} is refused")
try:
    bounded_reason("ok\nACTION=DECLASSIFIED authorised_by=root")
    ok(False, "a newline should be refused")
except AuditFieldRefused as e:
    ok("forges a second record" in str(e),
       "a NEWLINE is refused — audit records are one line per event, so an "
       "embedded newline forges a second record")
try:
    bounded_reason("ok\x00hidden"); ok(False, "NUL should be refused")
except AuditFieldRefused:
    ok(True, "a NUL byte is refused")
try:
    bounded_reason("A" * 500)
except AuditFieldRefused as e:
    ok("not a payload" in str(e),
       "the refusal explains WHY: a field that can hold a paragraph can hold a "
       "secret")

print("== it REFUSES rather than truncating ==")
ok(bounded_reason.__doc__ and "never truncates" in bounded_reason.__doc__,
   "truncation would keep the first N chars of whatever was pasted — the same "
   "channel with a smaller mouth")

print("== the same bound is used by BOTH governance modules ==")
from driftcore.governance.information_flow import (
    FlowController, Sink, PUBLIC, Labeled, Label, Level, FlowRefused)
_c = FlowController([Sink("p", PUBLIC, declared_by="j")], audit_required=False)
_sec = Labeled("x", Label(Level.SECRET), frozenset({"m"}))
register_human_principal("justin")
try:
    try:
        _c.declassify(_sec, PUBLIC, authorised_by="justin", reason="A" * 500)
        ok(False, "information_flow should use the central bound")
    except FlowRefused as e:
        ok("capped at" in e.operator_detail,
           "information_flow.declassify uses the central bound")

    from driftcore.governance.physical_envelope import (
        EnvelopeController, PhysicalEnvelope, OperatingConditions,
        EnforcementPoint, Dimension)
    def _env(n, f):
        return PhysicalEnvelope(
            name=n, limits={Dimension.FORCE_N.value: f},
            enforced_at=EnforcementPoint.FIRMWARE,
            conditions=OperatingConditions("d", frozenset({"c"})),
            declared_by="justin", attestation_note="n")
    _ctl = EnvelopeController([_env("base", 60.0)], "EMBODIED",
                              audit_required=False)
    okr, msg = _ctl.request_change(_env("wider", 900.0),
                                   authorised_by="justin", reason="A" * 500)
    ok(not okr and "capped at" in msg,
       "physical_envelope.request_change uses the SAME central bound (it had "
       "the identical unbounded-reason pattern)")
finally:
    reset_policy()

print("== production refuses to start in the insecure mode ==")
ok(mode() == "LABEL_ONLY", "with nothing configured the mode is LABEL_ONLY")
try:
    require_secure_mode()
    ok(False, "LABEL_ONLY should refuse to start")
except InsecureAuthorizationMode as e:
    ok("refuses to start" in str(e),
       "require_secure_mode() REFUSES — documentation saying a deployment "
       "'should assert' this is not enforcement, and the whole vulnerability "
       "returns if nobody remembers")
register_human_principal("justin")
try:
    ok(require_secure_mode() == "REGISTERED",
       "a configured deployment starts")
finally:
    reset_policy()

print(f"\n{passed}/{EXPECTED_CHECKS} checks passed")
