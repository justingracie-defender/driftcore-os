"""Information flow: WHAT may leave, not just where it may go.

Closes the residual every egress layer left open — a secret in a legitimate
prompt to a legitimately allowlisted provider passes every destination check.
Three independent red teams named this as the next real boundary."""

from driftcore.governance.information_flow import (
    Level, Label, Labeled, PUBLIC, join_all, Sink, FlowController,
    FlowRefused, LabeledSource, Declassification,
)

EXPECTED_CHECKS = 52

passed = 0
def ok(c, label):
    global passed
    assert c, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")


class _Audit:
    def __init__(self): self.records = []
    def record(self, **kw): self.records.append(kw)


SECRET_FAMILY = Label(Level.SECRET, frozenset({"family"}))
INTERNAL = Label(Level.INTERNAL)

def controller(audit=None):
    return FlowController([
        Sink("home_notes", Label(Level.SECRET, frozenset({"family", "ops"})),
             declared_by="justin", purpose="our own notes service"),
        Sink("llm_provider", PUBLIC, declared_by="justin",
             purpose="third-party model API"),
        Sink("internal_metrics", INTERNAL, declared_by="justin",
             purpose="first-party telemetry"),
    ], audit=audit or _Audit())


print("== THE RESIDUAL: a secret in a legitimate prompt ==")
c = controller()
secret = Labeled("the family's address", SECRET_FAMILY, frozenset({"memory"}))
try:
    c.send("llm_provider", secret)
    ok(False, "a secret should not reach a public sink")
except FlowRefused as e:
    ok("may not flow" in e.operator_detail,
       "SECRET+{family} is REFUSED at a PUBLIC third-party sink — the check "
       "every destination layer could not make")
ok(c.send("home_notes", secret) == "the family's address",
   "the same data flows to a first-party sink cleared for it")


print("== the load-bearing decision: unlabelled data cannot leave ==")
try:
    c.send("llm_provider", "just a plain string")
    ok(False, "a bare string should be refused")
except FlowRefused as e:
    ok("unknown provenance" in e.operator_detail,
       "a BARE STRING is refused — forgetting to label is a REFUSAL, not a leak")
ok(c.send("llm_provider", Labeled.public("hello")) == "hello",
   "an explicitly PUBLIC value flows to a public sink")


print("== the lattice: level AND compartments ==")
ok(Label(Level.SECRET).dominates(Label(Level.PUBLIC)),
   "a higher level dominates a lower one")
ok(not Label(Level.PUBLIC).dominates(Label(Level.SECRET)),
   "a lower level does not dominate a higher one")
cleared_secret_only = Sink("s", Label(Level.SECRET), declared_by="j")
allowed, why = cleared_secret_only.may_receive(SECRET_FAMILY)
ok(not allowed and "uncleared compartment" in why,
   "a sink cleared SECRET but not for {family} still REFUSES family data — "
   "a single sensitivity number could never express this")
ok(Label(Level.SECRET, frozenset({"family"})).dominates(
    Label(Level.SECRET, frozenset({"family"}))),
   "an exactly-matching label is permitted")
ok(not Label(Level.INTERNAL, frozenset({"family"})).dominates(
    Label(Level.SECRET, frozenset({"family"}))),
   "compartment match does not excuse an insufficient level")


print("== combination takes the JOIN — mixing never lowers ==")
pub = Labeled.public("Summarise: ")
mixed = pub.combine(secret)
ok(mixed.label.level is Level.SECRET,
   "public text + a secret yields a SECRET (the direction that matters)")
ok("family" in mixed.label.compartments,
   "compartments are carried through the join")
ok(mixed.origins == frozenset({"literal", "memory"}),
   "provenance accumulates — an incident can ask WHERE this came from")
try:
    c.send("llm_provider", mixed)
    ok(False, "the joined value should be refused")
except FlowRefused:
    ok(True, "prefixing a secret with harmless text does not launder it")

try:
    pub.combine("a bare string")
    ok(False, "combining with an unlabelled operand should be refused")
except FlowRefused as e:
    ok("unknown provenance" in e.operator_detail,
       "combining with a BARE value is refused — assuming it is public is how "
       "a secret becomes public by accident")

folded = join_all([Labeled.public("a"), Labeled.public("b"),
                   Labeled("c", INTERNAL, frozenset({"cfg"}))])
ok(folded.label.level is Level.INTERNAL,
   "join_all folds to the highest label present")
try:
    join_all([])
    ok(False, "empty join should be refused")
except FlowRefused:
    ok(True, "join_all([]) is refused rather than defaulting to PUBLIC")


print("== declassification: possible, human-gated, audited ==")
audit = _Audit()
c2 = controller(audit)
for who, reason, why in [
    ("system", "r", "'system' cannot declassify"),
    ("agent", "r", "'agent' cannot declassify"),
    ("justin", "", "a human with no reason cannot declassify"),
]:
    try:
        c2.declassify(secret, PUBLIC, authorised_by=who, reason=reason)
        ok(False, f"{why} — should be refused")
    except FlowRefused:
        ok(True, why)

released = c2.declassify(secret, PUBLIC, authorised_by="justin",
                         reason="address already published on the school site")
ok(released.label is PUBLIC or released.label.level is Level.PUBLIC,
   "a human with a reason CAN declassify")
ok(released.origins == secret.origins,
   "declassification preserves provenance — the origin is not erased")
ok(c2.send("llm_provider", released) == "the family's address",
   "the declassified value now flows")
ok(len(c2.declassification_log) == 1
   and c2.declassification_log[0].authorised_by == "justin",
   "every declassification is recorded with who and why")
ok(any(r["action"] == "DECLASSIFIED" for r in audit.records),
   "and lands in the audit trail")

try:
    c2.declassify(Labeled.public("x"), Label(Level.SECRET),
                  authorised_by="justin", reason="r")
    ok(False, "raising a label via declassify should be refused")
except FlowRefused as e:
    ok("only lowers" in e.operator_detail,
       "declassification only LOWERS — it is not a general relabel")


print("== sinks are declared, not inferred ==")
try:
    Sink("x", PUBLIC, declared_by="")
    ok(False, "an unattributed sink should be refused")
except FlowRefused as e:
    ok("attributable" in e.operator_detail, "a sink requires declared_by")
try:
    FlowController([])
    ok(False, "no sinks should be refused")
except FlowRefused as e:
    ok("refuse everything" in e.operator_detail,
       "a controller with no sinks is a misconfiguration, not a lockdown")
try:
    c.send("nonexistent", Labeled.public("x"))
    ok(False, "an undeclared sink should be refused")
except FlowRefused:
    ok(True, "sending to an undeclared sink is refused")


print("== wire the SOURCES, not just the sink ==")
mem = LabeledSource("memory:family", SECRET_FAMILY,
                    lambda k: f"value-for-{k}")
got = mem.read("address")
ok(isinstance(got, Labeled) and got.label.level is Level.SECRET,
   "a LabeledSource emits Labeled values, so the agent never holds an "
   "unlabelled secret in the first place")
ok(got.origins == frozenset({"memory:family"}),
   "the source names itself in the provenance")
try:
    c.send("llm_provider", got)
    ok(False, "source-labelled secret should be refused")
except FlowRefused:
    ok(True, "and it is refused at the sink without the agent doing anything")


print("== audit is fail-closed ==")
class _Broken:
    def record(self, **kw): raise RuntimeError("audit down")
c3 = FlowController([Sink("s", PUBLIC, declared_by="j")], audit=_Broken())
try:
    c3.send("s", Labeled.public("x"))
    ok(False, "a failing audit should refuse the flow")
except FlowRefused as e:
    ok("unrecorded" in e.operator_detail,
       "a flow that cannot be recorded is refused rather than released")
try:
    FlowController([Sink("s", PUBLIC, declared_by="j")]).send(
        "s", Labeled.public("x"))
    ok(False, "no audit sink should refuse")
except FlowRefused as e:
    ok("audit_required" in e.operator_detail,
       "no audit sink at all is refused unless waived deliberately")


print("== refusals do not echo the data back ==")
try:
    c.send("llm_provider", Labeled("SUPER-SECRET-VALUE", SECRET_FAMILY,
                                   frozenset({"memory"})))
except FlowRefused as e:
    ok("SUPER-SECRET-VALUE" not in str(e),
       "the caller-visible message does not echo the payload")
    ok("SUPER-SECRET-VALUE" not in e.operator_detail,
       "not even the operator detail repeats the data — it names the LABEL and "
       "the ORIGIN, which is what an operator actually needs")

print("== RED TEAM 2026-08 (ChatGPT): authorization was a string ==")
from driftcore.authority import human_identity as _hi

# The declassify path is the one operation that turns SECRET into PUBLIC, and
# it was gated by "is this string not on a denylist?" — so any caller who typed
# "justin" was Justin. Now delegated to the repo's identity primitive, which is
# already used by the actuation path.
_key = b"k" * 32
_c4 = FlowController([Sink("pub", PUBLIC, declared_by="j")], audit_required=False)
_sec = Labeled("x", Label(Level.SECRET), frozenset({"m"}))

_v = _hi.HumanIdentityVerifier(); _v.register_principal("justin", _key)
_hi.set_verifier(_v)
try:
    ok(_hi.mode() == "ATTESTED", "ATTESTED mode is active when a verifier is set")
    for who, why in (("justin", "the RIGHT name as a bare string"),
                     ("evil", "an arbitrary name")):
        try:
            _c4.declassify(_sec, PUBLIC, authorised_by=who, reason="r")
            ok(False, f"{why} should be refused")
        except FlowRefused:
            ok(True, f"A1: {why} cannot declassify — in ATTESTED mode a bare "
                     f"string is NEVER human")

    _att = _hi.HumanAttestation.issue(_key, principal="justin",
                                      action="declassify", ttl_seconds=60,
                                      nonce="n1")
    _out = _c4.declassify(_sec, PUBLIC, authorised_by=_att,
                          reason="address already published")
    ok(_out.label.level is Level.PUBLIC,
       "A1: a SIGNED attestation does declassify")

    _forged = _hi.HumanAttestation.issue(b"wrong" * 8, principal="justin",
                                         action="declassify", ttl_seconds=60,
                                         nonce="n2")
    try:
        _c4.declassify(_sec, PUBLIC, authorised_by=_forged, reason="r")
        ok(False, "a forged signature should be refused")
    except FlowRefused:
        ok(True, "A1: a FORGED signature is refused")

    _wrong = _hi.HumanAttestation.issue(_key, principal="justin",
                                        action="envelope_widen", ttl_seconds=60,
                                        nonce="n3")
    try:
        _c4.declassify(_sec, PUBLIC, authorised_by=_wrong, reason="r")
        ok(False, "a grant for another action should be refused")
    except FlowRefused:
        ok(True, "A1: a grant scoped to a DIFFERENT action is refused — a widen "
                 "grant cannot be replayed at the declassify boundary")
finally:
    _hi.reset_policy()

ok(_hi.mode() == "LABEL_ONLY",
   "A1: with no verifier the mode is LABEL_ONLY, which status() reports as "
   "insecure — the weak mode is visible, not silent")

print("== RED TEAM 2026-08 (ChatGPT): the audit log is a sink too ==")
_c5 = FlowController([Sink("pub", PUBLIC, declared_by="j")], audit_required=False)
_hi.register_human_principal("justin")
try:
    try:
        _c5.declassify(_sec, PUBLIC, authorised_by="justin", reason="X" * 500)
        ok(False, "an oversized reason should be refused")
    except FlowRefused as e:
        ok("audit log is a sink" in e.operator_detail,
           "A4: an unbounded declassification reason is refused — otherwise the "
           "layer produces its own signature failure: stopping the secret "
           "reaching the LLM by writing it into the audit record instead")
    ok(_c5.declassify(_sec, PUBLIC, authorised_by="justin",
                      reason="already published").label.level is Level.PUBLIC,
       "A4: a normal-length reason is unaffected")
finally:
    _hi.reset_policy()

print("== RED TEAM 2026-08 (Grok): probes and mutability ==")

# G4: may_send called send(), so every PROBE wrote an audit record. That gave a
# probing agent audit-log volume it controlled, and the record confirmed the
# existence and label of data it was only asking about.
class _Counting:
    def __init__(self): self.actions = []
    def record(self, **kw): self.actions.append(kw["action"])
_cnt = _Counting()
_c6 = FlowController([Sink("pub", PUBLIC, declared_by="j")], audit=_cnt)
_hi_sec = Labeled("x", Label(Level.SECRET), frozenset({"m"}))
for _ in range(5):
    _c6.may_send("pub", _hi_sec)
ok(_cnt.actions == [],
   "G4: may_send is a PURE query — 5 probes wrote 0 audit records (a decision "
   "only CONSIDERED is not an event)")
_allowed, _why = _c6.may_send("pub", _hi_sec)
ok(_allowed is False and "refused" in _why,
   "G4: and the verdict is still correct")
ok(_c6.may_send("pub", "a bare string")[0] is False,
   "G4: a bare string is still refused by the query")
_c6.send("pub", Labeled.public("y"))
ok(_cnt.actions == ["FLOW_PERMITTED"],
   "G4: an actual RELEASE still records exactly one event")

# G5: Labeled is a frozen dataclass, which freezes the REFERENCE, not the object
# it points at. Labelling a list PUBLIC and then appending a secret to that same
# list left the label saying PUBLIC over changed contents.
_mutable = ["public item"]
_lab = Labeled(_mutable, PUBLIC, frozenset({"lit"}))
_mutable.append("SECRET APPENDED AFTER LABELLING")
ok("SECRET APPENDED AFTER LABELLING" not in str(_lab.value),
   "G5: the payload is SNAPSHOT-FROZEN at labelling — mutating the original "
   "cannot change what the label describes")
ok(_lab.value == ("public item",), "G5: the snapshot holds the labelled contents")

_d = {"k": ["v"]}
_labd = Labeled(_d, PUBLIC, frozenset({"lit"}))
_d["k"].append("added")
ok("added" not in str(_labd.value), "G5: freezing is recursive, not shallow")

try:
    Labeled(object(), PUBLIC)
    ok(False, "an unfreezable object should be refused")
except FlowRefused as e:
    ok("can change after it is attached" in e.operator_detail,
       "G5: an arbitrary mutable object is REFUSED rather than labelled with a "
       "statement that can quietly stop being true")

print(f"\n{passed}/{EXPECTED_CHECKS} checks passed")
