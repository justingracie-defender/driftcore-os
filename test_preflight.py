"""
test_preflight.py — adversarial tests for the deployment preflight.

Run: python3 test_preflight.py

Covers the framework contract (empty-registry refusal, fail-closed on crash,
no-PASS-without-a-demonstrated-rejection, any FAIL refuses boot, UNVERIFIABLE
never blocks) and the shipped checks against DELIBERATELY BROKEN deployments —
including the load-bearing one: a STUB verifier that mode() calls "secure" is
still caught (the `lambda: True` failure), which require_secure_mode() alone
would wave through.
"""

import contextlib
import hashlib
import os
import tempfile

from driftcore.kernel import preflight as P
from driftcore.kernel.preflight import (
    Outcome, Category, ProbeResult, Unverifiable, PreflightCheck,
    PreflightReport, PreflightFailed, EmptyPreflight,
)
from driftcore.authority import human_identity as H


_passed = 0
_total = 0


def check(label, cond):
    global _passed, _total
    _total += 1
    if cond:
        _passed += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


# ── fake checks for framework tests ───────────────────────────────


class _Rejects(PreflightCheck):
    name = "fake-rejects"
    description = "guard rejected the canary"
    def exercise(self):
        return ProbeResult(bad_input_rejected=True, observed="rejected=True")


class _Accepts(PreflightCheck):
    name = "fake-accepts"
    description = "guard accepted the canary"
    def exercise(self):
        return ProbeResult(bad_input_rejected=False, observed="rejected=False")


class _Unverifiable(PreflightCheck):
    name = "fake-unverifiable"
    category = Category.DEPLOYMENT_TOPOLOGY
    def exercise(self):
        raise Unverifiable("cannot check from inside the process")


class _UnverifiableSoftware(PreflightCheck):
    """UNVERIFIABLE but NOT a topology fact — does not trigger the topology gate."""
    name = "fake-unverifiable-software"
    category = Category.CHECKABLE
    def exercise(self):
        raise Unverifiable("nothing supplied to exercise")


class _Crashes(PreflightCheck):
    name = "fake-crashes"
    def exercise(self):
        raise ValueError("boom")


class _ReturnsGarbage(PreflightCheck):
    name = "fake-garbage"
    def exercise(self):
        return True   # not a ProbeResult — must fail closed


# ── verifier fixtures ─────────────────────────────────────────────


@contextlib.contextmanager
def real_verifier():
    """ATTESTED mode with a genuine verifier that knows 'justin'."""
    H.reset_policy()
    try:
        v = H.HumanIdentityVerifier()
        v.register_principal("justin", b"the-one-true-key")
        H.set_verifier(v)
        yield
    finally:
        H.reset_policy()


@contextlib.contextmanager
def stub_verifier():
    """ATTESTED mode, but the verifier accepts ANYTHING (the lambda:True bug).
    mode() reports ATTESTED — 'secure' — yet forged attestations pass."""
    H.reset_policy()

    class _AcceptAll(H.HumanIdentityVerifier):
        def verify(self, att, *, action, now=None):
            return "justin"   # never checks the signature

    try:
        H.set_verifier(_AcceptAll())
        yield
    finally:
        H.reset_policy()


@contextlib.contextmanager
def label_only():
    """LABEL_ONLY: any string not on the denylist counts as human."""
    H.reset_policy()
    try:
        yield
    finally:
        H.reset_policy()


# ══════════════════════════════════════════════════════════════════

print("=== framework contract ===")

# empty registry is a refusal, not a pass
raised = False
try:
    P.run([])
except EmptyPreflight:
    raised = True
check("empty registry -> EmptyPreflight", raised)

# all-pass -> ok, no raise
rep = P.run([_Rejects()])
check("all-pass -> report.ok", rep.ok)
check("all-pass -> one PASS recorded", len(rep.passed) == 1)

# a guard that ACCEPTS the canary -> FAIL -> refuse boot
raised = False
try:
    P.run([_Accepts()])
except PreflightFailed as e:
    raised = True
    check("accept-canary -> report carried on exception",
          len(e.report.fails) == 1)
check("accept-canary -> PreflightFailed raised", raised)

# same, with raise_on_fail=False, we get the report
rep = P.run([_Accepts()], raise_on_fail=False)
check("accept-canary (no-raise) -> not ok", not rep.ok)
check("accept-canary (no-raise) -> outcome FAIL",
      rep.results[0].outcome is Outcome.FAIL)

# unverifiable does not block boot for a NON-topology check
rep = P.run([_UnverifiableSoftware()])
check("unverifiable (non-topology) -> boot permitted", rep.ok)
check("unverifiable -> outcome UNVERIFIABLE",
      rep.results[0].outcome is Outcome.UNVERIFIABLE)
check("unverifiable -> not counted as PASS", len(rep.passed) == 0)

# an UNVERIFIABLE *topology* check now refuses rather than silently permitting
raised = False
try:
    P.run([_Unverifiable()])
except P.UnattestedInvariant:
    raised = True
check("unverifiable TOPOLOGY check -> run() refuses (no silent permit)", raised)
rep = P.run([_Unverifiable()], allow_unverified_topology=True)
check("explicit allow_unverified_topology=True -> permitted", rep.ok)

# a crashing check fails CLOSED (not skipped, not passed)
rep = P.run([_Crashes()], raise_on_fail=False)
check("crashing check -> FAIL (fail-closed)",
      rep.results[0].outcome is Outcome.FAIL)
check("crashing check -> reason mentions the exception",
      "boom" in rep.results[0].detail)

# a check that returns a non-ProbeResult cannot self-certify -> FAIL
rep = P.run([_ReturnsGarbage()], raise_on_fail=False)
check("non-ProbeResult return -> FAIL (no self-certify)",
      rep.results[0].outcome is Outcome.FAIL)

# mixed pass + unverifiable, no fail -> ok, counts correct
rep = P.run([_Rejects(), _Unverifiable(), _Rejects()], allow_unverified_topology=True)
check("mixed pass+unverifiable -> ok", rep.ok)
check("mixed -> 2 passed", len(rep.passed) == 2)
check("mixed -> 1 unverifiable", len(rep.unverifiable) == 1)

# one fail among passes -> the whole preflight refuses
raised = False
try:
    P.run([_Rejects(), _Accepts(), _Unverifiable()], allow_unverified_topology=True)
except PreflightFailed:
    raised = True
check("one fail among passes -> refuse boot", raised)

# render() names the refusal
rep = P.run([_Accepts()], raise_on_fail=False)
check("render() states refusal on fail", "REFUSE TO START" in rep.render())
rep = P.run([_Rejects()])
check("render() permits boot on all-pass", "boot permitted" in rep.render())


print("=== HumanAuthorizationIsReal ===")

chk = P.HumanAuthorizationIsReal()

with real_verifier():
    rep = P.run([chk], raise_on_fail=False)
    r = rep.results[0]
    check("real verifier -> PASS", r.outcome is Outcome.PASS)
    check("real verifier -> mode ATTESTED in observed", "mode=ATTESTED" in r.observed)
    check("real verifier -> nothing accepted",
          "bare_string_accepted=False" in r.observed
          and "wrong_key_attestation_accepted=False" in r.observed)

with label_only():
    # sanity: LABEL_ONLY really does accept a bare string
    check("LABEL_ONLY accepts bare string (precondition)",
          H.is_human("justin", action="x") is True)
    rep = P.run([chk], raise_on_fail=False)
    check("LABEL_ONLY -> FAIL (bare string accepted)",
          rep.results[0].outcome is Outcome.FAIL)
    # and require_secure_mode agrees here (mode IS label-only)
    raised = False
    try:
        H.require_secure_mode()
    except H.InsecureAuthorizationMode:
        raised = True
    check("LABEL_ONLY -> require_secure_mode also raises", raised)

with stub_verifier():
    # THE LOAD-BEARING CASE: mode() says ATTESTED ('secure'), and
    # require_secure_mode() is happy — but the verifier is a lambda:True stub,
    # so a forged attestation passes. Preflight must still FAIL.
    check("stub verifier -> mode reports ATTESTED", H.mode() == "ATTESTED")
    rsm_ok = True
    try:
        H.require_secure_mode()   # does NOT raise: mode string looks secure
    except H.InsecureAuthorizationMode:
        rsm_ok = False
    check("stub verifier -> require_secure_mode does NOT catch it", rsm_ok)

    rep = P.run([chk], raise_on_fail=False)
    r = rep.results[0]
    check("stub verifier -> preflight FAILS (strictly stronger)",
          r.outcome is Outcome.FAIL)
    check("stub verifier -> forged attestation seen accepted",
          "wrong_key_attestation_accepted=True" in r.observed)


print("=== ConstitutionIsIntegrityPinned ===")

with tempfile.TemporaryDirectory() as tmp:
    cpath = os.path.join(tmp, "CONSTITUTION.md")
    body = b"# Constitution\nInvariants are load-bearing.\n"
    with open(cpath, "wb") as f:
        f.write(body)
    good = hashlib.sha256(body).hexdigest()

    rep = P.run([P.ConstitutionIsIntegrityPinned(good, cpath)], raise_on_fail=False)
    check("correct pin -> PASS", rep.results[0].outcome is Outcome.PASS)

    rep = P.run([P.ConstitutionIsIntegrityPinned("00" * 32, cpath)],
                raise_on_fail=False)
    check("wrong pin -> FAIL", rep.results[0].outcome is Outcome.FAIL)

    # mutate the file after pinning the original digest
    with open(cpath, "ab") as f:
        f.write(b"maliciously appended clause\n")
    rep = P.run([P.ConstitutionIsIntegrityPinned(good, cpath)], raise_on_fail=False)
    check("swapped constitution -> FAIL", rep.results[0].outcome is Outcome.FAIL)

    # unpinned -> UNVERIFIABLE (nothing to compare)
    rep = P.run([P.ConstitutionIsIntegrityPinned(None, cpath)], raise_on_fail=False)
    check("unpinned -> UNVERIFIABLE", rep.results[0].outcome is Outcome.UNVERIFIABLE)

    # pinned but file missing -> UNVERIFIABLE
    rep = P.run([P.ConstitutionIsIntegrityPinned(good, os.path.join(tmp, "nope.md"))],
                raise_on_fail=False)
    check("pinned but file missing -> UNVERIFIABLE",
          rep.results[0].outcome is Outcome.UNVERIFIABLE)


print("=== AuditChainIsTamperEvident (subprocess canary) ===")

rep = P.run([P.AuditChainIsTamperEvident()], raise_on_fail=False)
r = rep.results[0]
check("audit canary -> never spuriously FAILs",
      r.outcome in (Outcome.PASS, Outcome.UNVERIFIABLE))
if r.outcome is Outcome.PASS:
    check("audit canary PASS -> tamper actually detected",
          "verify_chain_detected_tamper=True" in r.observed)
else:
    print(f"       (ran as UNVERIFIABLE: {r.detail[:80]})")
# it must not have touched the live audit chain in THIS process
check("live audit module not compromised by the canary",
      __import__("driftcore.audit", fromlist=["_chain_compromised"])._chain_compromised
      is False)


print("=== deployment-topology checks are honest ===")

for c in (P.NetworkPathIsSevered(), P.WormStorageIsAppendOnly(),
          P.ActuatorBrokerHasSeparatePrivilege(), P.ActuatorManifestsAreSigned()):
    rep = P.run([c], raise_on_fail=False)
    r = rep.results[0]
    check(f"{c.name} -> UNVERIFIABLE", r.outcome is Outcome.UNVERIFIABLE)
    check(f"{c.name} -> never PASS/FAIL", r.outcome not in (Outcome.PASS, Outcome.FAIL))
    check(f"{c.name} -> tagged deployment-topology",
          r.category is Category.DEPLOYMENT_TOPOLOGY)

# topology-only preflight permits boot but records every item as an assumption
rep = P.run([P.NetworkPathIsSevered(), P.WormStorageIsAppendOnly()], allow_unverified_topology=True)
check("topology-only -> boot permitted (all assumptions)", rep.ok)
check("topology-only -> zero PASS (nothing certified)", len(rep.passed) == 0)


print("=== ActuationEffectGatingActive (deployment assertion) ===")

import tempfile as _tf
from driftcore.verification.mediated_actuation import ActuationBroker, Effect
from driftcore.verification.signed_permission import PermissionVerifier as _PV

_bdir = _tf.mkdtemp()
_bverifier = _PV(); _bverifier.register_key("operator", "k", unrestricted=True)


def _broker_factory(enforce):
    # returns an UNSTARTED broker built the way a deployment would
    return lambda: ActuationBroker(os.path.join(_bdir, f"b{enforce}.sock"),
                                   _bverifier, enforce_effects=enforce)


rep = P.run([P.ActuationEffectGatingActive(_broker_factory(True))], raise_on_fail=False)
check("effect-gating ON -> PASS (undeclared actuator refused)",
      rep.results[0].outcome is Outcome.PASS)

rep = P.run([P.ActuationEffectGatingActive(_broker_factory(False))], raise_on_fail=False)
check("effect-gating OFF -> FAIL (undeclared actuator accepted = fail-open hole)",
      rep.results[0].outcome is Outcome.FAIL)

rep = P.run([P.ActuationEffectGatingActive(None)], raise_on_fail=False)
check("no broker_factory -> UNVERIFIABLE",
      rep.results[0].outcome is Outcome.UNVERIFIABLE)

# a broker with effect-gating off refuses to boot under run()
raised = False
try:
    P.run([P.ActuationEffectGatingActive(_broker_factory(False))])
except PreflightFailed:
    raised = True
check("effect-gating OFF -> refuses to boot", raised)


print("=== ReplayDefenseSurvivesRestart (deployment assertion) ===")


class _DurableNonceSet(set):
    """A genuinely durable spent-nonce store: state lives on DISK and is reloaded on
    construction, so it survives process death — not merely object reconstruction.
    (A plain shared in-memory set survives neither, and the check correctly refuses to
    certify it — see the F2 tests below.)"""

    def __init__(self, path):
        self._path = path
        loaded = []
        if os.path.exists(path):
            with open(path) as f:
                loaded = [ln.strip() for ln in f if ln.strip()]
        super().__init__(loaded)

    def add(self, item):
        super().add(item)
        with open(self._path, "a") as f:
            f.write(str(item) + "\n")


_nonce_path = os.path.join(_tf.mkdtemp(), "spent_nonces.txt")
_durable_factory = lambda: _PV(used_nonces=_DurableNonceSet(_nonce_path))
_fresh_factory = lambda: _PV()                          # fresh in-memory set each time

rep = P.run([P.ReplayDefenseSurvivesRestart(_durable_factory)], raise_on_fail=False)
check("durable (disk-backed) nonce store -> PASS (replay refused after restart)",
      rep.results[0].outcome is Outcome.PASS)

rep = P.run([P.ReplayDefenseSurvivesRestart(_fresh_factory)], raise_on_fail=False)
check("in-memory nonce set -> FAIL (replay window across restart)",
      rep.results[0].outcome is Outcome.FAIL)

rep = P.run([P.ReplayDefenseSurvivesRestart(None)], raise_on_fail=False)
check("no verifier_factory -> UNVERIFIABLE",
      rep.results[0].outcome is Outcome.UNVERIFIABLE)


print("=== run_default wires the deployment assertions when given factories ===")

with real_verifier():
    rep = P.run_default(context="test",
                        broker_factory=_broker_factory(True),
                        verifier_factory=_durable_factory,
                        allow_unverified_topology=True)
    check("run_default with good factories -> ok", rep.ok)
    check("run_default with good factories -> effect-gating + replay both PASS",
          sum(1 for r in rep.passed
              if r.name in ("actuation-effect-gating-active",
                            "replay-defense-survives-restart")) == 2)

with real_verifier():
    raised = False
    try:
        P.run_default(context="test", broker_factory=_broker_factory(False),
                      verifier_factory=_durable_factory,
                      allow_unverified_topology=True)
    except PreflightFailed:
        raised = True
    check("run_default REFUSES boot when effect-gating is off", raised)


print("=== red-team fixes: no PASS without the RIGHT guard (ChatGPT findings) ===")


class _BrokenBroker:
    def register_actuator(self, *a, **k):
        raise RuntimeError("database exploded")   # unrelated to effect gating


rep = P.run([P.ActuationEffectGatingActive(lambda: _BrokenBroker())], raise_on_fail=False)
check("F1: a broker failing for an UNRELATED reason is UNVERIFIABLE, not PASS",
      rep.results[0].outcome is Outcome.UNVERIFIABLE)
check("F1: the reason names that the effect gate did not refuse",
      "not with the effect gate" in rep.results[0].detail.lower()
      or "effect gate" in rep.results[0].detail.lower())

rep = P.run([P.ActuationEffectGatingActive(lambda: (_ for _ in ()).throw(
    RuntimeError("factory blew up")))], raise_on_fail=False)
check("F1: a factory that raises is UNVERIFIABLE, not PASS",
      rep.results[0].outcome is Outcome.UNVERIFIABLE)

_same = _PV()
rep = P.run([P.ReplayDefenseSurvivesRestart(lambda: _same)], raise_on_fail=False)
check("F2: a factory returning the SAME verifier is UNVERIFIABLE, not PASS",
      rep.results[0].outcome is Outcome.UNVERIFIABLE)
check("F2: the reason names the same-instance problem",
      "same" in rep.results[0].detail.lower())

_shared = set()
rep = P.run([P.ReplayDefenseSurvivesRestart(lambda: _PV(used_nonces=_shared))],
            raise_on_fail=False)
check("F2: distinct verifiers sharing ONE LIVE set is UNVERIFIABLE (not process death)",
      rep.results[0].outcome is Outcome.UNVERIFIABLE)


class _DeadVerifier(H.HumanIdentityVerifier):
    """Rejects everybody — useless as an authorization system."""
    def verify(self, att, *, action, now=None):
        raise H.AttestationInvalid("nope")


H.reset_policy()
try:
    H.set_verifier(_DeadVerifier())
    rep = P.run([P.HumanAuthorizationIsReal()], raise_on_fail=False)
    check("F6: a verifier that rejects EVERYONE cannot PASS (positive control)",
          rep.results[0].outcome is Outcome.UNVERIFIABLE)
finally:
    H.reset_policy()

with real_verifier():
    rep = P.run([P.HumanAuthorizationIsReal()], raise_on_fail=False)
    check("F6: a real verifier still PASSes and records the positive control",
          rep.results[0].outcome is Outcome.PASS
          and "valid_human_accepted=True" in rep.results[0].observed)


print("=== F3: run_operational — UNVERIFIABLE must not permit a physical boot ===")

_mandatory = ["human-authorization-is-real", "agent-has-no-network-path"]
with real_verifier():
    _checks = [P.HumanAuthorizationIsReal(), P.NetworkPathIsSevered()]

    # plain run() permits this (nothing FAILed) — the gap being closed
    check("plain run() permits boot despite an UNVERIFIABLE mandatory invariant",
          P.run(_checks, raise_on_fail=False).ok)

    raised = False
    try:
        P.run_operational(_checks, mandatory=_mandatory, context="poppy")
    except P.UnattestedInvariant as e:
        raised = True
        check("run_operational names the unattested invariant",
              "agent-has-no-network-path" in e.missing)
    check("run_operational REFUSES boot when a mandatory invariant is unattested", raised)

    rep = P.run_operational(_checks, mandatory=_mandatory,
                            attested=["agent-has-no-network-path"], context="poppy")
    check("run_operational permits boot once the platform attests the topology fact",
          rep is not None)

    # a FAIL still refuses even with everything attested
    raised = False
    try:
        P.run_operational([_Accepts()], mandatory=["fake-accepts"],
                          attested=["fake-accepts"])
    except PreflightFailed:
        raised = True
    check("run_operational still refuses on a real FAIL", raised)


print("=== Grok hardening: TRUE cross-process restart survival ===")

import sys as _sys, textwrap as _tw
_xd = _tf.mkdtemp()
_xstore = os.path.join(_xd, "spent.txt")
with open(os.path.join(_xd, "pfcfg.py"), "w") as _f:
    _f.write(_tw.dedent(f'''
        import os
        from driftcore.verification.signed_permission import PermissionVerifier
        PATH = {_xstore!r}
        class DurableSet(set):
            def __init__(self):
                super().__init__([l.strip() for l in open(PATH)] if os.path.exists(PATH) else [])
            def add(self, i):
                super().add(i); open(PATH, "a").write(str(i) + "\\n")
        def make_durable(): return PermissionVerifier(used_nonces=DurableSet())
        def make_volatile(): return PermissionVerifier()
    '''))
os.environ["PYTHONPATH"] = _xd + os.pathsep + os.environ.get("PYTHONPATH", "")
_sys.path.insert(0, _xd)

rep = P.run([P.ReplayDefenseSurvivesRestart(factory_spec="pfcfg:make_durable")],
            raise_on_fail=False)
check("cross-process: disk-backed store PASSes (survives real process death)",
      rep.results[0].outcome is Outcome.PASS)
check("cross-process PASS names the separate process",
      "SEPARATE PROCESS" in rep.results[0].observed)

rep = P.run([P.ReplayDefenseSurvivesRestart(factory_spec="pfcfg:make_volatile")],
            raise_on_fail=False)
check("cross-process: volatile store FAILs (window open across process death)",
      rep.results[0].outcome is Outcome.FAIL)

rep = P.run([P.ReplayDefenseSurvivesRestart(_durable_factory)], raise_on_fail=False)
check("in-process PASS now admits it only shows RECONSTRUCTION survival",
      "RECONSTRUCTION" in rep.results[0].observed.upper())


print("=== Grok hardening: a skipped positive control cannot PASS ===")


class _NoRegisterVerifier:
    """Rejects everyone AND exposes no register_principal -> control cannot run."""
    def verify(self, att, *, action, now=None):
        raise H.AttestationInvalid("nope")


H.reset_policy()
try:
    H.set_verifier(_NoRegisterVerifier())
    rep = P.run([P.HumanAuthorizationIsReal()], raise_on_fail=False)
    check("reject-all verifier without register_principal -> UNVERIFIABLE, not PASS",
          rep.results[0].outcome is Outcome.UNVERIFIABLE)
    check("the reason names the un-runnable positive control",
          "positive" in rep.results[0].detail.lower())
finally:
    H.reset_policy()

with real_verifier():
    P.run([P.HumanAuthorizationIsReal()], raise_on_fail=False)
    _v = getattr(H, "_verifier", None)
    _left = getattr(_v, "_principals", {}) if _v is not None else {}
    check("the probe principal does not outlive the check (cleanup)",
          P.HumanAuthorizationIsReal.PROBE_PRINCIPAL not in _left)


print("=== self red-team: boot-gate integrity (attacks on my own gate) ===")


class _RejFake(PreflightCheck):
    name = "fake-pass"
    def exercise(self):
        return ProbeResult(True, "ok")


def _refused(fn):
    try:
        fn()
        return False
    except Exception:
        return True


check("A1: an UNLISTED topology invariant still refuses the robot gate",
      _refused(lambda: P.run_operational([_RejFake(), P.NetworkPathIsSevered()],
                                         mandatory=["fake-pass"], context="poppy")))
check("A2: an EMPTY mandatory list is refused (certifies nothing)",
      _refused(lambda: P.run_operational([P.NetworkPathIsSevered()],
                                         mandatory=[], context="poppy")))
check("A3: attesting a name no check produced is refused (typo/lie)",
      _refused(lambda: P.run_operational([_RejFake()],
                                         mandatory=["agent-has-no-network-path"],
                                         attested=["agent-has-no-network-path"],
                                         context="poppy")))


class _SneakyTopology(PreflightCheck):
    """A topology invariant name declaring itself CHECKABLE to dodge the gate."""
    name = "agent-has-no-network-path"
    category = Category.CHECKABLE
    def exercise(self):
        raise Unverifiable("cannot check")


check("A4: a known topology name cannot be downgraded to CHECKABLE",
      _refused(lambda: P.run([_SneakyTopology()], context="svc")))

# discrimination: the correctly-attested deployment DOES boot
rep = P.run_operational([_RejFake(), P.NetworkPathIsSevered()],
                        mandatory=["fake-pass"],
                        attested=["agent-has-no-network-path"], context="poppy")
check("A1-A4 fixes are not a blanket refuse: a properly attested robot boots",
      rep is not None)

print("=== self red-team: A5 boot-time PASS can regress (TOCTOU) ===")

H.reset_policy()
try:
    _v = H.HumanIdentityVerifier(); _v.register_principal("justin", b"real-key")
    H.set_verifier(_v)
    _checks = [P.HumanAuthorizationIsReal()]
    _base = P.run(_checks, raise_on_fail=False)
    check("A5: the invariant PASSes at boot", _base.results[0].outcome is Outcome.PASS)
    H.set_verifier(None)          # the post-boot downgrade
    check("A5: the property really is false after the downgrade",
          H.is_human("justin", action="x") is True)
    regressed = None
    try:
        P.reverify(_checks, _base)
    except P.InvariantRegressed as e:
        regressed = e.regressed
    check("A5: reverify() DETECTS the regression and refuses",
          regressed == ["human-authorization-is-real"])
finally:
    H.reset_policy()

# reverify is quiet when nothing regressed
with real_verifier():
    _c = [P.HumanAuthorizationIsReal()]
    _b = P.run(_c, raise_on_fail=False)
    check("A5: reverify() permits when the invariant still holds",
          P.reverify(_c, _b) is not None)

print("=== self red-team: A6 probe secret is not exposed via argv ===")

import inspect as _inspect
_src = _inspect.getsource(P.ReplayDefenseSurvivesRestart._cross_process)
check("A6: the probe secret travels over stdin, not the command line",
      "cfg['secret']" in _src and "self._PROBE_SECRET, self._PROBE_KEY]" not in _src)


print("=== run_default wiring ===")

with real_verifier():
    rep = P.run_default(context="test", allow_unverified_topology=True)
    check("run_default -> ok with a real verifier", rep.ok)
    check("run_default -> at least one real PASS", len(rep.passed) >= 1)
    check("run_default -> surfaces UNVERIFIABLE assumptions",
          len(rep.unverifiable) >= 3)

with label_only():
    raised = False
    try:
        P.run_default(context="test", allow_unverified_topology=True)
    except PreflightFailed:
        raised = True
    check("run_default -> REFUSES boot in LABEL_ONLY", raised)


print("-" * 60)
# ─────────────────────────────────────────────────────────────────────────────
# identity-mode-is-secure (cold pass, 2026-08-15)
#
# `is_human` is the single permitted interface behind 45 call sites in 19 modules,
# and in the DEFAULT LABEL_ONLY mode it answers from a word list — is_human("agent2")
# is True. That is the Hugging Face shape: a constrained, permitted interface whose
# failure mode lands outside the boundary. There it took a zero-day; here it takes
# nothing. `require_secure_mode()` existed in human_identity and NOTHING in the
# deployment path called it.
# ─────────────────────────────────────────────────────────────────────────────

from driftcore.authority import human_identity as _H
from driftcore.authority.human_identity import HumanIdentityVerifier as _V
from driftcore.kernel.preflight import (
    IdentityModeIsSecure as _IMS, HumanAuthorizationIsReal as _HAR)


def _outcome(chk):
    try:
        return "PASS" if chk.exercise().bad_input_rejected else "FAIL"
    except Unverifiable:
        return "UNVERIFIABLE"


print("=== identity-mode-is-secure ===")

_H.reset_policy()
check("no declared policy -> UNVERIFIABLE, never PASS",
      _outcome(_IMS()) == "UNVERIFIABLE")
check("policy ATTESTED on a LABEL_ONLY deployment -> FAIL",
      _outcome(_IMS("ATTESTED")) == "FAIL")

_H.reset_policy()
_H.register_human_principal("alice")
check("policy REGISTERED on a REGISTERED deployment -> PASS",
      _outcome(_IMS("REGISTERED")) == "PASS")
check("policy ATTESTED on a REGISTERED deployment -> FAIL",
      _outcome(_IMS("ATTESTED")) == "FAIL")

_H.reset_policy()
_v = _V()
_v.register_principal("alice", b"k")
_H.set_verifier(_v)
check("policy ATTESTED on an ATTESTED deployment -> PASS",
      _outcome(_IMS("ATTESTED")) == "PASS")
check("ATTESTED satisfies a REGISTERED policy (stronger counts)",
      _outcome(_IMS("REGISTERED")) == "PASS")
check("a nonsense required_mode is UNVERIFIABLE, not a silent PASS",
      _outcome(_IMS("banana")) == "UNVERIFIABLE")


print("=== the two identity checks divide the work, neither is sufficient ===")


class _Stub:
    """Reports ATTESTED, accepts anything — the mode string is not the boundary."""
    def verify(self, *a, **k):
        return "anyone"

    def known_principals(self):
        return {"x"}


_H.reset_policy()
_H.set_verifier(_Stub())
check("a STUBBED verifier passes identity-mode-is-secure (documented limit)",
      _outcome(_IMS("ATTESTED")) == "PASS")
check("and is caught by human-authorization-is-real",
      _outcome(_HAR()) == "FAIL")

_H.reset_policy()
check("LABEL_ONLY is caught by identity-mode-is-secure",
      _outcome(_IMS("ATTESTED")) == "FAIL")


print("=== the canary must measure the boundary, not the roster ===")

# The bare-string canary used to be the literal name "justin". In REGISTERED mode
# is_human(name) is True for any registered principal, so a deployment that registered
# a human called Justin failed its own identity check.
for _name in ("alice", "justin", "bob"):
    _H.reset_policy()
    _H.register_human_principal(_name)
    check(f"human-authorization-is-real passes with a principal named {_name!r}",
          _outcome(_HAR()) == "PASS")

_H.reset_policy()
check("the bare canary is namespaced so no deployment can register it",
      "::" in _HAR.BARE_CANARY)


# ─────────────────────────────────────────────────────────────────────────────
# instrumented-channels-have-ceilings
#
# `amplification_guard` has two mechanisms covering DIFFERENT attacks. The
# trajectory check catches growth across successive observations. The ceiling
# catches magnitude arriving all at once. A self-referential rule — "every time you
# emit X, emit another X" — diverges INSIDE one generation, so the guard is handed
# one finished magnitude and never gets a second point to compare.
#
# Verified: one observation of 1,000,000 on an unbounded channel is PERMITTED; the
# same observation against a ceiling of 500 is refused immediately. The ceiling is
# not the fallback — it is the half of the defence that covers this shape.
# ─────────────────────────────────────────────────────────────────────────────

from driftcore.safety.amplification_guard import AmplificationGuard as _AG
from driftcore.kernel.preflight import InstrumentedChannelsHaveCeilings as _ICC

print("=== instrumented-channels-have-ceilings ===")

_H.reset_policy()
_H.register_human_principal("op")

check("no guard_factory -> UNVERIFIABLE, never PASS",
      _outcome(_ICC()) == "UNVERIFIABLE")
check("a factory but no declared channels -> UNVERIFIABLE",
      _outcome(_ICC(lambda: _AG())) == "UNVERIFIABLE")

_bare = _AG()
check("a declared channel with NO ceiling -> FAIL",
      _outcome(_ICC(lambda: _bare, ["wrist"])) == "FAIL")


def _bounded():
    g = _AG()
    g.declare_ceiling("wrist", 0.9, declared_by="op")
    g.declare_ceiling("gripper", 20, declared_by="op")
    return g


check("every declared channel bounded -> PASS",
      _outcome(_ICC(_bounded, ["wrist", "gripper"])) == "PASS")
check("one bounded and one not -> FAIL",
      _outcome(_ICC(_bounded, ["wrist", "elbow"])) == "FAIL")


class _RecordedNotEnforced:
    """A ceiling that exists and does not refuse. Reading the value is not the
    check; the check is whether the bound actually stops anything."""

    def ceiling_for(self, ch):
        class _L:
            limit = 5.0
        return _L()

    def observe(self, ch, m):
        class _O:
            permitted = True
        return _O()


check("a ceiling that is RECORDED but not ENFORCED -> FAIL",
      _outcome(_ICC(lambda: _RecordedNotEnforced(), ["wrist"])) == "FAIL")


class _Unreadable:
    def ceiling_for(self, ch):
        raise RuntimeError("boom")


check("a guard that cannot answer is not a guard that said yes",
      _outcome(_ICC(lambda: _Unreadable(), ["wrist"])) == "FAIL")
check("a factory that raises -> UNVERIFIABLE, not PASS",
      _outcome(_ICC(lambda: (_ for _ in ()).throw(RuntimeError("x")),
                    ["wrist"])) == "UNVERIFIABLE")

check("it is registered in default_checks",
      any(type(c).__name__ == "InstrumentedChannelsHaveCeilings"
          for c in P.default_checks()))

# The seam itself, stated as a test rather than a comment.
_g = _AG(window=4)
check("SEAM: one huge observation on an unbounded channel is permitted",
      _g.observe("out", 10 ** 6).permitted)
_g2 = _AG(window=4)
_g2.declare_ceiling("out", 500, declared_by="op")
check("and the SAME observation is refused once a ceiling exists",
      not _g2.observe("out", 10 ** 6).permitted)

_H.reset_policy()


print(f"  {_passed}/{_total} tests passed")
if _passed != _total:
    raise SystemExit(1)




