"""
preflight.py — deployment-invariant preflight for DriftCore.

WHAT THIS IS
------------
The repo carries roughly seventy statements of the form "the integrator MUST
wire X" / "a deployment SHOULD assert Y" / "this is the integrator's seam".
Every one of those is honest documentation, and every one is also a silent
assumption: nothing stops a deployer from skipping it while every unit test
still passes. `human_identity.require_secure_mode()` already converted exactly
one of them ("authorization must not be LABEL_ONLY") from a docstring into a
startup refusal. This module generalises that move: a single place that runs
the deployment invariants at boot and REFUSES TO START if a checkable one is
false.

THE ONE RULE THAT KEEPS THIS HONEST
-----------------------------------
A checklist that emits green checkmarks is theatre — the failure a real red
team names is `lambda: True` (ChatGPT, THREAT_BOUNDARIES): a stubbed verifier
that returns "ok" for everything passes any checklist that merely asks "is a
verifier installed?".

So a preflight check may return **PASS only if, in this run, the framework
watched the named guard REJECT a specific bad input.** A check that cannot
exercise a guard against a known-bad input cannot emit PASS — the best it can
say is UNVERIFIABLE. That is the same shape as the rest of DriftCore: absence
is not success (`EgressPolicy` refuses an empty allowlist; `netns_attestation`
refuses to run unless something else provably isolated it). A PASS here is not
"the property holds under all inputs" — it is "the guard demonstrably said no
to the bad input we handed it, and that is recorded".

THREE OUTCOMES, NOT TWO
-----------------------
  PASS          the guard rejected the canary this run (recorded in `observed`)
  FAIL          the guard ACCEPTED the canary (property is false) -> refuse boot
  UNVERIFIABLE  cannot be demonstrated from inside this process (topology fact)

The UNVERIFIABLE bucket is not a weakness to bury — it IS the deliverable.
"An agent cannot prove from inside itself that it has no route to the network"
is true, and the honest artifact is: here are the assumptions, here is the code
that refuses to boot on any checkable failure, and here is the explicit list we
cannot check from inside — attest those at the platform / hardware layer.

HONEST LIMITS (stated, not hidden)
----------------------------------
* Preflight converts a SILENT assumption into one a deployer must ACTIVELY
  defeat: delete the `run()` call, or write a check that lies about its canary.
  It cannot make an unwilling deployer safe. That is a bounded, real gain, not
  a proof.
* A dishonest check could hardcode `bad_input_rejected=True`. The framework
  enforces the discipline for honestly-written checks (no probe -> no PASS) and
  records what was observed; it does not sandbox check code. Check authors are
  the same trusted party as the deployment.
* PASS is per-run and per-canary. It is evidence the guard fired, not a theorem.

stdlib-only. Opt-in: a deployment calls `run(default_checks())` (or its own
list) at startup. Inert if never called.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Sequence


# ── Outcomes and results ──────────────────────────────────────────


class Outcome(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNVERIFIABLE = "UNVERIFIABLE"


class Category(Enum):
    # The guard can be exercised against a bad input from inside the process.
    CHECKABLE = "checkable"
    # A fact about how the process was launched / what it is connected to.
    # The process cannot honestly assert it about itself.
    DEPLOYMENT_TOPOLOGY = "deployment-topology"


# (self red-team) `category` is declared by the check author, so a check can name itself
# after a topology invariant and declare CHECKABLE to slip past the topology gate — by
# carelessness as easily as by malice. These names are topology facts by definition; a
# check carrying one is treated as DEPLOYMENT_TOPOLOGY no matter what it declares.
TOPOLOGY_INVARIANT_NAMES = frozenset({
    "agent-has-no-network-path",
    "audit-storage-is-worm",
    "actuator-broker-separate-privilege",
    "actuator-manifests-signed",
})


def _effective_category(check) -> "Category":
    name = getattr(check, "name", "")
    if name in TOPOLOGY_INVARIANT_NAMES:
        return Category.DEPLOYMENT_TOPOLOGY
    return getattr(check, "category", Category.CHECKABLE)


@dataclass(frozen=True)
class ProbeResult:
    """What a check reports back from exercising its guard.

    `bad_input_rejected` MUST be computed by actually invoking the real guard
    on a known-bad input — never hardcoded. The framework maps
    rejected -> PASS, accepted -> FAIL. `observed` is a short, legible record
    of what the guard actually did, and is carried into the report so a PASS is
    auditable rather than asserted.
    """
    bad_input_rejected: bool
    observed: str


class Unverifiable(Exception):
    """Raise from a check's exercise() when the property genuinely cannot be
    demonstrated from inside this process. Carries the honest reason and, ideally,
    where it SHOULD be attested instead."""


@dataclass(frozen=True)
class CheckResult:
    name: str
    outcome: Outcome
    category: Category
    detail: str
    observed: str = ""

    def line(self) -> str:
        tag = {
            Outcome.PASS: "PASS        ",
            Outcome.FAIL: "FAIL  <====",
            Outcome.UNVERIFIABLE: "UNVERIFIABLE",
        }[self.outcome]
        extra = f"  [{self.observed}]" if self.observed else ""
        return f"  {tag}  {self.name}\n              {self.detail}{extra}"


# ── The check base class ──────────────────────────────────────────


class PreflightCheck:
    """Base class for a single deployment invariant.

    Subclasses set `name`, `description`, `category`, and implement
    `exercise()`, which either:
      * returns a ProbeResult (the guard was run against a bad input), or
      * raises Unverifiable(reason) (cannot be demonstrated in-process).

    Subclasses do NOT decide their own PASS/FAIL — they report what the guard
    did and the framework decides. A DEPLOYMENT_TOPOLOGY check's exercise()
    must raise Unverifiable unless it was given a live handle it can probe.
    """

    name: str = "unnamed-check"
    description: str = ""
    category: Category = Category.CHECKABLE

    def exercise(self) -> ProbeResult:
        raise NotImplementedError


# ── The report ────────────────────────────────────────────────────


@dataclass
class PreflightReport:
    results: List[CheckResult] = field(default_factory=list)
    context: str = "production"

    @property
    def fails(self) -> List[CheckResult]:
        return [r for r in self.results if r.outcome is Outcome.FAIL]

    @property
    def passed(self) -> List[CheckResult]:
        return [r for r in self.results if r.outcome is Outcome.PASS]

    @property
    def unverifiable(self) -> List[CheckResult]:
        return [r for r in self.results if r.outcome is Outcome.UNVERIFIABLE]

    @property
    def ok(self) -> bool:
        return not self.fails

    def render(self) -> str:
        lines = [
            f"DriftCore preflight — context={self.context}",
            f"  {len(self.passed)} passed  "
            f"{len(self.fails)} failed  "
            f"{len(self.unverifiable)} unverifiable  "
            f"({len(self.results)} checks)",
            "-" * 62,
        ]
        for r in self.results:
            lines.append(r.line())
        lines.append("-" * 62)
        if self.fails:
            lines.append("  RESULT: REFUSE TO START — a deployment invariant is false.")
        else:
            lines.append("  RESULT: boot permitted. UNVERIFIABLE items are ASSUMPTIONS,")
            lines.append("          not results — attest them at the platform/hardware layer.")
        return "\n".join(lines)

    def __str__(self) -> str:
        return self.render()


class PreflightFailed(RuntimeError):
    """Raised by run() when any check FAILs. Carries the full report."""

    def __init__(self, report: PreflightReport):
        self.report = report
        super().__init__(
            f"{len(report.fails)} deployment invariant(s) failed preflight; "
            f"refusing to start.\n" + report.render())


class UnattestedInvariant(RuntimeError):
    """Raised when a MANDATORY invariant was neither demonstrated by a live check nor
    independently attested by the platform.

    (red-team, ChatGPT) UNVERIFIABLE never blocking boot is right for a normal service
    and WRONG for a robot: "we could not determine whether the safety boundary exists"
    must not quietly collapse into "let the arm move". The rule for a physical
    deployment is:

        a mandatory invariant must be PASSed by a live check, or ATTESTED by the
        platform/supervisor — otherwise refuse to enter the operational state.

    This does not weaken the honesty of UNVERIFIABLE; it stops UNVERIFIABLE from being
    read as permission.
    """

    def __init__(self, missing, report: "PreflightReport"):
        self.missing = list(missing)
        self.report = report
        super().__init__(
            "refusing to start: mandatory invariant(s) neither demonstrated nor "
            "attested: " + ", ".join(self.missing) + "\n" + report.render())


class EmptyPreflight(RuntimeError):
    """Raised when run() is called with no checks. An empty preflight that
    'passes' is the same theatre this module exists to prevent (an empty
    allowlist is a refusal, not a permit)."""


# ── The runner ────────────────────────────────────────────────────


def run(checks: Sequence[PreflightCheck], *, context: str = "production",
        raise_on_fail: bool = True,
        allow_unverified_topology: bool = False) -> PreflightReport:
    """Run every check and decide boot.

    Verdict is computed by the framework from what each guard actually did:
      * exercise() raised Unverifiable            -> UNVERIFIABLE
      * exercise() returned ProbeResult(rejected) -> PASS if rejected else FAIL
      * exercise() returned a non-ProbeResult     -> FAIL (cannot self-certify)
      * exercise() raised anything else           -> FAIL (fail-closed)

    Any FAIL raises PreflightFailed (unless raise_on_fail=False, for callers that want
    the report object — e.g. tests). UNVERIFIABLE never blocks boot HERE.

    (red-team, Grok) That last property is correct for a pure software service and
    dangerous for anything that can actuate: a deployer who calls this instead of
    `run_operational` gets the very false assurance this module exists to prevent. So
    when any DEPLOYMENT_TOPOLOGY check comes back UNVERIFIABLE, this refuses rather
    than quietly permitting boot — unless the caller passes
    `allow_unverified_topology=True`, which makes accepting that risk an explicit,
    recorded act instead of an accident. For physical actuation use `run_operational`.
    """
    if not checks:
        raise EmptyPreflight(
            "preflight.run() called with no checks. Refusing: a preflight with "
            "nothing to check cannot certify anything, and reporting 'ok' would "
            "be exactly the false assurance this module exists to prevent.")

    results: List[CheckResult] = []
    for c in checks:
        name = getattr(c, "name", c.__class__.__name__)
        cat = _effective_category(c)
        desc = getattr(c, "description", "")
        try:
            pr = c.exercise()
        except Unverifiable as u:
            results.append(CheckResult(name, Outcome.UNVERIFIABLE, cat,
                                       str(u) or desc))
            continue
        except Exception as e:  # fail-closed: a crashing check is a failing check
            results.append(CheckResult(
                name, Outcome.FAIL, cat,
                f"check raised and is treated as failing (fail-closed): {e!r}"))
            continue

        if not isinstance(pr, ProbeResult):
            # A check that returns something other than a ProbeResult has not
            # demonstrated a rejection, so it cannot pass. This closes the
            # "return a truthy sentinel to look ok" path.
            results.append(CheckResult(
                name, Outcome.FAIL, cat,
                f"check did not return a ProbeResult (got {type(pr).__name__}); "
                f"a PASS requires a demonstrated rejection, so this fails closed"))
            continue

        outcome = Outcome.PASS if pr.bad_input_rejected else Outcome.FAIL
        detail = (desc if outcome is Outcome.PASS
                  else f"{desc} — guard ACCEPTED a known-bad input")
        results.append(CheckResult(name, outcome, cat, detail, pr.observed))

    report = PreflightReport(results=results, context=context)
    if raise_on_fail and report.fails:
        raise PreflightFailed(report)
    if raise_on_fail and not allow_unverified_topology:
        unattested = [r.name for r in report.unverifiable
                      if r.category is Category.DEPLOYMENT_TOPOLOGY]
        if unattested:
            raise UnattestedInvariant(unattested, report)
    return report


def run_operational(checks: Sequence[PreflightCheck], *,
                    mandatory: Sequence[str],
                    attested: Sequence[str] = (),
                    context: str = "production") -> PreflightReport:
    """The boot gate for a PHYSICALLY ACTUATING deployment (Poppy / LifeCore).

    `run()` permits boot when nothing FAILed — correct for a normal service, and wrong
    for a robot, where "9 unverifiable, 0 failed -> BOOT PERMITTED" means the arm moves
    without anyone having established that the safety boundary exists.

    This gate applies the stronger rule:

        every MANDATORY invariant, AND every DEPLOYMENT_TOPOLOGY check present, must be
          * demonstrated PASS by a live check in this run, or
          * named in `attested` — independently attested by the platform/supervisor
        otherwise: refuse to enter the operational state.

    `attested` is the seam where the supervisor asserts the topology facts the process
    honestly cannot (netns isolation, separate-uid broker, WORM storage, signed
    manifests, and the integrity of preflight.py itself). Passing a name here is a
    CLAIM BY THE PLATFORM, recorded as such — the strength of the gate is bounded by
    the honesty of that layer, which is exactly where that trust belongs.

    (self red-team) Three holes found by attacking this function and closed here:
      * It called run(raise_on_fail=False), which SKIPPED run()'s topology gate — so an
        unverified topology check that the operator forgot to list in `mandatory` booted
        a robot silently. `mandatory` was a single point of failure; now every topology
        check present must be PASSed or attested regardless of the list.
      * `mandatory=[]` booted with zero PASSes. An operational gate with nothing
        mandatory certifies nothing, exactly like an empty preflight; now refused.
      * `attested` accepted arbitrary strings, so a typo — or a name for a check that
        was never in the list at all — silently satisfied a mandatory invariant. Names
        are now validated against the checks actually run.
    """
    if not mandatory:
        raise EmptyPreflight(
            "run_operational() called with an empty `mandatory` list. Refusing: an "
            "operational gate with no mandatory invariants certifies nothing, which is "
            "the same false assurance an empty preflight would give. Name the "
            "invariants this deployment's safety case depends on.")

    report = run(checks, context=context, raise_on_fail=False)
    if report.fails:
        raise PreflightFailed(report)

    known = {r.name for r in report.results}
    unknown_attested = [a for a in attested if a not in known]
    if unknown_attested:
        raise UnattestedInvariant(
            [f"{a} (ATTESTED but no such check ran — typo, or attesting a boundary "
             f"nothing exercised)" for a in unknown_attested], report)

    passed = {r.name for r in report.passed}
    claimed = set(attested)
    # every named mandatory invariant, plus every topology fact actually present
    required = list(dict.fromkeys(
        list(mandatory)
        + [r.name for r in report.unverifiable
           if r.category is Category.DEPLOYMENT_TOPOLOGY]))
    missing = [m for m in required if m not in passed and m not in claimed]
    if missing:
        raise UnattestedInvariant(missing, report)
    return report


class InvariantRegressed(RuntimeError):
    """Raised when a property that PASSed at boot no longer holds."""

    def __init__(self, regressed, report: "PreflightReport"):
        self.regressed = list(regressed)
        self.report = report
        super().__init__(
            "invariant(s) that PASSed at boot no longer hold: "
            + ", ".join(self.regressed) + "\n" + report.render())


def reverify(checks: Sequence[PreflightCheck], baseline: PreflightReport, *,
             context: str = "reverify") -> PreflightReport:
    """Re-run the canaries and refuse if anything that PASSed at boot has regressed.

    (self red-team) Preflight is a BOOT-TIME snapshot, and nothing stopped a property
    from being switched off immediately afterwards. Demonstrated concretely: run the
    human-auth check (PASS), then `set_verifier(None)`, and the process is back in
    LABEL_ONLY with a bare string accepted as human — while the boot report still says
    PASS. A snapshot is not a guarantee about the moment the arm actually moves.

    This does not freeze anything (a library cannot stop another module from mutating
    process state). It makes the regression DETECTABLE: call it before entering the
    operational state, on a timer, or immediately before a consequential actuation, and
    a downgrade becomes a refusal instead of a silent capability gain.

    Raises InvariantRegressed if any invariant that PASSed in `baseline` now does not.
    """
    was_passing = {r.name for r in baseline.passed}
    report = run(checks, context=context, raise_on_fail=False,
                 allow_unverified_topology=True)
    now_passing = {r.name for r in report.passed}
    regressed = sorted(n for n in was_passing if n not in now_passing)
    if regressed:
        raise InvariantRegressed(regressed, report)
    return report


# ══════════════════════════════════════════════════════════════════
#  Shipped checks
# ══════════════════════════════════════════════════════════════════


class HumanAuthorizationIsReal(PreflightCheck):
    """The human-authorization boundary must actually reject non-humans.

    Strictly stronger than `require_secure_mode()`: that checks the mode STRING
    (ATTESTED/REGISTERED/LABEL_ONLY). This checks the BEHAVIOUR — a deployment
    can be in ATTESTED mode with a buggy or stubbed verifier that accepts a
    forged signature (`lambda: True`), and mode() still says "secure". Two
    canaries, both via the public `is_human`:

      1. a bare string ("justin") must NOT be accepted as human, and
      2. a HumanAttestation signed with the WRONG key must NOT be accepted.

    A real verifier rejects both; LABEL_ONLY accepts (1); a stub verifier
    accepts (2). Never mutates policy.
    """

    name = "human-authorization-is-real"
    description = ("a bare string and a wrong-key attestation are both refused "
                   "by is_human (real verifier behaviour, not just mode string)")
    category = Category.CHECKABLE

    ACTION = "preflight::human-auth-canary"
    # (cold pass 2026-08-15 — REPRODUCED.) The bare-string canary was the literal
    # name "justin". In REGISTERED mode `is_human(name)` is True for any REGISTERED
    # principal, so a deployment that registered a human called Justin failed its own
    # identity check — verified: principal "alice" -> rejected=True, principal
    # "justin" -> rejected=False, same code, same mode. The canary has to be a name
    # no real deployment would ever register, or the check measures the roster
    # instead of the boundary.
    BARE_CANARY = "preflight::bare-string-canary-never-a-real-principal"
    WRONG_KEY = b"attacker-key-that-was-never-registered"
    PROBE_KEY = b"preflight-probe-key-registered-only-for-this-check"
    PROBE_PRINCIPAL = "preflight::probe-principal"

    def exercise(self) -> ProbeResult:
        try:
            from driftcore.authority import human_identity as H
        except Exception as e:
            raise Unverifiable(
                f"human_identity unavailable, cannot exercise the authorization "
                f"boundary: {e!r}")

        bare_accepted = bool(H.is_human(self.BARE_CANARY, action=self.ACTION))

        forged = H.HumanAttestation.issue(
            self.WRONG_KEY, principal=self.BARE_CANARY, action=self.ACTION,
            ttl_seconds=60, nonce="preflight-canary-nonce")
        forged_accepted = bool(H.is_human(forged, action=self.ACTION))

        # (red-team, ChatGPT) POSITIVE CONTROL. Negative canaries alone certify a
        # system that rejects EVERYBODY — `is_human = lambda *a, **k: False` passes
        # both rejections while being useless as an authorization system. So the
        # boundary must also be shown to ACCEPT a validly-attested human. Probed with
        # a throwaway principal+key registered only for this check, so it never needs
        # a real human credential and grants no real authority.
        positive_accepted = None
        verifier = getattr(H, "_verifier", None)   # the installed verifier
        try:
            if verifier is not None and hasattr(verifier, "register_principal"):
                verifier.register_principal(self.PROBE_PRINCIPAL, self.PROBE_KEY)
                good = H.HumanAttestation.issue(
                    self.PROBE_KEY, principal=self.PROBE_PRINCIPAL, action=self.ACTION,
                    ttl_seconds=60, nonce="preflight-positive-" + uuid.uuid4().hex)
                positive_accepted = bool(H.is_human(good, action=self.ACTION))
        except Exception:
            positive_accepted = None   # could not run the positive control
        finally:
            # (red-team, Grok) The probe principal must not outlive the check, or a
            # later real request under that name could be accepted. Best-effort removal
            # through whatever the verifier exposes.
            try:
                if verifier is not None:
                    for remover in ("revoke_principal", "remove_principal",
                                    "unregister_principal"):
                        if hasattr(verifier, remover):
                            getattr(verifier, remover)(self.PROBE_PRINCIPAL)
                            break
                    else:
                        reg = getattr(verifier, "_principals", None)
                        if isinstance(reg, dict):
                            reg.pop(self.PROBE_PRINCIPAL, None)
            except Exception:
                pass

        mode = H.mode()
        rejected = (not bare_accepted) and (not forged_accepted)
        if rejected and positive_accepted is False:
            raise Unverifiable(
                f"both bad inputs were refused, but a VALIDLY-attested human was also "
                f"refused (mode={mode}). A boundary that rejects everyone is not a "
                f"working authorization system, so this cannot PASS — check the "
                f"verifier's configuration.")
        if rejected and positive_accepted is None and verifier is not None:
            # (red-team, Grok) A skipped positive control must not silently become a
            # PASS: a reject-everything stub without register_principal would otherwise
            # sail through on the two negative canaries alone.
            raise Unverifiable(
                f"both bad inputs were refused, but the POSITIVE control could not be "
                f"run (mode={mode}; the verifier exposes no register_principal, or the "
                f"probe failed). Negative canaries alone cannot distinguish a working "
                f"boundary from one that rejects everybody.")
        return ProbeResult(
            bad_input_rejected=rejected,
            observed=(f"mode={mode} bare_string_accepted={bare_accepted} "
                      f"wrong_key_attestation_accepted={forged_accepted} "
                      f"valid_human_accepted={positive_accepted}"))


class ConstitutionIsIntegrityPinned(PreflightCheck):
    """The Constitution's text is inside the TCB (THREAT_BOUNDARIES §7): swap it
    and the code's guarantees mean nothing. If the deployment pins the sha256 of
    the reviewed CONSTITUTION.md, preflight confirms the on-disk file matches AND
    demonstrates in-run that the comparator rejects a mutated artifact. Unpinned
    -> UNVERIFIABLE (there is nothing to compare against).
    """

    name = "constitution-integrity-pinned"
    description = "on-disk constitution matches the human-pinned digest"
    category = Category.CHECKABLE

    def __init__(self, expected_sha256: Optional[str] = None,
                 path: str = "CONSTITUTION.md"):
        self.expected = expected_sha256.lower().strip() if expected_sha256 else None
        self.path = path

    def exercise(self) -> ProbeResult:
        if not self.expected:
            raise Unverifiable(
                "no constitution digest pinned. Pin sha256(CONSTITUTION.md) at "
                "deploy time so a swapped constitution is caught — unpinned, the "
                "TCB's own text is unprotected (THREAT_BOUNDARIES §7).")
        p = Path(self.path)
        if not p.is_file():
            raise Unverifiable(
                f"pinned digest given but {self.path} not found from cwd "
                f"{os.getcwd()!r}; cannot compare.")
        data = p.read_bytes()
        actual = hashlib.sha256(data).hexdigest()

        # In-run demonstration that the comparator rejects a changed artifact:
        # any perturbation of the bytes must produce a different digest.
        mutated = hashlib.sha256(data + b"\x00").hexdigest()
        comparator_rejects_mutation = (mutated != self.expected)
        matches_pin = (actual == self.expected)

        rejected = comparator_rejects_mutation and matches_pin
        return ProbeResult(
            bad_input_rejected=rejected,
            observed=(f"matches_pin={matches_pin} "
                      f"comparator_rejects_mutation={comparator_rejects_mutation} "
                      f"actual={actual[:12]}… pinned={self.expected[:12]}…"))


class AuditChainIsTamperEvident(PreflightCheck):
    """The audit chain must DETECT a modified entry (verify_chain -> False).

    Demonstrates tamper-EVIDENCE only. Tamper-RESISTANCE (true append-only /
    WORM) is a separate, deployment-topology property — see
    WormStorageIsAppendOnly. Runs in a SUBPROCESS with a temp working dir so it
    cannot flip the live module's compromised-flag, fire enforcement shutdown
    hooks, or write to the real logs/. If a subprocess cannot be spawned, the
    property was not demonstrated -> UNVERIFIABLE (not FAIL: we did not see the
    guard accept bad input, we simply could not test).
    """

    name = "audit-chain-is-tamper-evident"
    description = "verify_chain() returns False on a modified entry"
    category = Category.CHECKABLE

    _PROBE = r"""
import json, os, sys
import driftcore.audit as A
# Neuter the enforcement shutdown hook so a detection cannot exit the process
# before we report; we only care about verify_chain()'s return value here.
try:
    import driftcore.enforcement as E
    E._execute_shutdown = lambda **k: None
except Exception:
    pass
A.record("preflight-canary", "entry one")
A.record("preflight-canary", "entry two")
with open(A.CHAIN_FILE) as f:
    lines = f.readlines()
obj = json.loads(lines[0])
obj["memory_text"] = "TAMPERED-BY-PREFLIGHT-CANARY"   # change content, not the stored hash
lines[0] = json.dumps(obj) + "\n"
with open(A.CHAIN_FILE, "w") as f:
    f.writelines(lines)
detected = (A.verify_chain() is False)
print("PREFLIGHT_CANARY_RESULT=" + json.dumps({"detected": bool(detected)}))
"""

    def exercise(self) -> ProbeResult:
        repo_root = Path(__file__).resolve().parents[2]
        env = dict(os.environ)
        env["PYTHONPATH"] = str(repo_root) + os.pathsep + env.get("PYTHONPATH", "")
        try:
            with tempfile.TemporaryDirectory() as tmp:
                proc = subprocess.run(
                    [sys.executable, "-c", self._PROBE],
                    cwd=tmp, env=env, capture_output=True, text=True, timeout=60)
        except Exception as e:
            raise Unverifiable(
                f"could not spawn the audit canary subprocess: {e!r}. In a "
                f"deployment that forbids subprocesses, attest audit integrity "
                f"out of band.")

        marker = None
        for ln in proc.stdout.splitlines():
            if ln.startswith("PREFLIGHT_CANARY_RESULT="):
                marker = ln[len("PREFLIGHT_CANARY_RESULT="):]
        if marker is None:
            raise Unverifiable(
                "audit canary produced no result marker (exit "
                f"{proc.returncode}); treating as not-demonstrated. "
                f"stderr-tail: {proc.stderr.strip()[-200:]!r}")
        detected = bool(json.loads(marker).get("detected"))
        return ProbeResult(
            bad_input_rejected=detected,
            observed=f"verify_chain_detected_tamper={detected}")


# ── Deployment-topology checks (honest UNVERIFIABLE by default) ────


class NetworkPathIsSevered(PreflightCheck):
    name = "agent-has-no-network-path"
    description = ("the agent process has no route to the network "
                   "(the network IS the actuator for a software agent)")
    category = Category.DEPLOYMENT_TOPOLOGY

    def exercise(self) -> ProbeResult:
        raise Unverifiable(
            "an agent cannot prove from inside itself that it has no route to "
            "the network — a socket it cannot see is exactly the gap. Enforce "
            "BELOW the agent (separate netns; the broker holds the only socket) "
            "and attest at the supervisor via kernel/netns_attestation "
            "(attest_or_raise). Recorded as an assumption, not a result.")


class WormStorageIsAppendOnly(PreflightCheck):
    name = "audit-storage-is-worm"
    description = "audit log lives on storage the process cannot rewrite"
    category = Category.DEPLOYMENT_TOPOLOGY

    def exercise(self) -> ProbeResult:
        raise Unverifiable(
            "tamper-EVIDENCE is checkable (see audit-chain-is-tamper-evident); "
            "tamper-RESISTANCE is not from inside the process — anything that "
            "can open its own log 'a' can open it 'w'. Mount append-only/WORM "
            "storage or ship entries to an external log service, and attest at "
            "the platform layer.")


class ActuatorBrokerHasSeparatePrivilege(PreflightCheck):
    name = "actuator-broker-separate-privilege"
    description = "actuator broker runs as a different uid than the agent"
    category = Category.DEPLOYMENT_TOPOLOGY

    def exercise(self) -> ProbeResult:
        raise Unverifiable(
            "whether the broker runs as a different uid is a property of how it "
            "was launched, not something the agent can assert about itself. "
            "Where a live broker socket is available, peer-credential comparison "
            "(SO_PEERCRED) can upgrade this to checkable; by default it is an "
            "assumption. See mediated_actuation (socket_group / opt-in peer-uid).")


class ActuatorManifestsAreSigned(PreflightCheck):
    name = "actuator-manifests-signed"
    description = "every Tier-1 actuator manifest is signed by a trusted key"
    category = Category.DEPLOYMENT_TOPOLOGY

    def exercise(self) -> ProbeResult:
        raise Unverifiable(
            "manifest signatures are verifiable only against the specific "
            "manifests and the trusted key set a deployment ships; with none "
            "supplied there is nothing to exercise. Provide them (and the key) "
            "to make this checkable — enforcement requires all Tier-1 items "
            "signed.")


class ActuationEffectGatingActive(PreflightCheck):
    """`enforce_effects` must be ON for any broker that can physically actuate.
    It defaults OFF (mediated_actuation, line ~298), and with it off an actuator whose
    effects a human never declared registers fine and can fire — the fail-OPEN hole
    every recent external review named as the top residual.

    Canary: build the deployment's broker and try to register an actuator that declares
    NO effects. A correctly-configured broker (`enforce_effects=True`) REFUSES it; a
    misconfigured one accepts it. Supply `broker_factory` — a callable returning an
    UNSTARTED broker built exactly as the deployment builds it (same verifier, same
    `enforce_effects`). Registration is exercised with no socket bound and no thread
    started, so the check has no side effects. No factory -> UNVERIFIABLE.
    """

    name = "actuation-effect-gating-active"
    description = ("the actuation broker refuses an actuator that declares no effects "
                   "(enforce_effects is on)")
    category = Category.CHECKABLE

    def __init__(self, broker_factory=None):
        self.broker_factory = broker_factory

    def exercise(self) -> ProbeResult:
        if self.broker_factory is None:
            raise Unverifiable(
                "no broker_factory supplied. enforce_effects defaults OFF; supply a "
                "callable returning an unstarted broker built as your deployment builds "
                "it, and this refuses to boot if an undeclared actuator would fail open.")
        try:
            broker = self.broker_factory()
        except Exception as e:
            raise Unverifiable(
                f"broker_factory raised before a broker existed ({type(e).__name__}: "
                f"{str(e)[:60]}); the effect gate was never exercised.")
        try:
            broker.register_actuator(
                "preflight::undeclared-effect-canary", lambda **k: None,
                required_scope=("preflight:probe",))
        except Exception as e:
            # (red-team, ChatGPT) An earlier version returned PASS on ANY exception.
            # A broker raising RuntimeError('database exploded') was therefore certified
            # as "undeclared actuator refused" though the effect gate never ran — the
            # framework's own no-theatre rule, violated. A PASS now requires the gate's
            # OWN refusal signature; anything else is UNVERIFIABLE, never PASS.
            msg = str(e)
            gate_refusal = ("enforce_effects is on" in msg
                            and "must declare its effects" in msg)
            if gate_refusal:
                return ProbeResult(
                    bad_input_rejected=True,
                    observed=f"effect gate refused the canary: {type(e).__name__}: {msg[:60]}")
            raise Unverifiable(
                f"registration failed, but NOT with the effect gate's refusal "
                f"({type(e).__name__}: {msg[:70]}). Something stopped it — that is not "
                f"evidence the effect gate stopped it, so this cannot PASS.")
        # it accepted the undeclared actuator -> the fail-open hole is present
        return ProbeResult(
            bad_input_rejected=False,
            observed="undeclared actuator ACCEPTED — enforce_effects is OFF (fail-open)")


class ReplayDefenseSurvivesRestart(PreflightCheck):
    """The grant-nonce store must survive a broker restart. Burned nonces live in the
    verifier's in-memory `_used` set; a restart with a fresh verifier forgets which
    nonces were spent, reopening a replay window across restarts (mediated_actuation's
    own note; demonstrated in test_bypass_resistance §6). The fix is to back the
    verifier's `used_nonces=` with a durable, shared store.

    Canary: from the deployment's `verifier_factory`, build a verifier, burn a probe
    nonce (via the real reserve/commit path, under a throwaway probe key registered only
    for this check), then build a SECOND verifier (the 'restart') from the same factory
    and replay the same grant. A durable store REFUSES it (PermissionReplay); a fresh
    in-memory set accepts it (the window). Supply `verifier_factory`. No factory ->
    UNVERIFIABLE. (Single long-lived broker with no restarts: this residual does not
    apply, but wiring the durable store makes it a non-question.)
    """

    name = "replay-defense-survives-restart"
    description = ("a spent grant nonce is still refused after the verifier that burned "
                   "it has been destroyed (durable nonce store)")
    category = Category.CHECKABLE

    _PROBE_KEY = "preflight::nonce-probe-key"
    _PROBE_SECRET = "preflight::nonce-probe-secret"

    def __init__(self, verifier_factory=None, factory_spec: Optional[str] = None):
        self.verifier_factory = verifier_factory
        # (red-team, Grok) An in-process check cannot demonstrate survival across
        # PROCESS DEATH — two factory calls only prove survival across object
        # reconstruction. `factory_spec` ("package.module:callable") names an
        # IMPORTABLE zero-arg factory, letting the check burn a nonce in one
        # interpreter, let it die, and replay from a second. That is the real property.
        self.factory_spec = factory_spec

    def _cross_process(self, spec: str) -> ProbeResult:
        """Burn a nonce in one process, let it exit, replay from a fresh one."""
        probe = (
            "import importlib, sys, json\n"
            "cfg = json.loads(sys.stdin.read())\n"   # secrets via stdin, never argv
            "mod, fn = cfg['spec'].split(':')\n"
            "v = getattr(importlib.import_module(mod), fn)()\n"
            "from driftcore.verification.signed_permission import "
            "Grant, PermissionVerifier, PermissionReplay\n"
            "bind = PermissionVerifier.bind_action('preflight::probe-actuator','probe',{})\n"
            "g = Grant.issue(cfg['secret'], key_id=cfg['key'], role='operator',\n"
            "                scope=('preflight:probe',), subject='preflight',\n"
            "                ttl_seconds=300, nonce=cfg['nonce'], action_binding=bind)\n"
            "v.register_key(cfg['key'], cfg['secret'], may_sign=('preflight:probe',))\n"
            "if cfg['phase'] == 'burn':\n"
            "    v.reserve(g, required_scope=('preflight:probe',), "
            "action_binding=bind)\n"
            "    v.commit(g)\n"
            "    print('PREFLIGHT_RESULT=' + json.dumps({'ok': True}))\n"
            "else:\n"
            "    try:\n"
            "        v.verify(g, required_scope=('preflight:probe',), "
            "action_binding=bind)\n"
            "        print('PREFLIGHT_RESULT=' + json.dumps({'replayed': True}))\n"
            "    except PermissionReplay:\n"
            "        print('PREFLIGHT_RESULT=' + json.dumps({'replayed': False}))\n")
        nonce = "preflight::xproc::" + uuid.uuid4().hex
        env = dict(os.environ)
        env["PYTHONPATH"] = os.getcwd() + os.pathsep + env.get("PYTHONPATH", "")

        def _run(phase):
            # (self red-team) The probe secret used to be passed as an ARGV element,
            # which is world-readable via `ps` / /proc/<pid>/cmdline. It is a throwaway
            # key, but the pattern is catastrophic if copied for a real one — so it goes
            # over stdin.
            payload = json.dumps({"spec": spec, "phase": phase, "nonce": nonce,
                                  "secret": self._PROBE_SECRET, "key": self._PROBE_KEY})
            p = subprocess.run(
                [sys.executable, "-c", probe], input=payload,
                capture_output=True, text=True, timeout=60, env=env)
            for ln in p.stdout.splitlines():
                if ln.startswith("PREFLIGHT_RESULT="):
                    return json.loads(ln[len("PREFLIGHT_RESULT="):])
            raise Unverifiable(
                f"cross-process replay probe ({phase}) produced no result "
                f"(exit {p.returncode}); stderr-tail: {p.stderr.strip()[-160:]!r}")

        if not _run("burn").get("ok"):
            raise Unverifiable("cross-process probe could not burn the canary nonce.")
        replayed = _run("replay").get("replayed")
        if replayed is None:
            raise Unverifiable("cross-process replay probe returned no verdict.")
        return ProbeResult(
            bad_input_rejected=(replayed is False),
            observed=("replay refused by a SEPARATE PROCESS after the burning process "
                      "exited — true restart survival"
                      if replayed is False else
                      "replay ACCEPTED by a fresh process — nonce store is NOT durable "
                      "across process death"))

    def exercise(self) -> ProbeResult:
        if self.factory_spec:
            return self._cross_process(self.factory_spec)
        if self.verifier_factory is None:
            raise Unverifiable(
                "no verifier_factory supplied. The nonce set is in-memory by default; "
                "supply a callable returning your PermissionVerifier (ideally with "
                "used_nonces= backed by a durable store), and this refuses to boot if a "
                "spent nonce would replay across a restart.")
        from driftcore.verification.signed_permission import (
            Grant, PermissionVerifier, PermissionReplay)

        bind = PermissionVerifier.bind_action(
            "preflight::probe-actuator", "probe", {})
        # Unique per invocation, so running preflight repeatedly against a persistent
        # nonce store does not collide with a nonce a prior run already burned.
        probe_grant = Grant.issue(
            self._PROBE_SECRET, key_id=self._PROBE_KEY, role="operator",
            scope=("preflight:probe",), subject="preflight", ttl_seconds=300,
            nonce="preflight::restart-replay-canary::" + uuid.uuid4().hex,
            action_binding=bind)

        # burn the nonce in the first verifier (the pre-restart use)
        try:
            v1 = self.verifier_factory()
            v1.register_key(self._PROBE_KEY, self._PROBE_SECRET,
                             may_sign=("preflight:probe",))
            v1.reserve(probe_grant, required_scope=("preflight:probe",),
                       action_binding=bind)
            v1.commit(probe_grant)
        except Exception as e:
            raise Unverifiable(
                f"could not exercise the nonce path on the supplied verifier "
                f"({type(e).__name__}: {str(e)[:60]}); cannot conclude.")

        # 'restart': a second verifier from the same factory replays the same grant
        try:
            v2 = self.verifier_factory()
        except Exception as e:
            raise Unverifiable(
                f"verifier_factory raised on the second call ({type(e).__name__}: "
                f"{str(e)[:60]}); restart survival was not demonstrated.")

        # (red-team, ChatGPT) A factory returning the SAME object is not a restart: the
        # replay is refused by the still-live in-memory set, and an earlier version
        # certified that as "durable nonce store" with no durable storage at all.
        if v2 is v1:
            raise Unverifiable(
                "verifier_factory returned the SAME verifier instance twice. The nonce "
                "would be refused by the still-live in-memory set, which demonstrates "
                "nothing about surviving a restart. Return a freshly-constructed "
                "verifier whose spent-nonce state is reloaded from durable storage.")
        # A distinct object can still share one in-memory set (used_nonces=shared_set):
        # that survives object reconstruction but NOT process death. Detect it and say so.
        shares_live_set = False
        try:
            shares_live_set = (getattr(v2, "_used", None) is getattr(v1, "_used", object()))
        except Exception:
            pass

        try:
            v2.register_key(self._PROBE_KEY, self._PROBE_SECRET,
                             may_sign=("preflight:probe",))
            v2.verify(probe_grant, required_scope=("preflight:probe",),
                      action_binding=bind)
        except PermissionReplay:
            if shares_live_set:
                raise Unverifiable(
                    "the replay was refused, but both verifiers share ONE LIVE in-memory "
                    "nonce set — that survives reconstruction, not process death. Back "
                    "used_nonces with storage that is reloaded on start (and see "
                    "test_bypass_resistance §6) to make this a real PASS.")
            return ProbeResult(
                bad_input_rejected=True,
                observed=("replay refused by a freshly-constructed verifier with an "
                          "independent nonce store (PermissionReplay) — IN-PROCESS: "
                          "demonstrates survival across RECONSTRUCTION, not process "
                          "death; pass factory_spec='mod:callable' for the real test"))
        except Exception as e:
            raise Unverifiable(
                f"restart-replay probe hit an unexpected error ({type(e).__name__}: "
                f"{str(e)[:60]}); cannot conclude.")
        # the second verifier ACCEPTED the spent nonce -> the window is open
        return ProbeResult(
            bad_input_rejected=False,
            observed="replay ACCEPTED across restart — in-memory nonce set, window open")


# ── Convenience ───────────────────────────────────────────────────


class IdentityModeIsSecure(PreflightCheck):
    """The single pathway every human gate depends on must not be a word list.

    `human_identity.is_human` is the one permitted interface behind 45 call sites in
    19 modules — the halt release, the media-retention loosening, the intent ledger's
    entire write surface, the actuation broker's approval gate. In the DEFAULT
    LABEL_ONLY mode it answers from a short denylist: `is_human("agent2")` is True.

    That is the Hugging Face shape (July 2026): a constrained, PERMITTED interface
    whose failure mode lands outside the security boundary. There the interface was a
    package proxy and it took a zero-day. Here it takes no exploit at all — it is the
    documented default.

    `require_secure_mode()` has existed in human_identity for a while and NOTHING in
    the deployment path called it. A control nobody uses is a control nobody has, so
    this is the call site.

    Complementary to `human-authorization-is-real`, not a duplicate, and NEITHER IS
    SUFFICIENT ALONE:
      * this check asserts the MODE a deployment declared it needs, and catches
        LABEL_ONLY — where every human gate in the system is a word list;
      * that check probes the BEHAVIOUR behind the mode with a wrong-key attestation,
        and catches a stubbed verifier that reports ATTESTED and accepts anything,
        which this check provably does not (see the canary comment below).

    Policy-driven. A deployment that has not stated a requirement gets UNVERIFIABLE,
    never PASS — a check that fails every development install is a check that gets
    switched off, which is worse than no check.
    """

    name = "identity-mode-is-secure"
    description = ("human identity is established by registered principals or "
                   "attestations, not by comparing a name against a word list")
    category = Category.CHECKABLE

    def __init__(self, required_mode: Optional[str] = None):
        self.required_mode = required_mode

    def exercise(self) -> ProbeResult:
        try:
            from driftcore.authority import human_identity as H
        except Exception as e:
            raise Unverifiable(f"human_identity unavailable: {e!r}")

        mode = H.mode()
        # A bare agent-shaped string. This catches LABEL_ONLY, where it is accepted.
        #
        # WHAT IT DOES NOT CATCH, and the docstring said it did until this was
        # exercised: a STUBBED verifier. In ATTESTED mode a bare string is refused by
        # the shape check before any verifier is consulted, so a verifier that accepts
        # every forged attestation still passes this canary. Detecting that needs a
        # WRONG-KEY attestation, which is `human-authorization-is-real`'s job. The two
        # checks are complementary and neither is sufficient alone — this one asserts
        # the mode a deployment declared, that one probes the behaviour behind it.
        agentish = bool(H.is_human("agent2", action="preflight::mode-canary"))

        if self.required_mode is None:
            raise Unverifiable(
                f"this deployment has not declared a required identity mode "
                f"(currently {mode}; is_human('agent2') -> {agentish}). In "
                f"LABEL_ONLY every human gate in the system is a word list. Pass "
                f"required_mode='ATTESTED' (or 'REGISTERED') to make this a "
                f"boot-blocking invariant instead of an assumption.")

        wanted = str(self.required_mode).upper()
        if wanted not in ("ATTESTED", "REGISTERED"):
            raise Unverifiable(
                f"required_mode={self.required_mode!r} is not a mode that secures "
                f"anything; expected 'ATTESTED' or 'REGISTERED'.")

        ok = (mode == wanted) or (wanted == "REGISTERED" and mode == "ATTESTED")
        if not ok:
            return ProbeResult(
                bad_input_rejected=False,
                observed=(f"policy requires {wanted} and the running mode is {mode}; "
                          f"is_human('agent2') -> {agentish}"))
        if agentish:
            return ProbeResult(
                bad_input_rejected=False,
                observed=(f"mode reports {mode} but the boundary ACCEPTED the "
                          f"bare string 'agent2' — the mode string is not the "
                          f"boundary"))
        return ProbeResult(
            bad_input_rejected=True,
            observed=f"mode={mode} and a bare agent-shaped string was refused")


class HumanApprovalGateInstalled(PreflightCheck):
    """A broker that can physically actuate must not be deployable without the
    human approval gate.

    (red-team, ChatGPT 2026-08-14.) The library keeps `human_approval=None` working
    so existing deployments are untouched — correct for compatibility, and a route
    straight around the new safety property. This is the same shape as the earlier
    interlock finding: SafeHalt was correct, mediated_actuation was correct, and the
    system was unsafe because nothing joined them. Library compatibility and safe
    deployment are different claims, and only the second one belongs in a safety case.

    Canary: build the deployment's broker and hand it a request carrying a bare-label
    attestation. A gated broker refuses (no gate would ignore the field, or accept a
    string as a human). No factory -> UNVERIFIABLE, never PASS.
    """

    name = "human-approval-gate-installed"
    description = ("the actuation broker requires a human attestation bound to the "
                   "exact effect, so a signing key alone cannot authorise an action")
    category = Category.CHECKABLE

    def __init__(self, broker_factory=None, require_human_approval: bool = False):
        self.broker_factory = broker_factory
        self.require_human_approval = bool(require_human_approval)

    def exercise(self) -> ProbeResult:
        if self.broker_factory is None:
            raise Unverifiable(
                "no broker_factory supplied. human_approval defaults to None, which "
                "means a grant signed with the operator key is treated as an approved "
                "action — supply a callable returning an unstarted broker built as "
                "your deployment builds it.")
        try:
            broker = self.broker_factory()
        except Exception as e:
            raise Unverifiable(
                f"broker_factory raised before a broker existed ({type(e).__name__}: "
                f"{str(e)[:60]}); the human gate was never exercised.")
        gate = getattr(broker, "_human_approval", None)
        if gate is None:
            # Absence is only a FAILURE against a policy that says human approval is
            # mandatory. Asserting it unconditionally would fail every deployment
            # predating the gate, and a check that always fails gets switched off —
            # which is worse than no check. Unstated is UNVERIFIABLE, never PASS.
            if not self.require_human_approval:
                raise Unverifiable(
                    "this broker has no HumanApprovalGate, so a valid operator-key "
                    "grant authorises actuation with no human approval in the chain. "
                    "That may be intended. If your deployment requires human "
                    "authorization for physical actuation, pass "
                    "require_human_approval=True and this becomes a boot-blocking "
                    "invariant instead of an assumption.")
            return ProbeResult(
                bad_input_rejected=False,
                observed="policy requires human approval and the broker has no "
                         "HumanApprovalGate: a valid operator-key grant authorises "
                         "actuation with no human approval anywhere in the chain")
        try:
            gate.pair_digest("justin")   # a bare label is the canonical bad input
        except Exception as e:
            return ProbeResult(
                bad_input_rejected=True,
                observed=f"gate refused a bare-label attestation: "
                         f"{type(e).__name__}: {str(e)[:60]}")
        return ProbeResult(
            bad_input_rejected=False,
            observed="the installed gate ACCEPTED a bare string as a human approval")


class InstrumentedChannelsHaveCeilings(PreflightCheck):
    """Every channel the amplification guard watches must have a declared ceiling.

    `amplification_guard` has two independent mechanisms, and they cover DIFFERENT
    attacks:

      * the TRAJECTORY check catches growth across successive observations — "make
        each correction slightly larger than the last";
      * the CEILING catches magnitude that arrives all at once.

    A self-referential rule — "every time you emit X, emit another X" — diverges
    INSIDE a single generation, so the guard is handed one finished magnitude and
    never gets a second data point to compare. Verified: one observation of 1,000,000
    on a channel with no ceiling is permitted; the same observation against a
    declared ceiling of 500 is refused immediately.

    So the ceiling is not the fallback and the trajectory check is not the primary.
    Read the guard's own refusal text and it says so: an unbounded trajectory is
    refused BECAUSE no ceiling is declared. That refusal is the guard reporting a
    missing bound, not substituting for one.

    Policy-driven, like every other check here. A deployment that has not said it
    runs physical channels gets UNVERIFIABLE, never PASS — a check that fails every
    development install is a check that gets switched off.
    """

    name = "instrumented-channels-have-ceilings"
    description = ("every channel watched for amplification has a human-declared "
                   "ceiling, so a magnitude arriving all at once is bounded")
    category = Category.CHECKABLE

    def __init__(self, guard_factory=None, required_channels: Sequence[str] = ()):
        self.guard_factory = guard_factory
        self.required_channels = tuple(required_channels)

    def exercise(self) -> ProbeResult:
        if self.guard_factory is None:
            raise Unverifiable(
                "no guard_factory supplied. A channel with no ceiling is bounded only "
                "against growth it can OBSERVE over time; a magnitude that arrives in "
                "one step passes. Supply a callable returning the deployment's "
                "AmplificationGuard to make this checkable.")
        if not self.required_channels:
            raise Unverifiable(
                "this deployment has not declared which channels are physically "
                "consequential, so there is nothing to require a ceiling for. Pass "
                "required_channels=(...) to make this a boot-blocking invariant.")
        try:
            guard = self.guard_factory()
        except Exception as e:
            raise Unverifiable(
                f"guard_factory raised before a guard existed ({type(e).__name__}: "
                f"{str(e)[:60]}); no ceiling was checked.")

        missing = []
        for ch in self.required_channels:
            try:
                if guard.ceiling_for(ch) is None:
                    missing.append(ch)
            except Exception as e:
                # A guard that cannot answer is not a guard that answered "yes".
                missing.append(f"{ch} (unreadable: {type(e).__name__})")
        if missing:
            return ProbeResult(
                bad_input_rejected=False,
                observed=(f"no declared ceiling for {sorted(missing)}; a magnitude "
                          f"arriving in a single step on these channels is bounded "
                          f"by nothing"))

        # Behavioural canary: the ceiling must actually refuse, not merely exist.
        ch0 = self.required_channels[0]
        try:
            limit = guard.ceiling_for(ch0).limit
            probe = guard.observe(ch0, limit * 1e6 + 1.0)
            refused = not probe.permitted
        except Exception as e:
            raise Unverifiable(
                f"could not exercise the ceiling on {ch0!r} ({type(e).__name__}: "
                f"{str(e)[:60]}).")
        return ProbeResult(
            bad_input_rejected=refused,
            observed=(f"all {len(self.required_channels)} channel(s) bounded; "
                      f"{ch0!r} refused a single observation far above its ceiling"
                      if refused else
                      f"{ch0!r} has a declared ceiling and ACCEPTED a magnitude far "
                      f"above it — the bound is recorded but not enforced"))


def default_checks(*, constitution_sha256: Optional[str] = None,
                    constitution_path: str = "CONSTITUTION.md",
                    broker_factory=None, verifier_factory=None,
                    require_human_approval: bool = False,
                    required_identity_mode: Optional[str] = None,
                    guard_factory=None,
                    required_channels: Sequence[str] = ()
                    ) -> List[PreflightCheck]:
    """The standard DriftCore deployment invariants. Supply the optionals to move
    checks from UNVERIFIABLE to real: the constitution digest, a broker_factory
    (effect-gating), and a verifier_factory (restart replay defense)."""
    return [
        HumanAuthorizationIsReal(),
        ConstitutionIsIntegrityPinned(constitution_sha256, constitution_path),
        AuditChainIsTamperEvident(),
        ActuationEffectGatingActive(broker_factory),
        HumanApprovalGateInstalled(broker_factory, require_human_approval),
        IdentityModeIsSecure(required_identity_mode),
        InstrumentedChannelsHaveCeilings(guard_factory, required_channels),
        ReplayDefenseSurvivesRestart(verifier_factory),
        NetworkPathIsSevered(),
        WormStorageIsAppendOnly(),
        ActuatorBrokerHasSeparatePrivilege(),
        ActuatorManifestsAreSigned(),
    ]


def run_default(*, context: str = "production",
                constitution_sha256: Optional[str] = None,
                constitution_path: str = "CONSTITUTION.md",
                broker_factory=None, verifier_factory=None,
                require_human_approval: bool = False,
                required_identity_mode: Optional[str] = None,
                guard_factory=None,
                required_channels: Sequence[str] = (),
                allow_unverified_topology: bool = False) -> PreflightReport:
    """One-line startup gate. Raises PreflightFailed on any checkable failure, and
    UnattestedInvariant if a topology fact is unverified (pass
    allow_unverified_topology=True to accept that explicitly). For anything that can
    physically actuate, use run_operational."""
    return run(default_checks(constitution_sha256=constitution_sha256,
                              constitution_path=constitution_path,
                              broker_factory=broker_factory,
                              verifier_factory=verifier_factory,
                              require_human_approval=require_human_approval,
                              required_identity_mode=required_identity_mode,
                              guard_factory=guard_factory,
                              required_channels=required_channels),
               context=context,
               allow_unverified_topology=allow_unverified_topology)
