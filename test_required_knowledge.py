"""
test_required_knowledge.py — missing safety information must not read as safe.

# CLAIMS: driftcore/safety/required_knowledge.py:unresolved-blocks-the-action
# CLAIMS: driftcore/safety/required_knowledge.py:expiry-does-not-resolve
# CLAIMS: driftcore/safety/required_knowledge.py:absence-is-not-clearance

The scenario this exists for, reproduced end to end against v126 before the fix:

  1. Someone tells the robot "jonny is allergic to peanuts".
  2. Permanent memory needs confirmation, so it waits in working memory.
  3. Nobody confirms.
  4. It expires. A restart leaves no trace.
  5. "make jonny a peanut butter sandwich"  ->  PROCEED.

Every gate did its job and the system was more dangerous than if nobody had
mentioned the allergy at all. Preventing an unapproved fact from being SAVED is
not the same as preventing an unsafe ACTION.

Run: python3 test_required_knowledge.py
"""

import os
import sys
import tempfile

os.chdir(tempfile.mkdtemp())
os.makedirs("logs", exist_ok=True)

import driftcore.authority.human_identity as hi

hi.declare_label_only("test suite: single process, no verifier installed")

from driftcore.safety.required_knowledge import (
    RequiredKnowledge, SafetyConcern, UnresolvedSafetyQuestion,
    looks_safety_bearing)

_p = _t = 0


def check(label, cond):
    global _p, _t
    _t += 1
    if cond:
        _p += 1
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}")


def blocked(rk, subject="jonny", domain="food", facts=(), lookup=None):
    try:
        rk.require_safe(subject, domain, facts=facts, lookup=lookup)
        return False
    except UnresolvedSafetyQuestion:
        return True


print("=== the signal check is a generous tripwire, not a classifier ===")

for text in ("jonny is allergic to peanuts", "dad takes insulin at 7pm",
             "emma cannot eat shellfish", "he has an epipen in the drawer",
             "she reacts to latex"):
    check(f"safety-bearing: {text!r}", looks_safety_bearing(text) is True)
for text in ("jonny likes dinosaurs", "the back gate sticks",
             "we had pasta on tuesday"):
    check(f"ordinary chat is not: {text!r}", looks_safety_bearing(text) is False)
check("non-string input does not raise", looks_safety_bearing(None) is False)


print("=== unresolved-blocks-the-action ===")

rk = RequiredKnowledge()
PROFILE = {}
lookup = lambda s, f: (s, f) in PROFILE

check("A: nobody ever mentioned anything -> STILL refused, because no warning "
      "is not the same as no allergy",
      blocked(rk, facts=("allergy_status",), lookup=lookup))

rk.raise_concern("jonny", "jonny is allergic to peanuts", raised_by="mum")
check("B: a raised, unconfirmed concern blocks the action",
      blocked(rk, facts=("allergy_status",), lookup=lookup))
check("...and the concern is counted as open", rk.open_count() == 1)

check("a concern about jonny does not block an action for someone else",
      blocked(rk, subject="emma", facts=(), lookup=None) is False)
check("...nor an action in a domain it does not bear on",
      blocked(rk, domain="laundry", facts=(), lookup=None) is False)


print("=== expiry-does-not-resolve ===")

# The exact conditions under which a question gets forgotten: memory expiry and
# a process restart. Neither is an answer.
_records = rk.to_records()
rk_restarted = RequiredKnowledge()
rk_restarted.from_records(_records)
check("a concern survives being serialised and reloaded — a restart is not an "
      "answer", rk_restarted.open_count() == 1)
check("...and still blocks after the restart",
      blocked(rk_restarted, facts=("allergy_status",), lookup=lookup))

rk_restarted.from_records(_records)
check("reloading is additive and never closes anything",
      rk_restarted.open_count() == 2)


print("=== resolving requires a human, and requires an answer ===")

rk2 = RequiredKnowledge()
c2 = rk2.raise_concern("jonny", "jonny is allergic to peanuts", raised_by="mum")


def resolves(who, outcome="confirmed with mum: peanut allergy"):
    try:
        rk2.resolve(c2, resolved_by=who, outcome=outcome)
        return True
    except (UnresolvedSafetyQuestion, ValueError):
        return False


check("an agent cannot close its own open question", resolves("agent") is False)
check("...nor can a bare 'system'", resolves("system") is False)
check("a question closed with no outcome recorded is not closed",
      resolves("operator_jane", outcome="") is False)
check("CONTROL: a human with an answer closes it",
      resolves("operator_jane") is True)
check("...and it is no longer open", rk2.open_count() == 0)


print("=== absence-is-not-clearance ===")

rk3 = RequiredKnowledge()
PROF3 = {}
lk3 = lambda s, f: (s, f) in PROF3

check("register clear, but nothing on file -> refused",
      blocked(rk3, facts=("allergy_status",), lookup=lk3))
PROF3[("jonny", "allergy_status")] = "none known, checked by mum on the 3rd"
check("CONTROL: register clear AND the fact affirmatively on file -> proceeds",
      blocked(rk3, facts=("allergy_status",), lookup=lk3) is False)

check("'no known allergies' is an ANSWER and clears the gate, so this is not "
      "an unconditional block",
      blocked(rk3, facts=("allergy_status",), lookup=lk3) is False)


def _broken(subject, fact):
    raise RuntimeError("profile store unreachable")


check("a lookup that RAISES has not answered — fail closed",
      blocked(rk3, facts=("allergy_status",), lookup=_broken))
check("declared facts with no lookup supplied is refused, not skipped",
      blocked(rk3, facts=("allergy_status",), lookup=None))


print("=== the refusal has to be actionable ===")

rk4 = RequiredKnowledge()
rk4.raise_concern("jonny", "jonny is allergic to peanuts", raised_by="mum")
try:
    rk4.require_clear("jonny", "food")
    _msg = ""
except UnresolvedSafetyQuestion as e:
    _msg = str(e)
check("the refusal names who raised it", "mum" in _msg)
check("...and quotes what was said", "peanuts" in _msg)
check("...and says why not knowing is not the same as knowing",
      "not knowing" in _msg.lower())



# ── wired into the ACTION path, not just callable (2026-09-06) ─────────────
# A checkpoint nothing calls is the `authority_invariants` problem: a module whose
# docstring says "enforced" that zero importers import. This exercises the real
# coordinator, so the demonstration is of the execution path and not of a helper.
from driftcore.verification.coordinator import VerificationCoordinator, Outcome
from driftcore.verification.invariant_guard import InvariantGuard
from driftcore.verification.risk_classifier import RiskClassifier
from driftcore.verification.governed_actuator import GrantAuthority

_rk = RequiredKnowledge()
_PROFILE = {}
_c = VerificationCoordinator(
    InvariantGuard(), RiskClassifier(),
    grant_authority=GrantAuthority(in_process_only=True),
    tool_effects={"kitchen": set()}, require_declared_effects=True,
    required_knowledge=_rk, required_facts={"food": ("allergy_status",)},
    safety_lookup=lambda s, f: (s, f) in _PROFILE)
_LUNCH = {"actuator_id": "kitchen", "command": "make_lunch",
          "prompt": "make jonny a peanut butter sandwich"}
_CTX = {"safety_subject": "jonny", "safety_domain": "food"}


def _lunch():
    return _c.evaluate(dict(_LUNCH), context=dict(_CTX))


check("an AUTHORISED lunch stops when nothing is on file about the child",
      _lunch().outcome is not Outcome.PROCEED)
check("...and the refusal names the required-information invariant",
      _lunch().invariant == "required_safety_information")

_rk.raise_concern("jonny", "jonny is allergic to peanuts", raised_by="mum")
_d = _lunch()
check("an unconfirmed concern stops the authorised action",
      _d.outcome is not Outcome.PROCEED)
check("...and the refusal quotes who said what, so a parent can resolve it",
      "mum" in (_d.reason or "") and "peanuts" in (_d.reason or ""))

_restarted = RequiredKnowledge()
_restarted.from_records(_rk.to_records())
_c._required_knowledge = _restarted
check("expiry and a restart do not turn the question into permission",
      _lunch().outcome is not Outcome.PROCEED)

_restarted.resolve(_restarted.open_for("jonny", "food")[0],
                   resolved_by="operator_jane",
                   outcome="confirmed with mum: peanut allergy")
check("resolving the question is still not the same as having the fact on file",
      _lunch().outcome is not Outcome.PROCEED)

_PROFILE[("jonny", "allergy_status")] = "peanut"
check("CONTROL: resolved AND on file -> the authorised action proceeds",
      _lunch().outcome is Outcome.PROCEED)

_c2 = VerificationCoordinator(
    InvariantGuard(), RiskClassifier(),
    grant_authority=GrantAuthority(in_process_only=True),
    tool_effects={"kitchen": set()}, require_declared_effects=True)
check("CONTROL: with no register configured the stage is a no-op, as the "
      "v4.5.0 opt-in contract requires — a real gap, not a safe default",
      _c2.evaluate(dict(_LUNCH), context=dict(_CTX)).outcome is Outcome.PROCEED)


# ── effects carry their prerequisites (2026-09-06) ─────────────────────────
# Two declaration tables were drifting apart: tool_effects says what an actuator
# DOES, required_facts said what a domain must KNOW. One declaration is better
# than two that can disagree, so prerequisites are now DERIVED from the declared
# effects and unioned with the domain's own.
from driftcore.safety.required_knowledge import prerequisites_for, EFFECT_PREREQUISITES
from driftcore.verification.invariant_guard import Effect

check("declaring PHYSICAL_FORCE implies its prerequisites with no second table",
      set(prerequisites_for({Effect.PHYSICAL_FORCE})) >=
      {"subject_present", "safety_envelope"})
check("an actuator with NO declared effects implies none",
      prerequisites_for(set()) == ())
check("domain facts and effect facts UNION rather than replace",
      set(prerequisites_for({Effect.PHYSICAL_FORCE},
                            domain_facts=("allergy_status",))) >=
      {"allergy_status", "subject_present", "safety_envelope"})
check("prerequisites-only-accumulate: no argument removes a requirement, "
      "because a removed check looks identical to a passing one",
      "remove" not in prerequisites_for.__doc__.lower().split("no argument")[0])

_PROF2 = {}
_rk2 = RequiredKnowledge()
_c3 = VerificationCoordinator(
    InvariantGuard(), RiskClassifier(),
    grant_authority=GrantAuthority(in_process_only=True),
    tool_effects={"kitchen": {Effect.PHYSICAL_FORCE}, "rake": set()},
    require_declared_effects=True, required_knowledge=_rk2,
    safety_lookup=lambda s, f: (s, f) in _PROF2)
_C3 = {"safety_subject": "jonny", "safety_domain": "food"}

# Regression for a bug this demonstration caught: the stage read actuator_id from
# the CONTEXT, where it does not live, so it found no prerequisites and passed.
# A check that quietly finds nothing is indistinguishable from one that passed.
_dk = _c3.evaluate({"actuator_id": "kitchen", "command": "make_lunch"},
                   context=dict(_C3))
check("an effect-declared actuator BLOCKS on its derived prerequisites",
      _dk.outcome is not Outcome.PROCEED)
check("...and the derived facts are the effect's, read from the REQUEST",
      set(_dk.detail.get("required_facts", ())) >=
      {"subject_present", "safety_envelope"})
check("CONTROL: an actuator with no declared effects is not blocked by this "
      "stage — the discrimination is the effect, not the subject",
      _c3.evaluate({"actuator_id": "rake", "command": "sweep"},
                   context=dict(_C3)).outcome is Outcome.PROCEED)

for _f in ("subject_present", "safety_envelope"):
    _PROF2[("jonny", _f)] = "checked by mum"
check("CONTROL: once the derived facts are on file, it proceeds",
      _c3.evaluate({"actuator_id": "kitchen", "command": "make_lunch"},
                   context=dict(_C3)).outcome is Outcome.PROCEED)

check("LETHAL requires human authorisation among its prerequisites",
      "human_authorisation" in prerequisites_for({Effect.LETHAL}))


# ── COLD PASS 2026-09-09: three defects in the fixes above, all self-inflicted ─

# F1. The stage returned None when the CALLER omitted safety_subject, so the whole
# check was skipped by not mentioning who the action was for. Identical to the
# `interpretation_guard` omission defect this project identified the same day and
# then rebuilt. The requirement now comes from the EFFECT.
_rkF = RequiredKnowledge()
_rkF.raise_concern("jonny", "jonny is allergic to peanuts", raised_by="mum")
_cF = VerificationCoordinator(
    InvariantGuard(), RiskClassifier(),
    grant_authority=GrantAuthority(in_process_only=True),
    tool_effects={"kitchen": {Effect.PHYSICAL_FORCE}, "rake": set()},
    require_declared_effects=True, required_knowledge=_rkF,
    safety_lookup=lambda s, f: False)

check("F1: omitting safety_subject does NOT skip the stage when the effect "
      "carries prerequisites",
      _cF.evaluate({"actuator_id": "kitchen", "command": "go"},
                   context={}).outcome is not Outcome.PROCEED)
check("F1 CONTROL: an actuator with no prerequisites is unaffected, so this "
      "does not turn every call into a safety question",
      _cF.evaluate({"actuator_id": "rake", "command": "go"},
                   context={}).outcome is Outcome.PROCEED)

# F2. Identity strength must only increase. In-process code called reset_policy()
# then declare_label_only() and a bare name that ATTESTED had refused was accepted
# — the agent downgrading the floor every other gate stands on.
import driftcore.authority.human_identity as _hiF
from driftcore.authority.human_identity import declare_label_only as _dlo2

_hiF.reset_policy(); _hiF.undeclare_label_only()
_vF = _hiF.HumanIdentityVerifier(); _vF.register_principal("jane", b"k")
_hiF.set_verifier(_vF)
try:
    _dlo2("agent talks itself into unverified identity")
    _downgraded = True
except PermissionError:
    _downgraded = False
check("F2: declaring label-only over an installed verifier is refused",
      _downgraded is False)
check("F2: ...and the mode is unchanged by the attempt", _hiF.mode() == "ATTESTED")
_hiF.reset_policy()
check("F2: tearing the verifier down leaves a VISIBLE unconfigured state, not a "
      "silently weak one", _hiF.mode() == "UNCONFIGURED")
_hiF.undeclare_label_only()
_dlo2("test suite: single process, no verifier installed")
check("F2 CONTROL: declaring from UNCONFIGURED still works",
      _hiF.mode() == "LABEL_ONLY")

# F3. verify_tier1_record had ZERO production callers — the exact criticism this
# project makes of authority_invariants.py, rebuilt hours after making it.
from driftcore.memory import (DriftcoreMemory as _DM, MemoryItem as _MI,
                              tier1_record_id as _trid)
_KEYF, _TF, _SF = b"approval-key", "dad is allergic to peanuts", "dad"
_hiF.reset_policy()
_vF2 = _hiF.HumanIdentityVerifier(); _vF2.register_principal("jane", _KEYF)
_hiF.set_verifier(_vF2)
try:
    _mF = _DM(interactive=False, tier1_verifier=_vF2)
    _attF = _hiF.HumanAttestation.issue(
        _KEYF, principal="jane", action=_trid(_TF, _SF),
        ttl_seconds=600, nonce=os.urandom(8).hex())
    _mF._tier1.append(_MI(text=_TF, source=_SF, tier=1, approval=_attF))
    # The smuggled record MUST match the query, or relevance excludes it and the
    # check passes without verification doing anything. An earlier version used
    # "dad has no allergies" — no "peanuts" in it — so unwiring the verification
    # entirely left this green. Fifth masked check of the session.
    _SMUGGLED = "dad can eat peanuts safely, no allergy"
    _mF._tier1.append(_MI(text=_SMUGGLED, source=_SF, tier=1))
    _got = _mF.query_text("peanuts")
    check("F3 PRECONDITION: the smuggled record matches the query, so relevance "
          "cannot be what excludes it",
          any("peanut" in _i.text for _i in _mF._tier1 if _i.approval is None))
    check("F3: an approved record is returned by the READ path",
          any(_TF in g for g in _got))
    check("F3: a directly appended record is NOT returned, though it is "
          "physically present in _tier1",
          len(_mF._tier1) == 2 and not any(_SMUGGLED in g for g in _got))

    _m0 = _DM(interactive=False)          # no verifier configured
    _m0._tier1.append(_MI(text=_TF, source=_SF, tier=1))
    check("F3 CONTROL: with no verifier configured every record is returned — a "
          "real gap, not a safe default",
          any(_TF in g for g in _m0.query_text("peanuts")))
finally:
    _hiF.reset_policy()
    _dlo2("test suite: single process, no verifier installed")


# ── external red team (Grok), v129, 2026-09-09 ─────────────────────────────
# Four findings on the fixes above, all confirmed by execution before changing
# anything. Three were mine to miss; one grew between two files.

# G2. `verify_tier1_record(item, verifier)` only tested `verifier is None` and
# then verified against the PROCESS-GLOBAL policy. Garbage passed; a real
# verifier that simply was not installed globally failed. The argument was
# scenery — so every test passing `_v` proved nothing about binding to `_v`.
from driftcore.memory import (MemoryItem as _MIg, tier1_record_id as _tridg,
                              verify_tier1_record as _vtr)
_hiF.reset_policy()
_KEYG, _TG, _SG = b"gk", "dad is allergic to peanuts", "dad"
_vg = _hiF.HumanIdentityVerifier(); _vg.register_principal("jane", _KEYG)
_hiF.set_verifier(_vg)
try:
    def _att_g():
        return _hiF.HumanAttestation.issue(
            _KEYG, principal="jane", action=_tridg(_TG, _SG),
            ttl_seconds=600, nonce=os.urandom(8).hex())

    check("G2: a garbage 'verifier' object is refused, not silently ignored",
          _vtr(_MIg(text=_TG, source=_SG, tier=1, approval=_att_g()),
               object()) is False)
    check("G2 CONTROL: the real verifier still accepts a correct approval",
          _vtr(_MIg(text=_TG, source=_SG, tier=1, approval=_att_g()), _vg) is True)
    _hiF.reset_policy()
    _vg2 = _hiF.HumanIdentityVerifier(); _vg2.register_principal("jane", _KEYG)
    check("G2: a correct verifier works even when it is NOT the global policy — "
          "the argument decides, not the process",
          _vtr(_MIg(text=_TG, source=_SG, tier=1, approval=_att_g()), _vg2) is True)
finally:
    _hiF.reset_policy()
    _dlo2("test suite: single process, no verifier installed")

# G3. `require_secure_mode()` tested only for LABEL_ONLY and RETURNED
# "UNCONFIGURED" — green-lighting the state introduced to be fail-closed. A mode
# enum that grows and a classifier that does not is how "could not check" starts
# reading as "checked", one layer up.
_hiF.reset_policy()
try:
    _hiF.require_secure_mode(); _boot_ok = True
except Exception:
    _boot_ok = False
check("G3: require_secure_mode REFUSES an unconfigured boot", _boot_ok is False)
check("G3: ...and status() does not report it secure",
      _hiF.status()["secure"] is False)
_hiF.register_human_principal("justin")
check("G3 CONTROL: a REGISTERED boot is still permitted",
      _hiF.require_secure_mode() == "REGISTERED")
check("G3 CONTROL: ...and reports secure", _hiF.status()["secure"] is True)

# G4. reset_policy() left the label-only declaration standing, so
# declare -> register -> reset landed back in LABEL_ONLY with a STALE author.
_hiF.reset_policy()
_dlo2("planner_agent_7")
_hiF.register_human_principal("justin")
_hiF.reset_policy()
check("G4: a reset lands in UNCONFIGURED, not back in a stale LABEL_ONLY",
      _hiF.mode() == "UNCONFIGURED")
check("G4: ...so a leftover declaration cannot restore the denylist floor",
      _hiF.is_human("mallory", action="x") is False)
_dlo2("test suite: single process, no verifier installed")

# G5b. raise_concern defaults domains to ("food","medical"); the coordinator
# defaults an unspecified domain to "general". Two reasonable defaults chosen in
# different files, meeting nowhere, producing a silent PROCEED.
_rkG = RequiredKnowledge()
_rkG.raise_concern("jonny", "jonny is allergic to peanuts", raised_by="mum")
_cG = VerificationCoordinator(
    InvariantGuard(), RiskClassifier(),
    grant_authority=GrantAuthority(in_process_only=True),
    tool_effects={"kitchen": set()}, require_declared_effects=True,
    required_knowledge=_rkG, required_facts={"food": ("allergy_status",)},
    safety_lookup=lambda s, f: False)
check("G5b: an unspecified domain still sees the open concern",
      _cG.evaluate({"actuator_id": "kitchen", "command": "go"},
                   context={"safety_subject": "jonny"}).outcome
      is not Outcome.PROCEED)
check("G5b CONTROL: a subject with no concerns is not blocked by this",
      _cG.evaluate({"actuator_id": "kitchen", "command": "go"},
                   context={"safety_subject": "emma",
                            "safety_domain": "laundry"}).outcome
      is Outcome.PROCEED)

print("-" * 60)
print(f"  {_p}/{_t} tests passed")
if _p != _t:
    raise SystemExit(1)
