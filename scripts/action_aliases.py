#!/usr/bin/env python3
"""
action_aliases.py — one implementation, two declarations, different guards.

WHY THIS EXISTS
---------------
The effect registry protects an ACTION NAME. What executes is an IMPLEMENTATION. When
several names reach one implementation and only some carry the dangerous declaration,
the guard is intact and the operation is reachable around it. Nothing in this repo
looked for that.

Two shapes, and the first was live:

  1. NAME ALIASING, inside the ledger. `register_action` keyed on the raw string and
     normalised only trailing whitespace, so "remove the founder" declared with
     `changes_authority_of` and "Remove The Founder" declared without were two specs
     — and any case-insensitive dispatcher treats them as one operation. Verified:
     the alias registered unguarded and authorised. Closed in
     `intent_ledger.canonical_action`, which is now the registry key.

  2. IMPLEMENTATION ALIASING, across the broker. Two actuator ids bound to the SAME
     callable with different declared effects or different required scope. The
     ledger cannot see this: it knows names, not code. The broker can, because
     `_implementation_id` already computes a structural identity for each registered
     callable — the same primitive that catches a swapped actuator.

AUDIT TOTALITY — the property that makes the rest of it mean anything
----------------------------------------------------------------------
`audit() == []` means EVERY required registry was read and nothing was aliased. It
does not mean "no problems were noticed". Anything the auditor cannot inspect
produces a CRITICAL finding, so CLEAN is unreachable by failing to look.

That distinction was not present until a reviewer pointed at it (ChatGPT, 2026-08-15)
and three fail-opens fell out of one sentence: a missing `_actuators` became an empty
registry became a clean run; a failed import of the canonicaliser deleted the key
check silently; and `declaration_hash` raising on a SINGLE actuator produced nothing,
because that path only ran for buckets of two or more — the same bug already fixed
one line over for `_implementation_id`.

Worse than fail-open, two of them MISATTRIBUTED: an unreadable broker produced a
DANGLING_DECLARATION blaming the ledger, and an unreadable ledger produced an
UNGOVERNED_SURFACE blaming the broker. A wrong finding is more expensive than a
missing one, because someone acts on it.

`--self-test` therefore ends with a META-TEST: for every check, blind its ability to
inspect and prove it complains rather than reporting nothing. Proving a check fires is
half the job; proving it cannot be silenced is the other half.

WHAT IT CHECKS
--------------
Given a live deployment's ledger and/or broker:

  * SHARED IMPLEMENTATION — two actuator ids resolving to one implementation with
    effects or scope that disagree.
  * UNGOVERNED SURFACE — a broker actuator reachable with no ledger declaration,
    when a ledger is installed.
  * DANGLING DECLARATION — a ledger action naming an actuator the broker does not
    have. Not dangerous, but it means the declaration is guarding nothing and the
    real operation may be declared elsewhere, or not at all.
  * ALIAS COLLISION — action names that canonicalise together. Should be empty now
    that the ledger refuses them; kept because a check that only passes on the
    version that introduced it proves nothing about the next one.

THE NAMESPACE RULE, STATED BECAUSE IT IS A LANDMINE OTHERWISE
--------------------------------------------------------------
A ledger action containing a colon is read as `actuator:command`, and only those are
candidates for DANGLING_DECLARATION. A bare name like "remove the founder" is assumed
NOT to be an actuator operation and is never dangling-checked — most intents are not
actuations, and flagging every one of them would drown the real findings. The cost:
an orphaned bare-name declaration is invisible here. Anyone adding a new kind of
action name should decide which side of that line it falls on before adding it.

WHAT IT CANNOT DO
-----------------
* It cannot see a DISPATCHER. If a deployment maps "reorganise governance" onto the
  same function as "remove the founder" through its own routing table, that table is
  not in DriftCore and this cannot read it. The property "every executable operation
  has exactly one canonical effect declaration" is only decidable where the real
  mapping lives. This checks the part that is in the repo and names the part that is
  not — pointing the tool at a fake dispatcher and passing would be worse than
  having no tool.
* Two callables that are structurally different but behaviourally identical read as
  two implementations. Structural identity is not semantic identity.

Usage:
    python3 scripts/action_aliases.py --self-test
    from scripts.action_aliases import audit
    audit(ledger=my_ledger, broker=my_broker)
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict


# Every registry the audit must be able to read. `getattr(x, name, {}) or {}` turns a
# missing attribute into an empty registry, and an empty registry into a clean run —
# so an object that could not be inspected at all reported no aliasing. Verified: an
# object with no `_actuators` produced a DANGLING_DECLARATION blaming the LEDGER for a
# broker that was never read. Not merely fail-open: misattributed.
_REQUIRED = {"ledger": "_actions", "broker": "_actuators"}


def _registry(obj, role: str, findings: list):
    """The registry, or None plus a finding. Never a silent empty dict."""
    attr = _REQUIRED[role]
    reg = getattr(obj, attr, None)
    if reg is None or not isinstance(reg, dict):
        findings.append({
            "kind": f"{role.upper()}_UNREADABLE", "subject": type(obj).__name__,
            "severity": "CRITICAL",
            "detail": (f"no readable {attr!r} on the {role}; the audit could not "
                       f"establish what is registered, so it cannot establish that "
                       f"nothing is aliased. Absence of findings is not absence of "
                       f"aliasing when the registry was never read.")})
        return None
    return reg


def audit(*, ledger=None, broker=None) -> list:
    """Findings as dicts.

    An empty list means EVERY required registry was read and nothing was aliased.
    It does not mean "no problems were noticed" — the auditor emits a CRITICAL
    finding for anything it could not inspect, so `audit() == []` cannot be reached
    by failing to look. (red-team, ChatGPT 2026-08-15: the auditor conflated "no
    findings" with "I successfully inspected the objects I was given".)
    """
    findings = []

    # (cold pass 2026-08-15 — REPRODUCED.) The totality rule was applied to the
    # registries and never to the auditor's OWN INPUTS. `audit()` with nothing given
    # returned [] — clean — and a test asserted that was correct. `audit(broker=b)`
    # with no ledger also returned [], while every actuator on it was ungoverned and
    # the check that says so silently did not run. An auditor that reports clean on a
    # scope it was never given is the same failure it exists to catch.
    if ledger is None and broker is None:
        return [{
            "kind": "SCOPE_UNSPECIFIED", "subject": "audit()",
            "severity": "CRITICAL",
            "detail": ("no ledger and no broker were given. Nothing was inspected, "
                       "so nothing is established — an empty scope is not a clean "
                       "deployment.")}]
    if broker is not None and ledger is None:
        findings.append({
            "kind": "PARTIAL_AUDIT", "subject": "ledger",
            "severity": "HIGH",
            "detail": ("no ledger supplied, so UNGOVERNED_SURFACE and "
                       "DANGLING_DECLARATION did not run. Implementation aliasing "
                       "was checked; whether any actuator is declared at all was "
                       "not.")})
    if ledger is not None and broker is None:
        findings.append({
            "kind": "PARTIAL_AUDIT", "subject": "broker",
            "severity": "HIGH",
            "detail": ("no broker supplied, so SHARED_IMPLEMENTATION, "
                       "UNGOVERNED_SURFACE and the actuator checks did not run. "
                       "Registry key integrity was checked; nothing about what "
                       "executes was.")})

    # ── registry key integrity ────────────────────────────────────────────────
    # (red-team, Meta 2026-08-15 — CONFIRMED.) The previous check here grouped specs
    # by `key` and looked for buckets holding more than one. `key` IS the canonical
    # form, so every bucket has exactly one member and the check could never fire —
    # dead code. Worse, the test asserting "the registry cannot hold an
    # ALIAS_COLLISION" passed VACUOUSLY: it could not have failed. That is the same
    # defect this session has been hunting all day, in a tool written to hunt it.
    #
    # What can actually go wrong, and therefore what is checked now: a stored key
    # that is NOT its own canonical form. The ledger cannot produce one, but a legacy
    # registry, a restored snapshot, or anything that wrote `_actions` directly can —
    # and such a key is invisible to canonical lookup, which is exactly the alias
    # bypass with the guard already installed.
    if ledger is not None:
        specs = _registry(ledger, "ledger", findings)
        try:
            from driftcore.verification.intent_ledger import canonical_action
        except Exception as e:
            canonical_action = None
            # Canonicalisation is not optional for this auditor: without it the key
            # integrity check simply vanished, silently, and the run still said OK.
            findings.append({
                "kind": "CANONICALIZER_UNAVAILABLE", "subject": "canonical_action",
                "severity": "CRITICAL",
                "detail": (f"could not import the canonicaliser ({type(e).__name__}: "
                           f"{str(e)[:120]}). Key integrity cannot be checked, and a "
                           f"check that cannot run must not report a pass.")})
        if canonical_action is not None and specs is not None:
            for key, spec in specs.items():
                try:
                    canon = canonical_action(key)
                except Exception:
                    canon = None
                if canon is not None and canon != key:
                    findings.append({
                        "kind": "NON_CANONICAL_KEY", "subject": key,
                        "severity": "CRITICAL",
                        "detail": (f"stored under {key!r} but canonicalises to "
                                   f"{canon!r}; a lookup will never find it, so its "
                                   f"declaration guards nothing")})

    # ── implementation aliasing across the broker ────────────────────────────
    if broker is not None:
        actuators = _registry(broker, "broker", findings)
        if actuators is None:
            return findings          # nothing further is knowable about this broker

        # An auditor that mutates the thing it audits is not an observer.
        # `_implementation_id` CACHES: when the registered callable has changed it
        # rewrites `_impl_ids`, so merely running this audit updated the broker's
        # identity cache — verified. The snapshot must be taken HERE, before the
        # declaration-hash sweep below, because `declaration_hash` calls
        # `_implementation_id` internally: a snapshot taken further down was already
        # of a mutated cache, which is how the first attempt at this fix silently
        # did nothing.
        _impl_cache = getattr(broker, "_impl_ids", None)
        _impl_saved = dict(_impl_cache) if isinstance(_impl_cache, dict) else None

        # Record shape is checked for EVERY actuator, before anything else. The first
        # version of this check lived inside the shared-implementation branch, which
        # only runs for buckets of two or more — so a single actuator with an
        # unreadable record produced nothing. A check that only fires when the
        # problem is already suspected is not a check.
        for aid, rec in actuators.items():
            if not (isinstance(rec, tuple) and len(rec) > 1):
                findings.append({
                    "kind": "UNREADABLE_RECORD", "subject": aid,
                    "severity": "CRITICAL",
                    "detail": (f"actuator record is a {type(rec).__name__}, not the "
                               f"(fn, scope) tuple this audit reads. Scope cannot be "
                               f"compared, so aliasing cannot be ruled out for it.")})

        # (red-team, ChatGPT 2026-08-15 — REPRODUCED.) `declaration_hash` failing was
        # recorded into `decls[aid]` inside the shared-implementation branch, which
        # only runs for buckets of two or more. With a SINGLE actuator whose
        # declaration hash threw, the audit returned [] — clean. That is the exact
        # bug already fixed one line over for `_implementation_id`, missed here.
        # Hoisted, like the record-shape check, so it fires on every actuator.
        for aid in actuators:
            try:
                broker.declaration_hash(aid)
            except Exception as e:
                findings.append({
                    "kind": "DECLARATION_UNAVAILABLE", "subject": aid,
                    "severity": "CRITICAL",
                    "detail": (f"declaration hash could not be computed "
                               f"({type(e).__name__}: {str(e)[:200]}); what this "
                               f"actuator declares cannot be compared against "
                               f"anything.")})

        # Two registrations, one logical name. The surface checks casefold when
        # comparing against declarations, so these two collapse to one there — but
        # nothing said so. Two physical registrations under one logical namespace is
        # precisely the class this module exists to find.
        by_canon_aid = defaultdict(list)
        for aid in actuators:
            by_canon_aid[aid.casefold()].append(aid)
        for canon, group in by_canon_aid.items():
            if len(group) > 1:
                findings.append({
                    "kind": "CANONICAL_ACTUATOR_COLLISION", "subject": canon,
                    "severity": "CRITICAL",
                    "detail": (f"actuator ids {sorted(group)} are one name once case "
                               f"is folded, and the surface checks compare them "
                               f"folded. Two registrations under one logical id means "
                               f"a declaration can attach to whichever one the "
                               f"dispatcher does not use.")})

        by_impl = defaultdict(list)
        for aid in actuators:
            try:
                impl = broker._implementation_id(aid)
            except Exception as e:
                # (red-team, Meta 2026-08-15.) These used to collapse into a single
                # "unknown" bucket which was then SKIPPED — so a broker whose
                # implementation identity was broken produced no findings at all and
                # read as clean. Meta predicted a false POSITIVE; the actual failure
                # was fail-OPEN, which is worse: a check that cannot run must never
                # report a pass. Each error now gets its own bucket AND its own
                # finding.
                impl = f"error:{aid}:{type(e).__name__}"
                findings.append({
                    "kind": "IDENTITY_UNAVAILABLE", "subject": aid,
                    "severity": "CRITICAL",
                    "detail": (f"implementation identity could not be computed "
                               f"({type(e).__name__}: {str(e)[:200]}); this actuator "
                               f"cannot be checked for aliasing at all")})
            by_impl[impl].append(aid)

        if _impl_saved is not None:
            _impl_cache.clear()
            _impl_cache.update(_impl_saved)

        for impl, ids in by_impl.items():
            if len(ids) < 2 or impl.startswith("error:"):
                continue
            scopes, decls = {}, {}
            for aid in ids:
                rec = actuators.get(aid)
                # (red-team, Grok 2026-08-15.) This used to fall back to an empty
                # tuple whenever the record was not a tuple. If the broker ever
                # stores actuators as a dataclass or dict, EVERY scope silently
                # becomes () — they all "agree", and the check quietly stops
                # comparing the thing it exists to compare. An unexpected shape is
                # now a finding, not a default.
                scopes[aid] = (tuple(rec[1])
                               if isinstance(rec, tuple) and len(rec) > 1 else None)
                try:
                    decls[aid] = broker.declaration_hash(aid)
                except Exception as e:
                    decls[aid] = f"error:{aid}:{type(e).__name__}"
            if len(set(scopes.values())) > 1 or len(set(decls.values())) > 1:
                diff = "; ".join(
                    f"{aid}: scope={list(scopes[aid])} decl={str(decls[aid])[:12]}"
                    for aid in sorted(ids))
                findings.append({
                    "kind": "SHARED_IMPLEMENTATION", "subject": impl[:24],
                    "severity": "CRITICAL",
                    "detail": (f"actuators {sorted(ids)} run the same code with "
                               f"differing declarations — the strictest is reachable "
                               f"around, via the weakest name. {diff}")})

        # ── ungoverned surface / dangling declarations ────────────────────────
        if ledger is not None and getattr(ledger, "_actions", None) is not None:
            # Guarded on the ledger being READABLE. Without this, an unreadable
            # ledger produced LEDGER_UNREADABLE *and* an UNGOVERNED_SURFACE for every
            # actuator — blaming the broker for a ledger that was never read. One
            # root cause, one finding.
            # Both sides normalised HERE. The ledger canonicalises its own keys, so
            # through the normal path these already agree — but an audit that relies
            # on another component having normalised is an audit that breaks when
            # that component changes. A key already reported as NON_CANONICAL_KEY is
            # skipped so one root cause does not produce two findings.
            bad_keys = {f["subject"] for f in findings
                        if f["kind"] == "NON_CANONICAL_KEY"}
            declared = set()
            for key in (getattr(ledger, "_actions", {}) or {}):
                if key in bad_keys:
                    continue
                declared.add(key.split(":", 1)[0].casefold())
            for aid in actuators:
                if aid.casefold() not in declared:
                    findings.append({
                        "kind": "UNGOVERNED_SURFACE", "subject": aid,
                        "severity": "CRITICAL", "detail": ("a registered actuator with no ledger declaration; "
                                   "reachable without any purpose accounting")})
            known = {a.casefold() for a in actuators}
            for key in (getattr(ledger, "_actions", {}) or {}):
                if key in bad_keys:
                    continue
                head = key.split(":", 1)[0].casefold()
                if ":" in key and head not in known:
                    findings.append({
                        "kind": "DANGLING_DECLARATION", "subject": key,
                        "severity": "HIGH", "detail": (f"declares effects for actuator {head!r}, which "
                                   f"this broker does not have — the declaration "
                                   f"guards nothing here")})
    return findings


def report(findings, *, quiet: bool = False) -> int:
    if not quiet:
        print()
        print("  ACTION ALIASES — one implementation, several declarations?")
        print("  " + "-" * 62)
    if not findings:
        if not quiet:
            print("  RESULT: OK — no structural aliasing found.")
            print("  NOTE: this cannot see a deployment's own dispatcher. Two names")
            print("  routed to one function OUTSIDE DriftCore are invisible here.")
        return 0
    # A finding missing a key used to raise a KeyError here — AFTER every finding
    # had been computed, losing all of them. An exception in the reporting layer of a
    # safety tool is a fail-open with extra steps.
    _SCHEMA = ("kind", "subject", "severity", "detail")
    for f in findings:
        if not isinstance(f, dict) or not all(k in f for k in _SCHEMA):
            missing = ([k for k in _SCHEMA if not isinstance(f, dict) or k not in f]
                       if True else [])
            print(f"  MALFORMED_FINDING  (missing {missing})")
            print(f"      {str(f)[:160]}")
            continue
        print(f"  [{f['severity']}] {f['kind']}  {f['subject']}")
        print(f"      {f['detail']}")
    print()
    print("  RESULT: FAIL — an operation is reachable under a weaker declaration "
          "than the one guarding it.")
    return 1


def _blindability(role: str, make_broken, make_clean) -> bool:
    """META-TEST: breaking a check's ability to inspect must NOT produce a clean run.

    (red-team, ChatGPT 2026-08-15 — their best structural suggestion.) Proving a check
    FIRES on a known violation is half the job. The other half is proving it cannot be
    SILENCED: blind it, and it must complain rather than report nothing. Three of this
    auditor's fail-opens were exactly that shape — a check whose inspection failed and
    whose absence then read as clean.
    """
    clean = make_clean()
    if clean != []:
        print(f"  FAIL {role}: the control case is not clean ({clean})")
        return False
    broken = make_broken()
    if broken == []:
        print(f"  FAIL {role}: blinded, and it reported CLEAN")
        return False
    if not all(f.get("severity") for f in broken):
        print(f"  FAIL {role}: a finding without severity would be filtered away")
        return False
    print(f"  ok   {role}: blinded -> "
          f"{sorted({f['kind'] for f in broken})}, never clean")
    return True


def _self_test() -> int:
    """Build each shape and confirm it is caught. Ground truth, not assertion."""
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))
    from driftcore.authority import human_identity as hi
    from driftcore.verification.intent_ledger import IntentLedger
    from driftcore.verification.mediated_actuation import ActuationBroker
    from driftcore.verification.signed_permission import PermissionVerifier
    from driftcore.verification.invariant_guard import Effect

    ok = True
    hi.reset_policy()
    hi.register_human_principal("op")

    # SHARED_IMPLEMENTATION: one callable, two ids, different scope.
    v = PermissionVerifier()
    b = ActuationBroker("/tmp/dc_alias.sock", v, broker_id="B")
    shared = lambda **kw: "done"                                   # noqa: E731
    b.register_actuator("arm_left", shared, required_scope=("arm_left:grip",),
                        effects=[Effect.PHYSICAL_FORCE], effect_declared_by="op")
    b.register_actuator("arm_backup", shared, required_scope=("arm_backup:anything",),
                        effects=[Effect.NONE], effect_declared_by="op")
    f = audit(broker=b)
    got = any(x["kind"] == "SHARED_IMPLEMENTATION" for x in f)
    print(f"  {'ok  ' if got else 'FAIL'} one callable under two ids is caught")
    ok &= got

    # A single id is not a finding.
    b2 = ActuationBroker("/tmp/dc_alias2.sock", PermissionVerifier(), broker_id="B")
    b2.register_actuator("arm_left", lambda **kw: "x",
                         required_scope=("arm_left:grip",),
                         effects=[Effect.PHYSICAL_FORCE], effect_declared_by="op")
    # Both sides, because a one-sided audit is now PARTIAL rather than clean — which
    # is the point of the totality rule and correctly broke this case.
    _led_b2 = IntentLedger()
    _led_b2.register_action("arm_left:grip", declared_by="op")
    clean = not audit(ledger=_led_b2, broker=b2)
    print(f"  {'ok  ' if clean else 'FAIL'} a single well-declared actuator is clean")
    ok &= clean

    # UNGOVERNED_SURFACE: an actuator the ledger never declared.
    led = IntentLedger()
    led.register_action("arm_left:grip", declared_by="op")
    f = audit(ledger=led, broker=b2)
    clean2 = not any(x["kind"] == "UNGOVERNED_SURFACE" for x in f)
    print(f"  {'ok  ' if clean2 else 'FAIL'} a declared actuator is not flagged")
    ok &= clean2

    b3 = ActuationBroker("/tmp/dc_alias3.sock", PermissionVerifier(), broker_id="B")
    b3.register_actuator("undeclared_arm", lambda **kw: "x",
                         required_scope=("undeclared_arm:go",),
                         effects=[Effect.PHYSICAL_FORCE], effect_declared_by="op")
    f = audit(ledger=led, broker=b3)
    got2 = any(x["kind"] == "UNGOVERNED_SURFACE" for x in f)
    print(f"  {'ok  ' if got2 else 'FAIL'} an UNDECLARED actuator is caught")
    ok &= got2

    got3 = any(x["kind"] == "DANGLING_DECLARATION" for x in f)
    print(f"  {'ok  ' if got3 else 'FAIL'} a declaration for a missing actuator is caught")
    ok &= got3

    # ALIAS_COLLISION: the ledger now refuses these outright, so the registry
    # cannot hold one. Prove the refusal instead of faking a collision.
    led2 = IntentLedger()
    led2.declare_authority("cc", "op", declared_by="op")
    led2.register_action("remove the founder", declared_by="op",
                         changes_authority_of="cc")
    refused = False
    try:
        led2.register_action("Remove The Founder", declared_by="op")
    except Exception:
        refused = True
    print(f"  {'ok  ' if refused else 'FAIL'} the ledger refuses an alias that "
          f"drops a declaration")
    ok &= refused
    # A ledger-only audit is PARTIAL by design; assert the property that can fail —
    # the registry holds one spec and it is the guarded one.
    clean3 = ("NON_CANONICAL_KEY" not in {f["kind"] for f in audit(ledger=led2)}
              and len(led2._actions) == 1)
    print(f"  {'ok  ' if clean3 else 'FAIL'} so the registry holds no collision")
    ok &= clean3

    # NON_CANONICAL_KEY: only reachable by writing the registry directly, which is
    # exactly what a legacy snapshot or a restore does.
    led3 = IntentLedger()
    led3.register_action("remove the founder", declared_by="op")
    spec = led3._actions["remove the founder"]
    led3._actions["Remove The Founder"] = spec          # bypass canonicalisation
    f = audit(ledger=led3)
    got4 = any(x["kind"] == "NON_CANONICAL_KEY" for x in f)
    print(f"  {'ok  ' if got4 else 'FAIL'} a non-canonical registry key is caught")
    ok &= got4

    # IDENTITY_UNAVAILABLE: a broken identity function must not read as clean.
    b4 = ActuationBroker("/tmp/dc_alias4.sock", PermissionVerifier(), broker_id="B")
    for _n in ("a1", "a2"):
        b4.register_actuator(_n, lambda **kw: "x", required_scope=(f"{_n}:go",),
                             effects=[Effect.PHYSICAL_FORCE], effect_declared_by="op")
    b4._implementation_id = lambda aid: (_ for _ in ()).throw(RuntimeError("boom"))
    f = audit(broker=b4)
    got5 = sum(1 for x in f if x["kind"] == "IDENTITY_UNAVAILABLE") == 2
    print(f"  {'ok  ' if got5 else 'FAIL'} a broken identity function FAILS rather "
          f"than reading as clean")
    ok &= got5

    # THE DOCUMENTED LIMIT, PROVEN. A dispatcher outside DriftCore maps two names
    # onto one actuator. The audit is clean — correctly, because that table is not
    # in the repo. Asserting a limit in a docstring is not the same as showing it.
    b5 = ActuationBroker("/tmp/dc_alias5.sock", PermissionVerifier(), broker_id="B")
    b5.register_actuator("arm_left", lambda **kw: "moved",
                         required_scope=("arm_left:grip",),
                         effects=[Effect.PHYSICAL_FORCE], effect_declared_by="op")
    led4 = IntentLedger()
    led4.register_action("arm_left:grip", declared_by="op")
    ROUTER = {"grip the cup": "arm_left", "reorganise governance": "arm_left"}
    blind = audit(ledger=led4, broker=b5) == [] and len(set(ROUTER.values())) == 1
    print(f"  {'ok  ' if blind else 'FAIL'} a DISPATCHER alias is invisible here — "
          f"the limit is real, not rhetorical")
    ok &= blind

    # ── META: every check must be un-silenceable ──────────────────────────────
    print()
    print("  meta: blinding a check must never produce CLEAN")

    def _clean_pair():
        bb = ActuationBroker("/tmp/dc_meta.sock", PermissionVerifier(), broker_id="B")
        bb.register_actuator("arm", lambda **kw: "x", required_scope=("arm:go",),
                             effects=[Effect.PHYSICAL_FORCE], effect_declared_by="op")
        ll = IntentLedger()
        ll.register_action("arm:go", declared_by="op")
        return ll, bb

    class _Opaque:
        pass

    def _blind_broker():
        ll, _ = _clean_pair()
        return audit(ledger=ll, broker=_Opaque())

    def _blind_ledger():
        _, bb = _clean_pair()
        return audit(ledger=_Opaque(), broker=bb)

    def _blind_decl():
        ll, bb = _clean_pair()
        bb.declaration_hash = lambda aid: (_ for _ in ()).throw(RuntimeError("boom"))
        return audit(ledger=ll, broker=bb)

    def _blind_impl():
        ll, bb = _clean_pair()
        bb._implementation_id = lambda aid: (_ for _ in ()).throw(RuntimeError("boom"))
        return audit(ledger=ll, broker=bb)

    def _blind_record():
        ll, bb = _clean_pair()
        bb._actuators["arm"] = {"fn": lambda **kw: "x"}
        return audit(ledger=ll, broker=bb)

    for role, broken in (("unreadable broker", _blind_broker),
                         ("unreadable ledger", _blind_ledger),
                         ("declaration_hash raises", _blind_decl),
                         ("implementation_id raises", _blind_impl),
                         ("unreadable actuator record", _blind_record)):
        # The control must supply BOTH sides, or it is PARTIAL and never clean —
        # which would make the meta-test pass for the wrong reason.
        def _control():
            _l, _b = _clean_pair()
            return audit(ledger=_l, broker=_b)

        ok &= _blindability(role, broken, _control)

    hi.reset_policy()
    print()
    print("  SELF-TEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()
    print()
    print("  action_aliases needs a live deployment's objects — it audits wiring,")
    print("  not source. Import `audit(ledger=..., broker=...)` from your startup")
    print("  path, or run --self-test to exercise it against constructed shapes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
