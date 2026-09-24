#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Mutation harness: break one fix at a time, confirm a control catches it.

A control that cannot fail proves nothing. This repo produced three of those in
three days, one of them the coordinator's own. So every mechanism in the patch
has its fix reverted and the envelope suite re-run; if the suite still passes,
the control for that mechanism is decorative and must be rewritten.

COMPOUND MUTATIONS. Since v4, `select_for` has a guard underneath every other
handler: whatever raises, the machine ends on the fallback. That guard MASKS
three older mechanisms (outage ordering, journal-first ordering, the fallback
on an unrecordable widening) — revert any one alone and the guard still lands
the machine safely, so no check can see it. That is defense in depth working,
but it means a single-layer mutation no longer proves the inner layer matters.
Those three are run as compounds (inner layer AND guard removed) and reported
as such. Where a layer can be observed on its own, it has its own isolation
check instead (F2-R3b, F2-R4, F2-R6).

Usage:  python3 mutation_harness_envelope.py [path-to-repo]
Run from (or point at) a tree that already has the envelope patch applied.
"""
import pathlib, shutil, subprocess, sys, tempfile

REPO = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
MOD = "driftcore/governance/physical_envelope.py"
if not (REPO / MOD).exists():
    sys.exit(f"{REPO / MOD} not found — pass the repo root as the first argument")

GUARD_OFF = (
    """                self._commit(self._fallback, float("inf"))
                if isinstance(e, Exception) and not isinstance(e, EnvelopeRefused):""",
    """                if isinstance(e, Exception) and not isinstance(e, EnvelopeRefused):""")

STORE_GUARD_OFF = (
    """            if current != expected or not _advances(current, new):""",
    """            if current != expected:""")

# (name, [(old, new), ...]) — every pair must apply, or the mutation SURVIVES.
MUTATIONS = [
 # ---- layer 1: evidence -> state -> expiry --------------------------------
 ("M1 order-independence: reduce by LIST POSITION instead of sequence", [(
  """            if group is None or ev.sequence > group[0].sequence:
                latest[key] = [ev]
            elif ev.sequence == group[0].sequence:
                group.append(ev)""",
  """            if True:
                latest[key] = [ev]""")]),

 ("M2 signed-FALSE retraction: drop the branch that removes a condition", [(
  """            if not next(iter(values)):""",
  """            if False:""")]),

 ("M3 same-sequence conflict (in one batch): last-writer-wins", [(
  """        in_batch = len(digests) > 1""",
  """        in_batch = False""")]),

 ("M4 cross-source disagreement: resolve to TRUE instead of fail-closed", [(
  """            values = {ev.value for ev in per_source.values()}
            if len(values) > 1:""",
  """            values = {any(ev.value for ev in per_source.values())}
            if False:""")]),

 ("M5 verifier outage: let the exception propagate (the old behaviour)", [(
  """                try:
                    verified = self._verify_proof(ev)
                except Exception as e:      # noqa: BLE001 — see below""",
  """                try:
                    verified = self._verify_proof(ev)
                except ZeroDivisionError as e:""")]),

 ("M5b verifier outage: propagate ANY exception", [(
  """                    verified = self._verify_proof(ev)
                except Exception as e:      # noqa: BLE001 — see below""",
  """                    verified = self._verify_proof(ev)
                except BaseException as e:
                    raise""")]),

 ("M6 epoch binding: accept evidence from any replay-state lifetime", [(
  """            if ev.epoch != self._epoch:""",
  """            if False:""")]),

 ("M7 freshness ceiling: accept any TTL the deployment did not declare", [(
  """            if ttl_seconds > max_ttl:""",
  """            if False:""")]),

 ("M8 deadline extension: same envelope, fresher evidence, deadline NOT moved", [(
  """            self._commit(chosen, deadline, evidence_digest)
            return chosen
        records = """,
  """            return chosen
        records = """)]),

 ("M9 screening purity: let a REJECTED record burn the sequence number", [(
  """            if sequence < high_water:""",
  """            self._high_water.compare_and_set(key, marks[key][2], (sequence, ""))
            if sequence < high_water:""")]),

 ("M10 the reported defect: allow require_proof=True with no verifier", [(
  """        if require_proof and verify_proof is None:""",
  """        if False:""")]),

 ("M11 evidence structure: stop validating ttl/value/sequence at construction", [(
  """        if self.ttl_seconds <= 0:""",
  """        if False:""")]),

 ("M12 replay store: never write it (stale readings win forever)", [(
  """            if self._high_water.compare_and_set(key, raw, entry):""",
  """            if True:""")]),

 ("M14 conflict policy: do NOT advance the replay mark on a conflict", [(
  """            entry = ((seq, CONFLICTED) if conflicted""",
  """            entry = (raw if conflicted""")]),

 ("M15 constructor: accept an empty epoch", [(
  """        if not isinstance(epoch, str) or not epoch.strip():""",
  """        if False:""")]),

 ("M16 constructor: accept an infinite freshness ceiling", [(
  """                or not math.isfinite(max_ttl_seconds)
                or max_ttl_seconds <= 0):""",
  """                or max_ttl_seconds <= 0):""")]),

 # ---- layer 2: declared set -> active envelope ----------------------------
 ("M18a who may add: compare with the CURRENT envelope only (the 700N attack)", [(
  """        new_safest = all(envelope.at_least_as_safe_as(e)
                         for e in self._envelopes)""",
  """        new_safest = (self._active is None
                      or envelope.at_least_as_safe_as(self._active))""")]),

 ("M18b who may add: the original limits.get(d, 0) heuristic (Sol)", [(
  """        new_safest = all(envelope.at_least_as_safe_as(e)
                         for e in self._envelopes)""",
  """        new_safest = self._active is None or not any(
            envelope.limits.get(d, 0) > self._active.limits.get(d, 0)
            for d in envelope.limits)""")]),

 ("M19a fallback frozen at construction (Sol)", [(
  """        if self._fallback is None or (
                envelope.at_least_as_safe_as(self._fallback)
                and not self._fallback.at_least_as_safe_as(envelope)):
            new_fallback = envelope""",
  """        if self._fallback is None:
            new_fallback = envelope""")]),

 ("M19b fallback replaced by ANY declaration (a guessed fallback)", [(
  """        if self._fallback is None or (
                envelope.at_least_as_safe_as(self._fallback)
                and not self._fallback.at_least_as_safe_as(envelope)):
            new_fallback = envelope""",
  """        new_fallback = envelope""")]),

 ("M20 declaration activates immediately, no evidence (Sol)", [(
  """        activate_now = current is None or envelope.at_least_as_safe_as(current)""",
  """        activate_now = True""")]),

 ("M21 clock domain: compare the authority's deadline on the controller clock", [(
  """        deadline = started + (snapshot.expires_at - snapshot.evaluated_at)""",
  """        deadline = snapshot.expires_at""")]),

 ("M22 a SIXTH DOOR: write _active directly in `active` (behaviour identical)", [(
  """            previous = self._active
            self._commit(self._fallback, float("inf"))
            self._log("ENVELOPE_EXPIRED", "system",""",
  """            previous = self._active
            self._active = self._fallback
            self._authorised_until = float("inf")
            self._log("ENVELOPE_EXPIRED", "system",""")]),

 ("M24 _commit: never bound a non-fallback envelope (infinite deadline)", [(
  """        self._authorised_until = (float("inf") if envelope is self._fallback
                                  else deadline)""",
  """        self._authorised_until = float("inf")""")]),

 # ---- layer 3: from SINT's fixture case list, 2026-09-22 -------------------
 ("M25 replay-store READ outage propagates (isolation: F2-R4)", [(
  """                    raw = self._high_water.get(key)
                except Exception as e:      # noqa: BLE001 — see below""",
  """                    raw = self._high_water.get(key)
                except ZeroDivisionError as e:""")]),

 ("M26 replay-store WRITE outage propagates (isolation: F2-R3b)", [(
  """        except Exception as e:      # noqa: BLE001 — an outage, as in _admit""",
  """        except ZeroDivisionError as e:""")]),

 ("M27 conflict recorded as an ordinary mark (seq, '') — Grok's literal clamp, generalized", [(
  """            entry = ((seq, CONFLICTED) if conflicted""",
  """            entry = ((seq, "") if conflicted""")]),

 ("M28 conflict across batches not detected", [(
  """            conflicted = in_batch or (seq == mark and stored != ""
                                      and stored not in digests)""",
  """            conflicted = in_batch""")]),

 ("M29a the authorization names nothing (digest dropped in _commit)", [(
  """        self._evidence_digest = ("" if envelope is self._fallback
                                 else evidence_digest)""",
  """        self._evidence_digest = \"\"""")]),

 ("M29b the digest covers ALL held conditions, not the ones relied on", [(
  """                      for condition in chosen.conditions.required""",
  """                      for condition in snapshot.support""")]),

 ("M30 the fallback guard under select_for removed", [GUARD_OFF]),

 ("M31 a door for the digest outside _commit (behaviour identical)", [(
  """            self.active     # an expired authorization names nothing
            return self._evidence_digest""",
  """            self.active     # an expired authorization names nothing
            self._evidence_digest = self._evidence_digest
            return self._evidence_digest""")]),

 # ---- round 4 (Grok, Sol), 2026-09-23 ---------------------------------------
 ("M33 v4's poison (N + 1, '') restored — overflows a signed 64-bit store at MAX", [(
  """            entry = ((seq, CONFLICTED) if conflicted""",
  """            entry = ((seq + 1, "") if conflicted""")]),

 ("M34 replay marks NOT scoped to the epoch", [(
  """            key = (self._epoch, ev.source, ev.condition)""",
  """            key = ("", ev.source, ev.condition)"""), (
  """            key = (self._epoch, source, condition)""",
  """            key = ("", source, condition)""")]),

 ("M35 admission does not refuse a conflicted sequence (isolation: F0-D12b, F3-M4)", [(
  """            if (sequence == high_water and marks[key][1] == CONFLICTED
                    and ev.value is not False):""",
  """            if False:""")]),

 ("M36 reading digest reverted to sha256(repr(payload))", [(
  """        return hashlib.sha256(self.canonical).hexdigest()""",
  """        return hashlib.sha256(repr(self.payload).encode()).hexdigest()""")]),

 ("M37 the guard catches only Exception (an interrupt leaves 800N standing)", [(
  """            except BaseException as e:
                # The specific handlers""",
  """            except Exception as e:
                # The specific handlers""")]),

 ("M38 the guard wraps interrupts in EnvelopeRefused", [(
  """                if isinstance(e, Exception) and not isinstance(e, EnvelopeRefused):""",
  """                if not isinstance(e, EnvelopeRefused):""")]),

 ("M39 cross-batch conflict detected BEFORE authentication (unauthenticated poison)", [(
  """            if self._require_proof:
                if not ev.proof:""",
  """            if (sequence == high_water
                    and marks[key][1] not in ("", CONFLICTED, ev.digest)):
                self._high_water.compare_and_set(
                    key, marks[key][2], (sequence, CONFLICTED))
            if self._require_proof:
                if not ev.proof:""")]),

 ("M40 any truthy verifier answer authenticates (Sol)", [(
  """                if verified is not True:
                    if verified is False:""",
  """                if not verified:
                    if True:""")]),

 ("M41+S write compares against a FRESH read WITH the store's own guard off", [(
  """            if self._high_water.compare_and_set(key, raw, entry):""",
  """            if self._high_water.compare_and_set(key, self._high_water.get(key), entry):"""), STORE_GUARD_OFF]),

 ("M42 a plain mapping without compare_and_set is accepted", [(
  """        if replay_state is not None and not (""",
  """        if False and not (""")]),

 ("M43 renewing a permissive lease on new evidence is not journaled (Sol)", [(
  """        if chosen is previous and (chosen is self._fallback
                                   or evidence_digest == self._evidence_digest):""",
  """        if chosen is previous:""")]),

 ("M44 an absent dissenting source is forgotten (Sol)", [(
  """            elif (not ev.value and condition in by_condition""",
  """            elif (False and condition in by_condition""")]),

 ("M45 the authorization digest drops the envelope NAME", [(
  """                + _text(active.name)""",
  """                + b"\"""")]),

 ("M46 the authorization digest drops the envelope LIMITS", [(
  """                + _uint64(len(active.limits)) + limits""",
  """                + b"\"""")]),

 ("M47 times with no exact binary64 value accepted at construction", [(
  """                exact = float(val) == val
            except OverflowError:
                exact = False
            if not exact:
                raise EnvelopeRefused(
                    f"evidence for""",
  """                exact = True
            except OverflowError:
                exact = False
            if not exact:
                raise EnvelopeRefused(
                    f"evidence for""")]),

 # ---- round 5 (v6): cold pass, Sol, GLM, 2026-09-23 --------------------------
 ("M48 W1 limits kept as the caller's mutable dict", [(
  """        object.__setattr__(self, "limits", MappingProxyType(frozen))""",
  """        pass""")]),

 ("M49 W1 required kept as the caller's mutable set", [(
  """        object.__setattr__(self, "required", names)""",
  """        pass""")]),

 ("M50 the store's own regression guard removed (isolation: F4-G1)", [STORE_GUARD_OFF]),

 ("M51 W4 evidence subclasses admitted", [(
  """            if type(ev) is not ConditionEvidence:""",
  """            if not isinstance(ev, ConditionEvidence):""")]),

 ("M52 S1 strings stored as given (subclasses, Enum members)", [(
  """    plain = str.__str__(value)
    if not _utf8_ok(plain):""",
  """    plain = value
    if not _utf8_ok(plain):""")]),

 ("M53 W2 the unchanged-reading shortcut restored (no compare-and-set)", [(
  """            if self._high_water.compare_and_set(key, raw, entry):""",
  """            if entry == raw:
                return "conflict" if conflicted else "accepted"
            if self._high_water.compare_and_set(key, raw, entry):""")]),

 ("M54 W9/A1 a lost compare-and-set is not re-read and re-judged", [(
  """            raw = self._high_water.get(key)
        if conflicted:""",
  """            break
        if conflicted:""")]),

 ("M55 W3 a conflict erases the source's dissent (v5)", [(
  """                self._remember_dissent(source, condition, group)
                rejected.append(
                    f"{condition}: conflicting readings""",
  """                self._latest.pop((source, condition), None)
                rejected.append(
                    f"{condition}: conflicting readings""")]),

 ("M56 W3 a signed FALSE at a conflicted sequence refused, not counted", [(
  """                    and ev.value is not False):""",
  """                    ):""")]),

 ("M57 M3 the fallback record does not name the dispute", [(
  """            causes = [r for r in snapshot.rejected
                      if r.split(":", 1)[0] in snapshot.conflicts]""",
  """            causes = []""")]),

 ("M58 W6 expiry not processed before selecting", [(
  """        self._expire_if_due()
        started = self._clock()""",
  """        started = self._clock()""")]),

 ("M59 W10 no deadline re-check before select_for returns", [(
  """        self._expire_if_due()
        return self._active""",
  """        return self._active""")]),

 ("M60 W5 an unconditional non-safest declaration accepted", [(
  """        if not new_safest and not envelope.conditions.required:""",
  """        if False:""")]),

 ("M61 W7 enforcement rank ignored", [(
  """                and math.isfinite(theirs) and mine >= theirs)""",
  """                and math.isfinite(theirs))""")]),

 ("M62 M1 request_change activation inherits the old evidence digest", [(
  """            self._commit(envelope, self._authorised_until,
                         self._evidence_digest_for(envelope, self._last_snapshot))""",
  """            self._commit(envelope, self._authorised_until, self._evidence_digest)""")]),

 ("M63 M1 authorization digest empty whenever evidence is empty", [(
  """            if active is None or active is self._fallback:""",
  """            if active is None or not evidence:""")]),

 ("M64 M2 the verifier-outage record does not name the record", [(
  """                        f"verifier raised {type(e).__name__} on {ev.condition!r} "
                        f"from {ev.source!r} at sequence {sequence}")""",
  """                        f"verifier raised {type(e).__name__}")""")]),

 ("M65 W8 one lock per wrapper, not per mapping", [(
  """        self._shared = _lock_for(self._m)""",
  """        self._shared = _SharedLock(self._m)""")]),

 ("M66 a NaN clock extends a wide authorization (main)", [(
  """        lapsed = (not math.isfinite(now) or math.isnan(deadline)
                  or now > deadline)""",
  """        lapsed = now > deadline""")]),

 ("M67 S3 lone surrogates accepted in names", [(
  """    if not _utf8_ok(plain):
        raise EnvelopeRefused(""",
  """    if False:
        raise EnvelopeRefused(""")]),

 ("M47b S2 limits with no exact binary64 value accepted", [(
  """                exact = float(val) == val
            except OverflowError:
                exact = False
            if not exact:
                raise EnvelopeRefused(
                    f"{self.name}.{dim}""",
  """                exact = True
            except OverflowError:
                exact = False
            if not exact:
                raise EnvelopeRefused(
                    f"{self.name}.{dim}""")]),

 ("M74 X1 evidence whose expiry overflows accepted at construction", [(
  """            finite_expiry = math.isfinite(self.issued_at + self.ttl_seconds)""",
  """            finite_expiry = True""")]),

 ("M75 X1 overflowing expiry not re-checked at the trust boundary", [(
  """                        and math.isfinite(issued_at + ttl_seconds)
""",
  """""")]),

 ("M76 C1 an injected clock that steps back is believed", [(
  """            now = self._time_floor if finite else raw""",
  """            now = raw""")]),

 ("M78 C2 a clock that is not a number raises instead of judging stale", [(
  """        try:
            finite = math.isfinite(raw)
        except (TypeError, ValueError, OverflowError):""",
  """        try:
            finite = math.isfinite(raw)
        except ZeroDivisionError:""")]),

 ("M79 U1 unconditional wide envelopes accepted at construction by default", [(
  """        if loose and not allow_unconditional_wide:""",
  """        if False:""")]),

 ("M80 U2 an opted-in unconditional wide envelope is not recorded", [(
  """                  + (f"; unconditional wide envelope(s) allowed by "
                     f"configuration: {list(self._unconditional_wide)}"
                     if self._unconditional_wide else ""))""",
  """                  )""")]),

 ("M77 W1 pickling does not rebuild through the constructor", [(
  """    def __reduce__(self):""",
  """    def _unused_reduce(self):""")]),

 # ---- checks that could not fail in v5 (independent cold pass, T1-T4) --------
 ("M17 every transition treated as toward safety (guard IN place; T1)", [(
  """        current = self._active
        return (chosen is self._fallback or current is None or chosen is None
                or chosen.at_least_as_safe_as(current))""",
  """        current = self._active
        return True""")]),

 ("M68 the renewal branch deleted (guard IN place; T1)", [(
  """        if chosen is previous:
            # RENEWING A PERMISSIVE LEASE""",
  """        if False:
            # RENEWING A PERMISSIVE LEASE""")]),

 ("M69 a sixth door by tuple unpacking, behaviour IDENTICAL (only T2 can see it)", [(
  """            previous = self._active
            self._commit(self._fallback, float("inf"))
            self._log("ENVELOPE_EXPIRED", "system",""",
  """            previous = self._active
            self._active, self._authorised_until, self._evidence_digest = (
                self._fallback, float("inf"), "")
            self._log("ENVELOPE_EXPIRED", "system",""")]),

 ("M73 a sixth door by setattr, behaviour IDENTICAL (only T2 can see it)", [(
  """            previous = self._active
            self._commit(self._fallback, float("inf"))
            self._log("ENVELOPE_EXPIRED", "system",""",
  """            previous = self._active
            setattr(self, "_active", self._fallback)
            setattr(self, "_authorised_until", float("inf"))
            setattr(self, "_evidence_digest", "")
            self._log("ENVELOPE_EXPIRED", "system",""")]),

 ("M70 the authority's lock removed (T3)", [(
  """        with self._lock:
            if finite and not raw < self._time_floor:""",
  """        if True:
            if finite and not raw < self._time_floor:""")]),

 ("M71 the controller's lock removed from select_for (T3)", [(
  """        with self._lock:
            try:
                return self._select_locked(evidence)""",
  """        if True:
            try:
                return self._select_locked(evidence)""")]),

 ("M72 a hidden physical constant in the module (T4)", [(
  """MAX_SEQUENCE = 2 ** 63 - 1
""",
  """MAX_SEQUENCE = 2 ** 63 - 1
FORCE_OVERRIDE_N = 5000.0
""")]),

 # ---- compounds: inner layers the guard now masks --------------------------
 ("M13+G outage ordering (report before demoting) WITH the guard removed", [(
  """        previous = self._active
        self._commit(self._fallback, float("inf"))
        log_failure = None""",
  """        previous = self._active
        raise EnvelopeRefused("verifier outage (reported before demoting)")
        log_failure = None"""), GUARD_OFF]),

 ("M17+G every transition treated as toward safety WITH the guard removed", [(
  """        current = self._active
        return (chosen is self._fallback or current is None or chosen is None
                or chosen.at_least_as_safe_as(current))""",
  """        current = self._active
        return True"""), GUARD_OFF]),

 ("M23+G unrecordable widening stays on previous WITH the guard removed", [(
  """        except EnvelopeRefused as e:
            self._commit(self._fallback, float("inf"))
            raise EnvelopeRefused(
                f"refused to activate""",
  """        except EnvelopeRefused as e:
            raise EnvelopeRefused(
                f"refused to activate"""), GUARD_OFF]),
]


def run(tree):
    r = subprocess.run([sys.executable, "test_physical_envelope.py"],
                       cwd=tree, capture_output=True, text=True, timeout=300)
    return r.returncode, (r.stdout + r.stderr)


def first_failure(out):
    for line in out.splitlines():
        if line.startswith("AssertionError: FAIL:"):
            return " ".join(line.split())[21:150]
        if line.startswith("AssertionError: PRIMER FAILED"):
            return "PRIMER FAILED — the attack could not even be set up"
    for line in out.splitlines():
        if line.startswith(("ValueError", "TypeError", "RuntimeError",
                            "KeyError", "EnvelopeRefused", "ConnectionError",
                            "driftcore")):
            return " ".join(line.split())[:120]
    return "raised before any check" if "Traceback" in out else "NO CONTROL FAILED"


with tempfile.TemporaryDirectory() as td:
    work = pathlib.Path(td) / "repo"
    shutil.copytree(REPO, work, symlinks=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git"))
    pristine = (work / MOD).read_text()

    code, out = run(work)
    print(f"BASELINE (unmutated): exit {code} | {out.strip().splitlines()[-1]}")
    assert code == 0, "baseline must pass before mutating"
    print()

    survivors = []
    for name, pairs in MUTATIONS:
        mutated, missing = pristine, []
        for old, new in pairs:
            if mutated.count(old) != 1:
                missing.append(f"anchor matches {mutated.count(old)} times")
                continue
            mutated = mutated.replace(old, new, 1)
        if missing:
            print(f"  !! {name}\n       NOT APPLIED ({'; '.join(missing)})")
            survivors.append(name)
            continue
        (work / MOD).write_text(mutated)
        for p in work.rglob("__pycache__"):
            shutil.rmtree(p, ignore_errors=True)
        code, out = run(work)
        caught = code != 0
        print(f"  {'CAUGHT ' if caught else 'SURVIVED'} {name}")
        print(f"           -> {first_failure(out)}")
        if not caught:
            survivors.append(name)
    (work / MOD).write_text(pristine)

    print()
    if survivors:
        print(f"{len(survivors)} MUTATION(S) SURVIVED OR DID NOT APPLY — "
              f"those controls are decorative:")
        for s in survivors:
            print("   ", s)
        sys.exit(1)
    print(f"All {len(MUTATIONS)} mutations caught. Every fix has a control that "
          f"can fail.")
