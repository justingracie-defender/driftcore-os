"""
safe_halt.py — Graduated Halt System

Halting is not binary. There are degrees.
A soft halt pauses. A hard halt stops. Isolation cuts the wire.
Recovery is always possible — but only after verification.
"""

import threading
from collections import deque
from datetime import datetime, timezone

MAX_LOG = 5000   # ring-buffer bound: the halt log must not be a DoS surface itself


RELEASE_ACTION = "safe_halt_release"


def _is_human(authorised_by, *, action: str) -> bool:
    """Shared identity gate, guarded.

    CLAIM gate-never-raises: no value of `authorised_by`, and no failure to import
    the identity module, produces an exception here — an unavailable identity means
    NOT human, never a crash at an authorization site.

    NOT pinned to ATTESTED, deliberately. A pin was tried here on 2026-08-31 and
    reverted: it broke 7 checks across test_halt_and_restart.py and
    test_halt_interlock_integration.py, and on reading, those checks were right and
    the pin was wrong. This module implements a SEVERITY LADDER — a HARD halt already
    routes to RestartAuthority.evaluate() for signed multi-party approval, while a
    SOFT halt is documented as software-only recovery with a simple release. Pinning
    the shared gate flattened the ladder, and it also swallowed the HARD refusal
    message that names RestartAuthority, leaving an operator refused with no
    direction. An operator who cannot find the sanctioned path is an operator who
    builds their own.

    The unconfigured-deployment hole is still open HERE and is tracked separately:
    with no `self._verifier` installed, a SOFT halt is releasable by any string off
    the LABEL_ONLY denylist. The narrower fix is to fail closed only when no verifier
    is present, rather than to demand an attestation always. Not yet decided.
    """
    try:
        from driftcore.authority.human_identity import is_human
    except Exception:
        return False
    try:
        return bool(is_human(authorised_by, action=action))
    except Exception:
        return False


def _policy_generation():
    """CLAIM policy-unpinned-refuses: a failed policy read yields None, and None is
    never equal to any version including another None, so a caller comparing a
    snapshot against a later read cannot mistake two failed lookups for an
    unchanged policy.

    CLAIM policy-gate-never-raises: no failure of the identity module produces an
    exception here, matching `_is_human`'s contract at the same site.
    """
    try:
        from driftcore.authority.human_identity import policy_generation
        g = policy_generation()
    except Exception:
        return None
    return g if isinstance(g, int) else None


class SafeHalt:

    # Halt severity is ORDERED. A halt may ratchet UP freely — any subsystem that
    # sees something worse should be able to escalate without asking. It may never
    # ratchet DOWN except through release(), which is authorised.
    _RANK = {None: 0, "SOFT": 1, "HARD": 2}

    # (red-team #1, P0) The MINIMUM restart-approval severity each halt level demands.
    # This is derived from the halt state, never accepted from the caller: a HARD halt
    # was released with a single OPERATOR approval because the caller passed
    # severity=MINOR, downgrading a two-person requirement (SEVERE needs OPERATOR plus
    # TECHNICIAN-or-MANUFACTURER) to one person by supplying an argument. That is the
    # same class as the authorized_by bug one level up: the component asking to resume
    # must not get to define what authorisation is sufficient for its own resumption.
    _HALT_REQUIRES = {"SOFT": "MODERATE", "HARD": "SEVERE"}

    # Cap on how many approvals will be signature-checked in one call. Verification is
    # cryptographic work driven by caller-supplied input, the same DoS shape already
    # bounded on the halt log.
    MAX_APPROVALS = 64

    def __init__(self, verifier=None, restart_authority=None,
                 severity_for_release=None):
        self.active = False
        self.level = None
        # Releases accepted on a label that nothing could verify. Non-empty means the
        # release log cannot be read as evidence a human acted. Mirrors
        # hardware_safety.unconfirmed_stops.
        self.unverified_releases: list = []
        # (red-team, self cold pass S1/S3) an unauthenticated caller can call hard_halt()
        # in a tight loop at zero cost; each call logs. A plain list is both unbounded
        # (the same memory-exhaustion shape found in sensor_interfaces this session) and
        # non-durable — lost on crash or restart. Bounded here as a floor; making the
        # log land in the real hash-chained audit trail is the deployment step, named
        # explicitly rather than silently assumed to already be true.
        self.log = deque(maxlen=MAX_LOG)
        # (red-team) `authorized_by` is a STRING THE CALLER CHOOSES. `release("agent")`
        # was refused but `release("human_operator")` released a HARD halt — naming an
        # authority is not proof of it, which is the failure this project hunts
        # everywhere else. A verifier is a callable(principal) -> bool supplied by the
        # deployment; without one, only SOFT halts can be released here and anything
        # more serious must go through governance.restart_authority.
        self._verifier = verifier
        # (red-team #7) SafeHalt.release() and RestartAuthority were two release paths
        # of very different strength, and NOTHING composed them: a single verifier
        # callable released a HARD halt while the multi-role, signed, distinct-person,
        # TTL-bounded path sat unused. An operator taking the weaker path silently
        # downgrades the protection the stronger one exists to provide. Same failure
        # class as the halt interlock — two modules individually correct, unsafe
        # because nothing joined them. When a restart_authority is supplied, a HARD
        # release MUST go through it; the verifier alone is no longer sufficient.
        # (red-team #3) halt/release are read-decide-mutate sequences on shared state
        # with no lock: thread A could verify a release while thread B raised a HARD
        # halt, then A clears active/level and the just-raised halt disappears. The
        # decision and the mutation must be one atomic step.
        self._lock = threading.RLock()
        # (red-team #3, 2026-09-01) Monotonic counter bumped on EVERY halt-state
        # mutation. Both release paths decide against a snapshot and then mutate; this
        # is what lets them detect that the state moved underneath them. An
        # (active, level) comparison is not sufficient — SOFT -> released -> SOFT is an
        # ABA sequence that compares equal while being a completely different halt.
        self._generation = 0
        self._restart_authority = restart_authority
        self._severity_for_release = severity_for_release

    def soft_halt(self) -> str:
        # (red-team) This used to overwrite `level` unconditionally, so calling
        # soft_halt() while in HARD halt DOWNGRADED it: "all operations suspended"
        # silently became "non-critical ops paused", with no authorisation and nothing
        # in the log to show a halt had been weakened. Escalation only.
        return self._escalate_to("SOFT",
                                 "SYSTEM_IN_SOFT_HALT — Non-critical ops paused")

    def hard_halt(self) -> str:
        return self._escalate_to("HARD",
                                 "SYSTEM_IN_HARD_HALT — All operations suspended")

    def _escalate_to(self, level: str, message: str) -> str:
        """Raise the halt to `level`. Never lowers it."""
        with self._lock:
            return self._escalate_to_locked(level, message)

    def _escalate_to_locked(self, level: str, message: str) -> str:
        # (red-team, self cold pass S2) _RANK[level] on an unranked level raised
        # KeyError. A halt-severity method that CRASHES on unexpected input is a
        # fail-OPEN pattern dressed as a bug: whatever called this expected a halt to
        # be recorded, an exception propagating up may abort the caller before the
        # halt is ever recorded as active. Unknown severities are refused explicitly.
        if level not in self._RANK:
            self._log(f"HALT_REQUEST_UNKNOWN_LEVEL={level!r}_REFUSED")
            raise ValueError(
                f"{level!r} is not a recognised halt level (know: "
                f"{sorted(k for k in self._RANK if k)}). Refusing rather than silently "
                f"either accepting or crashing past the halt.")
        if self._RANK[level] <= self._RANK[self.level] and self.active:
            self._log(f"{level}_HALT_REQUESTED_WHILE_IN_{self.level} — held at "
                      f"{self.level} (halts do not downgrade)")
            return (f"SYSTEM_REMAINS_IN_{self.level}_HALT — a halt is never weakened "
                    f"by a lesser one; release it deliberately instead")
        self.active = True
        self.level = level
        self._generation += 1
        self._log(f"{level}_HALT_TRIGGERED")
        return message

    def trigger(self) -> str:
        """Default halt — goes to hard halt."""
        return self.hard_halt()

    def release(self, authorized_by: str) -> str:
        """
        NOTE (v3.5): This simple string-based release is retained for
        MINOR severity / software-only recovery only. For anything more
        serious, use driftcore.governance.restart_authority.RestartAuthority,
        which requires signed, role-based, multi-party approval scaled to
        severity and embodiment class. Do not rely on this method alone to
        release a physically-capable system after a serious fault.

        (red-team 2026-08-31) `authorized_by` was `= "human_operator"`. Law Zero
        item 2 removed that default from SafetyKernel.release and left it here, so
        `SafeHalt().release()` still cleared a SOFT halt and wrote "HALT_RELEASED by
        human_operator" — a log naming a person who was never asked. Now required.
        No caller in the repo passed it bare, so nothing breaks: the default was
        only ever reachable by a caller who had not thought about who was releasing.
        """
        # (red-team #3, 2026-09-01) This method was a read-decide-mutate sequence with
        # NO lock, while hard_halt() took one. Demonstrated deterministically rather
        # than theorised: a blocking verifier held this method past its decision point,
        # hard_halt() succeeded from another thread because nothing blocked it, and the
        # returning release then cleared a halt it had never evaluated. The existing
        # 5/5 concurrency test passing was not evidence of correctness — the window is
        # only as wide as the verifier is slow, and the verifier is deployment-supplied.
        #
        # The lock is deliberately NOT held across `_is_human` or `self._verifier`.
        # Those are external code; holding a safety-kernel lock across a third party
        # means a slow or wedged verifier blocks hard_halt(). A halt that cannot be
        # RAISED is a worse failure than a halt wrongly released, and this project's
        # own rule is that fail-closed means end up safe, not seize up. So the shape is
        # snapshot -> decide unlocked -> compare-and-swap.
        # (red-team #3, 2026-09-01) The snapshot must contain EVERYTHING whose change
        # could invalidate the authorization, not just the halt level. Two stale-state
        # channels were demonstrated past the first version of this fix, both of which
        # left `_generation` untouched because (active, level) never moved:
        #   - the identity POLICY tightening mid-flight (public API:
        #     register_human_principal / set_verifier), so a release permitted under
        #     LABEL_ONLY committed under REGISTERED and was logged as VERIFIED — the
        #     C2 integrity signal reporting that somebody checked when nobody did;
        #   - a RestartAuthority installed mid-flight, so the HARD-halt gate that was
        #     evaluated as absent stayed absent and the weak path released a HARD halt.
        # Widening the snapshot is the fix; the halt counter alone was not enough.
        with self._lock:
            snap_level = self.level
            snap_generation = self._generation
            snap_authority = self._restart_authority
            snap_verifier = self._verifier
        snap_policy = _policy_generation()
        # (red-team #7) This must be checked BEFORE the verifier branch. Placed after
        # it, an installed verifier short-circuited the rule and the weak path still
        # released a HARD halt — the fix was present but unreachable, which is worse
        # than absent because it reads as closed.
        if snap_authority is not None and snap_level == "HARD":
            self._log(f"RELEASE_DENIED hard_requires_restart_authority "
                      f"principal={authorized_by!r}")
            return ("RELEASE_DENIED — a HARD halt is released only through "
                    "RestartAuthority.evaluate() with signed, role-correct approvals "
                    "from distinct people. Use release_with_approvals().")
        # (red-team, authority_sites sweep 2026-08-15.) This was a denylist of one
        # string: `release()` with no arguments returned SYSTEM_RESUMED on a soft halt,
        # because the parameter defaults to "human_operator". A verifier, when
        # installed, caught it below — but "when installed" is not a guarantee, and an
        # unconfigured deployment is exactly where this fires. The shared gate is
        # consulted FIRST so the site strengthens with the deployment's identity mode
        # instead of being frozen at a one-word list; the verifier check below is kept
        # as the second layer, not replaced by this.
        if not _is_human(authorized_by, action=RELEASE_ACTION):
            self._log(f"RELEASE_DENIED principal={authorized_by!r}")
            return ("RELEASE_DENIED — Only human operators can release a halt. "
                    f"{authorized_by!r} did not pass the shared human identity gate.")
        # (red-team) A denylist of one string is not authorisation: every principal
        # except the literal "agent" passed, so `release("human_operator")` freed a
        # HARD halt. With a verifier installed the principal must actually verify.
        if snap_verifier is not None:
            try:
                ok = bool(snap_verifier(authorized_by))
            except Exception as e:
                self._log(f"RELEASE_DENIED verifier_error={e!r}")
                return ("RELEASE_DENIED — the authorisation check failed; a halt is "
                        "not released on an unanswered question")
            if not ok:
                self._log(f"RELEASE_DENIED unverified={authorized_by!r}")
                return (f"RELEASE_DENIED — {authorized_by!r} did not verify as a human "
                        f"operator")
        elif snap_level == "HARD":
            # No verifier and a serious halt: refuse rather than accept a bare string.
            self._log(f"RELEASE_DENIED no_verifier level=HARD principal={authorized_by!r}")
            return ("RELEASE_DENIED — releasing a HARD halt needs a real authorisation "
                    "check. Install a verifier, or use "
                    "governance.restart_authority.RestartAuthority, which requires "
                    "signed, role-based, multi-party approval scaled to severity.")
        # (red-team 2026-08-31) The remaining hole in this file: with no verifier
        # installed AND the shared identity module in LABEL_ONLY, the gate above is a
        # six-word denylist, so release("planner_agent_7") cleared a SOFT halt and the
        # log recorded it exactly like a verified human release. Refusing was tried
        # and reverted — it flattened the SOFT/HARD ladder and left operators with no
        # sanctioned path. So the SOFT path stays open and the gap is made VISIBLE
        # instead, which is the rule hardware_safety already follows for simulated
        # relays: a stop that could not be confirmed is recorded as unconfirmed, never
        # as done. "We could not check" must never be readable as "we checked".
        released_level = snap_level
        verifiable = snap_verifier is not None
        if not verifiable:
            try:
                from driftcore.authority.human_identity import status as _id_status
                verifiable = bool(_id_status().get("secure") is True)
            except Exception:
                verifiable = False     # no identity module means not verifiable

        # (red-team #3, 2026-09-01) Compare-and-swap. Everything above decided against
        # `snap_generation`; if the halt state moved while that was happening, this
        # decision concerns a halt that no longer exists and must not be applied to
        # whatever replaced it. The unverified_releases write is inside the lock for a
        # second reason: a release that was REFUSED must not land in the integrity
        # ledger. `release_integrity_ok` is meant to be assertable by a deployment
        # check, so a false entry there is a false alarm on the one signal that says
        # whether the release log can be read as evidence a human acted.
        # Read the policy version BEFORE taking the halt lock: `policy_generation()`
        # takes the identity module's lock, and acquiring it while holding this one
        # would introduce a lock ordering this file cannot see the other side of.
        now_policy = _policy_generation()
        with self._lock:
            if self._generation != snap_generation:
                self._log(f"RELEASE_DENIED state_changed_during_authorization "
                          f"principal={authorized_by!r} was={snap_level!r} "
                          f"now={self.level!r}")
                return ("RELEASE_DENIED — the halt state changed while this release "
                        "was being authorised. The authorisation was granted against a "
                        "halt that no longer holds; re-request against the current "
                        "state.")
            if snap_policy is None or now_policy != snap_policy:
                self._log(f"RELEASE_DENIED policy_changed_during_authorization "
                          f"principal={authorized_by!r} was={snap_policy!r} "
                          f"now={now_policy!r}")
                return ("RELEASE_DENIED — the identity policy changed while this "
                        "release was being authorised, so the principal was checked "
                        "against rules that are no longer in force. Re-request under "
                        "the current policy.")
            if (self._restart_authority is not snap_authority
                    or self._verifier is not snap_verifier):
                self._log(f"RELEASE_DENIED authorization_wiring_changed "
                          f"principal={authorized_by!r} "
                          f"authority_swapped={self._restart_authority is not snap_authority} "
                          f"verifier_swapped={self._verifier is not snap_verifier}")
                return ("RELEASE_DENIED — the authorisation wiring changed while this "
                        "release was being authorised. The gate that was evaluated is "
                        "not the gate now installed; re-request against it.")
            self.active = False
            self.level = None
            self._generation += 1
            if verifiable:
                self._log(f"HALT_RELEASED by {authorized_by}")
            else:
                self.unverified_releases.append({
                    "principal": authorized_by,
                    "level": released_level,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                self._log(f"HALT_RELEASED_UNVERIFIED by {authorized_by!r} "
                          f"(no verifier installed and identity mode is insecure — this "
                          f"principal was accepted as a label, not established as a human)")
        return "SYSTEM_RESUMED"

    def _required_severity(self, caller_supplied=None):
        """The severity the restart authority must be evaluated at.

        Derived from the CURRENT HALT LEVEL. A caller-supplied severity may only make
        the bar STRONGER, never weaker — so passing a lower severity cannot reduce the
        approval requirement, and passing a higher one is always allowed.
        """
        from driftcore.governance.restart_authority import ShutdownSeverity
        order = list(ShutdownSeverity)
        rank = {s: i for i, s in enumerate(order)}
        by_name = {s.name: s for s in order}

        floor = by_name.get(self._HALT_REQUIRES.get(self.level, "SEVERE"), order[-1])
        candidates = [floor]
        if self._severity_for_release is not None:
            candidates.append(self._severity_for_release)
        if caller_supplied is not None:
            candidates.append(caller_supplied)
        # strongest wins: the caller can raise the bar, never lower it
        return max(candidates, key=lambda s: rank.get(s, len(order)))

    def release_with_approvals(self, approvals, severity=None) -> str:
        """Release a halt through the STRONG authority.

        (red-team #7) The only path that may lift a HARD halt once a RestartAuthority
        is installed. Delegates the decision entirely — signature verification, role
        coverage, distinct-person and TTL are RestartAuthority's job, not a second
        weaker copy of them here. A halt is lifted only if that authority returns
        AUTHORIZED; anything else leaves the halt in force.
        """
        if self._restart_authority is None:
            return ("RELEASE_DENIED — no RestartAuthority is installed, so there is no "
                    "authority to evaluate these approvals against. Refusing rather "
                    "than falling back to the weaker path.")
        # (red-team #4) Releasing when nothing is halted produced a bogus SYSTEM_RESUMED
        # audit event with no corresponding halt. Safety state transitions must be
        # explicit: there is nothing to release.
        with self._lock:
            if not self.active:
                self._log("RELEASE_DENIED no_active_halt")
                return "RELEASE_DENIED — there is no active halt to release."
            # (red-team #9) Bound the work an untrusted caller can force before any
            # cryptographic verification happens.
            try:
                n = len(approvals)
            except TypeError:
                return "RELEASE_DENIED — approvals must be a sized collection."
            if n > self.MAX_APPROVALS:
                self._log(f"RELEASE_DENIED too_many_approvals={n}")
                return (f"RELEASE_DENIED — {n} approvals exceeds the limit of "
                        f"{self.MAX_APPROVALS}; refusing before signature verification.")
            try:
                sev = self._required_severity(severity)
            except Exception as e:
                self._log(f"RELEASE_DENIED severity_derivation_failed={e!r}")
                return ("RELEASE_DENIED — the required severity could not be derived "
                        "from the halt state; refusing rather than guessing a bar.")
            # (red-team #3, 2026-09-01) The lock is dropped here, before evaluate() and
            # before the mutation below. `sev` was derived from THIS halt level and is
            # about to be spent against whatever the level is when the authority
            # answers. Demonstrated: a SOFT halt escalated to HARD during evaluate(),
            # and MODERATE-level approvals cleared the HARD halt. That is precisely the
            # severity downgrade red-team #1 closed for the caller-supplied argument,
            # reopened through a timing window instead of a parameter. Snapshot here,
            # revalidate before mutating.
            snap_level = self.level
            snap_generation = self._generation
        try:
            result = self._restart_authority.evaluate(sev, approvals)
        except Exception as e:
            self._log(f"RELEASE_DENIED restart_authority_error={e!r}")
            return ("RELEASE_DENIED — the restart authority could not be evaluated; a "
                    "halt is not lifted on an unanswered question.")
        # (red-team #10) The authority's answer is a plain dict, so validate its SHAPE
        # before acting on it. A None or malformed result would otherwise raise from
        # inside a safety control, or — worse with a different comparison — read as
        # authorised.
        if not isinstance(result, dict):
            self._log(f"RELEASE_DENIED malformed_authority_result="
                      f"{type(result).__name__}")
            return ("RELEASE_DENIED — the restart authority returned a "
                    f"{type(result).__name__}, not a decision. Refusing.")
        status = result.get("status")
        if status not in ("AUTHORIZED", "DENIED", "SIGNATURE_REJECTED"):
            self._log(f"RELEASE_DENIED unrecognised_status={status!r}")
            return (f"RELEASE_DENIED — unrecognised authority status {status!r}; a "
                    f"halt is not lifted on a verdict this code does not understand.")
        if status != "AUTHORIZED":
            self._log(f"RELEASE_DENIED restart_authority={status} severity={sev.name}")
            return f"RELEASE_DENIED — {status}: {str(result.get('reason',''))[:120]}"
        with self._lock:
            if self._generation != snap_generation:
                self._log(f"RELEASE_DENIED state_changed_during_authorization "
                          f"was={snap_level!r} now={self.level!r} "
                          f"evaluated_at={sev.name}")
                return ("RELEASE_DENIED — the halt state changed while the restart "
                        f"authority was evaluating. These approvals were checked "
                        f"against {sev.name}, derived from a {snap_level} halt that no "
                        f"longer holds. Re-submit against the current state.")
            self.active = False
            self.level = None
            self._generation += 1
            self._log(f"SYSTEM_RESUMED via RestartAuthority severity={sev.name} "
                      f"approvers={[a.get('approver_id') for a in result.get('approvals', []) if isinstance(a, dict)]}")
        return "SYSTEM_RESUMED"

    def status(self) -> dict:
        return {
            "active": self.active,
            "level": self.level,
            "unverified_releases": list(self.unverified_releases),
            # False means at least one halt was cleared by a principal nothing could
            # verify. A deployment check should assert this is True.
            "release_integrity_ok": not self.unverified_releases,
        }

    def _log(self, event: str):
        self.log.append({"event": event, "timestamp": datetime.now(timezone.utc).isoformat()})
