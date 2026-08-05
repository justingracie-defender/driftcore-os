"""
isolation_monitor.py — something that keeps looking.

WHY THIS EXISTS
───────────────
`verify_process()` answers "was this process's capability surface clean at this
instant". Nothing re-asked. The broker's attestation ages out and the wall stops
serving, which is fail-closed and correct — but it makes two very different facts
look identical:

    the surface DRIFTED (a socket appeared, a capability came back)
    nobody has LOOKED lately

The first is an attack in progress. The second is a supervisor that went to lunch.
Both presented as "stale attestation".

The July 2026 incident is what this is for. Its recon phase performed roughly 6,191
host / filesystem / /proc / network enumerations — the same enumeration this module
does, run from the other side of the boundary, looking for exactly what a bouncer
looks for. None of it crossed a broker, so a governor counting mediated actions saw
zero. Something has to watch the surface itself rather than the requests.

WHERE IT RUNS, AND WHY THAT IS THE WHOLE POINT
──────────────────────────────────────────────
In the SUPERVISOR, never in the subject. A process cannot audit its own confinement;
that is why `verify_self()` is marked untrusted and `attest_or_refuse()` rejects a
passing self-report. This module inherits that rule: it verifies someone ELSE.

WHAT IT IS NOT
──────────────
It is DETECTION, not prevention. It cannot stop a socket being opened; it can notice
one exists and trip a fail-closed response. The controls that actually prevent are an
empty network namespace and a real seccomp filter, neither of which any Python can
install or maintain. Treat a clean monitor as evidence that nothing observable has
changed — never as proof that nothing can.

THE FAILURE MODE THIS MODULE MUST NOT HAVE
──────────────────────────────────────────
A monitor that has stopped running looks exactly like a monitor seeing nothing wrong.
This project has already shipped that bug twice — a ratchet comparing a missing key to
a missing key, and a duplicated safety mechanism reporting success for code that never
ran. Here it is closed by construction rather than by care: the monitor's only way of
saying "still clean" is to REFRESH the broker's attestation, and an attestation that
stops being refreshed goes stale and stops the wall. Silence is not consent; silence is
a countdown.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from driftcore.kernel.isolation_manifest import (
    IsolationManifest, IsolationReport, verify_process,
)


@dataclass
class MonitorStatus:
    running: bool = False
    checks: int = 0
    drifts: int = 0
    errors: int = 0
    refreshes: int = 0            # attestations the broker ACCEPTED
    refresh_failures: int = 0     # verified clean, but the refresh did not land
    consecutive_refresh_failures: int = 0
    last_check_seconds: float = 0.0
    last_check_at: Optional[str] = None
    last_check_monotonic: Optional[float] = None
    last_verdict: Optional[str] = None
    consecutive_failures: int = 0


class IsolationMonitor:
    """Re-verifies a subject process on an interval, from outside it.

    on_verified: called with a clean report. In practice
        `broker.refresh_isolation_attestation` — which is what makes a stopped
        monitor fail closed instead of silent.
    on_drift:    called with the failing report. The fail-closed response: halt the
        broker, kill the sandbox, page a human. Deliberately injected rather than
        chosen here, because what to do about a compromised process is a deployment
        decision and this module's job is to FIND, not to decide.
    """

    def __init__(self, pid: int, manifest: IsolationManifest, *,
                 interval_seconds: float = 30.0,
                 on_verified: Optional[Callable[[IsolationReport], None]] = None,
                 on_drift: Optional[Callable[[IsolationReport], None]] = None,
                 reference_netns: Optional[str] = None,
                 stall_factor: float = 3.0,
                 first_check_grace_seconds: float = 60.0,
                 max_consecutive_failures: int = 3,
                 on_persistent_failure: Optional[Callable[[MonitorStatus], None]] = None,
                 _source_factory_for_tests: Optional[Callable[[], object]] = None):
        # TRUST BOUNDARY (external review). The source factory decides WHAT the monitor
        # looks at. An attacker who can influence it gets a monitor that inspects a
        # clean fiction and keeps refreshing the attestation on its behalf — the worst
        # possible outcome, because the wall then serves with confidence. Renamed to
        # say out loud that production must never pass it; the real path builds its own
        # _ProcSource from the pid.
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be > 0")
        self._pid = pid
        self._manifest = manifest
        self._interval = float(interval_seconds)
        self._on_verified = on_verified
        self._on_drift = on_drift
        self._reference_netns = reference_netns
        self._source_factory = _source_factory_for_tests
        self._max_consecutive_failures = max(1, int(max_consecutive_failures))
        self._stall_seconds = max(1.0, float(stall_factor)) * self._interval
        # A monitor that has NEVER completed a check gets a bounded grace, not a
        # grace proportional to its interval. At a 600s interval the stall window is
        # 1800s, so the object claimed to be watching for thirty minutes before
        # verifying anything even once — "about to look" reported as "looking".
        self._first_grace = min(self._stall_seconds, max(1.0,
                                                         float(first_check_grace_seconds)))
        self._started_monotonic = time.monotonic()
        self._on_persistent_failure = on_persistent_failure
        self._status = MonitorStatus()
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ── one pass, exposed so it can be driven synchronously in tests ──
    def check_once(self) -> IsolationReport:
        _t0 = time.monotonic()
        """Verify the subject once and dispatch. Never raises: a monitor that dies on
        an exception is a monitor that stops looking, which is the failure this module
        exists to avoid."""
        try:
            src = self._source_factory() if self._source_factory else None
            report = verify_process(self._pid, self._manifest,
                                    compare_to_self=self._reference_netns is None,
                                    reference_netns=self._reference_netns,
                                    source=src)
        except Exception as e:
            with self._lock:
                self._status.errors += 1
                self._status.checks += 1
                self._status.consecutive_failures += 1
                self._status.last_check_at = datetime.now(timezone.utc).isoformat()
                self._status.last_check_monotonic = time.monotonic()
                self._status.last_verdict = f"monitor error: {e!r}"
            # A monitor that cannot verify has NOT verified. Treated as drift, because
            # "I could not look" and "I looked and it was fine" must never coincide.
            report = IsolationReport(
                trusted=True, source=f"supervisor:{self._pid}",
                findings=[f"the monitor could not complete a check ({e!r}); a check "
                          f"that cannot run has not passed"])
            self._dispatch_drift(report)
            return report

        with self._lock:
            self._status.checks += 1
            self._status.last_check_at = datetime.now(timezone.utc).isoformat()
            self._status.last_check_monotonic = time.monotonic()
            # A verify_process creeping from 2s toward a 90s stall threshold is already
            # in danger and currently surfaces as nothing at all until it trips.
            self._status.last_check_seconds = time.monotonic() - _t0
            self._status.last_verdict = ("clean" if report.permitted
                                         else f"{len(report.findings)} finding(s)")
        if report.permitted:
            with self._lock:
                self._status.consecutive_failures = 0
            if self._on_verified:
                # VERIFYING and REFRESHING are two different successes, and conflating
                # them hid a whole failure mode: a callback that silently does nothing,
                # or that raises every time, leaves the model fail-closed (the
                # attestation ages out and the wall stops) while looking like healthy
                # monitoring. Counted separately so an operator can tell "the subject
                # is dirty" from "the subject is clean and the broker will not accept
                # my word for it".
                try:
                    self._on_verified(report)
                    with self._lock:
                        self._status.refreshes += 1
                        self._status.consecutive_refresh_failures = 0
                except Exception:
                    # A REFUSED REFRESH STREAK IS ALSO A CONDITION. consecutive_failures
                    # tracks drift and resets on every clean report, so a broker that
                    # rejected every single refresh incremented refresh_failures forever
                    # while the escalation channel — added precisely to stop silent
                    # repeated failure — never fired once. Same bug, other success path.
                    with self._lock:
                        self._status.refresh_failures += 1
                        self._status.consecutive_refresh_failures += 1
                        self._status.last_verdict = (
                            "clean, but the attestation refresh FAILED")
                        streak = self._status.consecutive_refresh_failures
                        snap = MonitorStatus(**vars(self._status))
                    snap.running = self.is_watching()
                    if (streak >= self._max_consecutive_failures
                            and self._on_persistent_failure):
                        try:
                            self._on_persistent_failure(snap)
                        except Exception:
                            pass
        else:
            with self._lock:
                self._status.drifts += 1
                self._status.consecutive_failures += 1
            self._dispatch_drift(report)
        return report

    def _dispatch_drift(self, report: IsolationReport) -> None:
        # PERSISTENT FAILURE (external review). Swallowing a handler exception keeps the
        # monitor looking, which is right — but it also means a failure mode that
        # repeats forever repeats SILENTLY. The counter existed and nothing compared it
        # to anything. A single drift is an event; N in a row is a condition, and the
        # two deserve different responses.
        with self._lock:
            consecutive = self._status.consecutive_failures
            snap = MonitorStatus(**vars(self._status))
        snap.running = self.is_watching()
        if consecutive >= self._max_consecutive_failures and self._on_persistent_failure:
            try:
                self._on_persistent_failure(snap)
            except Exception:
                pass
        if not self._on_drift:
            return
        try:
            self._on_drift(report)
        except Exception:
            pass          # a broken handler must not stop the monitor from looking

    # ── lifecycle ──
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()

        self._started_monotonic = time.monotonic()

        def _loop():
            while not self._stop.is_set():
                self.check_once()
                self._stop.wait(self._interval)

        self._thread = threading.Thread(target=_loop, daemon=True,
                                        name=f"isolation-monitor-{self._pid}")
        with self._lock:
            self._status.running = True
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=max(2.0, self._interval))
        with self._lock:
            self._status.running = False

    def is_watching(self) -> bool:
        """Whether monitoring is alive AND making forward progress.

        Two versions of the same bug have lived here. First `running` was a flag set
        in start() and never re-checked, so a dead thread reported True. Then liveness
        meant `thread.is_alive()`, which a thread stuck inside a blocking verification
        satisfies forever while completing zero cycles — alive is not the same as
        working, and a stalled monitor is exactly as blind as a stopped one.

        So progress is part of the answer: a thread that has not completed a check
        within `stall_factor` intervals is not watching, whatever its state says.
        """
        if self._thread is None or not self._thread.is_alive():
            return False
        with self._lock:
            last = self._status.last_check_monotonic
        if last is None:
            # started but no cycle has completed yet; allow one interval of grace
            return (time.monotonic() - self._started_monotonic) <= self._first_grace
        return (time.monotonic() - last) <= self._stall_seconds

    def stall_seconds(self) -> float:
        """How long without a completed check counts as stalled."""
        return self._stall_seconds

    def status(self) -> MonitorStatus:
        with self._lock:
            snap = MonitorStatus(**vars(self._status))
        snap.running = self.is_watching()      # observed, overriding the stored flag
        return snap
