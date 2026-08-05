"""
Continuous isolation monitor — the thing that keeps looking.

The gap it closes: verify_process() answered once, and nothing re-asked. So "the
surface drifted" and "nobody looked lately" both presented as a stale attestation.
One is an attack in progress; the other is a supervisor at lunch.
"""
import time
from driftcore.kernel.isolation_manifest import IsolationManifest, IsolationReport
from driftcore.kernel.isolation_monitor import IsolationMonitor

passed = 0
def ok(c, label):
    global passed
    assert c, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")

HOST = "net:[HOST]"
M = IsolationManifest(declared_by="justin")


class Subject:
    def __init__(self):
        self._fds = {"0": "pipe:[1]"}
        self._caps = 0
    def acquire_socket(self):
        self._fds["7"] = "socket:[8080]"
    def acquire_capability(self):
        self._caps = 1 << 13          # CAP_NET_RAW
    def fds(self): return dict(self._fds)
    def netns(self): return "net:[PRIVATE]"
    def interfaces(self): return ["lo"]
    def routes(self): return []
    def net_inodes(self): return {}
    def status(self):
        return {"CapEff": f"{self._caps:016x}", "CapBnd": f"{self._caps:016x}",
                "CapAmb": "0" * 16, "CapPrm": f"{self._caps:016x}", "CapInh": "0" * 16,
                "Seccomp": "2", "Seccomp_filters": "1", "NoNewPrivs": "1"}


print("== a clean subject verifies, and says so by REFRESHING ==")
subj = Subject()
verified, drifted = [], []
mon = IsolationMonitor(1, M, interval_seconds=0.05,
                       reference_netns=HOST,
                       _source_factory_for_tests=lambda: subj,
                       on_verified=verified.append, on_drift=drifted.append)
r = mon.check_once()
ok(r.permitted, "a clean surface verifies")
ok(len(verified) == 1 and not drifted,
   "and the ONLY way the monitor says 'still clean' is by refreshing the "
   "attestation — so a monitor that stops running stops refreshing, the attestation "
   "ages out, and the wall stops. Silence is a countdown, not consent")

print("== the surface DRIFTS mid-run — a socket appears ==")
subj.acquire_socket()
r = mon.check_once()
ok(not r.permitted and len(drifted) == 1,
   "an undeclared socket appearing AFTER the last clean check trips drift. This is "
   "the case a one-shot verifier structurally cannot see")
ok(len(verified) == 1, "and it does NOT refresh the attestation, so the wall winds down")
ok(any("socket" in f for f in r.findings), "the finding names what appeared")

print("== a capability comes back ==")
subj2 = Subject(); subj2.acquire_capability()
d2 = []
mon2 = IsolationMonitor(1, M, interval_seconds=0.05, reference_netns=HOST,
                        _source_factory_for_tests=lambda: subj2, on_drift=d2.append)
r = mon2.check_once()
ok(not r.permitted and d2, "a regained capability trips drift too")

print("== a monitor that CANNOT check has not checked ==")
def _explode():
    raise RuntimeError("proc unreadable")
d3 = []
mon3 = IsolationMonitor(1, M, interval_seconds=0.05, reference_netns=HOST,
                        _source_factory_for_tests=_explode, on_drift=d3.append)
r = mon3.check_once()
ok(not r.permitted and d3,
   "an error during verification is treated as DRIFT — 'I could not look' and "
   "'I looked and it was fine' must never coincide")
ok(mon3.status().errors == 1, "and the error is counted separately from a real drift")

print("== a broken drift handler must not stop the monitor looking ==")
def _bad(_r): raise RuntimeError("handler exploded")
mon4 = IsolationMonitor(1, M, interval_seconds=0.05, reference_netns=HOST,
                        _source_factory_for_tests=lambda: subj, on_drift=_bad)
r = mon4.check_once()
ok(not r.permitted, "the check still completes and still reports drift")
ok(mon4.status().checks == 1, "and the monitor keeps its books")

print("== it runs continuously, not once ==")
subj3 = Subject()
seen = []
mon5 = IsolationMonitor(1, M, interval_seconds=0.02, reference_netns=HOST,
                        _source_factory_for_tests=lambda: subj3, on_verified=seen.append)
mon5.start()
time.sleep(0.15)
subj3.acquire_socket()
time.sleep(0.1)
mon5.stop()
st = mon5.status()
ok(st.checks >= 3, f"the monitor performed repeated checks ({st.checks}), not one")
ok(st.drifts >= 1, "and caught the socket that appeared partway through the run")
ok(not st.running, "stop() halts it cleanly")

print("== honest scope ==")
ok(IsolationMonitor(1, M, interval_seconds=1).status().checks == 0,
   "a fresh monitor has verified NOTHING — it reports zero checks rather than a "
   "reassuring default")
try:
    IsolationMonitor(1, M, interval_seconds=0)
    ok(False, "a zero interval should be refused")
except ValueError:
    ok(True, "a zero/negative interval is refused rather than becoming a busy loop")

print(f"\nALL {passed} CHECKS PASSED")


print()
print("== COLD PASS: a stopped monitor must not claim to be watching ==")
_m = IsolationMonitor(1, M, interval_seconds=0.02, reference_netns=HOST,
                      _source_factory_for_tests=lambda: Subject())
_m.start()
time.sleep(0.05)
ok(_m.status().running is True and _m.is_watching(),
   "a live monitor reports running")
_m._stop.set()
_m._thread.join(timeout=1)
ok(_m.status().running is False,
   "a monitor whose thread has ENDED reports running=False. It was a flag set once in "
   "start() and never re-checked, so a dead thread reported True — and this module's "
   "own header says a stopped monitor must not look like one seeing nothing wrong. "
   "Written, then contradicted forty lines later by a stored boolean")
ok(not _m.is_watching(),
   "is_watching() observes the thread rather than remembering an intention")

print(f"\nALL {passed} CHECKS PASSED")


print()
print("== EXTERNAL REVIEW (Grok) ==")

# #5 — the factory decides WHAT the monitor looks at, so it is a trust boundary.
import inspect as _ins
_params = _ins.signature(IsolationMonitor.__init__).parameters
ok("source_factory" not in _params,
   "the public 'source_factory' is gone. An attacker who could influence it would get "
   "a monitor inspecting a clean fiction while still refreshing the attestation — the "
   "worst outcome, because the wall then serves with confidence")
ok("_source_factory_for_tests" in _params,
   "it survives named so production cannot pass it by accident")

# #8 — a single drift is an event; N in a row is a condition.
_d, _p = [], []
_mf = IsolationMonitor(1, M, interval_seconds=1, reference_netns=HOST,
                       max_consecutive_failures=3,
                       on_drift=_d.append, on_persistent_failure=_p.append,
                       _source_factory_for_tests=lambda: (_ for _ in ()).throw(
                           RuntimeError("proc gone")))
for _ in range(2):
    _mf.check_once()
ok(len(_d) == 2 and not _p,
   "two failures in a row are drifts, not yet a condition")
_mf.check_once()
ok(len(_p) == 1,
   "the THIRD consecutive failure escalates separately. The counter existed and "
   "nothing compared it to anything, so a failure mode that repeated forever repeated "
   "silently")
ok(_p[0].consecutive_failures >= 3 and _p[0].errors >= 3,
   "and the escalation carries the counters, so a watchdog sees how long it has been "
   "failing rather than just that it failed")

# a clean check clears the streak — a condition must be able to end
_ok_mon = IsolationMonitor(1, M, interval_seconds=1, reference_netns=HOST,
                           max_consecutive_failures=2,
                           _source_factory_for_tests=lambda: Subject())
_ok_mon.check_once()
ok(_ok_mon.status().consecutive_failures == 0,
   "a clean check resets the streak, so the condition can clear rather than latching "
   "forever on one bad moment")

print(f"\nALL {passed} CHECKS PASSED")


print()
print("== TEAM REVIEW: verified and refreshed are two different successes ==")
def _rejects(_r): raise PermissionError("broker declines the attestation")
_rm = IsolationMonitor(1, M, interval_seconds=0.05, reference_netns=HOST,
                       on_verified=_rejects,
                       _source_factory_for_tests=lambda: Subject())
_rm.check_once()
_rs = _rm.status()
ok(_rs.drifts == 0 and _rs.refresh_failures == 1 and _rs.refreshes == 0,
   "a CLEAN subject whose refresh is rejected records a refresh failure, not a drift. "
   "Conflating them hid a whole failure mode: a callback that silently does nothing "
   "leaves the model fail-closed while looking like healthy monitoring")
ok("refresh FAILED" in (_rs.last_verdict or ""),
   "and the verdict says which of the two failed, so an operator can tell 'the subject "
   "is dirty' from 'the subject is clean and the broker will not take my word for it'")

_good = []
_gm = IsolationMonitor(1, M, interval_seconds=0.05, reference_netns=HOST,
                       on_verified=_good.append,
                       _source_factory_for_tests=lambda: Subject())
_gm.check_once()
ok(_gm.status().refreshes == 1 and _gm.status().refresh_failures == 0,
   "a working refresh is counted as the separate success it is")

print("== and ALIVE is not the same as WORKING ==")
_gate = __import__("threading").Event()
def _hangs():
    _gate.wait(30)          # thread stays alive, no cycle ever completes
    return Subject()
_sm = IsolationMonitor(1, M, interval_seconds=0.05, reference_netns=HOST,
                       stall_factor=2.0, _source_factory_for_tests=_hangs)
_sm.start()
time.sleep(0.02)
ok(_sm.is_watching(), "a freshly started monitor gets one interval of grace")
time.sleep(0.3)
ok(_sm._thread.is_alive() and not _sm.is_watching(),
   "a monitor STUCK inside verification stops claiming to watch. This is the third "
   "variant of one bug: `running` was remembered rather than observed, then liveness "
   "meant thread.is_alive() — which a blocked thread satisfies forever while "
   "completing zero cycles. A stalled monitor is exactly as blind as a stopped one")
_gate.set()
_sm.stop()
ok(not _sm.is_watching(), "and a stopped monitor still reports the truth")

print(f"\nALL {passed} CHECKS PASSED")


print()
print("== MASTER-ENGINEER REVIEW: the OTHER success path needed escalation too ==")
_alerts = []
def _always_declines(_r): raise PermissionError("broker declines every refresh")
_rf = IsolationMonitor(1, M, interval_seconds=1, reference_netns=HOST,
                       max_consecutive_failures=3,
                       on_verified=_always_declines,
                       on_persistent_failure=_alerts.append,
                       _source_factory_for_tests=lambda: Subject())
for _ in range(2):
    _rf.check_once()
ok(_rf.status().consecutive_refresh_failures == 2 and not _alerts,
   "two refused refreshes are a streak, not yet a condition")
_rf.check_once()
ok(len(_alerts) == 1,
   "the THIRD consecutive refused refresh escalates. consecutive_failures tracks drift "
   "and resets on every clean report, so a broker rejecting EVERY refresh incremented a "
   "counter forever while the escalation channel — added precisely to stop silent "
   "repeated failure — never fired once. Same bug, other success path")
_ok = IsolationMonitor(1, M, interval_seconds=1, reference_netns=HOST,
                       on_verified=lambda r: None,
                       _source_factory_for_tests=lambda: Subject())
_ok.check_once()
ok(_ok.status().consecutive_refresh_failures == 0,
   "and a working refresh clears the streak, so the condition can end")

print("== a never-yet-checked monitor gets a BOUNDED grace ==")
_big = IsolationMonitor(1, M, interval_seconds=600, reference_netns=HOST,
                        _source_factory_for_tests=lambda: Subject())
ok(_big._first_grace <= 60.0 < _big.stall_seconds(),
   "at a 600s interval the stall window is 1800s, so the object claimed to be watching "
   "for THIRTY MINUTES before verifying anything even once — 'about to look' reported "
   "as 'looking'. The first-check grace is now bounded independently of the interval")

print("== check duration is observable before it becomes a stall ==")
_d = IsolationMonitor(1, M, interval_seconds=1, reference_netns=HOST,
                      _source_factory_for_tests=lambda: Subject())
_d.check_once()
ok(_d.status().last_check_seconds >= 0.0,
   "each check records how long it took. A verify creeping from 2s toward a 90s stall "
   "threshold is already in danger and previously surfaced as nothing until it tripped")

print(f"\nALL {passed} CHECKS PASSED")
