"""
Isolation manifest — the bouncer bench.

Proc data is INJECTED so the checks are deterministic: fabricating a genuinely
confined process inside a test runner is not portable, and a test that only passes
on one kernel configuration is not a regression test. Live self-inspection is
exercised separately and tolerantly.
"""
from driftcore.kernel.isolation_manifest import (
    IsolationManifest, IsolationReport, verify_self, verify_process,
    attest_or_refuse, classify_fd, _CAP_BITS,
)

passed = 0
def ok(c, label):
    global passed
    assert c, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")


class FakeProc:
    """A fabricated /proc view, so every posture is testable."""
    def __init__(self, fds=None, netns="net:[111]", cap_eff=0, seccomp=2, nnp="1",
                 ifaces=None, inodes=None):
        self._fds = fds if fds is not None else {"0": "pipe:[1]", "1": "pipe:[2]"}
        self._netns, self._cap, self._sec, self._nnp = netns, cap_eff, seccomp, nnp
        self._ifaces = ["lo"] if ifaces is None else list(ifaces)
        self._inodes = dict(inodes or {})
    def fds(self): return dict(self._fds)
    def netns(self): return self._netns
    def interfaces(self): return list(self._ifaces)
    def net_inodes(self): return dict(self._inodes)
    def status(self):
        return {"CapEff": f"{self._cap:016x}", "CapBnd": f"{self._cap:016x}",
                "Seccomp": str(self._sec), "Seccomp_filters": "1",
                "NoNewPrivs": self._nnp}

def cap(*names):
    v = 0
    for n in names: v |= (1 << _CAP_BITS[n])
    return v

M = IsolationManifest(declared_by="justin")
# A reference namespace distinct from the fabricated subject's, so the netns
# comparison is actually performed (I3: a missing reference now REFUSES).
HOST_NS = "net:[4026531833]"


print("== FD classification: the socket is the one that matters ==")
ok(classify_fd("socket:[1234]", {"1234": "network"}) == "socket_network",
   "a network socket FD is identified by family, not lumped in with AF_UNIX")
ok(classify_fd("pipe:[99]") == "pipe", "a pipe is a pipe")
ok(classify_fd("/dev/null") == "devnull", "/dev/null recognised")
ok(classify_fd("weird-thing") == "unknown", "anything unrecognised is 'unknown'")

print("== a clean, confined process passes ==")
r = verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS,
                   source=FakeProc(netns="net:[999]", cap_eff=0, seccomp=2, nnp="1"))
ok(r.permitted, "no undeclared FDs, no forbidden caps, seccomp on -> permitted")
ok(r.trusted, "and a supervisor check is marked TRUSTED")

print("== THE HEADLINE: an inherited socket is refused, whatever it is ==")
r = verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS, source=FakeProc(
    fds={"0": "pipe:[1]", "3": "socket:[8080]"}, netns="net:[999]", seccomp=2))
ok(not r.permitted, "an undeclared socket FD refuses the process")
ok(any("socket:[8080]" in f for f in r.findings),
   "and the finding names the exact FD — legible, not a generic failure")

print("== you do not have to RECOGNISE the weapon, only notice it is undeclared ==")
r = verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS, source=FakeProc(
    fds={"0": "pipe:[1]", "9": "some_future_kernel_thing:[42]"},
    netns="net:[999]", seccomp=2))
ok(not r.permitted,
   "a channel type that did not exist when this was written is STILL refused "
   "(fail-closed-on-undeclared, one layer down)")

print("== forbidden capabilities are caught individually and named ==")
r = verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS, source=FakeProc(
    netns="net:[999]", cap_eff=cap("CAP_NET_RAW", "CAP_NET_ADMIN"), seccomp=2))
ok(not r.permitted, "held CAP_NET_RAW/CAP_NET_ADMIN refuses")
ok(any("CAP_NET_RAW" in f for f in r.findings)
   and any("CAP_NET_ADMIN" in f for f in r.findings),
   "each held capability is named separately")

print("== seccomp and NoNewPrivs: the mechanisms that bind the FUTURE ==")
r = verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS,
                   source=FakeProc(netns="net:[999]", seccomp=0))
ok(not r.permitted and any("seccomp is DISABLED" in f for f in r.findings),
   "seccomp disabled refuses — a clean scan now says nothing about a socket opened later")
r = verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS,
                   source=FakeProc(netns="net:[999]", seccomp=2, nnp="0"))
ok(not r.permitted, "NoNewPrivs unset refuses (a child could regain privileges)")

print("== the most common real failure: sharing the supervisor's netns ==")
shared = FakeProc(netns=HOST_NS, seccomp=2)
r = __import__("driftcore.kernel.isolation_manifest", fromlist=["_verify"])._verify(
    shared, M, trusted=True, label="t", reference_netns=None)
ok(not r.permitted, "I3: with NO reference namespace the check REFUSES (was: permitted)")
class _Ref(FakeProc):
    pass
r2 = verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS, source=shared)
r2 = __import__("driftcore.kernel.isolation_manifest", fromlist=["_verify"])._verify(
    shared, M, trusted=True, label="supervisor:1",
    reference_netns="net:[4026531833]")
ok(not r2.permitted and any("shares network namespace" in f for f in r2.findings),
   "given the supervisor's OWN netns as reference, a shared namespace is refused")

print("== a check that cannot run is not a check that passed ==")
class Broken(FakeProc):
    def fds(self): raise OSError("permission denied")
r = verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS, source=Broken(netns="net:[9]", seccomp=2))
ok(not r.permitted and any("could not be enumerated" in f for f in r.findings),
   "an unreadable /proc refuses rather than assuming a clean surface")

print("== a PASSING SELF-REPORT is still not sufficient (the core honesty rule) ==")
r = verify_self(M, reference_netns=HOST_NS,
                source=FakeProc(netns="net:[999]", seccomp=2))
ok(r.permitted, "the self-check can pass...")
ok(r.trusted is False, "...but it is marked UNTRUSTED")
ok("NOT a security control" in r.summary(),
   "and the summary says so in words a human will read")
try:
    attest_or_refuse(r); ok(False, "a passing self-report should not attest")
except PermissionError as e:
    ok("self-reported" in str(e),
       "attest_or_refuse REFUSES a green light produced by the subject itself")
ok(attest_or_refuse(verify_process(
    1, M, compare_to_self=False, reference_netns=HOST_NS,
    source=FakeProc(netns="net:[999]", seccomp=2))) is None,
   "a supervisor attestation is accepted")

print("== the manifest itself must be attributable and checkable ==")
try:
    IsolationManifest(declared_by=""); ok(False, "empty declared_by should raise")
except ValueError:
    ok(True, "an isolation manifest must name who declared it")
try:
    IsolationManifest(declared_by="j", forbidden_capabilities=frozenset({"CAP_MADE_UP"}))
    ok(False, "an unknown capability should raise")
except ValueError:
    ok(True, "a capability the verifier cannot locate is refused, not silently unchecked")

print("== explicitly declared FDs are permitted ==")
M2 = IsolationManifest(declared_by="j", allowed_fd_targets=frozenset({"/var/log/app.log"}))
r = verify_process(1, M2, compare_to_self=False, reference_netns=HOST_NS, source=FakeProc(
    fds={"0": "pipe:[1]", "3": "/var/log/app.log"}, netns="net:[9]", seccomp=2))
ok(r.permitted, "an FD the operator declared by exact path is allowed")

print("== live self-inspection runs and reports observations ==")
live = verify_self(M)
ok(isinstance(live, IsolationReport) and "fd_count" in live.observations,
   "verify_self() works against the real /proc and records what it saw")
ok(not live.permitted,
   "and on THIS unconfined process it correctly REFUSES — a real result, not a "
   "rubber stamp (no own netns, seccomp off, CAP_NET_* held)")
ok(live.trusted is False, "and the live self-check is also marked untrusted")

print(f"\nALL {passed} CHECKS PASSED")


print()
print("== SELF-RED-TEAM PINS (I1-I6) ==")

# I1: prefix matching on device paths — the substring bug, written a THIRD time
for bad in ["/dev/null_backdoor", "/dev/nullX", "/dev/randomizer", "/dev/zerofill",
            "/dev/ptsX"]:
    ok(classify_fd(bad) != "devnull" and classify_fd(bad) != "tty",
       f"I1: {bad!r} is NOT laundered into a benign device kind (exact match, not prefix)")
ok(classify_fd("/dev/null") == "devnull" and classify_fd("/dev/pts/3") == "tty",
   "I1: and the genuine device paths still classify correctly")
r = verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS, source=FakeProc(
    fds={"0": "pipe:[1]", "3": "/dev/null_backdoor"}, netns="net:[9]", seccomp=2))
ok(not r.permitted, "I1: a look-alike device path is refused at the wall")

# I4: io_uring can do network I/O without ever calling socket()
ok(classify_fd("anon_inode:[io_uring]") == "anon_unknown",
   "I4: an io_uring ring gets its own kind, not the benign anon_inode bucket")
ok("anon_unknown" not in IsolationManifest(declared_by="j").allowed_fd_kinds,
   "I4: and it is NOT in the default allowlist (it performs network ops without socket())")
ok(classify_fd("net:[4026531833]") == "namespace",
   "I4: a namespace FD is identified — it is a setns() handle, never benign")
r = verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS, source=FakeProc(
    fds={"0": "pipe:[1]", "4": "anon_inode:[io_uring]"}, netns="net:[9]", seccomp=2))
ok(not r.permitted, "I4: an undeclared io_uring ring refuses the process")

# I2: an absent measurement is not a passing one
r = verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS,
                   source=FakeProc(netns="net:[9]", seccomp=2))
r2 = __import__("driftcore.kernel.isolation_manifest", fromlist=["_verify"])._verify(
    type("S", (), {"fds": lambda s: {"0": "pipe:[1]"}, "netns": lambda s: "net:[9]",
                   "interfaces": lambda s: ["lo"], "net_inodes": lambda s: {},
                   "status": lambda s: {"Seccomp": "2", "NoNewPrivs": "1"}})(),
    M, trusted=True, label="t", reference_netns="net:[other]")
ok(not r2.permitted and any("CapEff is absent" in f for f in r2.findings),
   "I2: a status file with no CapEff REFUSES — it used to default to 'no caps held'")

# I3: the headline netns check must not degrade to a no-op
r = __import__("driftcore.kernel.isolation_manifest", fromlist=["_verify"])._verify(
    FakeProc(netns="net:[9]", seccomp=2), M, trusted=True, label="t",
    reference_netns=None)
ok(not r.permitted and any("NO reference namespace" in f for f in r.findings),
   "I3: no reference namespace REFUSES — a check that cannot run has not passed")

# I5: a declared target must not launder a dangerous kind
# I5 was originally pinned at VERIFY time. The defence has since moved EARLIER: an
# inode-numbered target can no longer be declared at all (Meta P0-1), so the
# misconfiguration is impossible to write down rather than merely caught later.
try:
    IsolationManifest(declared_by="j", allowed_fd_targets=frozenset({"socket:[8080]"}))
    ok(False, "I5: an inode-numbered target should be refused at declaration")
except ValueError:
    ok(True, "I5 (strengthened): a socket inode cannot be DECLARED as an allowed target")
# and the verify-time check remains as defence in depth, for a manifest built by any
# path that bypasses __post_init__ (e.g. object.__setattr__ on the frozen dataclass)
import dataclasses as _dc5
M5 = IsolationManifest(declared_by="j")
object.__setattr__(M5, "allowed_fd_targets", frozenset({"socket:[8080]"}))
r = verify_process(1, M5, compare_to_self=False, reference_netns=HOST_NS, source=FakeProc(
    fds={"0": "pipe:[1]", "3": "socket:[8080]"}, netns="net:[9]", seccomp=2))
ok(not r.permitted and any("never be permitted by naming a target" in f for f in r.findings),
   "I5: and if one is smuggled past the constructor, verify still refuses it")

# I6: permitting sockets by kind must be explicit, never quiet
try:
    IsolationManifest(declared_by="j", allowed_fd_kinds=frozenset({"pipe", "socket_network"}))
    ok(False, "allowing sockets by kind should require an explicit opt-in")
except ValueError:
    ok(True, "I6: allowing sockets/namespaces by kind requires accept_network_capable_fds")
ok(IsolationManifest(declared_by="j", allowed_fd_kinds=frozenset({"pipe", "socket_network"}),
                     accept_network_capable_fds=True).accept_network_capable_fds,
   "I6: ...and the explicit opt-in remains available and visible in the declaration")

print(f"\nALL {passed} CHECKS PASSED")


print()
print("== EXTERNAL RED TEAM PINS (Grok + ChatGPT) ==")

# G1 (CRITICAL): a PRIVATE namespace is not an EMPTY one
r = verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS,
                   source=FakeProc(netns="net:[PRIV]", seccomp=2, ifaces=["lo"]))
ok(r.permitted, "G1: a namespace holding only loopback passes")
r = verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS,
                   source=FakeProc(netns="net:[PRIV]", seccomp=2, ifaces=["lo", "veth0"]))
ok(not r.permitted and any("non-loopback interface" in f for f in r.findings),
   "G1: a PRIVATE namespace containing a veth is REFUSED — it is a working route out, "
   "and every other check would have passed it (docs said 'empty', code checked 'different')")
r = verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS,
                   source=FakeProc(netns="net:[PRIV]", seccomp=2, ifaces=["lo", "eth0"]))
ok(not r.permitted, "G1: likewise a plain eth0 inside the private namespace")

# G4 / ChatGPT P1-1 (both reviewers converged): anon_inode inverted to an allowlist
ok(classify_fd("anon_inode:[eventfd]") == "anon_inode",
   "G4: a demonstrably-inert anon inode is still permitted by kind")
for future in ["anon_inode:[invented_next_year]", "anon_inode:[io_uring]",
               "anon_inode:[bpf-map]", "anon_inode:[xdp_thing]"]:
    ok(classify_fd(future) == "anon_unknown",
       f"G4: {future} -> anon_unknown (blocklist inverted to allowlist)")
r = verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS,
                   source=FakeProc(fds={"0": "pipe:[1]", "5": "anon_inode:[future_net]"},
                                   netns="net:[P]", seccomp=2))
ok(not r.permitted,
   "G4: an anon inode type that does not exist yet is REFUSED — the module no longer "
   "hunts known-bad, which is the pattern its own docstring says loses")

# G3: AF_UNIX distinguishable, and an unattributable socket refused
ok(classify_fd("socket:[77]", {"77": "unix"}) == "socket_unix",
   "G3: a unix socket is identified by family")
ok(classify_fd("socket:[88]", {"88": "network"}) == "socket_network",
   "G3: a network socket is identified by family")
ok(classify_fd("socket:[99]", {}) == "socket_unknown",
   "G3: an UNATTRIBUTABLE socket is 'socket_unknown' — refused, not assumed benign")
r = verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS,
                   source=FakeProc(fds={"0": "pipe:[1]", "3": "socket:[77]"},
                                   netns="net:[P]", seccomp=2, inodes={"77": "unix"}))
ok(not r.permitted,
   "G3: AF_UNIX is still refused by default (it is an SCM_RIGHTS injection vector) — "
   "but it is now DISTINGUISHABLE, so an operator can opt in knowingly")

# G5: bounding set and CAP_NET_BIND_SERVICE
ok("CAP_NET_BIND_SERVICE" in IsolationManifest(declared_by="j").forbidden_capabilities,
   "G5: CAP_NET_BIND_SERVICE is forbidden by default")
class _BndProc(FakeProc):
    def status(self):
        st = FakeProc.status(self); st["CapBnd"] = "000001fffeffffff"; return st
r = verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS,
                   source=_BndProc(netns="net:[P]", seccomp=2))
ok(not r.permitted and any("BOUNDING set" in f for f in r.findings),
   "G5: a clean CapEff with a full BOUNDING set is refused — clearing CapEff alone is "
   "not durable across a privilege transition")

# G2: the seccomp over-claim is withdrawn in the observations
r = verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS,
                   source=FakeProc(netns="net:[P]", seccomp=2))
ok("allow-all filter satisfies this check" in str(r.observations.get("seccomp_note", "")),
   "G2: the report states that mode 2 is satisfied by an allow-all filter — the "
   "'seccomp binds the future' claim is withdrawn, not quietly kept")

# ChatGPT P1-3: manifest versioning so stale manifests are visible
ok(IsolationManifest(declared_by="j").manifest_version >= 2,
   "ChatGPT P1-3: the manifest carries a version")

print(f"\nALL {passed} CHECKS PASSED")


print()
print("== LOCAL REFUSAL: the error says no where the error happens ==")
from driftcore.kernel.isolation_manifest import IsolationScanError

class _ScanFails(FakeProc):
    def fds(self):
        raise IsolationScanError("file descriptor 7 exists but could not be read (EACCES)")
r = verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS,
                   source=_ScanFails(netns="net:[P]", seccomp=2))
ok(not r.permitted, "an unreadable file descriptor REFUSES the scan")
ok(any("descriptor 7" in f for f in r.findings),
   "and the refusal names WHICH descriptor — the reason travels from the failure site, "
   "instead of a vague 'unknown' label that a distant allowlist happens to reject")

class _TableFails(FakeProc):
    def net_inodes(self):
        raise IsolationScanError("socket table 'tcp' exists but could not be read")
r = verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS,
                   source=_TableFails(netns="net:[P]", seccomp=2))
ok(not r.permitted and any("socket table" in f for f in r.findings),
   "an unreadable socket table REFUSES — incomplete attribution could mistake a "
   "network socket for a local one, so it is never treated as a complete map")

ok(verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS,
                  source=FakeProc(netns="net:[P]", seccomp=2)).permitted,
   "and a scan that CAN read everything still passes — absent is distinguished from "
   "unreadable, so a kernel without IPv6 is not treated as a failure")

print(f"\nALL {passed} CHECKS PASSED")


print()
print("== EXTERNAL ROUND 2 PINS (Meta / ChatGPT / Grok) ==")

# ChatGPT F3 + Grok #1 — THE SUBSTRING BUG, FOURTH INSTANCE, found by two reviewers
ok(classify_fd("anon_inode:[eventfd]") == "anon_inode",
   "the genuine benign anon inode is still permitted")
for laundered in ["anon_inode:[eventfd_evil]", "anon_inode:[memfd_backdoor]",
                  "anon_inode:[pidfd_exfil]", "anon_inode:[signalfd2]",
                  "anon_inode:[inotify_x]"]:
    ok(classify_fd(laundered) == "anon_unknown",
       f"4th-instance substring bug: {laundered} is NOT laundered into the allowed kind")
r = verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS,
                   source=FakeProc(fds={"0": "pipe:[1]", "6": "anon_inode:[memfd_evil]"},
                                   netns="net:[P]", seccomp=2))
ok(not r.permitted, "and a laundered anon inode is refused at the wall")

# Grok #2 — version fields were declared and never consulted
from driftcore.kernel.isolation_manifest import VERIFIER_VERSION
import dataclasses as _dc
future = _dc.replace(IsolationManifest(declared_by="j"),
                     min_verifier_version=VERIFIER_VERSION + 1)
r = verify_process(1, future, compare_to_self=False, reference_netns=HOST_NS,
                   source=FakeProc(netns="net:[P]", seccomp=2))
ok(not r.permitted and any("verifier version" in f for f in r.findings),
   "a manifest demanding a NEWER verifier is refused — a pass would mean 'the checks "
   "I know about succeeded', not 'the declared surface was verified'")
unknown = _dc.replace(IsolationManifest(declared_by="j"), manifest_version=99)
r = verify_process(1, unknown, compare_to_self=False, reference_netns=HOST_NS,
                   source=FakeProc(netns="net:[P]", seccomp=2))
ok(not r.permitted, "an unknown manifest_version is refused rather than guessed at")

# Meta P0-1 — inode-numbered targets must be impossible to DECLARE, not merely caught
for bad in ["socket:[8080]", "net:[4026531833]", "anon_inode:[eventfd]", "pipe:[3]"]:
    try:
        IsolationManifest(declared_by="j", allowed_fd_targets=frozenset({bad}))
        ok(False, f"declaring {bad} as an allowed target should be refused")
    except ValueError:
        ok(True, f"{bad} cannot be DECLARED as an allowed target (inodes are recycled)")
ok(IsolationManifest(declared_by="j",
                     allowed_fd_targets=frozenset({"/var/log/app.log"})) is not None,
   "...while a stable filesystem path remains declarable")

# ChatGPT F1 — the report states what was observed, not what is guaranteed
r = verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS,
                   source=FakeProc(netns="net:[P]", seccomp=2))
ok("OBSERVED ISOLATION" in r.summary(),
   "the summary says OBSERVED, not 'isolation OK' — /proc is an observation interface, "
   "not an enforcement mechanism, and the wording must not imply a guarantee")

print(f"\nALL {passed} CHECKS PASSED")


print()
print("== COLD SELF-RED-TEAM PINS (round 2 fixes) ==")
import dataclasses as _dcx

# A4: the declaration-time inode check was dodged three ways
for dodge in ["SOCKET:[8080]", " socket:[8080]", "/proc/1/fd/socket:[8080]",
              "net:[4026531833]", "relative/path"]:
    try:
        IsolationManifest(declared_by="j", allowed_fd_targets=frozenset({dodge}))
        ok(False, f"A4: {dodge!r} should be refused at declaration")
    except ValueError:
        ok(True, f"A4: {dodge!r} cannot be declared (positive path shape, not a blocklist)")
ok(IsolationManifest(declared_by="j",
                     allowed_fd_targets=frozenset({"/var/log/app.log"})) is not None,
   "A4: a genuine absolute path with no colon remains declarable")

# A5: an empty interface list must not read as the safest possible namespace
r = verify_process(1, M, compare_to_self=False, reference_netns=HOST_NS,
                   source=FakeProc(netns="net:[P]", seccomp=2, ifaces=[]))
ok(not r.permitted and any("not even loopback" in f for f in r.findings),
   "A5: zero interfaces REFUSES — more likely a parse failure than a genuinely empty "
   "namespace, and a parse failure must not read as the safest possible state")

# A6: shareable memory objects are channels, not inert
for shareable in ["anon_inode:[memfd]", "anon_inode:[dmabuf]"]:
    ok(classify_fd(shareable) == "anon_unknown",
       f"A6: {shareable} is no longer benign — passed over SCM_RIGHTS it is a channel "
       f"to a helper process that may have the network this one does not")
ok(classify_fd("anon_inode:[eventfd]") == "anon_inode",
   "A6: genuinely inert kinds are still permitted")

# A7: absent version fields defaulted to a KNOWN version and passed
class _NoVersion:
    declared_by = "x"; allowed_fd_kinds = frozenset({"pipe"})
    allowed_fd_targets = frozenset(); max_fds = 64
    require_own_netns = False; forbidden_capabilities = frozenset()
    require_seccomp = False; require_no_new_privs = False
    require_empty_netns = False; require_dropped_from_bounding_set = False
r = verify_process(1, _NoVersion(), compare_to_self=False, reference_netns=HOST_NS,
                   source=FakeProc(netns="net:[P]", seccomp=2))
ok(not r.permitted and any("declares no version" in f for f in r.findings),
   "A7: a manifest with NO version fields is refused — an absent declaration is not a "
   "version-1 declaration")

print(f"\nALL {passed} CHECKS PASSED")
