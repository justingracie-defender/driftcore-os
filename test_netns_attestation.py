"""External netns attestation: verifies isolation from OUTSIDE the process being
checked, because verify_self() in the agent's own address space is a self-report
a compromised agent can forge.

Established empirically before building this: against a fully sealed Python
process, ctypes->libc.socket(2), a subprocess child, and raw os fd ops all
reached the network while the static audit reported zero findings. Prevention is
a kernel property, so the check has to be a kernel-level observation."""

import os
import subprocess
import sys
import tempfile
import time

from driftcore.kernel.netns_attestation import (
    NetnsAttestor, AttestationResult, attest_or_raise, NotIsolated,
    AttestationMonitor,
)

EXPECTED_CHECKS = 36

passed = 0
def ok(c, label):
    global passed
    assert c, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")


def build_proc(root, *, isolated=True, extra_iface=False, v4route=False,
               v6route=False, inet_fd=False, fd_family=None):
    """Synthesize a /proc tree describing an (un)isolated process."""
    os.makedirs(f"{root}/self/ns", exist_ok=True)
    os.makedirs(f"{root}/9/ns", exist_ok=True)
    os.makedirs(f"{root}/9/net", exist_ok=True)
    os.makedirs(f"{root}/9/fd", exist_ok=True)
    os.symlink("net:[4026531833]", f"{root}/self/ns/net")
    os.symlink("net:[4026999999]" if isolated else "net:[4026531833]",
               f"{root}/9/ns/net")
    devs = "Inter-|Receive\n face |bytes\n    lo: 0 0\n"
    if extra_iface:
        devs += "  eth0: 0 0\n"
    open(f"{root}/9/net/dev", "w").write(devs)
    open(f"{root}/9/net/route", "w").write(
        "Iface\tDestination\neth0\t00000000\n" if v4route else "Iface\tDestination\n")
    open(f"{root}/9/net/ipv6_route", "w").write(
        "00000000000000000000000000000000 00 x eth0\n" if v6route else "")
    os.symlink("socket:[555]", f"{root}/9/fd/3")
    for t in ("tcp", "tcp6", "udp", "udp6", "raw", "raw6", "packet", "udplite"):
        row = "  sl local\n"
        if t == (fd_family or ("tcp" if inet_fd else None)):
            row += "   0: 0100007F:0050 " + " ".join(["x"] * 7) + " 555\n"
        open(f"{root}/9/net/{t}", "w").write(row)


def attest_synthetic(**kw) -> AttestationResult:
    d = tempfile.mkdtemp()
    build_proc(d, **kw)
    return NetnsAttestor(proc=d).attest(9)


print("== the verifier DISCRIMINATES: it is not a function that always fails ==")
ok(attest_synthetic().passed,
   "a genuinely isolated process PASSES (own netns, lo only, no routes, no "
   "inet fds)")

print("== each escape route is caught INDEPENDENTLY ==")
cases = [
    (dict(isolated=False), "distinct netns", "sharing the host network namespace"),
    (dict(extra_iface=True), "loopback only",
     "an own namespace with a veth pair — own netns is NOT no-network"),
    (dict(v4route=True), "no routes", "an IPv4 route off the machine"),
    (dict(v6route=True), "no routes",
     "an IPv6-only route (checking /proc/net/route alone would miss this)"),
    (dict(inet_fd=True), "no inherited inet sockets",
     "an INHERITED socket fd — no namespace or seccomp closes an fd you "
     "already hold"),
]
for kw, expect, why in cases:
    r = attest_synthetic(**kw)
    ok(not r.passed, f"FAILS on {why}")
    ok(any(c[0] == expect for c in r.failures),
       f"  ...and names the responsible check: {expect!r}")

print("== fail-closed: cannot-verify is not verified ==")
ok(not NetnsAttestor(proc="/nonexistent").attest(1).passed,
   "no procfs (non-Linux host) FAILS rather than passing by default")
ok(not NetnsAttestor().attest(999999).passed,
   "a nonexistent pid FAILS")
d = tempfile.mkdtemp()
build_proc(d)
os.remove(f"{d}/9/net/dev")
r = NetnsAttestor(proc=d).attest(9)
ok(not r.passed and any("could not read" in c[2] for c in r.failures),
   "an unreadable fact FAILS and says it could not read it")

print("== against the REAL, un-isolated environment ==")
real = NetnsAttestor().attest(os.getpid())
ok(not real.passed,
   "this un-isolated process is refused — a verifier that passed here would "
   "be worse than none, because it would convert an unknown into an assurance")
ok(len(real.failures) >= 1, "and it reports which facts failed")

child = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(5)"])
time.sleep(0.3)
try:
    ok(not NetnsAttestor().attest(child.pid).passed,
       "a child process is attested from OUTSIDE, without asking it anything")
finally:
    child.terminate()

print("== attest_or_raise is the startup gate ==")
try:
    attest_or_raise(os.getpid())
    ok(False, "should have raised")
except NotIsolated as e:
    ok("FAIL" in str(e),
       "attest_or_raise raises NotIsolated with the full report — an agent that "
       "cannot be attested should not be run")

d2 = tempfile.mkdtemp()
build_proc(d2)
ok(attest_or_raise(9, proc=d2).passed,
   "attest_or_raise returns the result when isolation holds")

print("== the report is legible to an operator ==")
ok("netns attestation for pid" in real.report() and "[FAIL]" in real.report(),
   "the report names the pid and marks each failing check")

print("== RED TEAM 2026-08 (Grok): EVERY socket family, not just tcp/udp ==")
# The first version walked only tcp/tcp6/udp/udp6, so a RAW or AF_PACKET fd
# returned "all non-inet" and the whole attestation PASSED — a false assurance,
# in the very check the docstring calls the one most systems miss.
for fam in ("tcp", "udp", "raw", "raw6", "packet", "udplite"):
    r = attest_synthetic(fd_family=fam)
    ok(not r.passed,
       f"G1: an inherited socket in net/{fam} is caught (was: raw/packet -> PASS)")
ok(any(c[0] == "no inherited inet sockets"
       for c in attest_synthetic(fd_family="packet").failures),
   "G1: and the AF_PACKET case names the socket check specifically")

# /proc/net/tcp puts the inode at column 9, /proc/net/packet at column 8. A
# hard-coded index would silently miss exactly the families just added.
d_col = tempfile.mkdtemp()
build_proc(d_col)
open(f"{d_col}/9/net/packet", "w").write("sk RefCnt Type Proto Iface R Rmem User Inode\n"
                                         "ffff 3 3 0003 2 1 0 0 555\n")
ok(not NetnsAttestor(proc=d_col).attest(9).passed,
   "G1: the inode is found regardless of which column the family puts it in")

# A family table we cannot read is a family we cannot clear.
d_unread = tempfile.mkdtemp()
build_proc(d_unread)
os.remove(f"{d_unread}/9/net/raw")
os.mkdir(f"{d_unread}/9/net/raw")          # unreadable as a file
r_unread = NetnsAttestor(proc=d_unread).attest(9)
ok(not r_unread.passed,
   "G1: an unreadable family table FAILS (cannot clear a family you cannot read)")

print("== RED TEAM 2026-08 (Grok): attestation must be CONTINUOUS ==")
# A startup check proves a fact about time T. setns, a veth injected over
# netlink, or an fd passed via SCM_RIGHTS all happen at T+1.
d_ok = tempfile.mkdtemp()
build_proc(d_ok)
breaches = []
mon = AttestationMonitor(9, attestor=NetnsAttestor(proc=d_ok),
                         on_breach=breaches.append, interval_seconds=0.05)
ok(mon.check_once().passed, "G2: monitor confirms isolation while it holds")
ok(mon.breached is None, "G2: no breach recorded yet")
mon.raise_if_breached()
ok(True, "G2: raise_if_breached is a no-op while isolation holds")

# now isolation lapses AFTER the startup check — a veth appears
open(f"{d_ok}/9/net/dev", "w").write("h\nh\n    lo: 0 0\n  eth0: 0 0\n")
ok(not mon.check_once().passed, "G2: the lapse is detected on re-attestation")
ok(mon.breached is not None, "G2: the breach is RECORDED, not just returned")
ok(len(breaches) == 1, "G2: the breach handler fired exactly once")
try:
    mon.raise_if_breached()
    ok(False, "raise_if_breached should raise after a breach")
except NotIsolated as e:
    ok("lapsed AFTER" in str(e),
       "G2: raise_if_breached halts subsequent work and says the lapse was "
       "post-startup")

print(f"\n{passed}/{EXPECTED_CHECKS} checks passed")
