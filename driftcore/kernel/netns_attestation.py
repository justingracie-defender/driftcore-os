"""
netns_attestation.py — ATTESTATION, NOT SELF-REPORT.

WHY THIS EXISTS
───────────────
`isolation_manifest.verify_self()` runs in the agent's own address space. It
catches the honest mistake — someone forgot the network namespace on a Tuesday —
and that is worth a lot. But it is a SELF-REPORT: agent code that can patch a
function can patch the function that checks it, and a compromised agent will
report exactly what it is asked to report.

This module runs in the SUPERVISOR and reads kernel-maintained facts about a
target pid. It never calls into the target, never asks it a question, and never
accepts a claim from it. The agent cannot forge `/proc/<pid>/ns/net`, because
the agent does not write it.

Established empirically first (self red team, 2026-08): against a fully sealed
Python process, `ctypes` → `libc.socket(2)` opened a socket, a `subprocess`
child opened one freely, and raw `os` fd operations were untouched — while the
static audit reported zero findings. In-process controls make unmediated egress
loud; they demonstrably do not prevent it. Prevention is a kernel property, so
the check has to be a kernel-level observation.

WHAT IS CHECKED, AND WHY EACH ONE
─────────────────────────────────
  1. NETNS IDENTITY   — the target's net namespace inode must differ from the
                        supervisor's. Same inode means the target shares the
                        host's network and nothing else here matters.
  2. INTERFACES       — only loopback. An `own` namespace is NOT `no network`:
                        a veth pair puts you back on the wire with a namespace
                        of your own. This is the check that catches that.
  3. ROUTES           — no IPv4 and no IPv6 routes. Checking only /proc/net/route
                        would read IPv4 and miss a v6-only escape entirely.
  4. INHERITED SOCKETS— the target must hold no AF_INET/AF_INET6 file descriptor.
                        THIS IS THE ONE MOST SYSTEMS MISS: a namespace does not
                        close a socket the process already has. An fd passed in
                        before isolation, or inherited across a fork, is a live
                        wire that survives every namespace and seccomp filter,
                        because no syscall needs to be made to use it.

FAIL-CLOSED
───────────
Every branch that cannot establish a fact returns FAIL, never PASS. An
unreadable /proc, a permission error, a non-Linux host, a vanished pid — all
"cannot verify", and cannot-verify is not verified. A verifier that reports PASS
when it simply could not look is worse than no verifier, because it converts an
unknown into a false assurance.

BOUNDARIES — READ BEFORE QUOTING THIS
─────────────────────────────────────
  * This attests a MOMENT. It is a snapshot at time T, not a binding on the
    future; the namespace is what binds the future. Re-attest on a schedule and
    treat a change as an incident.
  * Root on the host defeats it: an attacker who can write /proc or move the
    target between namespaces can lie to any observer in userspace.
  * Linux only. On any other platform this returns FAIL — correctly, because the
    guarantee it is checking for does not exist there.
  * It does not prove the broker is correct. It proves the agent has no path
    EXCEPT the broker. Those are different claims and both are needed.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass(frozen=True)
class AttestationResult:
    """The verdict. `passed` is True only if every check positively established
    its fact; anything else — including "could not look" — is False."""
    passed: bool
    pid: int
    checks: Tuple[Tuple[str, bool, str], ...] = ()

    @property
    def failures(self) -> List[Tuple[str, bool, str]]:
        return [c for c in self.checks if not c[1]]

    def report(self) -> str:
        lines = [f"netns attestation for pid {self.pid}: "
                 f"{'PASS' if self.passed else 'FAIL'}"]
        for name, ok, detail in self.checks:
            lines.append(f"  [{'ok' if ok else 'FAIL'}] {name}: {detail}")
        return "\n".join(lines)


class NetnsAttestor:
    """Reads kernel state about a target pid from OUTSIDE that process."""

    def __init__(self, *, proc: str = "/proc"):
        self._proc = proc

    # -- individual facts -------------------------------------------------

    def _netns_id(self, pid) -> Optional[str]:
        try:
            return os.readlink(f"{self._proc}/{pid}/ns/net")
        except Exception:
            return None

    def _check_distinct_netns(self, pid: int) -> Tuple[str, bool, str]:
        mine = self._netns_id("self")
        theirs = self._netns_id(pid)
        if mine is None or theirs is None:
            return ("distinct netns", False,
                    "could not read /proc/<pid>/ns/net for both processes")
        if mine == theirs:
            return ("distinct netns", False,
                    f"target shares the supervisor's network namespace ({theirs}); "
                    f"it is not isolated at all")
        return ("distinct netns", True, f"target={theirs} supervisor={mine}")

    def _check_interfaces(self, pid: int) -> Tuple[str, bool, str]:
        """An own namespace is not no-network: a veth pair is an interface."""
        path = f"{self._proc}/{pid}/net/dev"
        try:
            lines = open(path).read().splitlines()[2:]  # two header lines
        except Exception as e:
            return ("loopback only", False, f"could not read {path} ({e})")
        names = [l.split(":")[0].strip() for l in lines if ":" in l]
        extra = [n for n in names if n != "lo"]
        if extra:
            return ("loopback only", False,
                    f"target has non-loopback interface(s): {extra}")
        return ("loopback only", True, f"interfaces={names or ['(none)']}")

    def _check_routes(self, pid: int) -> Tuple[str, bool, str]:
        """BOTH families. Reading only /proc/net/route checks IPv4 and would
        miss a v6-only path completely."""
        found = []
        for fam, path, skip_header in (("ipv4", "net/route", True),
                                       ("ipv6", "net/ipv6_route", False)):
            full = f"{self._proc}/{pid}/{path}"
            try:
                lines = open(full).read().splitlines()
            except FileNotFoundError:
                continue          # family not present is fine
            except Exception as e:
                return ("no routes", False, f"could not read {full} ({e})")
            rows = lines[1:] if skip_header else lines
            rows = [r for r in rows if r.strip()]
            if fam == "ipv6":
                # The loopback/local rows are not a path off the machine.
                rows = [r for r in rows
                        if not re.search(r"\blo\b\s*$", r) and " lo" not in r]
            if rows:
                found.append(f"{fam}:{len(rows)} route(s)")
        if found:
            return ("no routes", False,
                    f"target has a route off the machine: {', '.join(found)}")
        return ("no routes", True, "no ipv4/ipv6 routes")

    # Every /proc/net table that can list a socket capable of reaching a wire.
    # The first version walked only tcp/tcp6/udp/udp6, so a RAW or AF_PACKET fd
    # returned "all non-inet" and the whole attestation PASSED — a false
    # assurance, in the one check the docstring calls out as the one most
    # systems miss. Red team (Grok, 2026-08).
    _SOCKET_TABLES = ("net/tcp", "net/tcp6", "net/udp", "net/udp6",
                      "net/udplite", "net/udplite6",
                      "net/raw", "net/raw6", "net/packet",
                      "net/sctp/eps", "net/sctp/assocs", "net/dccp/dccp")

    def _check_no_inherited_sockets(self, pid: int) -> Tuple[str, bool, str]:
        """The check most systems skip.

        A namespace does not close a socket the process ALREADY holds, and a
        seccomp filter does not either: using an existing fd needs no socket(2).
        An fd handed in before isolation, or inherited across a fork, is a live
        wire that survives both controls.
        """
        fddir = f"{self._proc}/{pid}/fd"
        try:
            fds = os.listdir(fddir)
        except Exception as e:
            return ("no inherited inet sockets", False,
                    f"could not enumerate {fddir} ({e})")
        inodes = set()
        for fd in fds:
            try:
                target = os.readlink(f"{fddir}/{fd}")
            except Exception:
                continue
            m = re.match(r"socket:\[(\d+)\]", target)
            if m:
                inodes.add(m.group(1))
        if not inodes:
            return ("no inherited inet sockets", True, "no socket fds held")

        # Which of those inodes belong to a network-capable family? Scan EVERY
        # column rather than a fixed index: /proc/net/tcp puts the inode at
        # column 9 but /proc/net/packet puts it at column 8, so a hard-coded
        # index silently misses exactly the families added above. A stray column
        # that happens to equal an inode would produce a false POSITIVE, which
        # fails toward refusing — the safe direction for a verifier.
        found = {}
        for tbl in self._SOCKET_TABLES:
            path = f"{self._proc}/{pid}/{tbl}"
            if not os.path.exists(path):
                continue          # family/module not present is fine
            try:
                rows = open(path).read().splitlines()[1:]
            except Exception as e:
                # A table we cannot read is a family we cannot clear.
                return ("no inherited inet sockets", False,
                        f"could not read {path} ({e}); cannot establish that no "
                        f"network socket is held")
            for row in rows:
                for col in row.split():
                    if col in inodes:
                        found.setdefault(tbl.rsplit("/", 1)[-1], 0)
                        found[tbl.rsplit("/", 1)[-1]] += 1
                        break
        if found:
            detail = ", ".join(f"{k}:{v}" for k, v in sorted(found.items()))
            return ("no inherited inet sockets", False,
                    f"target holds network socket fd(s) [{detail}] — a live wire "
                    f"that no namespace or seccomp filter can close, because "
                    f"using an existing fd requires no syscall to create one")
        return ("no inherited inet sockets", True,
                f"{len(inodes)} socket fd(s), none in any network family "
                f"(AF_UNIX is expected: it is the broker channel)")

    # -- the attestation --------------------------------------------------

    def attest(self, pid: int) -> AttestationResult:
        """Attest that `pid` has no network path. Fails closed on every branch
        that cannot establish its fact."""
        if not os.path.isdir(self._proc):
            return AttestationResult(
                False, pid,
                (("linux procfs", False,
                  f"{self._proc} is not available; this guarantee is Linux-only "
                  f"and cannot be established here"),))
        if not os.path.isdir(f"{self._proc}/{pid}"):
            return AttestationResult(
                False, pid,
                (("target exists", False, f"no such pid {pid}"),))

        checks = (
            self._check_distinct_netns(pid),
            self._check_interfaces(pid),
            self._check_routes(pid),
            self._check_no_inherited_sockets(pid),
        )
        return AttestationResult(all(c[1] for c in checks), pid, checks)


def attest_or_raise(pid: int, *, proc: str = "/proc") -> AttestationResult:
    """Attest and raise on failure. Use at supervisor startup, before handing
    the agent any work: an agent that cannot be attested should not be run."""
    result = NetnsAttestor(proc=proc).attest(pid)
    if not result.passed:
        raise NotIsolated(result.report())
    return result


class NotIsolated(RuntimeError):
    """The target could not be attested as having no network path.

    Raised on 'is not isolated' AND on 'could not determine', deliberately: a
    verifier that distinguishes them at the call site invites a caller to treat
    the second as benign, and cannot-verify is not verified.
    """


class AttestationMonitor:
    """Re-attests on an interval, because a startup check is a snapshot.

    `attest_or_raise` at startup proves a fact about time T. Everything an
    attacker needs happens at T+1: `setns(2)` if any helper retains
    CAP_SYS_ADMIN, a veth moved into the namespace over netlink, an fd passed in
    over the AF_UNIX channel via `SCM_RIGHTS` — none of which existed when the
    check ran. Red team (Grok, 2026-08) rated this High, correctly: the
    namespace binds the future, the *check* does not, and the two were being
    conflated.

    This does not make the namespace immutable — only the kernel can do that
    (an empty netns the process cannot leave, plus a seccomp filter that kills
    on `setns`/`unshare`). What it does is bound the window: a breach is noticed
    within `interval_seconds` instead of never.

    FAIL-CLOSED BY DEFAULT. With no handler supplied, a breach raises in the
    monitor thread and sets `.breached`, which callers must treat as a halt
    condition. A monitor whose default was "log and continue" would convert a
    live escape into a line in a file nobody reads.
    """

    def __init__(self, pid: int, *, interval_seconds: float = 5.0,
                 on_breach=None, attestor: Optional["NetnsAttestor"] = None):
        self._pid = pid
        self._interval = interval_seconds
        self._attestor = attestor or NetnsAttestor()
        self._on_breach = on_breach
        self._breached: Optional[AttestationResult] = None
        self._thread = None
        self._stop = None

    @property
    def breached(self) -> Optional[AttestationResult]:
        """The failing result, or None. Truthy means STOP."""
        return self._breached

    def check_once(self) -> AttestationResult:
        """One re-attestation. Records and reports a breach; never swallows it."""
        result = self._attestor.attest(self._pid)
        if not result.passed and self._breached is None:
            self._breached = result
            if self._on_breach is not None:
                self._on_breach(result)
        return result

    def start(self):
        """Begin periodic re-attestation on a daemon thread."""
        import threading
        if self._thread is not None:
            return self
        self._stop = threading.Event()

        def _loop():
            # Event.wait(timeout) is MONOTONIC-safe: CPython implements the
            # timeout as a lock acquire with a monotonic deadline (since 3.3),
            # so a wall-clock jump in either direction cannot stretch or skip
            # the re-attestation interval. Stated explicitly because grepping
            # this file for "monotonic" finds nothing and invites the wrong
            # conclusion — the guarantee comes from the stdlib primitive, not
            # from code here. (A self-red-team pass reached exactly that wrong
            # conclusion; leaving this note so the next reader does not.)
            while not self._stop.wait(self._interval):
                if self.check_once().passed is False:
                    # Stop re-reporting the same breach; the first one is the
                    # incident and the caller has been told.
                    break

        self._thread = threading.Thread(target=_loop, daemon=True,
                                        name=f"netns-attest-{self._pid}")
        self._thread.start()
        return self

    def stop(self):
        if self._stop is not None:
            self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval * 2)
            self._thread = None

    def raise_if_breached(self):
        """Call before any consequential action. An agent whose isolation has
        lapsed must not be handed more work."""
        if self._breached is not None:
            raise NotIsolated(
                "isolation lapsed AFTER the startup attestation:\n"
                + self._breached.report())
