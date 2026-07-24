"""
isolation_manifest.py — the bouncer, and an honest account of what a bouncer can do.

THE IDEA
────────
P0 in THREAT_MODEL_ONE_DOOR.md says the agent process must have no unmediated network
path, and that this framework cannot verify it. That is true of a *self-report*, but it
is not the whole story: a process can enumerate a great deal about its own confinement,
and a SUPERVISOR can enumerate it about someone else's with far more authority.

The trick is not to hunt for weapons. You cannot enumerate every channel — io_uring, a
vendor SDK with its own transport, a kernel interface invented next year. Hunting for
known-bad is the same unbounded game as a keyword list, and it loses the same way.

So this applies the pattern the rest of the repo already runs on, one layer down:

    DECLARE THE EXPECTED CAPABILITY SURFACE. REFUSE ANYTHING UNDECLARED.

You do not need to recognise the weapon. You need to notice that something is there
which nobody declared. An unexpected socket FD is a refusal, whatever it turns out to be.

THREE LIMITS, STATED BEFORE THE CODE RATHER THAN AFTER
─────────────────────────────────────────────────────
1. THE SELF-CHECK IS A MISCONFIGURATION SMOKE TEST, NOT A SECURITY CONTROL.
   `verify_self()` runs in the same address space as the agent. If agent code has
   already executed, it can patch the scanner, or patch the result. Against a hostile
   in-process adversary it is worth nothing. Against the failure that will actually
   happen — someone forgetting the network namespace on a Tuesday — it is worth a lot.
   Run it as the FIRST thing in the process, before any agent code, and prefer the
   supervisor path below.

2. A CHECK IS A MOMENT; CAPABILITIES ARE A TIMELINE.
   A bouncer checks at the door. A process can acquire a socket AFTER startup: dlopen a
   library, spawn a helper, receive an FD over a Unix socket via SCM_RIGHTS, import a
   module lazily. Checked clean at 9pm, a knife comes through the window at 11pm.
   Scanning does not bind the future. Only an empty netns or a seccomp filter does,
   because those make the syscall itself fail. This module therefore REPORTS ON those
   mechanisms rather than pretending to replace them.

3. A GREEN LIGHT FROM THE SUBJECT IS WORSE THAN NO LIGHT.
   It manufactures confidence without evidence. Every result here carries `trusted`,
   which is False for self-checks, and the summary says so in words.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, FrozenSet, List, Optional

# Linux capability bit numbers for the network-relevant capabilities.
_CAP_BITS = {
    "CAP_NET_BIND_SERVICE": 10,
    "CAP_NET_BROADCAST": 11,
    "CAP_NET_ADMIN": 12,
    "CAP_NET_RAW": 13,
    "CAP_SYS_ADMIN": 21,
    "CAP_SYS_PTRACE": 19,
    "CAP_SYS_MODULE": 16,
}

_SECCOMP_MODES = {0: "DISABLED", 1: "STRICT", 2: "FILTER"}

# Kinds that an exact-target declaration must never be able to launder, because their
# /proc targets are unstable inode numbers rather than stable names.
_NEVER_BY_TARGET = frozenset({"socket_network", "socket_unix", "socket_unknown",
                              "namespace", "anon_unknown"})
_NETWORK_CAPABLE_KINDS = frozenset({"socket_network", "socket_unix", "socket_unknown",
                                    "namespace", "anon_unknown"})


# Device paths are matched EXACTLY, never by prefix. A prefix test classified
# "/dev/null_backdoor", "/dev/randomizer" and "/dev/zerofill" as benign devnull —
# the identical substring-vs-whole-token bug this repo already fixed twice (the
# escalation lexicon reading "kill" inside "skill", and classify() in the kernel
# guard). Written a third time in a new module, found by self-red-team. The lesson
# is evidently not "remember not to do this"; it is "never write prefix matching
# against a security-relevant name at all".
_BENIGN_DEVICES = frozenset({"/dev/null", "/dev/zero", "/dev/urandom", "/dev/random",
                             "/dev/full"})
_TTY_RE = re.compile(r"^/dev/(tty|pts/\d+)$")

# anon_inode kinds that are NOT benign. io_uring in particular can perform network
# operations (IORING_OP_CONNECT/SEND/RECV) without ever calling socket(), so an
# io_uring ring is a network-capable channel that a socket-focused scan misses
# entirely. This is exactly the "channel it does not know about" class, so it gets
# its own kind and is NOT in the default allowlist.
# INVERTED after external review (Grok #4 and ChatGPT P1-1 converged). This was a
# BLOCKLIST: known-bad anon inodes were refused and everything else permitted — which
# is "hunt known-bad", the exact pattern this module's own docstring says loses. Linux
# adds anon inode types regularly; the next one that can do network I/O would have been
# silently allowed. Now only demonstrably-inert kinds are named, and anything else is
# 'anon_unknown', which is not in any default allowlist.
_BENIGN_ANON = ("eventfd", "eventpoll", "timerfd", "signalfd", "inotify",
                "fanotify", "pidfd", "memfd", "dmabuf", "sync_file")


def classify_fd(target: str, net_inodes: Optional[Dict[str, str]] = None) -> str:
    """Classify an FD. `net_inodes` maps socket inode -> family ('network'/'unix'),
    built from /proc/<pid>/net/*; without it a socket cannot be attributed and is
    classified 'socket_unknown', which is refused."""
    """Classify an FD by its /proc readlink target. Anything unrecognised is
    'unknown' — and unknown is refused, not shrugged at."""
    if target.startswith("socket:"):
        # Grok #3: every socket used to collapse to one kind, so AF_UNIX could not be
        # permitted without also permitting AF_INET. Inodes ARE attributable via
        # /proc/<pid>/net/{tcp,tcp6,udp,udp6,unix}, so the two are now distinguishable.
        # A socket that cannot be attributed is 'socket_unknown' and is REFUSED — an
        # unattributable socket is not a benign one.
        inode = target[len("socket:"):].strip("[]")
        fam = (net_inodes or {}).get(inode)
        if fam == "unix":
            return "socket_unix"
        if fam == "network":
            return "socket_network"
        return "socket_unknown"
    if target.startswith("pipe:"):
        return "pipe"
    if target.startswith("anon_inode:"):
        inner = target[len("anon_inode:"):].strip("[]").lower()
        for benign in _BENIGN_ANON:
            if benign in inner:
                return "anon_inode"
        # io_uring, bpf, userfaultfd, perf_event AND every kind invented after this
        # code was written all land here — and 'anon_unknown' is refused by default.
        return "anon_unknown"
    if target.startswith(("net:", "ipc:", "mnt:", "pid:", "user:", "uts:", "cgroup:")):
        return "namespace"       # a namespace FD is a setns() handle — never benign
    if target in _BENIGN_DEVICES:
        return "devnull"
    if _TTY_RE.match(target):
        return "tty"
    if target.startswith("/"):
        return "file"
    return "unknown"


@dataclass(frozen=True)
class IsolationManifest:
    """The DECLARED capability surface. A human writes this; the verifier refuses
    anything outside it. Same discipline as the effect registry: the declaration is
    the control, and it must be attributable."""
    declared_by: str
    # FD kinds this process is expected to hold. 'socket' deliberately absent by
    # default: a process that should have no network has no business holding one.
    allowed_fd_kinds: FrozenSet[str] = frozenset({"pipe", "devnull", "tty", "anon_inode"})
    allowed_fd_targets: FrozenSet[str] = frozenset()   # exact paths, e.g. a log file
    max_fds: int = 64
    require_own_netns: bool = True
    forbidden_capabilities: FrozenSet[str] = frozenset(
        {"CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_NET_BIND_SERVICE", "CAP_SYS_ADMIN",
         "CAP_SYS_MODULE", "CAP_SYS_PTRACE"})
    # Dropping from the BOUNDING set is the durable removal; CapEff alone can be
    # regained across a privilege transition (Grok #5).
    require_dropped_from_bounding_set: bool = True
    manifest_version: int = 2      # ChatGPT P1-3: stale manifests must fail closed
    min_verifier_version: int = 2
    require_seccomp: bool = True
    require_no_new_privs: bool = True
    accept_network_capable_fds: bool = False   # explicit opt-in; see __post_init__
    require_empty_netns: bool = True           # G1: own netns is NOT no network

    def __post_init__(self):
        if not self.declared_by:
            raise ValueError(
                "declared_by is required: an isolation manifest states what a process "
                "is permitted to hold, which is a safety-critical declaration")
        # Permitting sockets or namespace handles by KIND defeats the module's whole
        # purpose. It stays possible — an operator may have a genuine reason — but it
        # cannot be quiet.
        risky = self.allowed_fd_kinds & _NETWORK_CAPABLE_KINDS
        if risky and not self.accept_network_capable_fds:
            raise ValueError(
                f"allowed_fd_kinds includes {sorted(risky)}, which permits unmediated "
                f"network/namespace handles and defeats the purpose of this manifest. "
                f"If that is genuinely intended, set accept_network_capable_fds=True so "
                f"the decision is explicit and visible in the declaration.")
        for cap in self.forbidden_capabilities:
            if cap not in _CAP_BITS:
                raise ValueError(
                    f"unknown capability {cap!r}; known: {sorted(_CAP_BITS)}. A "
                    f"capability the verifier cannot locate would be silently unchecked.")


@dataclass
class IsolationReport:
    trusted: bool                    # False for self-checks — the subject is the auditor
    source: str                      # "self" or "supervisor:<pid>"
    findings: List[str] = field(default_factory=list)   # each is a REFUSAL reason
    observations: Dict[str, object] = field(default_factory=dict)
    checked_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def permitted(self) -> bool:
        return not self.findings

    def summary(self) -> str:
        head = ("ISOLATION OK" if self.permitted else
                f"ISOLATION REFUSED ({len(self.findings)} finding(s))")
        trust = ("" if self.trusted else
                 "  [SELF-REPORTED — a misconfiguration smoke test, NOT a security "
                 "control: in-process code could patch this result]")
        return head + trust + "".join(f"\n  - {f}" for f in self.findings)


class _ProcSource:
    """Reads /proc for a pid. Injectable so verification is testable without
    fabricating a real confined process."""

    def __init__(self, pid: Optional[int] = None):
        self.pid = pid
        self.base = f"/proc/{pid}" if pid is not None else "/proc/self"

    def fds(self) -> Dict[str, str]:
        out = {}
        d = f"{self.base}/fd"
        for name in os.listdir(d):
            try:
                out[name] = os.readlink(f"{d}/{name}")
            except OSError:
                out[name] = "unknown"
        return out

    def netns(self) -> str:
        return os.readlink(f"{self.base}/ns/net")

    def interfaces(self) -> List[str]:
        """Interface names inside the subject's network namespace."""
        names = []
        with open(f"{self.base}/net/dev") as fh:
            for i, line in enumerate(fh):
                if i < 2 or ":" not in line:      # two header lines
                    continue
                names.append(line.split(":", 1)[0].strip())
        return names

    def net_inodes(self) -> Dict[str, str]:
        """socket inode -> 'network' | 'unix', read from the subject's own net tables."""
        out: Dict[str, str] = {}
        for fam, files, idx in (("network", ("tcp", "tcp6", "udp", "udp6", "raw",
                                             "raw6", "packet"), 9),
                                ("unix", ("unix",), 6)):
            for f in files:
                try:
                    with open(f"{self.base}/net/{f}") as fh:
                        next(fh, None)             # header
                        for line in fh:
                            parts = line.split()
                            if len(parts) > idx:
                                out[parts[idx].rstrip(":")] = fam
                except (OSError, StopIteration):
                    continue
        return out

    def status(self) -> Dict[str, str]:
        out = {}
        with open(f"{self.base}/status") as fh:
            for line in fh:
                if ":" in line:
                    k, v = line.split(":", 1)
                    out[k.strip()] = v.strip()
        return out


def _verify(source, manifest: IsolationManifest, *, trusted: bool, label: str,
            reference_netns: Optional[str] = None) -> IsolationReport:
    rep = IsolationReport(trusted=trusted, source=label)

    # ── file descriptors: fail closed on ANYTHING undeclared ──
    try:
        fds = source.fds()
        try:
            net_inodes = source.net_inodes()
        except Exception:
            net_inodes = {}      # unattributable -> sockets become 'socket_unknown'
        rep.observations["fd_count"] = len(fds)
        kinds: Dict[str, int] = {}
        for num, target in sorted(fds.items()):
            kind = classify_fd(target, net_inodes)
            kinds[kind] = kinds.get(kind, 0) + 1
            if target in manifest.allowed_fd_targets and kind not in _NEVER_BY_TARGET:
                continue
            if target in manifest.allowed_fd_targets and kind in _NEVER_BY_TARGET:
                rep.findings.append(
                    f"file descriptor {num} -> {target} is listed in allowed_fd_targets, "
                    f"but its KIND is {kind!r}, which can never be permitted by naming a "
                    f"target. Socket and namespace handles are identified by unstable "
                    f"inode numbers; allowing one by exact string would be permitting "
                    f"whatever happens to hold that inode next.")
                continue
            if kind not in manifest.allowed_fd_kinds:
                rep.findings.append(
                    f"undeclared file descriptor {num} -> {target} (kind {kind!r}). "
                    f"An FD nobody declared is refused whatever it turns out to be; "
                    f"a 'socket' here means an unmediated network path exists.")
        rep.observations["fd_kinds"] = kinds
        if len(fds) > manifest.max_fds:
            rep.findings.append(
                f"{len(fds)} open file descriptors exceeds the declared max "
                f"{manifest.max_fds}")
    except OSError as e:
        rep.findings.append(
            f"file descriptors could not be enumerated ({e}); refusing rather than "
            f"assuming none — a check that cannot run is not a check that passed")

    # ── network namespace ──
    if manifest.require_own_netns:
        try:
            ns = source.netns()
            rep.observations["netns"] = ns
            if reference_netns is not None and ns == reference_netns:
                rep.findings.append(
                    f"process shares network namespace {ns} with the reference "
                    f"(supervisor/host). It is not network-isolated: an empty netns is "
                    f"what makes 'no socket' a property rather than a hope.")
            elif reference_netns is None:
                # This used to be recorded as a note and PERMITTED, which turned the
                # headline check — "is the agent sharing my namespace" — into a no-op
                # whenever the supervisor could not read its own netns. The single most
                # common isolation failure silently stopped being checked.
                rep.findings.append(
                    "require_own_netns is set but NO reference namespace was available "
                    "to compare against, so network isolation could not be established. "
                    "Refusing: a check that cannot be performed has not passed. (Supply "
                    "the supervisor's namespace, or use verify_process(compare_to_self=True).)")
        except OSError as e:
            rep.findings.append(f"network namespace could not be read ({e}); refusing")

    # ── G1 (external red team, CRITICAL): a PRIVATE namespace is not an EMPTY one ──
    # The check above only established "different from the reference". A private netns
    # containing a veth, macvlan or any routed interface passes it and still has a
    # fully working network path. This module's own comments said "empty netns" while
    # the code checked "different netns" — a doc-vs-code mismatch of exactly the kind
    # this project keeps finding elsewhere. Emptiness is now measured: loopback only.
    if getattr(manifest, "require_empty_netns", False):
        try:
            ifaces = source.interfaces()
            rep.observations["interfaces"] = ifaces
            routable = [i for i in ifaces if i != "lo"]
            if routable:
                rep.findings.append(
                    f"network namespace contains non-loopback interface(s) {routable}. "
                    f"A PRIVATE namespace is not an EMPTY one: a veth or macvlan inside "
                    f"it is a working route out, and every other check here would still "
                    f"pass. Emptiness is the property that makes 'no network' true.")
        except (OSError, AttributeError) as e:
            rep.findings.append(
                f"network interfaces could not be enumerated ({e}); refusing — "
                f"namespace emptiness is unverified, and unverified is not empty")

    # ── capabilities + seccomp ──
    try:
        st = source.status()
        if "CapEff" not in st:
            # Previously `st.get("CapEff", "0")` -> 0 -> "no capabilities held" -> PASS.
            # A status file without the field (other kernel, other runtime, non-Linux)
            # silently reported clean. An absent measurement is not a passing one.
            rep.findings.append(
                "CapEff is absent from process status, so held capabilities could not "
                "be determined. Refusing: an unmeasurable capability set is not an "
                "empty one.")
        cap_eff = int(st.get("CapEff", "0"), 16)
        rep.observations["CapEff"] = st.get("CapEff", "")
        for cap in sorted(manifest.forbidden_capabilities):
            if cap_eff & (1 << _CAP_BITS[cap]):
                rep.findings.append(
                    f"{cap} is HELD. It must be dropped from the bounding set — with "
                    f"it, network configuration or raw sockets remain reachable "
                    f"regardless of any application-layer allowlist.")
        if getattr(manifest, "require_dropped_from_bounding_set", False):
            if "CapBnd" not in st:
                rep.findings.append(
                    "CapBnd is absent, so the bounding set could not be checked; refusing")
            else:
                cap_bnd = int(st.get("CapBnd", "0"), 16)
                for cap in sorted(manifest.forbidden_capabilities):
                    if cap_bnd & (1 << _CAP_BITS[cap]):
                        rep.findings.append(
                            f"{cap} remains in the BOUNDING set. Clearing CapEff alone is "
                            f"not durable — it can be regained across a privilege "
                            f"transition. Drop it from CapBnd.")
        seccomp = int(st.get("Seccomp", "0"))
        rep.observations["seccomp"] = _SECCOMP_MODES.get(seccomp, str(seccomp))
        rep.observations["seccomp_filters"] = st.get("Seccomp_filters", "unknown")
        if manifest.require_seccomp and seccomp == 0:
            rep.findings.append(
                "seccomp is DISABLED. Without a syscall filter, a clean scan says "
                "nothing about a socket opened one millisecond later.")
        elif manifest.require_seccomp:
            # HONESTY FIX (external red team G2): mode 2 is satisfied by an ALLOW-ALL
            # filter, which many runtimes install. This check establishes that a filter
            # EXISTS, never that it forbids anything. The earlier claim that "seccomp
            # binds the future" over-reached and is withdrawn: only an EMPTY netns is
            # verified here, and the filter's contents must be attested externally
            # (a known-good profile hash), which this module cannot do.
            rep.observations["seccomp_note"] = (
                "mode only: an allow-all filter satisfies this check. Filter CONTENTS "
                "are NOT verified here and must be externally attested.")
        nnp = st.get("NoNewPrivs", "0")
        rep.observations["NoNewPrivs"] = nnp
        if manifest.require_no_new_privs and nnp != "1":
            rep.findings.append(
                "NoNewPrivs is not set, so a child can regain privileges via setuid")
    except (OSError, ValueError) as e:
        rep.findings.append(
            f"capability/seccomp status could not be read ({e}); refusing")

    return rep


def verify_self(manifest: IsolationManifest, *, reference_netns: Optional[str] = None,
                source=None) -> IsolationReport:
    """Check THIS process against the manifest.

    HONEST LABEL: `trusted=False`. This is a misconfiguration smoke test. It catches
    the forgotten netns, the inherited socket, the capability nobody dropped — the
    failures that actually happen. It does NOT survive an adversary with code
    execution in this process, who can patch either the scan or its result. Run it
    before any agent code loads, and prefer verify_process() from a supervisor.
    """
    return _verify(source or _ProcSource(None), manifest,
                   trusted=False, label="self", reference_netns=reference_netns)


def verify_process(pid: int, manifest: IsolationManifest, *,
                   compare_to_self: bool = True, reference_netns: Optional[str] = None,
                   source=None) -> IsolationReport:
    """Check ANOTHER process from a supervisor. This is the one with authority.

    The subject is not the auditor: the agent cannot patch a scan running in a
    different address space. If `compare_to_self`, the supervisor's own network
    namespace is used as the reference, so "the agent shares my netns" — the single
    most common isolation failure — is caught directly.
    """
    ref = reference_netns
    if ref is None and compare_to_self:
        try:
            ref = os.readlink("/proc/self/ns/net")
        except OSError:
            ref = None   # -> _verify refuses; a missing reference is not a pass
    return _verify(source or _ProcSource(pid), manifest,
                   trusted=True, label=f"supervisor:{pid}", reference_netns=ref)


def attest_or_refuse(report: IsolationReport) -> None:
    """Fail-closed helper for a startup path: raise unless isolation verified.

    Deliberately refuses a PASSING SELF-REPORT as sufficient for the wall property.
    A green light produced by the thing being inspected is not evidence, and the
    posture event in the broker says exactly that.
    """
    if not report.permitted:
        raise PermissionError(report.summary())
    if not report.trusted:
        raise PermissionError(
            "isolation was self-reported and passed, which is NOT sufficient to claim "
            "the wall property: the process that answered the question is the process "
            "under question. Obtain a supervisor attestation via verify_process().\n"
            + report.summary())
