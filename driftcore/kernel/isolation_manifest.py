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

_CAP_BY_BIT = {v: k for k, v in _CAP_BITS.items()}


def decode_caps(mask: int) -> list:
    """Every capability bit SET in the mask, named where known and numbered where not.

    The verifier knew 7 of ~41 Linux capabilities, so a capability outside that list
    was invisible — hunt-known-bad, the exact pattern this module rejects for file
    descriptors and anon inodes two hundred lines above. Decoding the whole mask means
    a capability introduced by a future kernel is REPORTED rather than missed, because
    it appears as an unnamed bit rather than as nothing at all.
    """
    out = []
    # Width derived from the value, not fixed at 64. A mask wider than 64 bits (a
    # future kernel) would otherwise have its high capabilities silently invisible —
    # the exact "unknown becomes nothing" failure this function exists to prevent.
    # Bounded. /proc is trusted for CONTENT here but not for FORMAT: a malformed or
    # hostile CapEff string would otherwise make this loop as long as the value.
    for bit in range(min(max(64, mask.bit_length()), 256)):
        if mask & (1 << bit):
            out.append(_CAP_BY_BIT.get(bit, f"CAP_UNKNOWN_BIT_{bit}"))
    return out


_SECCOMP_MODES = {0: "DISABLED", 1: "STRICT", 2: "FILTER"}

# The verifier's own version. A manifest may demand a newer verifier than this; if it
# does, this verifier does not know the checks that manifest expects and must refuse.
# The version fields existed but `_verify` never read them — a version field used as
# documentation rather than as a control, which is the failure mode it exists to prevent.
VERIFIER_VERSION = 2
KNOWN_MANIFEST_VERSIONS = frozenset({1, 2})

# Kinds that an exact-target declaration must never be able to launder, because their
# /proc targets are unstable inode numbers rather than stable names.
_NEVER_BY_TARGET = frozenset({"socket_network", "socket_unix", "socket_unknown",
                              "namespace", "anon_unknown"})
# 'file' and 'unknown' join this set: /dev/net/tun, /dev/ppp and /dev/tap* all
# classify as "file", so an operator adding "file" to allowed_fd_kinds would silently
# permit a TUN device — network capability arriving through a kind that sounds inert.
# The module's rule is that network-capable surface must be EXPLICIT, so permitting a
# broad kind now requires the same deliberate opt-in as permitting a socket. The
# intended path for the few files an agent should hold is an exact allowed_fd_targets
# entry, which is unaffected.
_NETWORK_CAPABLE_KINDS = frozenset({"socket_network", "socket_unix", "socket_unknown",
                                    "namespace", "anon_unknown", "file", "unknown"})


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

# Loopback interface names, matched EXACTLY. The routes oracle was written as
# `not r.startswith("lo")` — a prefix test on a name that decides "can a packet
# leave" — in the SAME commit as the comment above declaring that security-relevant
# name comparisons in this file use frozenset membership. It permitted "loophole",
# "lo0" and "local0" as loopback. That is the fifth instance of this bug in this
# repository. "Remember not to do this" has now failed five times; the standing rule
# is that any name test deciding a security property is membership in a frozenset.
# EXACTLY "lo". On Linux the loopback interface is always and only `lo`; "lo0" is
# BSD/Solaris and "loopback" is not a Linux default either. Both were in this set for
# one commit, and both are names an attacker can CREATE on Linux — so the allowlist
# written to fix a too-loose prefix test was itself too loose. Replacing a bad test
# with a generous list is the same error wearing a different mechanism: what matters
# is not "am I using membership" but "is the set exactly the real thing".
_LOOPBACK_NAMES = frozenset({"lo"})


def _is_loopback(name: str) -> bool:
    """Exact, alias-aware loopback test. Used by BOTH the interface and route oracles
    so they cannot disagree — a disagreement between two oracles for the same property
    is where a false permit hides."""
    return name.split(":", 1)[0] in _LOOPBACK_NAMES

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
# EXACT MATCH ONLY. This was written as `if benign in inner` — a substring test — which
# laundered anon_inode:[eventfd_evil], [memfd_backdoor] and [pidfd_exfil] into the
# permitted kind. That is the SAME substring-vs-whole-token bug this file's own comments
# record as having been fixed three times already (escalation lexicon "kill" in "skill",
# kernel guard classify(), and the /dev path prefix test two hundred lines above this
# one). Fourth instance, found by two independent reviewers.
#
# The recurrence is the finding. "Remember not to do this" has now failed four times, so
# the rule is structural instead: SECURITY-RELEVANT NAME COMPARISONS IN THIS FILE USE
# frozenset MEMBERSHIP. No `in` against a string, no startswith, no regex with a
# non-anchored tail. If a comparison cannot be expressed as set membership, it is not a
# name comparison and needs a different mechanism.
# memfd and dmabuf were removed from this set in self-red-team. Both are SHAREABLE
# memory objects: a memfd passed to another process over SCM_RIGHTS is a two-way
# communication channel, and "a channel to a helper process that does have network" is
# precisely the bypass this module exists to notice. They are inert only while nobody
# shares them, which is not a property an FD scan can establish. Undeclared -> refused;
# a deployment that genuinely needs one declares it as a kind and says why.
_BENIGN_ANON = frozenset({
    "eventfd", "eventpoll", "timerfd", "signalfd", "inotify",
    "fanotify", "pidfd", "sync_file"})


def classify_fd(target: str, net_inodes: Optional[Dict[str, str]] = None) -> str:
    """Classify an FD by its /proc readlink target.

    `net_inodes` maps socket inode -> family ('network'/'unix'), built from
    /proc/<pid>/net/*; without it a socket cannot be attributed and is classified
    'socket_unknown'. Anything unrecognised is 'unknown'. Both are refused by default —
    unknown is not shrugged at.

    All name comparisons here are frozenset membership, never containment. See the
    note on _BENIGN_ANON for why that is a structural rule in this file rather than
    a thing to remember.
    """
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
        if inner in _BENIGN_ANON:          # exact membership, never containment
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


class IsolationScanError(Exception):
    """The capability surface could not be fully enumerated.

    Raised at the point of failure rather than encoded as a vague placeholder. The
    three sites that now raise this used to label the unreadable thing "unknown", or
    silently skip it, and rely on a rule three files away to refuse the label later.
    That worked — but the safety lived somewhere other than the failure, so a
    reasonable-looking edit to the allowlist would have turned all three into bypasses
    in the same afternoon, with nothing connecting the change to the breakage.

    An error that says no where it happens is an error a reviewer can read in one place.
    """


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
    # DEFAULT DENY. Previously this was `forbidden_capabilities` — a list of seven
    # named capabilities, out of roughly forty-one, with everything unnamed silently
    # permitted. Inverted: the process may hold ONLY what is declared here, and the
    # default is nothing, because an agent behind a wall needs no capabilities at all.
    # Replaced rather than added alongside: two mechanisms governing one property is
    # how the duplicated quarantine gave a false durability signal.
    permitted_capabilities: FrozenSet[str] = frozenset()
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
        # Inode-numbered targets can never be declared. `socket:[8080]` names an inode
        # that the kernel recycles, so allowing it by exact string permits whatever holds
        # that inode next — a TOCTOU by construction. _verify already refuses these, but
        # refusing at declaration makes the misconfiguration impossible to write down
        # rather than merely caught later.
        # A declared target must BE a stable filesystem path — asserted as a positive
        # shape, not as a blocklist of prefixes. The blocklist version split on ":" and
        # was dodged three ways in self-red-team: "SOCKET:[8080]" (case),
        # " socket:[8080]" (leading space), and "/proc/1/fd/socket:[8080]" (the inode
        # reference embedded in something that IS a path). Enumerating the bad forms is
        # the losing game this project keeps refusing to play everywhere else.
        # A target in the DEVICE tree can be anything — /dev/net/tun, /dev/ppp,
        # /dev/tap0 all provide network and all classify as an ordinary "file". The
        # KIND gate now requires an opt-in for broad kinds; the exact-target path did
        # not, so naming a device by path walked straight past it. Structural test on
        # the path's first component, not a list of known device names.
        for t in self.allowed_fd_targets:
            parts = tuple(x for x in t.split("/") if x)
            if parts and parts[0] == "dev" and not self.accept_network_capable_fds:
                raise ValueError(
                    f"allowed_fd_targets contains {t!r}, a path in the device tree. "
                    f"Devices can provide network capability (/dev/net/tun, /dev/ppp, "
                    f"/dev/tap*) while classifying as an ordinary file, so declaring "
                    f"one requires accept_network_capable_fds=True — the same "
                    f"deliberate opt-in as permitting a socket.")
        for t in self.allowed_fd_targets:
            if t != t.strip():
                raise ValueError(
                    f"allowed_fd_targets contains {t!r} with surrounding whitespace; "
                    f"it would never match a real /proc target. Refusing rather than "
                    f"silently trimming.")
            if not t.startswith("/"):
                raise ValueError(
                    f"allowed_fd_targets contains {t!r}, which is not an absolute "
                    f"filesystem path. Only stable paths may be declared by name.")
            if ":" in t:
                raise ValueError(
                    f"allowed_fd_targets contains {t!r}. A ':' means it references a "
                    f"kernel object by RECYCLED INODE NUMBER (socket:[..], net:[..], "
                    f"anon_inode:[..]) — possibly embedded inside something that looks "
                    f"like a path. Permitting it would permit whatever holds that inode "
                    f"next. Declare an FD KIND instead.")
        for cap in self.permitted_capabilities:
            if cap not in _CAP_BITS and not cap.startswith("CAP_UNKNOWN_BIT_"):
                raise ValueError(
                    f"unknown capability {cap!r}; known: {sorted(_CAP_BITS)}. Permitting "
                    f"a capability the verifier cannot locate would permit a bit it "
                    f"cannot check.")


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
        # "ISOLATION OK" implies a guarantee. What this holds is a snapshot of
        # observable properties at one instant — /proc is an observation interface, not
        # an enforcement mechanism. The wording says so.
        head = ("OBSERVED ISOLATION: no findings" if self.permitted else
                f"OBSERVED ISOLATION: REFUSED ({len(self.findings)} finding(s))")
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
            except FileNotFoundError:
                # The descriptor was closed between listing and reading. Benign and
                # common in a live process — it is gone, so it holds nothing.
                continue
            except OSError as e:
                # A descriptor that EXISTS and cannot be read is a ticket we cannot
                # check. Refuse here, naming it, rather than labelling it "unknown"
                # and depending on a distant allowlist to reject that label.
                raise IsolationScanError(
                    f"file descriptor {name} exists but could not be read ({e}). An FD "
                    f"that cannot be identified cannot be cleared. If this is a "
                    f"transient race, re-run the scan; if it persists, the supervisor "
                    f"lacks the privilege to inspect this process and must not "
                    f"attest to it.") from e
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

    def routes(self) -> List[str]:
        """Interfaces that have a ROUTE in the subject's namespace.

        Interface NAMES are a proxy: `lo:0` and other aliases slip past a `!= "lo"`
        test, and a renamed loopback defeats it entirely. What actually determines
        whether a packet can leave is the routing table, so read that too. Emptiness
        is then the conjunction of both oracles rather than one name comparison.
        """
        out = []
        # BOTH families. This read only /proc/net/route, which is IPv4, while the
        # comment said "the routing table" — a namespace with IPv6-only connectivity
        # was unmeasured by the stronger oracle. A table that does not exist on this
        # kernel lists no routes; a table that exists and cannot be READ is a refusal,
        # raised so the caller records it rather than assuming emptiness.
        for fam in ("route", "ipv6_route"):
            try:
                with open(f"{self.base}/net/{fam}") as fh:
                    if fam == "route":
                        next(fh, None)         # IPv4 table has a header; ipv6_route does not
                    for line in fh:
                        parts = line.split()
                        if not parts:
                            continue
                        # IPv4: iface is column 0. IPv6: iface is the LAST column.
                        out.append(parts[0] if fam == "route" else parts[-1])
            except FileNotFoundError:
                continue
        return out

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
                except FileNotFoundError:
                    # That protocol table does not exist on this kernel (e.g. no IPv6).
                    # A table that is absent lists no sockets, so nothing is unmeasured.
                    continue
                except OSError as e:
                    # The table EXISTS and could not be read, so socket attribution is
                    # incomplete and we cannot tell AF_UNIX from AF_INET. Refuse here
                    # rather than returning a partial map that silently looks complete.
                    raise IsolationScanError(
                        f"socket table {f!r} exists but could not be read ({e}). Socket "
                        f"attribution would be incomplete, so a network socket could be "
                        f"mistaken for a local one.") from e
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

    # ── the manifest must be one this verifier actually understands ──
    # getattr(..., 1) meant an object with no version fields defaulted to a KNOWN
    # version and passed. An absent declaration is not a version-1 declaration.
    if not hasattr(manifest, "manifest_version") or \
            not hasattr(manifest, "min_verifier_version"):
        rep.findings.append(
            "the manifest declares no version. This verifier cannot tell which checks "
            "it was written to expect, so a pass would be meaningless. Refusing.")
    mv = getattr(manifest, "manifest_version", None)
    need = getattr(manifest, "min_verifier_version", None)
    if mv is None or need is None:
        return rep
    rep.observations["manifest_version"] = mv
    rep.observations["verifier_version"] = VERIFIER_VERSION
    if need > VERIFIER_VERSION:
        rep.findings.append(
            f"manifest requires verifier version {need} but this verifier is "
            f"{VERIFIER_VERSION}. It does not implement the checks the manifest expects, "
            f"so a pass here would mean 'the checks I know about succeeded', not 'the "
            f"declared surface was verified'. Refusing.")
    if mv not in KNOWN_MANIFEST_VERSIONS:
        rep.findings.append(
            f"manifest_version {mv} is not one this verifier knows "
            f"({sorted(KNOWN_MANIFEST_VERSIONS)}); refusing rather than guessing which "
            f"defaults it intended.")

    # ── file descriptors: fail closed on ANYTHING undeclared ──
    try:
        fds = source.fds()
        net_inodes = source.net_inodes()
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
    except AttributeError as e:
        # An incomplete scan SOURCE (missing a method) is a wiring error, not a clean
        # surface. The previous bare `except Exception` swallowed this too and carried
        # on with an empty map. _verify must stay TOTAL — it always returns a report,
        # never raises — so this becomes a refusal rather than a crash.
        rep.findings.append(
            f"the scan source is incomplete ({e}); refusing. A verifier that cannot "
            f"ask every question has not asked them.")
    except IsolationScanError as e:
        # The scan named its own failure. Carry that reason through verbatim: the
        # operator needs to know WHICH descriptor or table was unreadable, not merely
        # that something was.
        rep.findings.append(f"capability surface could not be enumerated: {e}")
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
            if not ifaces:
                # Loopback is present in essentially every namespace, so an EMPTY list
                # is far more likely to mean "/proc/net/dev did not parse" than
                # "genuinely no interfaces" — and a format change would then read as
                # the safest possible result. Unmeasured is not empty.
                rep.findings.append(
                    "no network interfaces were listed at all, not even loopback. That "
                    "is more likely a parse failure than a genuinely empty namespace, "
                    "and a parse failure must not read as the safest possible state.")
            # Routes are the stronger oracle; interface names are the weaker one.
            # Both are consulted, and a source that cannot answer the route question
            # is a refusal rather than a pass.
            try:
                routes = source.routes()
                rep.observations["routes"] = routes
                routed_out = [r for r in routes if not _is_loopback(r)]
                if routed_out:
                    rep.findings.append(
                        f"the namespace has route(s) out via {sorted(set(routed_out))}. "
                        f"A routing entry is what actually lets a packet leave; "
                        f"interface names alone can be aliased ('lo:0') or renamed.")
            except AttributeError:
                # A source that cannot answer the route question has not answered it.
                # This was `pass` — a silent skip that let any source lacking routes()
                # bypass the stronger oracle entirely while the report still said
                # "no findings". That is the same shape as every other swallow this
                # module has removed.
                rep.findings.append(
                    "the scan source cannot report routes, so namespace emptiness "
                    "rests on interface NAMES alone — and names can be aliased "
                    "('lo:0') or renamed. Refusing: a check that cannot run has not "
                    "passed.")
            except OSError as e:
                rep.findings.append(
                    f"the routing table could not be read ({e}); refusing — namespace "
                    f"emptiness is unverified, and unverified is not empty")
            routable = [i for i in ifaces if not _is_loopback(i)]
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
        held_eff = decode_caps(cap_eff)
        rep.observations["capabilities_effective"] = held_eff
        undeclared_eff = [c for c in held_eff if c not in manifest.permitted_capabilities]
        if undeclared_eff:
            rep.findings.append(
                f"undeclared capabilities HELD (effective): {undeclared_eff}. The "
                f"process may hold only what the manifest declares, and it declares "
                f"{sorted(manifest.permitted_capabilities) or 'none'}. Any of these can "
                f"reach past an application-layer allowlist; an unnamed bit is a "
                f"capability this kernel has and this verifier has no name for, which "
                f"is exactly the case a list of known-bad names would have missed.")
        if getattr(manifest, "require_dropped_from_bounding_set", False):
            if "CapBnd" not in st:
                rep.findings.append(
                    "CapBnd is absent, so the bounding set could not be checked; refusing")
            else:
                cap_bnd = int(st.get("CapBnd", "0"), 16)
                held_bnd = decode_caps(cap_bnd)
                rep.observations["capabilities_bounding"] = held_bnd
                # Ambient, permitted and inheritable sets were never observed. Ambient
                # capabilities in particular survive exec under conditions NoNewPrivs
                # does not fully eliminate.
                for other in ("CapAmb", "CapPrm", "CapInh"):
                    if other not in st:
                        rep.findings.append(
                            f"{other} is absent from process status; that capability "
                            f"set could not be checked. Refusing rather than assuming "
                            f"it is empty.")
                        continue
                    held_other = decode_caps(int(st[other], 16))
                    rep.observations[f"capabilities_{other[3:].lower()}"] = held_other
                    extra = [c for c in held_other
                             if c not in manifest.permitted_capabilities]
                    if extra:
                        rep.findings.append(
                            f"undeclared capabilities in {other}: {extra}. Ambient "
                            f"capabilities survive exec; permitted and inheritable "
                            f"sets feed future privilege transitions.")
                undeclared_bnd = [c for c in held_bnd
                                  if c not in manifest.permitted_capabilities]
                if undeclared_bnd:
                    rep.findings.append(
                        f"undeclared capabilities remain in the BOUNDING set: "
                        f"{undeclared_bnd}. Clearing the effective set alone is not "
                        f"durable — a bounding-set capability can be regained across a "
                        f"privilege transition.")
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
