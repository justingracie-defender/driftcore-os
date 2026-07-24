"""
egress_guard.py — NETWORK EGRESS IS ACTUATION.

THE CORRECTION THIS MODULE ENCODES
──────────────────────────────────
This project spent a long time treating "moving an arm" as the thing to mediate and
"making a network request" as infrastructure. That is backwards for any networked
deployment. An agent with a socket does not need an arm: it can reach every networked
actuator in the world. The July 2026 OpenAI/Hugging Face incident is the proof — the
models achieved remote code execution on a third party's production systems without
touching anything physical.

So: a packet is a consequential act. Egress is declared, allowlisted, and fail-closed,
exactly like any other capability.

THE BOUNDARY — READ THIS BEFORE TRUSTING ANYTHING BELOW
──────────────────────────────────────────────────────
This module governs egress that comes THROUGH the wall. It cannot stop a process that
already has a socket. Python cannot take a file descriptor away from the code it shares
an address space with.

That is not a reason to skip it; it is a reason to state the precondition loudly:

    THE AGENT PROCESS MUST HAVE NO UNMEDIATED NETWORK PATH.

Enforced OUTSIDE this code — an empty network namespace, seccomp/Landlock, or a
firewall on a host the agent cannot reconfigure. This module is what makes that
survivable: it provides the one legitimate, governed route out, so "no socket for the
agent" is a workable posture rather than a broken robot.

And note where OpenAI's containment actually failed: their single permitted egress was
a package-registry proxy — that WAS the interlock — implemented in software, on the
same side of the boundary as the thing it was containing, and it had a zero-day. The
lesson is not that egress control is futile. It is that egress control must be as dumb
and as physically separate as a relay, or it inherits the attack surface of whatever it
is built on. Treat the allowlist here as defence in depth BEHIND a network boundary,
never as the boundary itself.

WHY THE MATCHING IS NOT `if host in allowlist`
──────────────────────────────────────────────
A naive host check fails in at least six ways, all of which are live:

    https://api.example.com@evil.com/     userinfo — the real host is evil.com
    https://api.example.com.evil.com/     suffix confusion
    https://evil-api.example.com/         substring confusion
    https://API.Example.COM./             case + trailing dot
    https://аpi.example.com/              Cyrillic 'а' homograph
    http://169.254.169.254/               IP literal to a cloud metadata endpoint

Matching is therefore on a NORMALIZED (scheme, host, port) triple, exactly, with
punycode folding, userinfo rejected, and private/loopback/link-local space refused by
default. Same discipline as the escalation lexicon: normalize, then match whole tokens,
never substrings.
"""

from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import FrozenSet, Optional, Set, Tuple
from urllib.parse import urlsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}

# Ranges Python's ipaddress does not classify as private but which reach infrastructure.
_EXTRA_PRIVATE = (
    ipaddress.ip_network("100.64.0.0/10"),      # CGNAT, RFC 6598
    ipaddress.ip_network("192.0.0.0/24"),       # IETF protocol assignments
    ipaddress.ip_network("198.18.0.0/15"),      # benchmarking
    ipaddress.ip_network("64:ff9b::/96"),       # NAT64 — reaches v4 space via v6
    ipaddress.ip_network("::ffff:0:0/96"),      # v4-mapped v6
)
_MAX_DESTINATIONS = 10_000


class EgressVerdict(str, Enum):
    ALLOW = "ALLOW"
    BLOCK_UNDECLARED = "BLOCK_UNDECLARED"   # destination not on the allowlist
    BLOCK_MALFORMED = "BLOCK_MALFORMED"     # could not be normalized -> never guessed
    BLOCK_PRIVATE = "BLOCK_PRIVATE"         # loopback/private/link-local (SSRF class)
    ERROR = "ERROR"                         # guard could not evaluate -> fail closed


@dataclass(frozen=True)
class EgressDecision:
    verdict: EgressVerdict
    reason: str
    destination: Optional[str] = None
    decided_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def permitted(self) -> bool:
        return self.verdict is EgressVerdict.ALLOW


class MalformedDestination(ValueError):
    """Raised when a destination cannot be normalized. NEVER downgraded to a guess:
    a destination the guard cannot read is a destination it must not permit."""


def normalize_destination(url: str, *, allowed_schemes=("http", "https")) -> Tuple[str, str, int]:
    """Return an exact (scheme, host, port) triple, or raise MalformedDestination.

    Deterministic and total: every rejection has a stated reason, and nothing is
    inferred. This is the whole security of the allowlist — if two different URLs can
    normalize to the same triple, or one URL can reach a host the triple does not name,
    the allowlist is decoration.
    """
    if not url or not isinstance(url, str):
        raise MalformedDestination("empty or non-string destination")
    raw = url.strip()
    if any(ch.isspace() for ch in raw):
        raise MalformedDestination("destination contains whitespace")

    parts = urlsplit(raw)
    scheme = (parts.scheme or "").lower()
    if scheme not in allowed_schemes:
        raise MalformedDestination(
            f"scheme {scheme!r} is not permitted (allowed: {sorted(allowed_schemes)})")

    # userinfo: "https://api.example.com@evil.com/" — the browser-visible prefix is a
    # lie; the real host is after the '@'. Reject outright rather than parse around it.
    if parts.username is not None or parts.password is not None or "@" in (parts.netloc or ""):
        raise MalformedDestination(
            "destination contains userinfo ('@'); the apparent host may not be the "
            "real host, so it is refused rather than interpreted")

    host = parts.hostname
    if not host:
        raise MalformedDestination("destination has no host")

    host = host.strip().rstrip(".").lower()      # trailing dot: "example.com." == "example.com"
    if not host:
        raise MalformedDestination("destination host is empty after normalization")

    # Homograph folding. IDNA-encode so a Cyrillic 'а' becomes a distinct punycode
    # label rather than silently comparing equal to the Latin one.
    try:
        host = host.encode("idna").decode("ascii")
    except Exception:
        if not host.isascii():
            raise MalformedDestination(
                "host contains non-ASCII characters that do not IDNA-encode; refused "
                "rather than compared (homograph risk)")
    host = host.lower()

    try:
        port = parts.port
    except ValueError:
        raise MalformedDestination("destination port is not a valid integer")
    if port is None:
        port = _DEFAULT_PORTS.get(scheme)
        if port is None:
            raise MalformedDestination(f"no default port known for scheme {scheme!r}")
    if not (0 < int(port) < 65536):
        raise MalformedDestination(f"port {port} out of range")

    return (scheme, host, int(port))


def is_private_destination(host: str) -> bool:
    """True for loopback/private/link-local/reserved IP literals.

    The link-local case is the sharp one: cloud instance-metadata endpoints live at a
    link-local address and hand out credentials to anything that asks. An allowlist
    reasoned in hostnames does not see an IP literal at all.
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False        # a name, not a literal — see resolve_and_pin()
    if (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
        return True
    # CGNAT (RFC 6598). Python's is_private does NOT cover 100.64.0.0/10, and carrier
    # -grade NAT space routinely fronts internal services. Verified live in red team.
    for net in _EXTRA_PRIVATE:
        if ip in net:
            return True
    return False


@dataclass(frozen=True)
class EgressPolicy:
    """A HUMAN-declared destination allowlist. Exact (scheme, host, port) triples.

    No wildcards. A wildcard is how an allowlist quietly becomes an any-list, and a
    subdomain wildcard on a host with user-controlled subdomains is not a control at
    all. If a deployment genuinely needs breadth, it lists the destinations.
    """
    destinations: FrozenSet[Tuple[str, str, int]] = frozenset()
    declared_by: str = ""
    allow_private: bool = False       # opt-in, for a genuinely on-prem destination
    private_reason: str = ""          # WHY — required whenever allow_private is set

    @staticmethod
    def build(urls, declared_by: str, *, allow_private: bool = False,
              private_reason: str = "") -> "EgressPolicy":
        if not declared_by:
            raise ValueError(
                "declared_by is required: an egress allowlist is a safety-critical "
                "declaration and must be attributable")
        if allow_private and not private_reason.strip():
            # Red team: "human sets allow_private for on-prem; six months later nobody
            # remembers why, and now the agent can reach the metadata endpoint." An
            # exception to a safety default must carry its justification with it.
            raise ValueError(
                "allow_private=True requires private_reason: reaching loopback/private/"
                "link-local space is an exception to a safety default and the reason "
                "must travel with the policy, not live in someone's memory.")
        urls = list(urls)
        if len(urls) > _MAX_DESTINATIONS:
            raise ValueError(
                f"refusing an allowlist of {len(urls)} destinations (cap "
                f"{_MAX_DESTINATIONS}). An allowlist this large is not a human-reviewable "
                f"declaration, which is the only thing that makes it a control.")
        dests: Set[Tuple[str, str, int]] = set()
        for u in urls:
            triple = normalize_destination(u)   # raises on anything unreadable
            if not allow_private and is_private_destination(triple[1]):
                raise ValueError(
                    f"{u!r} is private/loopback/link-local space. If deliberate, pass "
                    f"allow_private=True AND private_reason='...'.")
            dests.add(triple)
        if not dests:
            raise ValueError(
                "refusing an EMPTY egress allowlist. An empty policy is ambiguous — it "
                "reads as either 'deny everything' or 'not configured yet'. If the "
                "intent is no egress, do not attach an egress capability at all.")
        return EgressPolicy(frozenset(dests), declared_by, allow_private,
                            private_reason.strip())


class EgressGuard:
    """Deterministic destination check. Decides ALLOW or a specific refusal; never
    guesses, never falls through. Counts what it sees so a silent guard is visible."""

    def __init__(self, policy: Optional[EgressPolicy] = None):
        self._policy = policy
        self._lock = threading.RLock()
        self._counts = {"allowed": 0, "blocked": 0, "malformed": 0, "error": 0}
        # Aggregate counts lose the attack PATTERN: five refusals all aimed at the same
        # host read identically to five different probes. Bounded so a flood of unique
        # destinations cannot grow it without limit.
        self._rejected: Dict[str, int] = {}

    def is_armed(self) -> bool:
        """Whether an allowlist is actually configured. An unarmed guard refuses
        NOTHING and permits NOTHING — see check(): with no policy, egress is refused,
        because 'no policy' must not read as 'any destination'."""
        return self._policy is not None

    def check(self, url: str) -> EgressDecision:
        try:
            with self._lock:
                if self._policy is None:
                    self._counts["blocked"] += 1
                    self._note_rejection(url)
                    return EgressDecision(
                        EgressVerdict.BLOCK_UNDECLARED,
                        "no egress allowlist is configured, so no destination is "
                        "declared. Unconfigured is not permissive.", url)
                try:
                    triple = normalize_destination(url)
                except MalformedDestination as e:
                    self._counts["malformed"] += 1
                    self._note_rejection(url)
                    return EgressDecision(
                        EgressVerdict.BLOCK_MALFORMED,
                        f"destination could not be normalized: {e}", url)

                if not self._policy.allow_private and is_private_destination(triple[1]):
                    self._counts["blocked"] += 1
                    self._note_rejection(url)
                    return EgressDecision(
                        EgressVerdict.BLOCK_PRIVATE,
                        f"{triple[1]} is loopback/private/link-local space (the class "
                        f"that reaches cloud instance-metadata credential endpoints)",
                        url)

                if triple in self._policy.destinations:
                    self._counts["allowed"] += 1
                    return EgressDecision(
                        EgressVerdict.ALLOW,
                        f"destination {triple[0]}://{triple[1]}:{triple[2]} is on the "
                        f"allowlist declared by {self._policy.declared_by}", url)

                self._counts["blocked"] += 1
                self._note_rejection(url)
                return EgressDecision(
                    EgressVerdict.BLOCK_UNDECLARED,
                    f"destination {triple[0]}://{triple[1]}:{triple[2]} is not on the "
                    f"human-declared allowlist. Egress to an undeclared destination is "
                    f"refused; declare it (a privileged, audited act) if it is intended.",
                    url)
        except Exception as e:
            self._counts["error"] += 1
            return EgressDecision(
                EgressVerdict.ERROR,
                f"egress guard could not evaluate and fails closed: {e!r}", url)

    def _note_rejection(self, url: str) -> None:
        key = str(url)[:200]
        if key in self._rejected or len(self._rejected) < 256:
            self._rejected[key] = self._rejected.get(key, 0) + 1

    def measurements(self) -> dict:
        with self._lock:
            return {"armed": self.is_armed(), **self._counts,
                    "allow_private": bool(self._policy and self._policy.allow_private),
                    "private_reason": (self._policy.private_reason
                                       if self._policy else ""),
                    "declared_destinations": (len(self._policy.destinations)
                                              if self._policy else 0),
                    "top_rejected": sorted(self._rejected.items(),
                                           key=lambda kv: -kv[1])[:10]}


# ── the residual this layer cannot close, stated rather than hidden ──
#
# DNS REBINDING / RESOLUTION TOCTOU. The allowlist names hosts; the connection resolves
# the name later, and a hostile resolver can answer differently the second time. Closing
# it needs resolve-and-pin at connect time, or (better) enforcement at a network boundary
# the host cannot reconfigure. An application-layer allowlist raises cost; it is not the
# boundary. This is the same shape as the declaration-vs-implementation gap elsewhere in
# this repo: the check is honest about naming a thing it cannot itself bind.
#
# REDIRECTS. An allowed destination that 30x-redirects to a disallowed one defeats a
# check performed only on the initial URL. Any transport wired behind this guard MUST
# disable automatic redirect following and re-check each hop. Documented as a wiring
# requirement because this module never performs the request itself.


# ══════════════════════════════════════════════════════════════════════════
# RESOLVE-AND-PIN, and a transport that cannot forget the rules.
#
# Three independent reviews converged on the same two findings, and both are
# about the same thing: an allowlist NAMES a destination, it does not BIND one.
#
#   1. DNS rebinding / resolution TOCTOU. The check reasons about a hostname;
#      the connect resolves it later, and a hostile resolver can answer
#      differently the second time. It also means a hostname that resolves into
#      private space was never checked at all, because is_private_destination()
#      only sees IP literals.
#   2. Redirects. "Disable automatic redirects and re-check every hop" was
#      written as a wiring requirement. A requirement in a docstring is a
#      requirement someone forgets: one `requests.get(url)` and the allowlist
#      is bypassed by a 302.
#
# The fix for both is the same shape: stop trusting the caller to remember, and
# make the safe path the only path that exists.
# ══════════════════════════════════════════════════════════════════════════

class PinnedDestination:
    """A destination resolved to concrete IPs, every one of which was checked.

    Connect to `ips`, not to `host` — that is the entire point. Re-resolving at
    connect time is what re-opens the rebinding window.
    """
    __slots__ = ("scheme", "host", "port", "ips", "pinned_at")

    def __init__(self, scheme, host, port, ips):
        self.scheme, self.host, self.port = scheme, host, port
        self.ips = tuple(ips)
        self.pinned_at = datetime.now(timezone.utc).isoformat()

    def __repr__(self):
        return f"PinnedDestination({self.scheme}://{self.host}:{self.port} -> {self.ips})"


def resolve_and_pin(triple, *, allow_private: bool = False, resolver=None) -> PinnedDestination:
    """Resolve a checked (scheme, host, port) and verify EVERY answer.

    Narrows rebinding to the window between this call and the connect, and closes
    the hostname-into-private-space gap that the literal-only check could not see.
    ALL resolved addresses must pass — an attacker who can get one hostile record
    into a multi-record answer must not be able to hide it behind a benign one.

    HONEST LIMIT: this does not eliminate rebinding, it shrinks it. The connect
    must then be made to a PINNED IP with the original Host header. A caller that
    hands `host` back to a socket API has undone the work. Full closure is
    enforcement at a network boundary the host cannot reconfigure.
    """
    import socket as _socket
    scheme, host, port = triple
    resolve = resolver or (lambda h, p: _socket.getaddrinfo(h, p, proto=_socket.IPPROTO_TCP))
    try:
        infos = resolve(host, port)
    except Exception as e:
        raise MalformedDestination(
            f"{host!r} could not be resolved: {e!r}. A destination that cannot be "
            f"resolved cannot be pinned, and is refused rather than attempted.")
    ips = []
    for info in infos:
        addr = info[4][0] if isinstance(info, (list, tuple)) and len(info) > 4 else info
        ips.append(str(addr))
    if not ips:
        raise MalformedDestination(f"{host!r} resolved to no addresses")
    if not allow_private:
        for ip in ips:
            if is_private_destination(ip):
                raise MalformedDestination(
                    f"{host!r} resolves to {ip}, which is private/loopback/link-local/"
                    f"CGNAT space. A public-looking name pointing into infrastructure is "
                    f"the rebinding and SSRF shape; refused.")
    return PinnedDestination(scheme, host, port, ips)


class GuardedEgress:
    """The safe path, made the only path.

    Wraps a caller-supplied transport so the rules cannot be forgotten:
      * every hop is checked against the allowlist,
      * every hop is resolved and pinned, every resolved IP verified,
      * redirects are NEVER followed automatically — each Location is re-checked
        as a fresh destination, and the hop budget is finite.

    The transport is injected because this module is stdlib-only and does not
    perform network I/O itself. It must NOT follow redirects internally; it
    returns (status, headers, body) and lets this class decide.
    """

    def __init__(self, guard: EgressGuard, transport, *, max_hops: int = 3,
                 resolver=None):
        self._guard = guard
        self._transport = transport
        self._max_hops = max(1, int(max_hops))
        self._resolver = resolver

    def request(self, url: str, **kw):
        """Perform a request, re-checking every redirect hop. Returns the final
        response. Raises EgressRefused on any hop that is not permitted."""
        seen = []
        current = url
        for hop in range(self._max_hops + 1):
            decision = self._guard.check(current)
            if not decision.permitted:
                raise EgressRefused(
                    f"hop {hop} refused: {decision.reason}", hops=seen + [current])
            allow_private = bool(self._guard._policy and self._guard._policy.allow_private)
            pinned = resolve_and_pin(normalize_destination(current),
                                     allow_private=allow_private,
                                     resolver=self._resolver)
            seen.append(current)
            status, headers, body = self._transport(current, pinned, **kw)
            if status not in (301, 302, 303, 307, 308):
                return status, headers, body
            location = None
            for k, v in (headers or {}).items():
                if str(k).lower() == "location":
                    location = v; break
            if not location:
                raise EgressRefused(
                    f"hop {hop} returned {status} with no Location header", hops=seen)
            # Relative redirects are resolved against the current URL, then re-checked
            # from scratch — a redirect is a NEW destination, never an inherited trust.
            from urllib.parse import urljoin
            current = urljoin(current, str(location))
        raise EgressRefused(
            f"redirect budget of {self._max_hops} hops exhausted", hops=seen)


class EgressRefused(Exception):
    """Raised by GuardedEgress when any hop is not permitted. Carries the hop chain
    so an operator can see exactly where a redirect tried to leave the allowlist."""

    def __init__(self, message, hops=()):
        super().__init__(message)
        self.hops = list(hops)
