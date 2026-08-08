"""
one_door_client.py — THE SAFE PATH, MADE THE ONLY PATH.

WHY THIS EXISTS
───────────────
Three controls now exist and each is sound in isolation:

    egress_guard      WHERE a request may go       (destination allowlist)
    payload_shape     WHAT the request LINE says   (declared path + query)
    request_schema    WHAT the BODY and HEADERS say (declared keys + types)

They were never composed. Red team (ChatGPT, 2026-08) asked the question that
matters: *can every network request be forced through all three?* The answer in
this repo was no. `driftcore/adapters/llm_adapter.py` calls
`urllib.request.urlopen` directly — four times — sending a full JSON body and an
API-key header to an external host, consulting the egress guard zero times.

egress_guard.py predicted exactly this in its own docstring: "one
`requests.get(url)` and the allowlist is a suggestion." A control that depends on
every programmer remembering to call it is not a control; it is a convention.

WHAT THIS MODULE DOES
─────────────────────
1. `OneDoorClient` chains the three layers in the only correct order and owns the
   transport, so validated bytes are sent bytes:

       destination  ->  request line  ->  body + headers  ->  pinned transport
       (allowlist)      (declared)        (declared)          (GuardedEgress)

2. `seal_network()` makes the alternate paths FAIL LOUDLY at import time, by
   replacing `socket.socket` for AF_INET/AF_INET6 and `urllib.request.urlopen`
   with functions that raise. After sealing, a forgotten `urlopen()` is a crash
   with a pointed error message instead of a silent exfiltration channel.

ORDER MATTERS
─────────────
Destination is checked FIRST and always. A body is only shaped for a destination
already known to be permitted, so a refused host never reaches body validation
and never produces a schema error an attacker could read as a probe. Cheapest,
most-authoritative check first — same discipline as the authority resolver.

WHAT SEALING IS AND IS NOT
──────────────────────────
`seal_network()` is a DEVELOPMENT AND DEFENCE-IN-DEPTH control, not a sandbox.
It runs inside the process it is protecting, so anything that can execute
arbitrary Python can undo it: re-import the module, reach for the saved original,
call the C-level socket API, spawn a subprocess. It exists to turn an honest
mistake into an immediate, attributable failure — which is the common case — not
to contain a determined adversary.

The real boundary is the OS: a network namespace with no route, seccomp, or the
broker process holding the only socket. Those are outside Python and are what
isolation_manifest.py and broker_process.py are for. Sealing is the smoke alarm;
the namespace is the fire door. Do not ship one and claim the other.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Tuple

from driftcore.kernel.egress_guard import (
    EgressGuard, GuardedEgress, EgressRefused,
)
from driftcore.kernel.payload_shape import (
    PayloadShapeGuard, PayloadRefused,
)
from driftcore.kernel.request_schema import RequestSchemaGuard, SchemaRefused


class OneDoorRefused(Exception):
    """A request was refused by one of the composed layers.

    Carries which layer refused, so an operator can tell a misconfiguration
    ("the host isn't declared") from an attack ("the body had extra keys")
    without reading three different exception types.
    """

    def __init__(self, layer: str, operator_detail: str,
                 generic: str = "request refused"):
        self.layer = layer
        self.operator_detail = f"[{layer}] {operator_detail}"
        super().__init__(generic)


class NoBodySchema:
    """An explicit declaration that a client sends no bodies and no custom
    headers. Distinguishes "we decided not to send bodies" from "nobody
    configured a schema", which look identical when the parameter is optional."""

    def check_headers(self, headers):
        raise SchemaRefused(
            "this client is declared NoBodySchema: it sends no custom headers. "
            "Declare a RequestSchemaGuard if headers are genuinely needed")

    def canonical_body(self, payload):
        raise SchemaRefused(
            "this client is declared NoBodySchema: it sends no bodies. "
            "Declare a RequestSchemaGuard if a body is genuinely needed")


class TransportContractViolation(Exception):
    """A transport broke the contract GuardedEgress depends on."""


class _ContractedTransport:
    """Makes the "must not follow redirects" contract enforceable.

    GuardedEgress re-checks every hop itself, which only works if the transport
    hands redirects BACK rather than following them internally. That was
    documented and not enforced: red team (ChatGPT, 2026-08) wrote a transport
    that silently followed a 302 to an undeclared host and OneDoorClient could
    not see it happen.

    A wrapper cannot read the transport's mind, but it can check the observable
    consequences: a response that is a redirect the caller never got to inspect,
    a final URL that differs from the requested one, or a hop count the transport
    reports. Anything inconsistent is a refusal, because a transport that quietly
    relocated the request has taken the decision away from the layer that owns it.
    """

    def __init__(self, transport):
        self._transport = transport

    def __call__(self, url, pinned, **kw):
        result = self._transport(url, pinned, **kw)
        if not (isinstance(result, tuple) and len(result) == 3):
            raise TransportContractViolation(
                "transport must return (status, headers, body); a transport with "
                "a different shape is not the one GuardedEgress can re-check")
        status, headers, body = result
        headers = headers or {}

        # If the transport reports where it ended up, it must be where we sent it.
        for key in ("x-final-url", "x-effective-url", "location-followed"):
            for k, v in headers.items():
                if str(k).lower() == key and str(v) != url:
                    raise TransportContractViolation(
                        f"transport followed a redirect internally (reported "
                        f"final URL differs from the requested one); redirects "
                        f"must be returned for hop-by-hop re-checking, not "
                        f"resolved inside the transport")
        # A transport that reports having made more than one request has made a
        # decision that belongs to GuardedEgress.
        for k, v in headers.items():
            if str(k).lower() in ("x-redirect-count", "x-hop-count"):
                try:
                    if int(v) > 0:
                        raise TransportContractViolation(
                            f"transport reports {v} internal redirect(s); every "
                            f"hop must be returned and re-checked")
                except (TypeError, ValueError):
                    pass
        return status, headers, body


class PinnedHTTPTransport:
    """A transport that owns the socket, so nothing can redirect or re-serialize
    behind the guards.

    `_ContractedTransport` can only catch a transport that SELF-REPORTS what it
    did. Red team (Meta, 2026-08) pointed out the obvious hole and it reproduced
    immediately: a transport that follows a 302 and reports nothing — which is
    exactly what `requests` and `httpx` do by default — returns 200 with the
    attacker's body and looks perfectly clean.

    Three trust assumptions disappear when the transport is ours:

      * REDIRECTS. We never follow. The status and Location come straight back
        for GuardedEgress to re-check as a fresh destination.
      * DNS. We connect to the ALREADY-PINNED address; no second lookup, so the
        name cannot resolve differently between check and connect. SNI and the
        Host header still carry the original hostname.
      * SERIALIZATION. The canonical body bytes are written to the socket
        verbatim. No HTTP library gets a chance to re-encode a dict and reorder
        keys, which would break the evidence chain between what was validated
        and what was sent.

    Ships with the module because a security control that makes people write
    their own transport has handed the guarantee back to the caller.

    IMPORTANT — THIS TRANSPORT AND `seal_network()` ARE MUTUALLY EXCLUSIVE IN ONE
    PROCESS. The seal blocks AF_INET sockets, and this class opens one. That is
    not a bug in either; it is the architecture stating itself. The intended
    deployment is two processes:

        agent process    seal_network() applied at start. No sockets. Builds
                         requests, hands them to the broker over AF_UNIX.
        broker process   holds the only socket. Runs OneDoorClient with this
                         transport. Never seals.

    If you seal and then try to use this transport in the same process, you get
    NetworkSealed — which is the correct answer to "the component that is not
    supposed to have network access just tried to open a socket". Self-red-team
    2026-08 found this composition contradiction undocumented; a reader could
    reasonably have assumed the two headline controls compose, and they do not.
    """

    def __init__(self, *, timeout: float = 30.0, max_response_bytes: int = 1 << 20):
        self._timeout = timeout
        self._max_response = max_response_bytes

    def __call__(self, url, pinned, *, method: str = "GET",
                 body: Optional[bytes] = None,
                 headers: Optional[Mapping[str, str]] = None, **_ignored):
        import socket as _socket
        import ssl
        from urllib.parse import urlsplit

        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query

        ip = getattr(pinned, "ip", None) or getattr(pinned, "address", None)
        if not ip:
            raise TransportContractViolation(
                "no pinned address supplied; connecting by name would re-resolve "
                "and reopen the rebinding window that pinning exists to close")

        # Connect to the PINNED address. The hostname is still used for SNI and
        # the Host header, so the server sees the request it expects.
        raw = _socket.socket(_socket.AF_INET6 if ":" in str(ip) else _socket.AF_INET,
                             _socket.SOCK_STREAM)
        raw.settimeout(self._timeout)
        try:
            raw.connect((str(ip), port))
            if parts.scheme == "https":
                ctx = ssl.create_default_context()
                sock = ctx.wrap_socket(raw, server_hostname=host)
            else:
                sock = raw

            lines = [f"{method.upper()} {target} HTTP/1.1",
                     f"Host: {host}",
                     "Connection: close",
                     "Accept-Encoding: identity"]  # no compression: see request_schema
            # Header values are interpolated into a hand-built request, so a value
            # containing CRLF would inject arbitrary extra headers (and a body)
            # that no schema ever approved. The schema's TOKEN charset already
            # rejects CRLF, but this class is public and usable with any headers:
            # a transport that is only safe when someone else validated its input
            # is not a control. Self-red-team, 2026-08.
            _method = method.upper()
            if not _method.isalpha():
                raise TransportContractViolation(
                    f"method {method!r} is not alphabetic; a crafted method would "
                    f"inject into the request line")
            for _part, _label in ((target, "request target"), (host, "host")):
                if any(c in str(_part) for c in ("\r", "\n", "\x00", " ")):
                    raise TransportContractViolation(
                        f"{_label} contains a control character or space; it would "
                        f"split the request line")
            for k, v in (headers or {}).items():
                ks, vs = str(k), str(v)
                if any(c in ks or c in vs for c in ("\r", "\n", "\x00")):
                    raise TransportContractViolation(
                        f"header {ks!r} contains CR, LF or NUL; that would inject "
                        f"headers the schema never approved (request smuggling)")
                if ":" in ks or not ks.strip():
                    raise TransportContractViolation(
                        f"header name {ks!r} is malformed")
                lines.append(f"{ks}: {vs}")
            if body is not None:
                lines.append(f"Content-Length: {len(body)}")
                lines.append("Content-Type: application/json")
            request = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")

            sock.sendall(request)
            if body is not None:
                # The canonical bytes, verbatim. Nothing re-serializes them.
                sock.sendall(body)

            chunks, total = [], 0
            while total < self._max_response:
                # Bound each read so the cap cannot be overshot by a full buffer:
                # checking before the recv allowed one 64KB overshoot per call.
                want = min(65536, self._max_response - total)
                chunk = sock.recv(want)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            raw_response = b"".join(chunks)
        finally:
            try:
                raw.close()
            except Exception:
                pass

        head, _, payload = raw_response.partition(b"\r\n\r\n")
        head_lines = head.decode("iso-8859-1").split("\r\n")
        # A status line we cannot read is a response we cannot reason about.
        if not head_lines or not head_lines[0].startswith("HTTP/1."):
            raise TransportContractViolation(
                "response has no readable HTTP/1.x status line; refusing rather "
                "than guessing what the peer meant")
        status = 0
        if head_lines and head_lines[0].startswith("HTTP/"):
            try:
                status = int(head_lines[0].split()[1])
            except (IndexError, ValueError):
                status = 0
        if not 100 <= status <= 599:
            raise TransportContractViolation(
                f"response status {status!r} is not a valid HTTP status code")
        # 1xx are INTERIM: the real response follows. This minimal reader does
        # not continue past them, so returning one as if it were the answer
        # would hand the caller status=100 and an empty body as though the
        # request had succeeded. Self-red-team via red team (ChatGPT, 2026-08).
        if 100 <= status < 200:
            raise TransportContractViolation(
                f"response is an interim {status}; this reader does not continue "
                f"to the final response, and returning the interim as the answer "
                f"would look like success")

        resp_headers = {}
        seen_counts = {}
        for line in head_lines[1:]:
            if line[:1] in (" ", "\t"):
                # obs-fold continuation: deprecated and a classic smuggling
                # primitive, since intermediaries disagree about unfolding.
                raise TransportContractViolation(
                    "response uses obs-fold header continuation; parsers "
                    "disagree about it, which is how smuggling happens")
            k, sep, v = line.partition(":")
            if sep:
                key = k.strip()
                seen_counts[key.lower()] = seen_counts.get(key.lower(), 0) + 1
                resp_headers[key] = v.strip()
        # Duplicate framing headers, or Content-Length together with
        # Transfer-Encoding, are the two canonical request-smuggling setups:
        # two parsers read two different message boundaries. There is no safe
        # "pick one" — the only correct answer is to refuse.
        if seen_counts.get("content-length", 0) > 1:
            raise TransportContractViolation(
                "response carries multiple Content-Length headers; parsers would "
                "disagree about where the body ends")
        if seen_counts.get("transfer-encoding", 0) and seen_counts.get("content-length", 0):
            raise TransportContractViolation(
                "response carries both Content-Length and Transfer-Encoding; this "
                "is the canonical smuggling ambiguity and has no safe resolution")
        cl = resp_headers.get("Content-Length") or resp_headers.get("content-length")
        if cl is not None:
            if not str(cl).strip().isdigit():
                raise TransportContractViolation(
                    f"Content-Length {cl!r} is not a non-negative integer")
        # This is a deliberately minimal HTTP reader: it does not de-chunk. A
        # chunked reply would come back with its size prefixes still embedded,
        # so a caller parsing the body would read framing bytes as data. Refuse
        # rather than hand back something that looks like a body and is not.
        # Self-red-team, 2026-08.
        for k, v in resp_headers.items():
            if k.lower() == "transfer-encoding" and "chunked" in v.lower():
                raise TransportContractViolation(
                    "response uses chunked transfer-encoding, which this minimal "
                    "reader does not decode; returning the framed bytes as a body "
                    "would silently corrupt whatever consumes it")
            if k.lower() == "content-encoding" and v.strip().lower() not in ("", "identity"):
                raise TransportContractViolation(
                    f"response is {v!r}-encoded despite Accept-Encoding: identity; "
                    f"a compressed body defeats the capacity accounting")
        # Redirects are RETURNED, never followed. GuardedEgress re-checks the
        # Location as a brand-new destination with its own allowlist decision.
        return status, resp_headers, payload


class OneDoorClient:
    """The composed egress path. Nothing leaves except through here.

    The transport is injected and must match GuardedEgress's contract: it is
    called as `transport(url, pinned, **kw)` and returns `(status, headers,
    body)`. It must NOT follow redirects — GuardedEgress re-checks every hop
    itself, and a transport that follows redirects internally would carry a
    validated request to a destination no layer approved.
    """

    def __init__(self,
                 egress: EgressGuard,
                 shape: PayloadShapeGuard,
                 transport,
                 schema: "RequestSchemaGuard | NoBodySchema",
                 *, max_hops: int = 3, resolver=None):
        """`schema` is REQUIRED. Pass `NoBodySchema()` for a client that sends no
        bodies or custom headers.

        It was optional, defaulting to None, which refused bodies safely — but
        red team (Meta, 2026-08) made the ergonomic argument and it is right:
        someone sets `schema=None` "just for this one debug call" and never puts
        it back, and the default made that a one-word change. Requiring an
        explicit choice means "this client sends no bodies" is a decision that
        appears in the code, not an absence that looks like an oversight.
        """
        if schema is None:
            raise ValueError(
                "schema is required: pass a RequestSchemaGuard, or NoBodySchema() "
                "to declare that this client sends no bodies or custom headers. "
                "An optional schema becomes a disabled schema.")
        self._shape = shape
        self._schema = schema
        # Keep our own reference rather than reaching through GuardedEgress's
        # privates (`_guarded._guard`): private access is brittle and would break
        # silently on an internal refactor of a safety module. Red team, 2026-08.
        self._egress = egress
        self._guarded = GuardedEgress(egress, _ContractedTransport(transport),
                                      max_hops=max_hops, resolver=resolver)

    def request(self, url: str, method: str = "GET", *,
                body: Any = None,
                headers: Optional[Mapping[str, str]] = None,
                **kw) -> Tuple[int, Mapping, bytes]:
        # 1. DESTINATION. First and always: a refused host must never reach body
        #    validation, both because it is wasted work and because a schema
        #    error is a signal an attacker could read.
        decision = self._egress.check(url)
        if not decision.permitted:
            raise OneDoorRefused("destination", decision.reason)

        # 2. REQUEST LINE.
        try:
            self._shape.check(url, method)
        except PayloadRefused as e:
            raise OneDoorRefused("request-line",
                                 getattr(e, "operator_detail", str(e)))

        # 3. BODY AND HEADERS. Absent a schema, both are refused outright — the
        #    same conservative default as ShapedRequest. An undeclared body is an
        #    unconstrained channel beside a perfectly declared URL.
        send_headers = None
        send_body = None
        if body is not None or headers:
            try:
                if headers:
                    try:
                        send_headers = self._schema.check_headers(headers)
                    except SchemaRefused as e:
                        # Report headers under their own layer name; an operator
                        # reading "body-schema" for a header refusal wastes time
                        # looking in the wrong place.
                        raise OneDoorRefused(
                            "header-schema",
                            getattr(e, "operator_detail", str(e)))
                if body is not None:
                    # Canonical bytes: what was validated is what is transmitted.
                    send_body = self._schema.canonical_body(body)
            except SchemaRefused as e:
                raise OneDoorRefused("body-schema",
                                     getattr(e, "operator_detail", str(e)))

        # 4. TRANSPORT, via GuardedEgress: pinned DNS, every redirect hop
        #    re-checked, finite hop budget.
        if send_body is not None:
            kw["body"] = send_body
        if send_headers is not None:
            kw["headers"] = send_headers
        kw["method"] = method
        try:
            return self._guarded.request(url, **kw)
        except EgressRefused as e:
            raise OneDoorRefused("destination", str(e))


# ── Sealing the alternate paths ───────────────────────────────────────────

class NetworkSealed(RuntimeError):
    """Raised when sealed code attempts a raw network call."""


_ORIGINAL = {}
_SEALED = False
_SEAL_TOKEN = None

_MESSAGE = (
    "raw network access is sealed in this process. Every request must go through "
    "OneDoorClient so that the destination allowlist, the declared request line, "
    "and the declared body/header schema all apply. A direct call here would "
    "bypass all three — which is exactly the gap this seal exists to close."
)


def seal_network(*, allow_unix: bool = True) -> object:
    """Make raw network calls fail loudly in this process.

    Replaces `urllib.request.urlopen` and internet-family `socket.socket` with
    functions that raise NetworkSealed. AF_UNIX is left working by default
    because the broker and isolation monitor legitimately use UNIX sockets, and
    a UNIX socket cannot reach the network.

    Idempotent. See the module docstring on what this is and is not: it converts
    a forgotten call into an immediate, attributable crash. It does not contain
    an adversary who can execute arbitrary Python.
    """
    global _SEALED, _SEAL_TOKEN
    if _SEALED:
        return _SEAL_TOKEN
    import socket as _socket
    import urllib.request as _urllib

    _ORIGINAL["socket"] = _socket.socket
    _ORIGINAL["urlopen"] = _urllib.urlopen
    _ORIGINAL["create_connection"] = _socket.create_connection

    real_socket = _socket.socket
    inet_families = {int(_socket.AF_INET), int(_socket.AF_INET6)}

    class _SealedSocket(real_socket):
        def __init__(self, family=-1, *a, **kw):
            fam = int(_socket.AF_INET) if family == -1 else int(family)
            if fam in inet_families:
                raise NetworkSealed(
                    f"{_MESSAGE} (attempted socket family "
                    f"{'AF_INET6' if fam == int(_socket.AF_INET6) else 'AF_INET'})")
            if not allow_unix and fam == int(getattr(_socket, "AF_UNIX", -2)):
                raise NetworkSealed(f"{_MESSAGE} (AF_UNIX also sealed)")
            super().__init__(family, *a, **kw)

    def _sealed_urlopen(*a, **kw):
        raise NetworkSealed(f"{_MESSAGE} (attempted urllib.request.urlopen)")

    def _sealed_create_connection(*a, **kw):
        raise NetworkSealed(f"{_MESSAGE} (attempted socket.create_connection)")

    _socket.socket = _SealedSocket
    _socket.create_connection = _sealed_create_connection
    _urllib.urlopen = _sealed_urlopen

    # `socket.socket` is a thin Python wrapper over the C extension `_socket`.
    # Replacing only the wrapper leaves `import _socket; _socket.socket(...)` as a
    # ONE-LINE restore of full AF_INET capability. Red team (Grok, 2026-08)
    # confirmed this empirically. Seal the extension too — it is the layer that
    # actually opens the file descriptor, so every higher-level library that
    # eventually reaches a socket (http.client, urllib3, requests, httpx,
    # asyncio's default transports) is covered by this one substitution rather
    # than by enumerating libraries forever.
    try:
        import _socket as _c_socket
        _ORIGINAL["_socket.socket"] = _c_socket.socket
        c_real = _c_socket.socket

        def _sealed_c_socket(family=-1, *a, **kw):
            fam = int(_socket.AF_INET) if family == -1 else int(family)
            if fam in inet_families:
                raise NetworkSealed(
                    f"{_MESSAGE} (attempted _socket.socket, the C extension)")
            if not allow_unix and fam == int(getattr(_socket, "AF_UNIX", -2)):
                raise NetworkSealed(f"{_MESSAGE} (AF_UNIX also sealed)")
            return c_real(family, *a, **kw)

        # A plain function, not a subclass: socket.socket inherits from
        # _socket.socket, so replacing the C class with another class breaks that
        # inheritance chain (and with it AF_UNIX, which the broker needs).
        # Guarding the constructor is enough — the family check is what matters.
        _c_socket.socket = _sealed_c_socket
    except NetworkSealed:
        raise
    except Exception:
        raise NetworkSealed(
            "could not seal the _socket C extension; refusing to report a seal "
            "that a one-line import would bypass")

    _SEALED = True
    _SEAL_TOKEN = object()
    return _SEAL_TOKEN


def unseal_network(token: object = None) -> None:
    """Restore the originals. Requires the token returned by `seal_network()`.

    A public, argument-free unseal makes the seal decorative: red team (ChatGPT,
    2026-08) hammered concurrent seal/unseal and watched 339,573 sockets open
    through the unsealed windows. The caller that sealed holds the token; agent
    code that merely imports this module cannot reverse it.

    This is still in-process and therefore still defeatable by anything that can
    read module globals — see the module docstring. It removes the trivial
    `unseal_network()` call, not the class of attack.
    """
    global _SEALED, _SEAL_TOKEN
    if not _SEALED:
        return
    if token is None or token is not _SEAL_TOKEN:
        raise NetworkSealed(
            "unseal_network() requires the token returned by seal_network(). "
            "An unseal that any caller can invoke is not a seal.")
    import socket as _socket
    import urllib.request as _urllib
    _socket.socket = _ORIGINAL["socket"]
    _socket.create_connection = _ORIGINAL["create_connection"]
    _urllib.urlopen = _ORIGINAL["urlopen"]
    if "_socket.socket" in _ORIGINAL:
        import _socket as _c_socket
        _c_socket.socket = _ORIGINAL["_socket.socket"]
    _SEALED = False
    _SEAL_TOKEN = None


def is_sealed() -> bool:
    return _SEALED


def audit_bypasses(root: str = "driftcore") -> list:
    """Static scan for code that could reach the network without OneDoorClient.

    Complements the runtime seal: the seal catches a call that executes, this
    catches one sitting in a module nobody has imported yet. Returns a list of
    (path, lineno, source) so it can be asserted on in CI — a bypass that fails
    the build never ships.
    """
    import ast
    import os

    findings = []
    targets = {"urlopen", "create_connection", "socket"}
    # Sanctioned holders of a socket, identified by PATH not basename. The skip
    # list previously matched any file with these names ANYWHERE in the tree, so
    # planting `driftcore/agents/sneaky/broker_process.py` made a bypass
    # invisible to the gate. Self-red-team 2026-08.
    sanctioned = {
        os.path.normpath("driftcore/kernel/one_door_client.py"),
        os.path.normpath("driftcore/verification/broker_process.py"),
        os.path.normpath("driftcore/verification/mediated_actuation.py"),
    }
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(dirpath, fn)
            if os.path.normpath(path) in sanctioned:
                continue
            try:
                src = open(path, encoding="utf-8").read()
                tree = ast.parse(src)
            except Exception:
                continue
            lines = src.splitlines()

            # Aliased imports: `from urllib.request import urlopen as u` then
            # `u(...)` was invisible, because the call is a bare Name the scan
            # did not know about. Collect local aliases for the target names.
            aliases = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    for a in node.names:
                        if a.name in targets:
                            aliases.add(a.asname or a.name)
                elif isinstance(node, ast.Import):
                    for a in node.names:
                        if a.name in ("socket", "_socket") and a.asname:
                            aliases.add(a.asname)

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                fname = None
                if isinstance(node.func, ast.Attribute):
                    fname = node.func.attr
                elif isinstance(node.func, ast.Name):
                    fname = node.func.id
                hit = fname in targets or fname in aliases
                # getattr(socket, "socket")(...) and friends: the attribute name
                # is a string literal, so the plain scan never sees it.
                if fname == "getattr" and len(node.args) >= 2:
                    second = node.args[1]
                    if isinstance(second, ast.Constant) and second.value in targets:
                        hit = True
                if hit:
                    line = (lines[node.lineno - 1].strip()
                            if node.lineno <= len(lines) else "")
                    # AF_UNIX sockets cannot reach the network.
                    if fname == "socket" and "AF_UNIX" in line:
                        continue
                    findings.append((path, node.lineno, line))
    return findings
