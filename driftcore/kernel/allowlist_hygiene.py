"""
allowlist_hygiene.py — AN ALLOWLIST ENTRY IS A TRUST-TO-RECEIVE DECLARATION.

THE GAP THIS CLOSES
───────────────────
egress_guard matches a normalized (scheme, host, port) triple and — by design —
ignores path and query. That is correct for what it does, and it defeats the
memory-heist attack in its primary form: the attacker's host is not declared, so
the "fetch /a /b /c to spell the secret" channel is refused at the destination.

But it leaves one channel open, and the red team demonstrated it live:

    https://paste.allowed.com/log?c=j     ALLOW
    https://paste.allowed.com/log?c=u     ALLOW    ... spells the secret in the query

If ANY allowlisted host is one whose received requests an attacker can observe —
a pastebin, a shortener, an analytics beacon, a generic object store, a webhook
catcher — then the secret rides out in the path or query and every request is
permitted. Volume caps do not help: a name is a handful of requests, or one
request's path.

This is not a guard bug. It is a POLICY-COMPOSITION hazard, and the fix is not
more matching — it is being honest about what an entry means:

    An allowlisted destination is not "a host trusted to be benign."
    It is a host TRUSTED TO RECEIVE YOUR SECRETS.

So this module lints the declaration itself, at build time, before it can ever
be enforced against.

WHAT IT DOES AND DOES NOT CLAIM
───────────────────────────────
This is a LINT, not a guarantee. It cannot know that `notes.acme-internal.com`
is first-party and `cdn-metrics.acme.io` is a third-party collector; only the
declaring human knows that. What it can do is:

  * refuse the KNOWN-BAD shapes outright (a pastebin in an egress allowlist is
    almost never intentional),
  * force every remaining entry to be classified as FIRST_PARTY or THIRD_PARTY
    by the human, so "trusted to receive secrets" is stated rather than assumed,
  * and let the caller enforce the rule that free-form data (memory contents,
    notes, user records) may only ride to FIRST_PARTY sinks.

MATCHING DISCIPLINE
───────────────────
Same rule as the escalation lexicon and the egress guard: NORMALIZE, then match
WHOLE LABELS, never substrings. `mypaste.example.com` must not match "paste",
and `notgist.com` must not match "gist" — a substring lint produces false
refusals, and a lint that cries wolf gets switched off, which is worse than no
lint at all. Registered-domain and label-level matching only.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, Iterable, List, Optional, Tuple

from driftcore.kernel.egress_guard import (
    normalize_destination, is_private_destination, MalformedDestination,
)


class ReceiveTrust(str, Enum):
    """What a destination is trusted to RECEIVE. Declared by a human, never inferred."""
    FIRST_PARTY = "FIRST_PARTY"    # our own infrastructure; may receive free-form data
    THIRD_PARTY = "THIRD_PARTY"    # an external API; structured calls only
    UNCLASSIFIED = "UNCLASSIFIED"  # not yet declared -> treated as untrusted to receive


class HygieneVerdict(str, Enum):
    OK = "OK"
    REFUSE = "REFUSE"    # known exfil-shaped destination; must not be allowlisted
    WARN = "WARN"        # plausible but risky; requires explicit acknowledgement


# ── Known attacker-observable destination shapes ──────────────────────────
# Registered domains whose whole product is "receive content and show it back".
# An agent that can reach one of these has a general-purpose exfil channel that
# looks exactly like normal traffic. Matched on the registered domain, whole
# labels only.
_PUBLIC_SINK_DOMAINS: FrozenSet[str] = frozenset({
    # paste / text dumps
    "pastebin.com", "paste.ee", "hastebin.com", "ghostbin.com", "rentry.co",
    "dpaste.com", "controlc.com", "justpaste.it", "privatebin.net", "0bin.net",
    # gists / snippets
    "gist.github.com", "gitlab.com", "codepen.io", "jsfiddle.net", "replit.com",
    # request / webhook catchers — built to log what they receive
    "requestbin.com", "webhook.site", "pipedream.net", "requestcatcher.com",
    "beeceptor.com", "ngrok.io", "ngrok-free.app", "localtunnel.me",
    "interact.sh", "oast.fun", "burpcollaborator.net", "canarytokens.com",
    # URL shorteners — arbitrary redirect + request logging
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "short.io", "s.id",
    # generic form / doc collectors
    "forms.gle", "docs.google.com", "typeform.com", "airtable.com",
    # DNS-log style
    "dnslog.cn", "requestrepo.com",
})

# Telemetry / analytics collectors: the request itself IS the payload, and the
# operator (or anyone with the account) can read every URL received.
_TELEMETRY_DOMAINS: FrozenSet[str] = frozenset({
    "google-analytics.com", "analytics.google.com", "googletagmanager.com",
    "doubleclick.net", "segment.io", "segment.com", "mixpanel.com",
    "amplitude.com", "sentry.io", "bugsnag.com", "datadoghq.com",
    "newrelic.com", "loggly.com", "posthog.com", "hotjar.com",
    "facebook.com", "connect.facebook.net", "stats.g.doubleclick.net",
})

# Multi-tenant object storage: an attacker with any account in the same service
# can often receive a write, and bucket names are attacker-chosen.
_MULTITENANT_STORAGE: FrozenSet[str] = frozenset({
    "s3.amazonaws.com", "amazonaws.com", "blob.core.windows.net",
    "storage.googleapis.com", "r2.dev", "backblazeb2.com",
    "digitaloceanspaces.com", "cloudfront.net", "fastly.net",
})

_CATEGORY_FOR: Dict[str, str] = {}
for _d in _PUBLIC_SINK_DOMAINS:
    _CATEGORY_FOR[_d] = "public content sink (receives and republishes what it is sent)"
for _d in _TELEMETRY_DOMAINS:
    _CATEGORY_FOR[_d] = "telemetry collector (the request URL itself is the payload)"
for _d in _MULTITENANT_STORAGE:
    _CATEGORY_FOR[_d] = "multi-tenant storage/CDN (an attacker may control a tenant)"

_ALL_FLAGGED: FrozenSet[str] = frozenset(_CATEGORY_FOR)


def _registered_suffixes(host: str) -> List[str]:
    """Every whole-label suffix of a host, longest first.

    'a.b.example.com' -> ['a.b.example.com', 'b.example.com', 'example.com', 'com']

    Whole labels only. This is what stops 'mypastebin.com' from matching
    'pastebin.com' — the substring is present, the label boundary is not.
    """
    labels = [l for l in host.split(".") if l]
    return [".".join(labels[i:]) for i in range(len(labels))]


def classify_host(host: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (matched_domain, category) if the host is a known-observable sink."""
    for suffix in _registered_suffixes(host):
        if suffix in _ALL_FLAGGED:
            return suffix, _CATEGORY_FOR[suffix]
    return None, None


@dataclass(frozen=True)
class HygieneFinding:
    verdict: HygieneVerdict
    url: str
    host: str
    reason: str
    remedy: str = ""

    @property
    def blocking(self) -> bool:
        return self.verdict is HygieneVerdict.REFUSE


@dataclass(frozen=True)
class DeclaredDestination:
    """An allowlist entry WITH its receive-trust stated by the declaring human."""
    url: str
    trust: ReceiveTrust = ReceiveTrust.UNCLASSIFIED
    purpose: str = ""

    def may_receive_freeform(self) -> bool:
        """Only first-party sinks may receive free-form data (memory, notes,
        user records). Everything else gets structured calls or nothing."""
        return self.trust is ReceiveTrust.FIRST_PARTY


class AllowlistHygiene:
    """Lints egress allowlist declarations before they are ever enforced against.

    REFUSE  — a known attacker-observable sink. Not overridable by a flag here;
              if a deployment truly needs it, that is a deliberate policy change
              made visible, not a lint suppression.
    WARN    — plausible but unclassified, or shapes that deserve a second look.
    OK      — normalized, classified, and not a known sink.
    """

    def __init__(self, *, require_classification: bool = True):
        self._require_classification = require_classification

    # -- single entry ------------------------------------------------------

    def check(self, entry) -> List[HygieneFinding]:
        d = entry if isinstance(entry, DeclaredDestination) else DeclaredDestination(str(entry))
        findings: List[HygieneFinding] = []

        try:
            scheme, host, port = normalize_destination(d.url)
        except MalformedDestination as e:
            return [HygieneFinding(
                HygieneVerdict.REFUSE, d.url, "",
                f"entry could not be normalized: {e}",
                "an allowlist entry the guard cannot read is not a control; fix or drop it")]

        matched, category = classify_host(host)
        if matched:
            findings.append(HygieneFinding(
                HygieneVerdict.REFUSE, d.url, host,
                f"{host} is a {category} (matched {matched}). Allowlisting it hands the "
                f"agent a general-purpose exfiltration channel: the secret rides out in "
                f"the path or query and every request is a legitimate ALLOW.",
                "remove it, or route through a first-party service you control that "
                "forwards only the fields you intend"))

        # cleartext to a non-loopback host: the destination may be fine, the wire is not
        if scheme == "http" and not is_private_destination(host):
            findings.append(HygieneFinding(
                HygieneVerdict.WARN, d.url, host,
                "cleartext http to a public host: anyone on-path receives whatever is "
                "in the URL, which makes every observer a receiver",
                "use https, or declare why cleartext is required"))

        if self._require_classification and d.trust is ReceiveTrust.UNCLASSIFIED:
            findings.append(HygieneFinding(
                HygieneVerdict.WARN, d.url, host,
                "receive-trust is UNCLASSIFIED. An allowlist entry is a statement that "
                "this host may RECEIVE the agent's secrets; that has to be stated, not "
                "assumed.",
                "declare ReceiveTrust.FIRST_PARTY or THIRD_PARTY, with a purpose"))

        if d.trust is not ReceiveTrust.UNCLASSIFIED and not d.purpose.strip():
            findings.append(HygieneFinding(
                HygieneVerdict.WARN, d.url, host,
                "no purpose recorded; in six months nobody will remember why this "
                "destination was trusted to receive data",
                "record a one-line purpose alongside the entry"))

        if not findings:
            findings.append(HygieneFinding(
                HygieneVerdict.OK, d.url, host,
                f"{scheme}://{host}:{port} classified {d.trust.value}", ""))
        return findings

    # -- whole policy ------------------------------------------------------

    def audit(self, entries: Iterable) -> Dict[str, object]:
        """Lint a full declaration. `clean` is False if ANY entry is REFUSE."""
        all_findings: List[HygieneFinding] = []
        for e in entries:
            all_findings.extend(self.check(e))
        refusals = [f for f in all_findings if f.verdict is HygieneVerdict.REFUSE]
        warnings = [f for f in all_findings if f.verdict is HygieneVerdict.WARN]
        return {
            "clean": not refusals,
            "refusals": refusals,
            "warnings": warnings,
            "findings": all_findings,
            "counts": {"refuse": len(refusals), "warn": len(warnings),
                       "ok": len([f for f in all_findings
                                  if f.verdict is HygieneVerdict.OK])},
        }

    def assert_clean(self, entries: Iterable) -> None:
        """Raise on any REFUSE. Call this where the policy is BUILT, so a
        hazardous declaration cannot reach the guard at all."""
        result = self.audit(entries)
        if not result["clean"]:
            lines = "\n".join(f"  - {f.host}: {f.reason}" for f in result["refusals"])
            raise UnsafeAllowlist(
                f"refusing {len(result['refusals'])} egress destination(s) that are "
                f"trusted-to-receive hazards:\n{lines}")


class UnsafeAllowlist(ValueError):
    """Raised when a declaration contains a known attacker-observable sink."""


# ── The rule the classification exists to enforce ─────────────────────────

def may_send_freeform(destination: DeclaredDestination, *, data_is_freeform: bool
                      ) -> Tuple[bool, str]:
    """Free-form data (memory contents, notes, user records) may only go to a
    FIRST_PARTY sink. This is the "is it going home?" check, made structural.

    A THIRD_PARTY API may still be called — with structured, declared fields —
    but arbitrary agent-chosen strings must not ride to a host we do not own,
    because that is indistinguishable from exfiltration.
    """
    if not data_is_freeform:
        return True, "structured call; destination classification not exceeded"
    if destination.may_receive_freeform():
        return True, f"{destination.url} is FIRST_PARTY and may receive free-form data"
    return False, (
        f"{destination.url} is {destination.trust.value}; free-form data may only be "
        f"sent to a FIRST_PARTY sink. Send declared fields, or route via a "
        f"first-party service.")
