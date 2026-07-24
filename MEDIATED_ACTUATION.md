
## Breach coupling — the permission set collapses on breach

Adversarial testing of the claim *"blast radius = granted permission set"* found it true
at the permission layer and incomplete at the coupling. Seven attacks on the grant model
were all refused — wrong scope, forged signature, unknown signer, expired grant, wrong
subject, wrong action-binding, replay after consume. Injected text cannot manufacture any
of them, because it cannot produce an HMAC over a key it does not hold.

But the broker had **no reference to breach state**. A system already holding in
RESTRICTED or HALT could still actuate on a valid, unexpired, correctly-bound grant until
that grant expired on its own. The blast radius was equal to the permission set, and the
permission set did not shrink when something went wrong — backwards, since the moment the
wall matters most is *after* a violation.

**The gate.** `ActuationBroker(..., posture_source=breach_response.is_operational)`. It
runs **first in `_handle`**, before the grant is even parsed:

- **Breached → refused**, regardless of grant validity. Verified: the actuator does not
  fire.
- **Fail-closed.** A posture source that *raises* is a refusal, not a fall-through — a
  wall that cannot check its own state does not open.
- **Ordering matters.** Because the check precedes verification, a breached system's
  grants are never evaluated, so a breach cannot be probed as an oracle for grant validity.
- **Recovery, not a brick.** A human acknowledgement restores operation. Containment held
  by a human, consistent with the rest of the architecture.

**Honest default.** `posture_source=None` leaves the broker **ungated**, and that is a real
gap rather than a neutral default — an ungated broker will actuate for a HALTED system
holding a valid grant. It defaults off only so existing deployments do not change
behaviour silently. `is_breach_gated()` reports the state, so *"no refusals"* is never
mistaken for *"the gate is working."* Production deployments must wire it.

**What the wall does and does not promise.** The agent never holds an actuator; it holds a
proxy that writes bytes to a unix socket owned by a separate OS user. The actuator is not
in the agent's address space, so bypassing the proxy does not bypass the guard — it simply
does not act. What remains outside the module's control is whether a deployment later
grants the agent a *direct* handle to an effector. That is a deployment property, stated
here rather than assumed.

## Separate-user deployment: the socket group

The class documents running the agent as a **separate OS user** — that separation is the
whole point of the wall. But the socket was created mode **0600**, which only the owner
uid can connect to. Under the documented deployment the agent got `EACCES` and could not
reach the wall at all; the only configuration that actually worked was same-uid, where
`require_peer_uid` is a no-op and the isolation the docstring described did not exist.

Resolved with a **shared group** that the broker user and the agent user both belong to,
and nobody else:

```python
ActuationBroker(sock, verifier, socket_group="driftcore-actuation")
```

**The ordering is deliberate — tighten, set group, then open:**

1. `bind()` under `umask(0o177)` → socket is **0600**, owner-only. There is no window in
   which the wrong group can connect.
2. `chown(-1, gid)` → group becomes the shared group, **still 0600**, so nothing is
   reachable yet.
3. `chmod(0o660)` → only now can the shared group connect.

Doing the `chmod` before the `chown` would briefly expose the socket to the broker's
*primary* group, which is not the group we intend to admit.

**Fail closed.** If the group cannot be resolved or applied, the broker **refuses to
start** and removes the half-created socket — a wall whose door cannot be locked correctly
does not open. The result is also re-checked with `stat` rather than trusting that the
calls succeeded.

**Default.** With no `socket_group`, the socket stays **0600**. That is the safe default,
but it means the agent must run as the *same* user — so `require_peer_uid` is a no-op and
the process isolation described above does not exist. Separate-user deployments must pass
`socket_group`. The docstring now says this plainly instead of claiming an isolation model
the file permissions contradicted.
