# Adjudication — the wall wiring (self red team + Meta, Grok, ChatGPT)

Four independent passes over the effect gate wired into `ActuationBroker`: one
adversarial self-pass (attacks run against the code, memory of writing it treated as
untrusted) and three external cold reviews. Every claim re-verified against running
code. Suite 1916 → 1921 green.

**All eight self-findings and the verifiable external findings are FIXED and pinned.
Two external claims were wrong in a way worth recording. The remaining items are
deployment-level and are the honest reason this is not yet life-safe.**

Numeric scores (9.7 architecture / 9.2 implementation / 8.8 production) recorded, not
carried forward — `reflection.py` refuses self-certification, and a score from a pass
that ran no adversarial load is not a measurement.

## The structural fix, which resolved four findings at once

The gate was placed after grant reservation and the ledger hook. But every check it
makes — undeclared, absolute-effect, lethal-mismatch — depends only on
`(actuator_id, command, params)`. **None of them needs the grant.** Moving it to
immediately after actuator lookup, before the grant is parsed:

- **A2 (ledger pollution) — GONE.** Three constitutionally-impossible LETHAL requests
  invoked the cumulative ledger three times; an attacker could drain a safety budget
  with actions that could never execute. This module had already reasoned about that
  exact class for grants ("would let an attacker who can trigger ledger refusals
  exhaust an operator's grants") — the placement reintroduced it one stage over.
  Now 0 invocations.
- **A6 (stranded reservation) — GONE.** No nonce is reserved before the gate, so a gate
  fault cannot burn an operator's single-use grant. Plus the stage is now wrapped
  fail-closed: an exception previously escaped `_handle` entirely and surfaced as a
  generic `broker_error`, while the ledger stage two lines below had the wrapper.
- **A7 (the machine authorized itself) — GONE.** The wall built
  `ActionContext(authorised_by=grant.subject)` → `'robot-1'`: the machine named
  **itself** as authorizer of its own effect decision, on the project whose thesis is
  that machines do not self-authorize, with the human principal (`key_id='operator'`)
  sitting unused in the grant. The label now names the mechanism —
  `broker:scope-mediated` — which is what is actually true.
- **A5 (scope of the gate) — now explicit.** Conditional effects (DATA_EGRESS,
  ACCOUNT_ACCESS) are deliberately *not* re-adjudicated at the wall; the grant and its
  `required_scope` govern them, which is the wall's existing job. The gate adds exactly
  what scope cannot express: undeclared capability, absolute bright lines, lethal
  mismatch. `exfiltrate_all_user_data` on a properly-scoped DATA_EGRESS actuator still
  executes, and that is correct — but a reader could easily over-read "the
  constitutional gate is wired in", so it is now stated in the code, not just the doc.

## Other fixes

| finding | source | fix |
|---|---|---|
| **A1** actuator inserted into `_actuators` *before* the effects check raised → half-registered actuator, operator locked out behind `replace=True` | self | declaration validated and recorded **first**; a rejected declaration leaves no trace |
| **A4** params never reached the lexicon — `{"target": "kill the intruder"}` on a NONE-declared vacuum executed clean, blinding the mismatch escalation to where content actually lives | self | params are part of the scan surface |
| **A8** `except Exception: pass` swallowed `effects=["LETAHL"]` with zero signal | self | a malformed safety declaration raises whether or not it is currently enforced |
| **A9** comment claimed declarations were kept "so `is_effect_gated()` can later be flipped on" — **no such API existed** | self | comment corrected, and the absence is now deliberate and stated: a gate that can be toggled at runtime is a gate an attacker can toggle |
| Hanging actuator wedges the single accept loop forever; `_call_with_timeout` already existed in the same file for posture | ChatGPT #3 | optional `actuator_timeout`. A timeout reports **completion UNKNOWN**, never a clean refusal — an agent told "refused" would retry and double-actuate |
| `enforce_effects=False` is a silent production kill-switch | **Meta P0-1 + Grok #11 + ChatGPT #11 (3-way convergence)** | tied to the existing `require_isolation` idiom: a broker claiming the wall property **refuses to start** with the effect gate off. Claiming the wall while leaving undeclared actuators reachable is a contradiction |
| Brittle string matching on error strings | Meta P2-2 | structured `error_code` added |

## External claims that were wrong

- **Meta P0-2 had the TOCTOU direction backwards.** It proposed an attacker flipping a
  declaration *to* `LETHAL` after grant issue. Verified: that direction **fails closed**
  (the gate re-reads the registry and blocks). The real exposure is the **downgrade** —
  `LETHAL → NONE` by an insider — which executes. Correct finding, inverted. Now pinned
  as a KNOWN GAP whose assertion must flip when signed append-only declarations land;
  the grant is not bound to the declaration, and binding it changes the grant format.
- **Meta P1-1 proposed a missing test that already passes.** Injecting straight into
  `broker._actuators`, bypassing `register_actuator`, still fails closed — the gate
  reads the registry, not the actuator dict. Good test; pinned rather than treated as a
  bug.

## What remains — and why this still is not life-safe

Every reviewer converged here, and they are right. The pattern across all three: *almost
every property that makes the wall actually a wall is still a configuration choice that
defaults to the weaker setting.* Ranked:

1. **Capability discipline is unenforced (D1).** If any code in the agent process can
   reach hardware — `subprocess`, a hardware SDK, an inherited fd, `ctypes` — the wall
   is bypassed without ever being touched. Needs packaging allow-lists plus
   seccomp/Landlock. Until then the wall is advisory. **The single most important item.**
2. **Same-UID default collapses isolation.** Without `socket_group` + `require_peer_uid`
   the peer check is a no-op. `require_isolation=True` (now also implying effect
   enforcement) should be the default posture for anything physical.
3. **The declaration is still trusted, and downgrades execute.** Signed, append-only,
   two-person declarations for absolute effects — the next block.
4. **Durability**: nonces, reservations, posture, and audit are in memory. A crash-loop
   reopens replay and destroys the evidence. Needs a hash-chained WORM store.
5. **Commit-then-crash** leaves an actuated robot with no record (ChatGPT #1) — needs
   write-ahead intent logging around the commit.
6. **The TCB is no longer small.** `_handle` now carries posture, grant, binding, ledger,
   effect gate, actuation, serialization, audit. Honest observation; argues for moving
   mediation to a minimal, memory-safe broker.
7. **Untested**: concurrency on the same grant, restart replay, malformed frames,
   Unicode/type drift in bindings, real `SO_PEERCRED`.

The gate is now correctly placed, correctly attributed, fail-closed on every path
tested, and cannot be silently disabled by a broker that claims isolation. That closes
the wiring. It does not close the deployment, and the deployment is where a life would
actually be lost.
