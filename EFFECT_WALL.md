# The effect gate, wired into the actuation wall

The fail-closed-on-undeclared guarantee now holds on the ENFORCED path — not just in
the gate module in isolation. `ActuationBroker` (the mediation wall that is the sole
path to a real actuator) runs the constitutional effect gate as a stage in its request
handler, so an actuator whose effects a human never declared cannot act, regardless of
a valid grant or innocent wording.

## What was wired

`ActuationBroker.__init__(..., enforce_effects: bool = False)`. When on:

- **Registration requires an effect declaration.** `register_actuator(..., effects=[...],
  effect_declared_by="name")` is mandatory — you cannot register a capability that can
  actuate without declaring what it does. Fail closed at registration, not just at call
  time. `{Effect.NONE}` is the explicit "no consequential effect" declaration.
- **A new gate stage** runs in `_handle`, after the breach gate, scope reservation, and
  ledger hook, but BEFORE the nonce is committed and the actuator runs. A refusal
  `release`s the grant, records the reason, and returns fail-closed — nothing actuates
  and the grant is not burned. Placement mirrors the existing ledger-hook stage exactly.
- The gate is given an authorized `ActionContext` because a validly-reserved grant means
  an authorized subject approved this exact bound action; it still enforces the
  undeclared floor and the absolute-effect bright lines (LETHAL, OVERSIGHT_CONTROL, …).

Outcomes at the wall, all fail-closed except ALLOW:
- undeclared/empty-declared actuator → `effect_block_undeclared`
- declared absolute effect → `effect_block`
- lethal-shaped wording/name mismatch on a benign declaration → `effect_hold_for_review`
- gate internal error → `effect_block_error`

## Proven end-to-end (`test_effect_wall_integration.py`, 9 checks)

Driving the broker's real `_handle` path with `enforce_effects=True`: a declared-benign
actuator actuates; a declared-LETHAL actuator is refused even with a valid grant and
nothing fires; a lethal-suggestively-named benign actuator is HELD; a refused action
releases the grant; and — for contrast — an unenforced broker still actuates an
undeclared actuator, which is exactly why enforcement must be on in production.

## The opt-in, and why it is loud rather than silent

`enforce_effects` defaults **off**, following the broker's own established idiom for
breach-posture gating: a default that changes behaviour is not forced on existing
deployments, but the gap is not neutral and is reported. `is_effect_gated()` returns
whether enforcement is on, so "no refusals" can never be mistaken for "the gate works".

**This is not the same as the gate being optional in principle.** For any deployment
that can physically actuate, `enforce_effects=True` is mandatory and undeclared actuation
is a fail-open hole (the Meta cold review's "G2"). The default-off exists only so the
25 existing broker tests and any legacy deployment do not silently change under them;
the correct production posture is enforcement on, every actuator declared.

## What this does and does not close

CLOSES: the undeclared-actuator fail-open on the enforced path (G2), the placement of
the effect decision at the true choke point, and the "gate exists but isn't wired" gap.

DOES NOT close (still staged, see THREAT_MODEL_ONE_DOOR.md):
- The declaration is still trusted — a LETHAL actuator mis-declared benign is not caught
  here (signed, two-person declarations are next).
- Capability discipline (D1): the broker must be the ONLY path to an actuator; a raw
  import/reflection call around the wall still bypasses everything. Enforced by the
  separate-UID process isolation, which is the highest deployment priority.
- Effect-level vs scope-level authorization is coarse here (a valid grant is treated as
  authorization for the declared effect); finer coupling is a refinement.
- The default-off means a deployment that forgets `enforce_effects=True` is unprotected —
  which is why `is_effect_gated()` must be asserted in deployment checks.
