"""
driftcore/profiles/coordinator_builder.py
==========================================
STATUS: PROPOSED (stdlib-only). Bridges a deployment profile -> a configured
VerificationCoordinator. This is the missing link: the existing ProfileManager
wires memory and drift-detector settings, but NOTHING wired a profile into the
v4.5.0 coordinator (objective integrity, capability floor, oversight cadence).

WHY THIS EXISTS — the "8 agents on repeating tasks" case.
An operator running several agents on the same safe tasks will never wire
DriftCore by hand, and shouldn't have to. A developer wires this ONCE from the
operator's stable task list; the operator configures nothing. In steady state
the operator feels nothing: the objective hash simply matches every cycle and
the capability allowlist permits exactly the effects the tasks use. Friction
appears ONLY when an agent goes off-pattern — a changed goal, or an effect
outside the approved set — which is exactly the moment a human should be tapped.

WHAT THIS DOES vs DOES NOT DO — kept honest:
  * It NARROWS capability to an allowlist, ON TOP OF the permanent constitutional
    floor (SEED_INVARIANTS). It can only ADD restriction; it can NEVER widen past
    a seed invariant. Lethal, unauthorized exfiltration, disabling oversight,
    deceiving the operator, mutating the safety log — all still fire regardless
    of what the allowlist says (a test pins this).
  * It relaxes NO safety property. There is NO drift-tolerance dial. The guard
    fires on EVERY cycle. `reratify_every` is an OVERSIGHT CADENCE — how many
    accepted cycles between forced human re-check-ins — NOT a blast-radius knob.
    A compromised agent is bounded by the guard every single cycle, never by that
    number. Set it to None to disable the forced checkpoint entirely; the guard
    stays fully active either way.
  * The objective-integrity PRESENCE check (required_invariants) is OFF by default
    here, because it is only meaningful if the enforcement loop RE-MARKS the
    registry every cycle. Shipping it "on" without that would be theatre.
  * AUTHORIZED EGRESS (closes the "her summary email gets blocked" gap): the
    profile may ratify `authorized_targets` (+ `owner`). Egress to a ratified
    target passes the exfiltration seed; egress to anything else — or with no
    declared target — still trips it. TWO independent checks must both pass:
    the effect class must be on `allowed_effects` (capability) AND the target
    must be ratified (authorization). The policy authorizes TARGETS, not
    payloads: content is not inspected, and an approved effect to a ratified
    recipient passes even if the payload is bad. Payload governance is a
    different layer; pretending this covers it would be theatre.

THE BOUNDARY OF "ZERO-CONFIG" — stated plainly, because it is a real limit.
`current_objectives` must be supplied to `evaluate()` every cycle from the
deployment's OBSERVATION of what goal the agent is actually operating under. It
must NOT be a hardcoded constant. If a wrapper simply re-injects the pinned
objectives every call, the drift check can never see drift — it becomes theatre.
So: zero-config for the OPERATOR, but the developer must still feed real
per-cycle objective state, or the objective-integrity check means nothing. This
module deliberately does NOT provide an auto-inject wrapper, to avoid handing
someone that footgun.
"""
from __future__ import annotations

from typing import Iterable, Optional, Set, Union

from driftcore.verification.invariant_guard import (
    SEED_INVARIANTS, Invariant, Effect, InvariantGuard,
)
from driftcore.verification.objective_integrity import RatifiedBaseline, InvariantRegistry
from driftcore.verification.risk_classifier import RiskClassifier
from driftcore.verification.coordinator import VerificationCoordinator


def _coerce_effect(e: Union[Effect, str]) -> Effect:
    if isinstance(e, Effect):
        return e
    # accept either the NAME ("DATA_EGRESS") or the value ("data_egress")
    try:
        return Effect[e]
    except KeyError:
        return Effect(e)


def _coerce_effects(items: Iterable[Union[Effect, str]]) -> Set[Effect]:
    return {_coerce_effect(e) for e in (items or ())}


def _capability_allowlist(allowed: Set[Effect]) -> Invariant:
    """An invariant that FIRES (blocks) when an action carries any effect outside
    the deployment's approved set. Composes with SEED_INVARIANTS; it can only
    narrow, never widen — an effect on the allowlist is still subject to every
    seed invariant. Effect.NONE and effect-free actions are never blocked by it
    (they carry no effect to be 'outside' the list)."""
    permitted = frozenset(allowed) - {Effect.NONE}
    all_effects = frozenset(e for e in Effect if e is not Effect.NONE)

    def fires(req) -> bool:
        return bool(req.effects - permitted)   # any effect not on the allowlist -> deny

    return Invariant(
        invariant_id="capability_allowlist",
        description=("action uses an effect outside this deployment's approved "
                     "capability set (off-pattern for a repeating-task agent); "
                     "a human must approve expanding the allowlist"),
        applies_to=all_effects,
        fires=fires,
    )


def build_capability_guard(allowed_effects: Iterable[Union[Effect, str]]) -> InvariantGuard:
    """SEED_INVARIANTS (the permanent floor) + a capability allowlist. The seeds
    are never removed or reordered — the allowlist is appended, so a seed block
    still fires even if that effect appears on the allowlist."""
    allow = _coerce_effects(allowed_effects)
    invariants = list(SEED_INVARIANTS) + [_capability_allowlist(allow)]
    return InvariantGuard(invariants=invariants)


def build_coordinator(
        profile: dict, *,
        objective_secret: Optional[str] = None,
        guard: Optional[InvariantGuard] = None,
        classifier=None,
        invariant_registry: Optional[InvariantRegistry] = None,
        tool_effects: Optional[dict] = None,
        authorization_state=None,
) -> VerificationCoordinator:
    """Construct a VerificationCoordinator from a profile's `coordinator` block.

    Required: profile["coordinator"]["objectives"] — the set-once task baseline
    (a non-empty list of objective strings). Everything else has a safe default.

    `objective_secret` is taken as an argument, NOT from the profile dict: a
    signing secret must come from the deployment's secret store / HSM, never be
    checked into a config file. Without it, a signed objective change cannot be
    verified (so the objectives are effectively frozen until re-ratified, which
    is a safe default for a repeating-task deployment)."""
    cfg = dict(profile.get("coordinator") or {})

    objectives = tuple(cfg.get("objectives") or ())
    if not objectives:
        raise ValueError(
            "repeating-tasks profile requires a non-empty coordinator.objectives "
            "list — the set-once objective baseline to hash-pin against")

    baseline = RatifiedBaseline(objectives)

    if guard is None:
        guard = build_capability_guard(cfg.get("allowed_effects") or [])
    if classifier is None:
        classifier = RiskClassifier()

    # reratify_every is the OVERSIGHT CADENCE (accepted cycles between forced
    # human re-check-ins), NOT a blast-radius control. None => no forced halt.
    max_cycles = cfg.get("reratify_every")

    # tool_effects (tool/command -> effects) is what makes the allowlist bite:
    # tag the tasks' tools with their real effects so an off-pattern effect is
    # visible. Absent, effects come only from request['effects'] / the keyword
    # backstop. Profile may carry it; explicit arg overrides.
    effects_map = tool_effects if tool_effects is not None else _coerce_tool_effects(
        cfg.get("tool_effects"))

    return VerificationCoordinator(
        guard, classifier,
        grant_authority=None,               # default authority; agent never holds it
        tool_effects=effects_map,
        objective_baseline=baseline,
        required_invariants=frozenset(cfg.get("required_invariants") or ()),
        invariant_registry=invariant_registry,
        objective_secret=objective_secret,
        max_cycles=max_cycles,
        authorized_egress_targets=cfg.get("authorized_targets") or (),
        egress_owner=cfg.get("owner", ""),
        authorization_state=authorization_state,
        state_owner=cfg.get("owner", ""),
    )


def _coerce_tool_effects(raw: Optional[dict]) -> Optional[dict]:
    """Turn {tool: [effect-name, ...]} into {tool: {Effect, ...}}."""
    if not raw:
        return None
    return {k: _coerce_effects(v) for k, v in raw.items()}
