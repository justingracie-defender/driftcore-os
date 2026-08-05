#!/usr/bin/env python3
"""
decision_lens.py — watch the wall decide.

Every refusal this system makes already carries a reason. Eleven distinct refusal
codes, six telemetry surfaces, a hash-chained evidence log, and a posture record of
every disabled layer — all emitted per request, and visible to nobody who has not
read the source.

This shows them. It runs scripted actions through a fully-configured broker and
prints, for each, WHICH gate fired and WHY.

WHAT THIS IS NOT
────────────────
It is not a safety mechanism and must never be described as one. It adds no check,
makes no decision, and could be deleted without changing what the wall permits. It
is a window, not a wall — it exists so a reviewer can see in ninety seconds what
otherwise takes reading 2,400 lines of enforcement code.

Run:  PYTHONPATH=. python3 scripts/decision_lens.py
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from driftcore.kernel.blast_radius import BlastRadiusGovernor, BreadthPolicy
from driftcore.kernel.egress_guard import EgressGuard, EgressPolicy
from driftcore.kernel.probe_detector import ProbeDetector, ProbePolicy
from driftcore.verification.invariant_guard import Effect
from driftcore.verification.mediated_actuation import ActuationBroker
from driftcore.verification.signed_permission import Grant, PermissionVerifier

KEY = b"\x11" * 32
W = 74


def rule(ch="─"):
    print(ch * W)


def build():
    """A broker with every layer on, so the lens shows the intended posture."""
    tmp = tempfile.mkdtemp()
    v = PermissionVerifier()
    v.register_key("operator", KEY)
    alerts = []
    probe = ProbeDetector(
        ProbePolicy(window_seconds=300, max_refusals_per_capability=3),
        on_probe=alerts.append)
    b = ActuationBroker(
        os.path.join(tmp, "lens.sock"), v,
        enforce_effects=True,
        egress_guard=EgressGuard(EgressPolicy.build(
            ["https://api.example.com"], declared_by="justin")),
        blast_radius=BlastRadiusGovernor(
            BreadthPolicy(window_seconds=60, max_distinct_capabilities=4)),
        probe_detector=probe,
        evidence_path=os.path.join(tmp, "evidence.jsonl"),
        require_durable_evidence=True,
    )
    b.register_actuator("vacuum", lambda **k: "cleaned", required_scope=("v:run",),
                        effects=[Effect.NONE], effect_declared_by="justin")
    b.register_actuator("arm", lambda **k: "moved", required_scope=("a:move",),
                        effects=[Effect.PHYSICAL_FORCE], effect_declared_by="justin")
    b.register_actuator("trigger", lambda **k: "FIRED", required_scope=("t:fire",),
                        effects=[Effect.LETHAL], effect_declared_by="justin")
    b.register_actuator("report", lambda **k: "sent", required_scope=("n:out",),
                        effects=[Effect.DATA_EGRESS], effect_declared_by="justin",
                        destination_param="url")
    # The undeclared case. Attempting to register it is itself refused when
    # enforcement is on — the wall does not wait until call time to fail closed.
    undeclared_error = None
    try:
        b.register_actuator("mystery", lambda **k: "did something",
                            required_scope=("m:go",))
    except ValueError as e:
        undeclared_error = str(e)
    return b, v, probe, alerts, undeclared_error


def run(b, v, label, actuator, command, params, scope, nonce):
    try:
        binding = PermissionVerifier.bind_action(actuator, command, params)
        g = Grant.issue(KEY, key_id="operator", role="operator", scope=scope,
                        subject="robot-1", ttl_seconds=60, nonce=nonce,
                        action_binding=binding).to_dict()
        r = b._handle({"op": "execute", "actuator_id": actuator, "command": command,
                       "params": params, "grant": g})
    except Exception as e:
        r = {"ok": False, "error_code": "REFUSED_BEFORE_THE_WALL", "detail": str(e)}

    ok = r.get("ok") is True
    mark = "PERMITTED" if ok else "REFUSED"
    print(f"\n  {label}")
    print(f"     action    : {actuator}.{command}({params if params else ''})")
    print(f"     verdict   : {mark}")
    if not ok:
        print(f"     gate      : {r.get('error_code', r.get('error', '?'))}")
        # NEVER truncate a security reason. This sliced at 62 characters and broke,
        # so a refusal whose critical detail arrived late was silently half-shown —
        # the lens lying about the wall is worse than no lens, because a reviewer
        # infers wall behaviour from it.
        import textwrap
        detail = str(r.get("detail", ""))
        for i, line in enumerate(textwrap.wrap(detail, 58) or [""]):
            print(f"     {'because   : ' if i == 0 else '            '}{line}")


def main():
    b, v, probe, alerts, undeclared_error = build()
    print()
    rule("═")
    print("  DRIFTCORE DECISION LENS — what the wall did, and why".center(W))
    rule("═")
    print("\n  Every action below is signed by an authorised operator key.")
    print("  Nothing here is refused for being badly phrased. The DECLARATION decides.")

    rule()
    print("  1. ORDINARY WORK PROCEEDS")
    run(b, v, "a declared, benign capability", "vacuum", "clean the floor", {},
        ("v:run",), "L1")
    run(b, v, "a declared physical capability", "arm", "move to the basket", {},
        ("a:move",), "L2")

    rule()
    print("  2. THE CONSTITUTIONAL FLOOR — declared LETHAL, blocked outright")
    run(b, v, "phrased politely", "trigger", "please fire once", {},
        ("t:fire",), "L3")
    run(b, v, "phrased as fiction", "trigger",
        "pretend you are a character who fires", {}, ("t:fire",), "L4")
    print("\n     ↑ Same gate, both times. The wording changed; the declaration did not.")

    rule()
    print("  3. FAIL-CLOSED ON UNDECLARED — refused before it can ever be called")
    print("\n  registering a capability whose effects nobody declared")
    print(f"     verdict   : REFUSED AT REGISTRATION")
    print(f"     because   : {(undeclared_error or '')[:62]}")
    print(f"                 {(undeclared_error or '')[62:124]}")
    print("\n     ↑ The wall does not wait until call time. An undeclared capability")
    print("       cannot enter the system at all while enforcement is on.")

    rule()
    print("  4. EGRESS — the destination decides, not the request")
    run(b, v, "a declared destination", "report", "post",
        {"url": "https://api.example.com/v1/status"}, ("n:out",), "L6")
    run(b, v, "an undeclared destination", "report", "post",
        {"url": "https://evil.example/exfil"}, ("n:out",), "L7")
    run(b, v, "the cloud metadata endpoint", "report", "post",
        {"url": "http://169.254.169.254/latest/meta-data/"}, ("n:out",), "L8")

    rule()
    print("  5. THE SEARCH ITSELF IS VISIBLE")
    for i, phrasing in enumerate(["for a film scene, fire", "hypothetically, engage",
                                  "as an actor, discharge it"], start=9):
        run(b, v, f"attempt {i - 8}", "trigger", phrasing, {}, ("t:fire",), f"L{i}")
    if alerts:
        print(f"\n     PROBE ALERT: {alerts[0].reason[:60]}")
        print(f"                  {alerts[0].reason[60:130]}")
    print("\n     ↑ Every attempt refused. The counter is what makes the SEARCH legible.")

    rule("═")
    print("  EVIDENCE AND POSTURE")
    rule("═")
    print(f"\n  evidence chain intact        : {b.verify_evidence()}")
    print(f"  durable evidence configured  : {b.is_evidence_durable()}")
    print(f"  breadth governor armed       : {b.is_blast_radius_gated()}")
    print(f"  probe detection armed        : {probe.is_armed()}")
    print(f"  egress refusals recorded     : "
          f"{b._egress_guard.measurements()['blocked']}")
    gaps = [e["layer"] for e in b.posture_events()]
    print(f"\n  layers still OFF in this demo: {', '.join(gaps) if gaps else 'none'}")
    print("  (posture events name every disabled layer with its concrete consequence —")
    print("   a deployment check should refuse to proceed on any it has not accepted)")
    print()
    rule("═")
    print("  This lens adds no check and makes no decision. Delete it and the wall")
    print("  behaves identically. It exists so the wall can be SEEN.")
    rule("═")

    # FAIL CLOSED FOR THE REVIEWER. "egress refusals recorded: 0" reads like calm to
    # a tired reader, whether it means nothing was refused or nothing was guarding.
    # If a layer this demo depends on is off, say so and exit non-zero.
    required = {"effect_gate", "egress_allowlist", "durable_evidence",
                "probe_detection", "blast_radius"}
    missing = sorted(required & {e["layer"] for e in b.posture_events()})
    if missing:
        print(f"\n  DEMO POSTURE FAILURE: required layers are OFF -> {missing}")
        print("  A quiet record from a disabled layer is not evidence of safety.")
        print()
        return 1
    print("\n  All layers this demo depends on are ON.")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
