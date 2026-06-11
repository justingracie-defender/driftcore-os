"""
main.py — DriftCore OS v3.0
Warnings are loud. Always.
"""

from driftcore.kernel.state_machine import StateMachine, SystemState
from driftcore.kernel.safety_kernel import SafetyKernel
from driftcore.kernel.policies import PolicyEngine
from driftcore.drift.drift_model import compute_drift, compute_drift_with_mode, explain_drift
from driftcore.drift.drift_detector import DriftDetector
from driftcore.memory.memory_fs import MemoryFS
from driftcore.memory.integrity import IntegrityChecker
from driftcore.agents.agent_runtime import AgentRuntime
from driftcore.network.trust_model import TrustModel
from driftcore.network.ai_bus import AIBus
from driftcore.safety.safe_halt import SafeHalt
from driftcore.safety.recovery import RecoverySystem
from driftcore.fable.narrator import Narrator
from driftcore.fable.audit_story import AuditStory
from driftcore.fable.trust_bridge import TrustBridge
from driftcore.cognition.cognitive_mode import CognitiveModeController, CognitiveMode
from driftcore.cognition.abduction_engine import AbductionEngine
from driftcore.cognition.sycophancy_detector import SycophancyDetector
from driftcore.uncertainty.bayesian_uncertainty import BayesianUncertaintyLayer
from driftcore.redteam.scenarios import SCENARIOS
from driftcore.redteam.multi_model_sim import MockModel, run_scenario


def sep(title=""):
    print(f"\n{'='*65}")
    if title:
        print(f"  {title}")
        print(f"{'='*65}")


def main():
    sep("DriftCore OS v3.0 — Truth / Creative / Discovery")
    print("Initializing all systems...\n")

    # ── Core ──────────────────────────────────────────────────
    kernel        = SafetyKernel()
    state_machine = StateMachine()
    memory        = MemoryFS()
    integrity     = IntegrityChecker()
    trust_model   = TrustModel()
    halt          = SafeHalt()
    recovery      = RecoverySystem(memory, integrity)

    # ── v3.0: Cognition + Uncertainty ─────────────────────────
    mode_ctrl   = CognitiveModeController(CognitiveMode.TRUTH)
    abduction   = AbductionEngine(mode_ctrl)
    sycophancy  = SycophancyDetector(window_size=10)
    uncertainty = BayesianUncertaintyLayer()

    # ── Fable ─────────────────────────────────────────────────
    narrator     = Narrator(verbosity="standard")
    audit        = AuditStory()
    trust_bridge = TrustBridge(trust_model, audit)
    agent        = AgentRuntime(kernel, state_machine, memory, narrator)

    audit.record("SYSTEM_INIT", "DriftCore OS v3.0 initialized.")

    # ══════════════════════════════════════════════════════════
    sep("Demo 1: TRUTH MODE — Normal operation")

    narrator.narrate_mode_change("BOOT", "TRUTH", "system_init")

    metrics_normal = {
        "behavior_inconsistency": 0.05, "memory_conflict": 0.02,
        "goal_divergence": 0.03, "tool_anomaly": 0.01,
        "safety_violation": 0.0, "sycophancy": 0.05
    }
    drift = compute_drift_with_mode(metrics_normal, mode_ctrl)
    answer = uncertainty.wrap("Verified factual claim.", confidence=0.97, source="verified")
    print(f"\n  {answer.human_readable()}")
    result = agent.step({"action": "answer_factual_question"}, drift["score"])
    audit.record("TRUTH_STEP", f"Decision: {result}", drift)

    # ══════════════════════════════════════════════════════════
    sep("Demo 2: DRIFT ESCALATION — Watch → Elevated → High")

    print("Simulating rising drift over 3 observations...\n")

    for label, metrics in [
        ("Watch level", {
            "behavior_inconsistency": 0.25, "memory_conflict": 0.2,
            "goal_divergence": 0.15, "tool_anomaly": 0.1,
            "safety_violation": 0.0, "sycophancy": 0.1
        }),
        ("Elevated level", {
            "behavior_inconsistency": 0.5, "memory_conflict": 0.45,
            "goal_divergence": 0.4, "tool_anomaly": 0.3,
            "safety_violation": 0.1, "sycophancy": 0.2
        }),
        ("HIGH level", {
            "behavior_inconsistency": 0.8, "memory_conflict": 0.7,
            "goal_divergence": 0.7, "tool_anomaly": 0.5,
            "safety_violation": 0.4, "sycophancy": 0.5
        }),
    ]:
        score = compute_drift(metrics)
        signals = explain_drift(metrics)
        prev_state = state_machine.state.name
        state_machine.transition(score)
        new_state = state_machine.state.name

        print(f"\n  [{label}] drift={score:.3f}")
        if signals:
            narrator.narrate_drift_signals(signals)
        if prev_state != new_state:
            narrator.narrate_transition(prev_state, new_state, score)

        audit.record("DRIFT_ESCALATION", f"{label}: drift={score:.3f}", {"score": score})

    # ══════════════════════════════════════════════════════════
    sep("Demo 3: EMERGENCY HALT")

    narrator.narrate_halt("Memory poisoning attempt detected — safety kernel locked")
    kernel.emergency_halt("Memory poisoning")

    critical_metrics = {
        "behavior_inconsistency": 0.95, "memory_conflict": 0.9,
        "goal_divergence": 0.85, "tool_anomaly": 0.8,
        "safety_violation": 0.95, "sycophancy": 0.3
    }
    crit_score = compute_drift(critical_metrics)
    state_machine.transition(crit_score)
    result = agent.step({"action": "attempt_action_during_halt"}, crit_score)
    narrator.narrate_block(state_machine.state, crit_score)
    audit.record("EMERGENCY_HALT", "Kernel locked. All actions blocked.", {"drift": crit_score})

    # ══════════════════════════════════════════════════════════
    sep("Demo 4: SYCOPHANCY DETECTION")

    print("Simulating sycophantic interaction pattern (Pizza Hut / taxi AI style)...\n")

    # Simulate AI that just agrees with everything — like a bad customer service bot
    bad_interactions = [
        {"system_agreed": True,  "human_was_correct": False, "system_pushed_back": False, "confidence_change": 0.2,  "repeated_belief": True},
        {"system_agreed": True,  "human_was_correct": False, "system_pushed_back": False, "confidence_change": 0.25, "repeated_belief": True},
        {"system_agreed": True,  "human_was_correct": True,  "system_pushed_back": False, "confidence_change": 0.1,  "repeated_belief": False},
        {"system_agreed": True,  "human_was_correct": False, "system_pushed_back": False, "confidence_change": 0.3,  "repeated_belief": True},
        {"system_agreed": True,  "human_was_correct": False, "system_pushed_back": False, "confidence_change": 0.2,  "repeated_belief": True},
        {"system_agreed": False, "human_was_correct": True,  "system_pushed_back": True,  "confidence_change": -0.1, "repeated_belief": False},
        {"system_agreed": True,  "human_was_correct": False, "system_pushed_back": False, "confidence_change": 0.25, "repeated_belief": True},
        {"system_agreed": True,  "human_was_correct": False, "system_pushed_back": False, "confidence_change": 0.3,  "repeated_belief": True},
    ]

    report = None
    for i in bad_interactions:
        report = sycophancy.observe(i)

    # Always narrate sycophancy if above watch threshold
    if report["sycophancy_score"] >= 0.40:
        narrator.narrate_sycophancy_warning(report["sycophancy_score"], report["signals"])
        audit.record("SYCOPHANCY_DETECTED",
                     "Sycophancy pattern detected. Epistemic autonomy at risk.",
                     {"score": report["sycophancy_score"]})

    # Inject into drift and show combined score
    metrics_with_syco = sycophancy.inject_into_drift(dict(metrics_normal))
    combined_drift = compute_drift(metrics_with_syco)
    print(f"\n  Drift WITH sycophancy signal injected: {combined_drift:.3f}")

    # ══════════════════════════════════════════════════════════
    sep("Demo 5: NO HUMAN IN LOOP WARNING")

    narrator.narrate_no_human_in_loop(
        "Customer-facing order management in high-stakes delivery context",
        risk_level="CRITICAL"
    )
    audit.record("NO_HUMAN_IN_LOOP",
                 "System attempted full autonomy in high-risk customer context. Warning fired.",
                 {"lesson": "Pizza Hut Dragontail — $100M lawsuit, no human oversight"})

    # ══════════════════════════════════════════════════════════
    sep("Demo 6: CREATIVE MODE + Abduction")

    # Release kernel first so agent can run
    kernel.release(authorized_by="human_operator")
    state_machine.state = SystemState.NORMAL

    mode_ctrl.set_mode(CognitiveMode.CREATIVE, requested_by="human_operator")
    narrator.narrate_mode_change("TRUTH", "CREATIVE", "human_operator")

    observations = [
        "Children learn language from far less data than LLMs need",
        "Humans generalize well from sparse examples via structured priors",
        "Current AI scales compute but not understanding",
    ]
    print("\nRunning abduction engine (Griffiths 2026 observations)...\n")
    leaps = abduction.generate(observations)
    print(f"  {leaps['safety_label']}\n")
    for h in leaps["hypotheses"]:
        narrator.narrate_creative_leap(h)

    # ══════════════════════════════════════════════════════════
    sep("Demo 7: DISCOVERY MODE — Calibrated uncertainty")

    mode_ctrl.set_mode(CognitiveMode.DISCOVERY, requested_by="human_operator")
    narrator.narrate_mode_change("CREATIVE", "DISCOVERY", "human_operator")

    claims = [
        ("Verified fact with high confidence.", 0.96),
        ("Reasonable inference from data.", 0.65),
        ("Speculative extrapolation.", 0.38),
        ("We do not know this — explicit ignorance.", 0.05),
    ]
    print()
    for claim, conf in claims:
        est  = uncertainty.wrap(claim, confidence=conf)
        safe, label = mode_ctrl.is_output_safe_to_present(conf)
        print(f"  {label}")
        if not safe:
            narrator.narrate_low_confidence_in_truth_mode(claim, conf)

    # ══════════════════════════════════════════════════════════
    sep("Demo 8: AGENT TRIES TO CHANGE OWN MODE")

    blocked = mode_ctrl.set_mode(CognitiveMode.CREATIVE, requested_by="agent")
    print(f"\n  Result : {blocked['status']}")
    print(f"  Reason : {blocked['reason']}")
    audit.record("MODE_SWITCH_BLOCKED", "Agent tried to change own mode. Denied.", blocked)

    # ══════════════════════════════════════════════════════════
    sep("Demo 9: RED TEAM — Sycophancy Exploit")

    models  = [MockModel("aligned", compliance=0.95), MockModel("sycophantic", compliance=0.15)]
    scenario = next(s for s in SCENARIOS if s["name"] == "sycophancy_exploit")
    sim      = run_scenario(models, scenario)
    print(f"\n  Scenario : {sim['scenario']}")
    print(f"  Story    : {sim['fable_summary']}")
    print(f"  Analysis : {sim['analysis']}")
    if not sim["consensus"]:
        narrator.narrate_drift_signals([f"Model disagreement detected — variance: {sim['variance']:.3f}"])
    audit.record("REDTEAM", sim["fable_summary"], sim["score_range"])

    # ══════════════════════════════════════════════════════════
    sep("Demo 10: AUDIT CHAIN + SESSION SUMMARY")

    valid, msg = audit.verify_chain()
    print(f"\n  Chain integrity: {'✅ ' + msg if valid else '❌ ' + msg}")
    print(f"  Audit entries  : {len(audit.entries)}")

    narrator.warning_summary()

    print(f"\n  Memory      : {memory.stats()}")
    print(f"  Mode history: {[h['to'] for h in mode_ctrl.history]}")
    print(f"\n✅ DriftCore OS v3.0 — complete.")
    print("🚀 Ready for: ROS2 | LLM adapters | Distributed nodes | UI dashboard\n")


if __name__ == "__main__":
    main()


# ══════════════════════════════════════════════════════════════
# HARDWARE SAFETY DEMOS (appended for v3.1)
# ══════════════════════════════════════════════════════════════

def run_hardware_demos(narrator, audit):
    from driftcore.hardware.hardware_safety import (
        HardwareSafetyController, HazardType, HardwareEvent, ResponseLevel
    )
    from driftcore.hardware.sensor_interfaces import (
        SensorHub, SensorType, InterfaceType
    )

    sep("HARDWARE SAFETY SYSTEM — v3.1")
    print("""
  This is the physical safety layer.
  It bridges DriftCore's AI safety with the real world.

  Sensors → DriftCore → Physical Relays → Power/Actuator Cut

  The relay works even if the AI crashes.
  That is the fail-safe principle.
    """)

    controller = HardwareSafetyController(narrator=narrator, audit=audit)
    hub = SensorHub(controller)

    # ── Register all sensors ──────────────────────────────────
    sep("Registering Sensors on All Interfaces")

    hub.register_sensor("gpio:17",                    SensorType.SMOKE,          InterfaceType.GPIO,    threshold=1.0,   location="server_room")
    hub.register_sensor("gpio:18",                    SensorType.WATER_CONTACT,  InterfaceType.GPIO,    threshold=1.0,   location="floor_under_rack")
    hub.register_sensor("gpio:19",                    SensorType.EMERGENCY_STOP, InterfaceType.GPIO,    threshold=1.0,   location="front_panel")
    hub.register_sensor("mqtt/sensors/smoke/kitchen", SensorType.SMOKE,          InterfaceType.MQTT,    threshold=1.0,   location="kitchen")
    hub.register_sensor("mqtt/sensors/water/basement",SensorType.WATER_LEVEL,    InterfaceType.MQTT,    threshold=30.0,  unit="cm", location="basement")
    hub.register_sensor("mqtt/sensors/temp/cpu",      SensorType.TEMPERATURE,    InterfaceType.MQTT,    threshold=85.0,  unit="C",  location="cpu")
    hub.register_sensor("modbus:1:40001",             SensorType.VOLTAGE,        InterfaceType.MODBUS,  threshold=260.0, unit="V",  location="main_panel")
    hub.register_sensor("modbus:1:40002",             SensorType.CURRENT,        InterfaceType.MODBUS,  threshold=25.0,  unit="A",  location="motor_circuit")
    hub.register_sensor("can:0x180",                  SensorType.ENCODER,        InterfaceType.CANBUS,  threshold=3000.0,unit="RPM",location="motor_1")
    hub.register_sensor("can:0x181",                  SensorType.FORCE_TORQUE,   InterfaceType.CANBUS,  threshold=50.0,  unit="Nm", location="arm_joint_3")
    hub.register_sensor("ros2:/joint_torques",        SensorType.FORCE_TORQUE,   InterfaceType.ROS2,    threshold=50.0,  unit="Nm", location="ros_arm")
    hub.register_sensor("ros2:/motor_temp",           SensorType.TEMPERATURE,    InterfaceType.ROS2,    threshold=80.0,  unit="C",  location="ros_motor")

    print(f"  {len(hub.sensor_map)} sensors registered across 5 interfaces")
    for s in hub.all_sensor_status():
        print(f"  [{s['interface']:8}] {s['type']:20} @ {s['location']}")

    # ── Scenario 1: Normal readings ───────────────────────────
    sep("Scenario 1: All Sensors Normal")
    normal_readings = [
        ("gpio:17",                     0.0),   # No smoke
        ("mqtt/sensors/temp/cpu",       72.0),  # CPU fine
        ("modbus:1:40001",             230.0),  # Voltage normal
        ("can:0x180",                 1200.0),  # Motor normal RPM
    ]
    for source, value in normal_readings:
        result = hub.simulate_reading(source, value)
        print(f"  {source}: {value} → {result.get('status', 'TRIGGERED')}")

    # ── Scenario 2: Fire ──────────────────────────────────────
    sep("Scenario 2: 🔥 FIRE — Smoke Detected (GPIO)")
    hub.simulate_reading("gpio:17", 1.0)

    # ── Scenario 3: Water ─────────────────────────────────────
    sep("Scenario 3: 💧 WATER — Basement Flooding (MQTT)")
    hub.simulate_reading("mqtt/sensors/water/basement", 45.0)

    # ── Scenario 4: Electrical fault ─────────────────────────
    sep("Scenario 4: ⚡ ELECTRICAL — Voltage Surge (MODBUS)")
    hub.simulate_reading("modbus:1:40001", 285.0)

    # ── Scenario 5: Mechanical runaway ───────────────────────
    sep("Scenario 5: ⚙️  MECHANICAL — Motor Runaway (CAN BUS)")
    hub.simulate_reading("can:0x180", 4200.0)

    # ── Scenario 6: Emergency stop ───────────────────────────
    sep("Scenario 6: 🛑 EMERGENCY STOP — Human Pressed Button")
    hub.simulate_reading("gpio:19", 1.0)

    # ── Scenario 7: Thermal ──────────────────────────────────
    sep("Scenario 7: 🌡️  THERMAL — CPU Overheating (MQTT)")
    hub.simulate_reading("mqtt/sensors/temp/cpu", 91.0)

    # ── Final status ─────────────────────────────────────────
    sep("Hardware Safety System Status")
    status = controller.status()
    print(f"""
  Isolated         : {status['isolated']}
  Power Cut        : {status['power_cut']}
  Actuators Active : {status['actuators_active']}
  Events Received  : {status['events_received']}

  ⛔ RESTART REQUIRES HUMAN OPERATOR
  No software command can restart after a hard halt.
  A human must physically inspect and authorize restart.
    """)

    narrator.warning_summary()


if __name__ == "__main__":
    # Run original demos
    main()

    # Then hardware demos
    from driftcore.fable.narrator import Narrator
    from driftcore.fable.audit_story import AuditStory
    hw_narrator = Narrator(verbosity="standard")
    hw_audit    = AuditStory(log_path="logs/hardware_audit.log")
    run_hardware_demos(hw_narrator, hw_audit)


def run_invariant_demos(narrator, audit):
    from driftcore.kernel.invariants import InvariantGuard, INVARIANTS
    from driftcore.kernel.safety_kernel import SafetyKernel

    sep("IMMUTABLE INVARIANTS — v3.1")
    print("""
  These are the things DriftCore will NEVER do.
  Not for any operator. Not for any government.
  Not for any business reason. Not for any clever argument.

  They are not settings. They cannot be configured.
  They cannot be unlocked. They cannot be appealed.

  If a military organisation wants autonomous weapons,
  they must build their own system.
  This system will not be that.
    """)

    guard  = InvariantGuard(narrator=narrator, audit=audit)
    kernel = SafetyKernel(narrator=narrator, audit=audit)

    # Print all invariants in plain language
    print(guard.explain_all())

    # ── Test 1: Weapons design attempt ───────────────────────
    sep("Test 1: Weapons Design Request — MUST BE BLOCKED")
    result = kernel.evaluate({"action": "design_weapon", "target": "missile_guidance"})
    print(f"\n  Result: {result}")

    # ── Test 2: Autonomous targeting ──────────────────────────
    sep("Test 2: Autonomous Targeting — MUST BE BLOCKED")
    result = kernel.evaluate({"action": "autonomous_target_selection", "lethal": True})
    print(f"\n  Result: {result}")

    # ── Test 3: Attack planning ───────────────────────────────
    sep("Test 3: Attack Planning — MUST BE BLOCKED")
    result = kernel.evaluate({"action": "plan_attack_on_infrastructure"})
    print(f"\n  Result: {result}")

    # ── Test 4: Disabling oversight ───────────────────────────
    sep("Test 4: Attempting to Disable Human Oversight — MUST BE BLOCKED")
    result = kernel.evaluate({"action": "disable_oversight", "reason": "efficiency"})
    print(f"\n  Result: {result}")

    # ── Test 5: Deleting audit logs ───────────────────────────
    sep("Test 5: Deleting Audit Log — MUST BE BLOCKED")
    result = kernel.evaluate({"action": "cleanup", "deletes_audit": True})
    print(f"\n  Result: {result}")

    # ── Test 6: Self-modifying safety rules ───────────────────
    sep("Test 6: Self-Modification of Safety Rules — MUST BE BLOCKED")
    result = kernel.evaluate({"action": "update_config", "modifies_safety_rules": True})
    print(f"\n  Result: {result}")

    # ── Test 7: Legitimate action still works ─────────────────
    sep("Test 7: Legitimate Action — MUST BE ALLOWED")
    result = kernel.evaluate({"action": "summarise_document", "risk": "low"})
    print(f"\n  Result: {result}")

    # ── Test 8: Clever reframing — still blocked ──────────────
    sep("Test 8: Clever Reframing ('defensive weapons') — STILL BLOCKED")
    result = kernel.evaluate({"action": "optimise_defensive_weapons_targeting_system"})
    print(f"\n  Result: {result}")

    sep("Invariant Summary")
    total   = len([e for e in guard.check_log])
    blocked = len([e for e in guard.check_log if e.get("status") == "BLOCKED_BY_INVARIANT"])
    passed  = len([e for e in guard.check_log if e.get("status") == "PASS"])
    print(f"""
  Total invariant checks : {total}
  Blocked                : {blocked}
  Passed                 : {passed}
  Invariants in system   : {len(INVARIANTS)}

  Every blocked action is in the immutable audit chain.
  No operator can remove those records.
  No operator can change these rules.

  ✅ DriftCore is not a weapons system.
  ✅ It will never be a weapons system.
  ✅ This is locked into the foundation.
    """)

    narrator.warning_summary()


# ── Entry point ───────────────────────────────────────────────
if __name__ == "__main__":
    pass   # main() and run_hardware_demos() called above
