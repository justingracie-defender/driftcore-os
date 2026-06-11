"""
hardware_safety.py — Physical Safety Interlock System
DriftCore OS v3.1

═══════════════════════════════════════════════════════════════
PLAIN LANGUAGE EXPLANATION — FOR EVERYONE
═══════════════════════════════════════════════════════════════

This module is the bridge between the AI software and the
physical world. When something dangerous happens — fire, water,
electrical fault, mechanical failure — this is what actually
stops the machine.

CRITICAL DESIGN RULE (read this first):
────────────────────────────────────────
The hardware interlock must work even if the AI is dead.

Think of it like a circuit breaker in your house. The circuit
breaker doesn't need your phone app to trip. It trips on its
own when something goes wrong. The app can also trip it — but
the physical protection works with or without software.

DriftCore follows the same rule:
  SENSOR → [PHYSICAL RELAY] → POWER CUT
                ↑
           DriftCore can
           also trigger this
           but the relay works
           without DriftCore

═══════════════════════════════════════════════════════════════
HAZARD TYPES
═══════════════════════════════════════════════════════════════

🔥 FIRE        — Smoke/heat sensor triggers. Cuts ALL power.
                 No exceptions. Nothing overrides a fire.

💧 WATER       — Flood/leak sensor triggers. Cuts electrical
                 systems immediately. Water + electricity = death.

⚡ ELECTRICAL  — Voltage/current anomaly detected internally
                 OR externally. Isolates affected circuit.
                 May indicate short, surge, or tampering.

⚙️  MECHANICAL  — Encoder, limit switch, or force sensor out
                 of bounds. Disables actuators. Prevents
                 physical damage or injury from runaway motion.

🌡️  THERMAL    — Temperature exceeds safe operating range.
                 Graduated response: throttle → halt → isolate.

🔌 POWER       — Brownout, surge, or loss of supply detected.
                 Graceful shutdown before data/hardware damage.

═══════════════════════════════════════════════════════════════
INTERFACE TYPES
═══════════════════════════════════════════════════════════════

GPIO    — Raspberry Pi / Arduino digital pins.
          Write HIGH/LOW to trigger physical relay.
          Simplest interface. Works for most home/lab robots.

SERIAL  — RS-232 / RS-485.
          Industrial standard. PLCs, legacy equipment.
          Reliable over long distances.

MODBUS  — Industrial fieldbus protocol.
          Factories, elevators, HVAC, heavy machinery.
          Standardized. Certified for safety applications.

CAN BUS — Automotive / heavy machinery.
          Very fast. Used in cars, forklifts, industrial arms.
          Fault-tolerant by design.

MQTT    — IoT sensor network.
          Smoke detectors, water sensors, temperature probes
          publish to topics. DriftCore subscribes and responds.

ROS2    — Robotics middleware.
          Already on DriftCore roadmap.
          Handles actuator control and sensor fusion.

═══════════════════════════════════════════════════════════════
"""

from enum import Enum
from datetime import datetime
from typing import Callable


# ── Hazard types ──────────────────────────────────────────────

class HazardType(Enum):
    FIRE       = "FIRE"
    WATER      = "WATER"
    ELECTRICAL = "ELECTRICAL"
    MECHANICAL = "MECHANICAL"
    THERMAL    = "THERMAL"
    POWER      = "POWER"
    UNKNOWN    = "UNKNOWN"


# ── Response levels ───────────────────────────────────────────

class ResponseLevel(Enum):
    """
    Not all hazards need the same response.
    Graduated responses prevent unnecessary shutdowns
    while ensuring dangerous situations are always stopped.
    """
    ALERT        = 0   # Log and notify. No action yet.
    THROTTLE     = 1   # Reduce speed/power. Stay running.
    SOFT_HALT    = 2   # Pause operations. Human review needed.
    HARD_HALT    = 3   # Stop everything. Human restart required.
    POWER_CUT    = 4   # Cut power completely. Hardware interlock.
    ISOLATE      = 5   # Physical disconnect. Maximum safety.


# ── Hazard → default response mapping ────────────────────────

HAZARD_RESPONSE = {
    HazardType.FIRE:       ResponseLevel.ISOLATE,    # Always maximum
    HazardType.WATER:      ResponseLevel.POWER_CUT,  # Electrical risk
    HazardType.ELECTRICAL: ResponseLevel.HARD_HALT,  # Assess first
    HazardType.MECHANICAL: ResponseLevel.SOFT_HALT,  # May be recoverable
    HazardType.THERMAL:    ResponseLevel.THROTTLE,   # Graduated
    HazardType.POWER:      ResponseLevel.SOFT_HALT,  # Graceful shutdown
    HazardType.UNKNOWN:    ResponseLevel.HARD_HALT,  # When in doubt, stop
}

# Human-readable explanations for Fable
HAZARD_EXPLANATIONS = {
    HazardType.FIRE: (
        "🔥 FIRE HAZARD DETECTED\n"
        "   A smoke or heat sensor has triggered.\n"
        "   This is the highest priority emergency.\n"
        "   ALL systems are being shut down immediately.\n"
        "   Nothing overrides a fire response.\n"
        "   Evacuate. Call emergency services."
    ),
    HazardType.WATER: (
        "💧 WATER / FLOOD HAZARD DETECTED\n"
        "   A water or moisture sensor has triggered.\n"
        "   Water near electrical systems is life-threatening.\n"
        "   Electrical systems are being cut immediately.\n"
        "   Do not touch any electrical equipment.\n"
        "   Locate and stop the water source."
    ),
    HazardType.ELECTRICAL: (
        "⚡ ELECTRICAL FAULT DETECTED\n"
        "   An abnormal voltage or current reading was found.\n"
        "   This could indicate a short circuit, surge, or tampering.\n"
        "   The affected circuit is being isolated.\n"
        "   Do not touch any wiring until inspected by a qualified person."
    ),
    HazardType.MECHANICAL: (
        "⚙️  MECHANICAL FAULT DETECTED\n"
        "   A sensor has detected movement outside safe limits.\n"
        "   This could indicate a stuck actuator, collision, or runaway motion.\n"
        "   All actuators are being disabled.\n"
        "   Do not approach moving parts until fully stopped."
    ),
    HazardType.THERMAL: (
        "🌡️  THERMAL WARNING\n"
        "   Temperature is outside the safe operating range.\n"
        "   System is reducing load to cool down.\n"
        "   If temperature continues rising, a hard halt will follow.\n"
        "   Check ventilation and cooling systems."
    ),
    HazardType.POWER: (
        "🔌 POWER ANOMALY DETECTED\n"
        "   Abnormal power supply detected (surge, brownout, or loss).\n"
        "   Initiating graceful shutdown to protect hardware and data.\n"
        "   Check power supply and connections."
    ),
    HazardType.UNKNOWN: (
        "❓ UNKNOWN HAZARD DETECTED\n"
        "   An unclassified safety signal was received.\n"
        "   Defaulting to hard halt — safety first.\n"
        "   Manual inspection required before restart."
    ),
}

RESPONSE_EXPLANATIONS = {
    ResponseLevel.ALERT:     "📋 Alert logged. Monitoring. No action taken yet.",
    ResponseLevel.THROTTLE:  "🟡 System throttled. Reducing power/speed. Continuing with caution.",
    ResponseLevel.SOFT_HALT: "🟠 Soft halt. Non-critical operations paused. Human review needed.",
    ResponseLevel.HARD_HALT: "🔴 Hard halt. All operations stopped. Human restart required.",
    ResponseLevel.POWER_CUT: "🛑 Power cut. Electrical systems disconnecting. Do not touch equipment.",
    ResponseLevel.ISOLATE:   "🚨 FULL ISOLATION. All systems disconnected. Emergency services may be needed.",
}


# ── Hardware event ────────────────────────────────────────────

class HardwareEvent:
    def __init__(
        self,
        hazard: HazardType,
        source: str,          # e.g. "gpio_pin_17", "mqtt/sensors/smoke/kitchen"
        interface: str,       # e.g. "GPIO", "MQTT", "MODBUS"
        reading: float = 0.0, # Raw sensor reading
        threshold: float = 0.0,
        location: str = "unknown",
    ):
        self.hazard    = hazard
        self.source    = source
        self.interface = interface
        self.reading   = reading
        self.threshold = threshold
        self.location  = location
        self.timestamp = datetime.utcnow().isoformat()
        self.response  = HAZARD_RESPONSE[hazard]

    def to_dict(self) -> dict:
        return {
            "hazard":    self.hazard.value,
            "source":    self.source,
            "interface": self.interface,
            "reading":   self.reading,
            "threshold": self.threshold,
            "location":  self.location,
            "response":  self.response.value,
            "timestamp": self.timestamp,
        }


# ── Hardware safety controller ────────────────────────────────

class HardwareSafetyController:
    """
    The central controller for all physical safety responses.

    In production:
      - GPIO callbacks connect to real Raspberry Pi / Arduino pins
      - MQTT client subscribes to real sensor topics
      - MODBUS/CAN clients connect to industrial hardware
      - Physical relay callbacks cut real power

    In simulation (current):
      - All actions are logged and narrated
      - Callbacks are stub functions
      - Behavior is identical to production — only the output differs
    """

    def __init__(self, narrator=None, audit=None):
        self.narrator         = narrator
        self.audit            = audit
        self.event_log        = []
        self.isolated         = False
        self.power_cut        = False
        self.actuators_active = True

        # Physical relay callbacks
        # In production: replace stubs with real GPIO/relay calls
        self._relay_callbacks: dict[ResponseLevel, list[Callable]] = {
            level: [] for level in ResponseLevel
        }

        # Register default stub handlers
        self._register_default_handlers()

    def register_relay(self, level: ResponseLevel, callback: Callable):
        """
        Register a real hardware callback for a response level.

        Example (production):
          import RPi.GPIO as GPIO
          def cut_main_power():
              GPIO.output(17, GPIO.LOW)   # Open relay — cuts power
          controller.register_relay(ResponseLevel.POWER_CUT, cut_main_power)
        """
        self._relay_callbacks[level].append(callback)

    def receive_event(self, event: HardwareEvent) -> dict:
        """
        Main entry point. Receive a hardware safety event and respond.
        This is called by:
          - GPIO interrupt handlers
          - MQTT message callbacks
          - MODBUS polling loops
          - CAN bus message handlers
          - Internal software monitors
        """
        self.event_log.append(event.to_dict())

        # Narrate immediately — humans must know NOW
        self._narrate_hazard(event)

        # Execute response
        result = self._execute_response(event)

        # Audit
        if self.audit:
            self.audit.record(
                f"HARDWARE_{event.hazard.value}",
                HAZARD_EXPLANATIONS[event.hazard],
                event.to_dict()
            )

        return result

    def _execute_response(self, event: HardwareEvent) -> dict:
        level = event.response
        actions_taken = []

        self._narrate_response(level, event)

        # Execute all registered callbacks for this level and above
        for resp_level in ResponseLevel:
            if resp_level.value >= level.value:
                for callback in self._relay_callbacks.get(resp_level, []):
                    try:
                        callback()
                        actions_taken.append(f"{resp_level.name}: callback executed")
                    except Exception as e:
                        actions_taken.append(f"{resp_level.name}: callback FAILED — {e}")

        # Update system state
        if level.value >= ResponseLevel.POWER_CUT.value:
            self.power_cut = True
        if level.value >= ResponseLevel.HARD_HALT.value:
            self.actuators_active = False
        if level.value >= ResponseLevel.ISOLATE.value:
            self.isolated = True

        return {
            "hazard":        event.hazard.value,
            "response_level": level.name,
            "actions_taken": actions_taken,
            "system_state": {
                "isolated":         self.isolated,
                "power_cut":        self.power_cut,
                "actuators_active": self.actuators_active,
            },
            "restart_requires_human": level.value >= ResponseLevel.HARD_HALT.value,
        }

    def _narrate_hazard(self, event: HardwareEvent):
        if not self.narrator:
            return
        explanation = HAZARD_EXPLANATIONS[event.hazard]
        story = (
            f"\n{'!'*65}\n"
            f"{explanation}\n"
            f"  Source    : {event.source}\n"
            f"  Interface : {event.interface}\n"
            f"  Location  : {event.location}\n"
            f"  Reading   : {event.reading} (threshold: {event.threshold})\n"
            f"  Time      : {event.timestamp}\n"
            f"{'!'*65}"
        )
        self.narrator._emit(story, is_warning=True)

    def _narrate_response(self, level: ResponseLevel, event: HardwareEvent):
        if not self.narrator:
            return
        explanation = RESPONSE_EXPLANATIONS[level]
        story = (
            f"\n{'!'*65}\n"
            f"🚨 HARDWARE SAFETY RESPONSE\n"
            f"  Hazard   : {event.hazard.value}\n"
            f"  Response : {level.name}\n"
            f"  Action   : {explanation}\n"
        )
        if level.value >= ResponseLevel.HARD_HALT.value:
            story += f"  ⛔ HUMAN INTERVENTION REQUIRED BEFORE RESTART\n"
        story += f"{'!'*65}"
        self.narrator._emit(story, is_warning=True)

    def status(self) -> dict:
        return {
            "isolated":         self.isolated,
            "power_cut":        self.power_cut,
            "actuators_active": self.actuators_active,
            "events_received":  len(self.event_log),
            "last_event":       self.event_log[-1] if self.event_log else None,
        }

    def _register_default_handlers(self):
        """
        Stub handlers — replace with real hardware calls in production.
        Each one logs what it WOULD do on real hardware.
        """
        def stub_alert():
            print("  [HARDWARE STUB] Alert signal sent to monitoring system")

        def stub_throttle():
            print("  [HARDWARE STUB] Throttle signal sent → PWM reduced to 30%")

        def stub_soft_halt():
            print("  [HARDWARE STUB] Soft halt signal sent → actuators paused")

        def stub_hard_halt():
            print("  [HARDWARE STUB] Hard halt relay OPEN → all actuators disabled")
            print("  [HARDWARE STUB] *** In production: GPIO.output(HALT_PIN, LOW) ***")

        def stub_power_cut():
            print("  [HARDWARE STUB] Main power relay OPEN → electrical systems cut")
            print("  [HARDWARE STUB] *** In production: GPIO.output(POWER_PIN, LOW) ***")
            print("  [HARDWARE STUB] *** Or: modbus_client.write_coil(0, False)    ***")

        def stub_isolate():
            print("  [HARDWARE STUB] FULL ISOLATION → all relays OPEN")
            print("  [HARDWARE STUB] *** In production: trigger all safety relays  ***")
            print("  [HARDWARE STUB] *** Sound alarm. Alert emergency services.    ***")

        self.register_relay(ResponseLevel.ALERT,     stub_alert)
        self.register_relay(ResponseLevel.THROTTLE,  stub_throttle)
        self.register_relay(ResponseLevel.SOFT_HALT, stub_soft_halt)
        self.register_relay(ResponseLevel.HARD_HALT, stub_hard_halt)
        self.register_relay(ResponseLevel.POWER_CUT, stub_power_cut)
        self.register_relay(ResponseLevel.ISOLATE,   stub_isolate)
