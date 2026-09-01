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

    CLAIM ladder-descends: a commanded level fires that level and every LESSER
    one, never a greater one, so a mild hazard cannot trigger a severe response.
    CLAIM state-matches-relays: reported system state reflects only what a relay
    actually returned, never what was merely commanded.
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
        quality: str = "VALID",
    ):
        # VALID  = the sensor produced a real measurement.
        # CORRUPT = it could not be trusted and was tripped as a precaution.
        # Both are unsafe, but they call for different human responses, so they must
        # not be collapsed — and `source` stays clean provenance rather than being
        # overloaded to smuggle this.
        self.quality   = quality
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
            "quality":   self.quality,
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
        # Commanded stops whose physical action could NOT be confirmed. Non-empty means
        # a hazard fired and the machine may still be live — see status().
        self.unconfirmed_stops: list = []

        # Physical relay callbacks
        # In production: replace stubs with real GPIO/relay calls
        self._relay_callbacks: dict[ResponseLevel, list[Callable]] = {
            level: [] for level in ResponseLevel
        }

        # Register default stub handlers
        self._register_default_handlers()

    def register_relay(self, level: ResponseLevel, callback: Callable, *,
                       simulated: bool = False):
        """
        Register a real hardware callback for a response level.

        Example (production):
          import RPi.GPIO as GPIO
          def cut_main_power():
              GPIO.output(17, GPIO.LOW)   # Open relay — cuts power
          controller.register_relay(ResponseLevel.POWER_CUT, cut_main_power)
        """
        # A SIMULATED relay is recorded as commanded and NEVER as confirmed.
        # (red-team, Law Zero readiness pass, 2026-08-30.) The default handlers print
        # "[HARDWARE STUB] Main power relay OPEN" and returned normally, so a
        # controller with no wiring at all reported stop_confirmed=True, power_cut=True
        # and an EMPTY unconfirmed_stops list. Verified by execution on a fire event.
        # Every layer above then believes the machine is dead. A stub that CONFIRMS is
        # worse than no stub: the no-relay state was already honest, and this made the
        # dishonest state look better than it.
        self._relay_callbacks[level].append((callback, bool(simulated)))

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

        # (red-team) COMMANDED is not CONFIRMED. This loop used to swallow a relay
        # exception into a string and then set power_cut/isolated/actuators_active
        # regardless — so a relay that raised ("stuck closed, power did NOT cut"), or a
        # level with no relay wired at all, still produced system_state{power_cut:True}
        # and status() reporting the machine as stopped. That is `lambda: True` at the
        # physical layer: the software believing the machine is safe while it is live.
        # A stop is now only recorded as achieved when a relay actually returned.
        # (red-team) THE LADDER RAN THE WRONG WAY. This loop used to fire every level
        # AT OR ABOVE the commanded one, which inverted the whole point of a graduated
        # response: a THERMAL warning mapped to THROTTLE ("reduce speed, stay running")
        # commanded SOFT_HALT, HARD_HALT, POWER_CUT and ISOLATE as well — a routine
        # over-temperature physically disconnected the machine. ResponseLevel's own
        # docstring says graduation exists to PREVENT unnecessary shutdowns.
        #
        # Correct semantics: a commanded level implies every LESSER action (isolating
        # implies cutting power implies halting implies alerting), never a greater one.
        # Severity descends so the most consequential relay is commanded FIRST —
        # time-to-stop matters, and a fire should not wait on the alert relay.
        #
        # A level BELOW the commanded one with no relay wired is a deployment choice,
        # not a fault: a rig with no PWM throttle can still isolate. Only the COMMANDED
        # level must be physically achievable, so unwired lesser levels are reported
        # separately in `not_wired` instead of raising a false integrity breach. Under
        # the old rule a thermal warning on a rig without an isolation contactor
        # latched stop_integrity_ok=False and screamed "treat the machine as LIVE" —
        # alarm fatigue on the one signal that cannot afford it.
        confirmed_levels = set()
        failures = []
        not_wired = []
        commanded_levels = []
        for resp_level in sorted(ResponseLevel, key=lambda l: l.value, reverse=True):
            if resp_level.value <= level.value:
                callbacks = self._relay_callbacks.get(resp_level, [])
                commanded_levels.append(resp_level)
                if not callbacks:
                    if resp_level is level:
                        failures.append(
                            f"{resp_level.name}: NO RELAY REGISTERED — nothing physical "
                            f"was commanded at this level")
                    else:
                        not_wired.append(
                            f"{resp_level.name}: no relay wired (lesser level, "
                            f"not required for this stop)")
                    continue
                for entry in callbacks:
                    callback, simulated = (entry if isinstance(entry, tuple)
                                           else (entry, False))
                    try:
                        callback()
                        if simulated:
                            actions_taken.append(
                                f"{resp_level.name}: SIMULATED relay ran (no physical "
                                f"effect)")
                            if resp_level is level:
                                failures.append(
                                    f"{resp_level.name}: SIMULATED RELAY ONLY — a stub "
                                    f"printed a message; nothing physical was "
                                    f"commanded at this level")
                            continue
                        actions_taken.append(f"{resp_level.name}: callback executed")
                        confirmed_levels.add(resp_level)
                    except Exception as e:
                        actions_taken.append(
                            f"{resp_level.name}: callback FAILED — {e}")
                        failures.append(f"{resp_level.name}: relay raised — {e}")

        def _achieved(target: "ResponseLevel") -> bool:
            """True only if some relay at or above `target` actually returned."""
            return any(l.value >= target.value for l in confirmed_levels)

        # State reflects what was CONFIRMED, never merely what was commanded.
        if level.value >= ResponseLevel.POWER_CUT.value and _achieved(ResponseLevel.POWER_CUT):
            self.power_cut = True
        if level.value >= ResponseLevel.HARD_HALT.value and _achieved(ResponseLevel.HARD_HALT):
            self.actuators_active = False
        if level.value >= ResponseLevel.ISOLATE.value and _achieved(ResponseLevel.ISOLATE):
            self.isolated = True

        # A stop is confirmed only when the COMMANDED level itself physically happened.
        # `not failures` alone is not enough: with the ladder corrected, a commanded
        # level with no relay is the only absence that counts, and it is already a
        # failure — but stating the conjunct explicitly keeps the invariant readable
        # and survives future edits to the failure list.
        commanded_achieved = _achieved(level)
        stop_confirmed = commanded_achieved and not failures
        if not stop_confirmed:
            # A human must learn this without parsing strings out of a list.
            self.unconfirmed_stops.append({
                "hazard": event.hazard.value,
                "commanded": level.name,
                "failures": list(failures),
                "timestamp": event.timestamp,
            })
            self._narrate_unconfirmed(level, event, failures)

        return {
            "hazard":        event.hazard.value,
            "response_level": level.name,
            "actions_taken": actions_taken,
            # Explicit, machine-checkable: did the physical stop actually happen?
            "stop_confirmed": stop_confirmed,
            "failures":       list(failures),
            # Lesser levels with no relay: visible for review, deliberately NOT a failure.
            "not_wired":      list(not_wired),
            # (red-team, cold pass 2026-08-14.) A state flag can be satisfied by a
            # HIGHER confirmed level than the one it names: an ISOLATE relay that
            # returns sets power_cut=True even when no POWER_CUT relay exists. That
            # is sound ONLY under the load-bearing deployment assumption that a relay
            # registered at level L achieves level L — an ISOLATE relay wired to a
            # siren makes this a false report of a physical fact. The inference is
            # listed rather than left in a comment, so a reviewer can see which parts
            # of the state were OBSERVED and which were DEDUCED.
            "inferred_state": [
                name for name, lv in (("power_cut", ResponseLevel.POWER_CUT),
                                      ("isolated", ResponseLevel.ISOLATE))
                if _achieved(lv) and lv not in confirmed_levels],
            "commanded_levels": [l.name for l in commanded_levels],
            "system_state": {
                "isolated":         self.isolated,
                "power_cut":        self.power_cut,
                "actuators_active": self.actuators_active,
            },
            "restart_requires_human": level.value >= ResponseLevel.HARD_HALT.value,
        }

    def _narrate_unconfirmed(self, level, event, failures):
        """A commanded stop that could not be confirmed is the worst state the system
        can be in: the hazard is real and the machine may still be live. Say so."""
        msg = (f"UNCONFIRMED STOP — {event.hazard.value} commanded {level.name} but "
               f"the physical action was NOT confirmed: {'; '.join(failures)}. "
               f"Treat the machine as LIVE and intervene physically.")
        print(f"  🚨🚨 {msg}", flush=True)
        if self.narrator:
            try:
                self.narrator.narrate(msg)
            except Exception:
                pass
        if self.audit:
            try:
                self.audit.record("HARDWARE_STOP_UNCONFIRMED", msg, event.to_dict())
            except Exception:
                pass

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
            "unconfirmed_stops": list(self.unconfirmed_stops),
            "stop_integrity_ok": not self.unconfirmed_stops,
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

        self.register_relay(ResponseLevel.ALERT,     stub_alert, simulated=True)
        self.register_relay(ResponseLevel.THROTTLE,  stub_throttle, simulated=True)
        self.register_relay(ResponseLevel.SOFT_HALT, stub_soft_halt, simulated=True)
        self.register_relay(ResponseLevel.HARD_HALT, stub_hard_halt, simulated=True)
        self.register_relay(ResponseLevel.POWER_CUT, stub_power_cut, simulated=True)
        self.register_relay(ResponseLevel.ISOLATE,   stub_isolate, simulated=True)
