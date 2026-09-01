"""
sensor_interfaces.py — Physical Sensor Port Definitions
DriftCore OS v3.1

═══════════════════════════════════════════════════════════════
PLAIN LANGUAGE — FOR EVERYONE
═══════════════════════════════════════════════════════════════

This file defines how DriftCore listens to the physical world.
Sensors are the system's eyes and ears. Without them, the AI
is blind to physical danger.

Each interface type connects a different kind of sensor:

GPIO    — The simplest connection. A single wire goes HIGH
          when triggered. Smoke detector, door switch, float
          valve. Plug it into a Raspberry Pi pin and done.

MQTT    — A network protocol for IoT devices. Sensors publish
          readings to a topic (like a radio channel). DriftCore
          subscribes and listens. Works over WiFi. Scales to
          hundreds of sensors in a building.

MODBUS  — Industrial standard. Used in factories, hospitals,
          elevators. Very reliable. Works over long cable runs.
          Most industrial sensors speak Modbus.

CAN BUS — Used in cars and heavy machinery. Very fast. Designed
          to survive in harsh environments with electrical noise.
          What your car uses to talk between its computers.

ROS2    — Robot middleware. Handles multiple sensor streams
          simultaneously. Already on DriftCore roadmap.
          The standard for modern robotics.

SERIAL  — Old but reliable. RS-232 / RS-485. Direct cable
          connection to sensors and PLCs. Still common in
          industrial settings.

═══════════════════════════════════════════════════════════════
SENSOR TYPES AND WHAT THEY DETECT
═══════════════════════════════════════════════════════════════

SMOKE           → Fire (early warning)
HEAT            → Fire (confirmation) / Thermal overload
WATER_CONTACT   → Flood, leak, spill near electrical
WATER_LEVEL     → Tank overflow, basement flooding
VOLTAGE         → Electrical fault, surge, brownout
CURRENT         → Short circuit, overcurrent
TEMPERATURE     → Thermal management
ENCODER         → Motor position — detect runaway or stall
LIMIT_SWITCH    → Physical boundary — robot hit a wall
FORCE_TORQUE    → Too much force — collision detection
VIBRATION       → Mechanical failure, imbalance
POWER_SUPPLY    → UPS, mains power status
EMERGENCY_STOP  → Human pressed the big red button

═══════════════════════════════════════════════════════════════
"""

import threading
from collections import OrderedDict, deque
from enum import Enum
from datetime import datetime, timezone

MAX_RECORDS = 5000        # ring-buffer bound: safety state must not be a memory DoS
MAX_WARN_SOURCES = 1000   # bound on rate-limit bookkeeping (A9)
from driftcore.hardware.hardware_safety import HazardType, HardwareEvent


class SensorType(Enum):
    SMOKE          = "SMOKE"
    HEAT           = "HEAT"
    WATER_CONTACT  = "WATER_CONTACT"
    WATER_LEVEL    = "WATER_LEVEL"
    VOLTAGE        = "VOLTAGE"
    CURRENT        = "CURRENT"
    TEMPERATURE    = "TEMPERATURE"
    ENCODER        = "ENCODER"
    LIMIT_SWITCH   = "LIMIT_SWITCH"
    FORCE_TORQUE   = "FORCE_TORQUE"
    VIBRATION      = "VIBRATION"
    POWER_SUPPLY   = "POWER_SUPPLY"
    EMERGENCY_STOP = "EMERGENCY_STOP"


class InterfaceType(Enum):
    GPIO   = "GPIO"
    MQTT   = "MQTT"
    MODBUS = "MODBUS"
    CANBUS = "CANBUS"
    ROS2   = "ROS2"
    SERIAL = "SERIAL"
    INTERNAL = "INTERNAL"   # Software monitor (voltage watchdog, etc)


# Map sensor types to hazard types
SENSOR_HAZARD_MAP = {
    SensorType.SMOKE:          HazardType.FIRE,
    SensorType.HEAT:           HazardType.FIRE,
    SensorType.WATER_CONTACT:  HazardType.WATER,
    SensorType.WATER_LEVEL:    HazardType.WATER,
    SensorType.VOLTAGE:        HazardType.ELECTRICAL,
    SensorType.CURRENT:        HazardType.ELECTRICAL,
    SensorType.TEMPERATURE:    HazardType.THERMAL,
    SensorType.ENCODER:        HazardType.MECHANICAL,
    SensorType.LIMIT_SWITCH:   HazardType.MECHANICAL,
    SensorType.FORCE_TORQUE:   HazardType.MECHANICAL,
    SensorType.VIBRATION:      HazardType.MECHANICAL,
    SensorType.POWER_SUPPLY:   HazardType.POWER,
    SensorType.EMERGENCY_STOP: HazardType.MECHANICAL,  # E-stop = mechanical halt
}

# Plain-language sensor descriptions (for Fable + documentation)
SENSOR_DESCRIPTIONS = {
    SensorType.SMOKE: (
        "Smoke Detector — detects particles from combustion. "
        "First line of fire detection. Triggers before visible flames."
    ),
    SensorType.HEAT: (
        "Heat Sensor — detects rapid temperature rise or absolute high temperature. "
        "Confirms fire when smoke detector has already triggered."
    ),
    SensorType.WATER_CONTACT: (
        "Water Contact Sensor — detects liquid touching the sensor pad. "
        "Placed near electrical equipment, under servers, on floor near pipes."
    ),
    SensorType.WATER_LEVEL: (
        "Water Level Sensor — detects water rising above a set level. "
        "Used in sumps, tanks, basements. Float valve or capacitive."
    ),
    SensorType.VOLTAGE: (
        "Voltage Monitor — measures supply voltage continuously. "
        "Detects surges, sags, brownouts. Protects hardware from damage."
    ),
    SensorType.CURRENT: (
        "Current Sensor — measures electrical current draw. "
        "Spike = short circuit. Drop = broken connection. Both are danger signals."
    ),
    SensorType.TEMPERATURE: (
        "Temperature Sensor — monitors operating temperature. "
        "Mounted on motors, CPUs, power supplies, batteries."
    ),
    SensorType.ENCODER: (
        "Encoder — measures motor rotation position and speed. "
        "Detects runaway (too fast), stall (too slow), or unexpected movement."
    ),
    SensorType.LIMIT_SWITCH: (
        "Limit Switch — a physical button triggered when a part reaches its boundary. "
        "Robot arm hit the wall. Conveyor reached end of track."
    ),
    SensorType.FORCE_TORQUE: (
        "Force / Torque Sensor — measures how hard the system is pushing or twisting. "
        "Too much force = collision with unexpected object (maybe a person)."
    ),
    SensorType.VIBRATION: (
        "Vibration Sensor — detects abnormal shaking or oscillation. "
        "Indicates mechanical imbalance, loose parts, or bearing failure."
    ),
    SensorType.POWER_SUPPLY: (
        "Power Supply Monitor — watches the main power input and UPS. "
        "Mains loss, battery low, or inverter fault triggers graceful shutdown."
    ),
    SensorType.EMERGENCY_STOP: (
        "Emergency Stop — the big red button. Human-triggered. "
        "Always wired directly to hardware. Software confirms but does not control."
    ),
}


def _is_corrupt(value) -> bool:
    """True when a reading cannot be trusted: not a number, NaN, or infinite.
    Never raises — an unreadable sensor must trip, not crash the polling loop."""
    if isinstance(value, bool):
        return False                      # GPIO high/low is a legitimate reading
    if not isinstance(value, (int, float)):
        return True                       # None, str, object: unreadable
    f = float(value)
    if f != f:                            # NaN
        return True
    return f in (float("inf"), float("-inf"))


class SensorReading:
    """A single reading from a physical sensor."""

    def __init__(
        self,
        sensor_type: SensorType,
        interface: InterfaceType,
        source: str,          # Pin number, MQTT topic, Modbus register, etc.
        value: float,
        threshold: float,
        unit: str = "",
        location: str = "unknown",
        normally_closed: bool = False,
    ):
        self.sensor_type = sensor_type
        self.interface   = interface
        self.source      = source
        self.value       = value
        self.threshold   = threshold
        self.unit        = unit
        self.location    = location
        # (red-team A14) aware UTC, not naive utcnow(): mixing the two produces
        # subtle age-arithmetic bugs against `last_seen`, which is aware.
        self.timestamp   = datetime.now(timezone.utc).isoformat()
        self.normally_closed = normally_closed
        # Fail-safe: a reading the sensor cannot be trusted to have produced means
        # TRIGGERED. When in doubt, stop.
        #
        # (red-team) The comment above this line always claimed "NaN or IMPOSSIBLE
        # value", but only NaN was handled. A disconnected sensor returning None, or a
        # driver handing back the string "HIGH", RAISED TypeError from inside receive()
        # — which in a polling loop kills the loop, so every LATER sensor goes unread
        # too. And -inf sailed through as a NORMAL reading. Now anything that is not a
        # finite number is corrupt, and corruption never reaches a comparison.
        self.corrupted   = _is_corrupt(value)
        if self.corrupted:
            self.triggered = True
        elif normally_closed:
            # (red-team) NORMALLY-CLOSED wiring: the line is held HIGH while safe, so a
            # cut wire, a loose connector or a lost supply reads LOW and MUST trip. Real
            # emergency stops are wired this way precisely so that losing the wire stops
            # the machine. With only `value >= threshold`, an E-stop line falling to 0.0
            # read as NORMAL — the failure mode the wiring exists to prevent.
            # `threshold` is the MINIMUM HEALTHY level for a held-closed line, so the
            # trip is a fall BELOW it. Using <= would trip a line sitting correctly at
            # its nominal value — a permanently-asserted e-stop, which in practice gets
            # disabled by whoever is trying to work, and an e-stop that has been
            # disabled protects no one.
            self.triggered = float(value) < threshold
        else:
            self.triggered = float(value) >= threshold

    @property
    def quality(self) -> str:
        """VALID = the sensor produced a real measurement. CORRUPT = it could not be
        trusted and was tripped as a precaution. (red-team) Both must cause safe
        behaviour, but they are operationally different: 'fire detected' and 'fire
        sensor failed' call for different human responses, and collapsing them makes
        diagnosis and recovery guess."""
        return "CORRUPT" if self.corrupted else "VALID"

    def to_hardware_event(self) -> HardwareEvent:
        return HardwareEvent(
            hazard    = SENSOR_HAZARD_MAP[self.sensor_type],
            source    = self.source,
            interface = self.interface.value,
            reading   = self.value,
            threshold = self.threshold,
            location  = self.location,
            quality   = self.quality,
        )

    def describe(self) -> str:
        status = "🚨 TRIGGERED" if self.triggered else "✅ Normal"
        return (
            f"[{self.sensor_type.value}] {status}\n"
            f"  Interface : {self.interface.value}\n"
            f"  Source    : {self.source}\n"
            f"  Reading   : {self.value}{self.unit} (threshold: {self.threshold}{self.unit})\n"
            f"  Location  : {self.location}\n"
            f"  What it does: {SENSOR_DESCRIPTIONS[self.sensor_type]}"
        )


class SensorHub:
    """
    Central hub that receives readings from all interfaces.
    Routes triggered readings to the HardwareSafetyController.

    In production:
      GPIO     → RPi.GPIO event_detect callbacks register here
      MQTT     → paho-mqtt on_message callbacks register here
      MODBUS   → pymodbus polling loop sends readings here
      CAN bus  → python-can message handler sends here
      ROS2     → rclpy subscription callbacks register here
      SERIAL   → pyserial read loop sends readings here
    """

    def __init__(self, safety_controller):
        self.controller  = safety_controller
        self.readings    = deque(maxlen=MAX_RECORDS)
        self.sensor_map  = {}  # source → SensorType
        # Readings that arrived for a source nobody registered. Non-empty means the
        # sensor map does not match the rig, and hazards may be reaching no controller.
        self.unrouted    = deque(maxlen=MAX_RECORDS)
        # (red-team) `readings` and `unrouted` were unbounded lists, and the UNROUTED
        # warning printed on every occurrence — so an unmatched source could exhaust
        # memory AND flood the log until the real alarms were unreadable. Both are now
        # bounded ring buffers, and the warning is rate-limited per source.
        # (red-team A9) The deques were bounded but THIS dict was not. A flood of
        # UNIQUE unregistered sources — typos, a misconfigured MQTT topic wildcard, a
        # buggy or compromised driver — grew it without limit: 20,000 entries while the
        # deques held at 5,000. Memory exhaustion kills the whole safety process, so
        # the rate-limit state is an LRU with an approximate, bounded memory.
        self._unrouted_warned = OrderedDict()
        # (red-team A11) Production wiring is callback- and thread-based (RPi.GPIO
        # callbacks, paho-mqtt on_message, pymodbus pollers, python-can, rclpy). The
        # compound operations here are check-then-act — read the config, then build a
        # reading; test the lock flag, then write the map — and those are racy even
        # where CPython makes an individual dict write atomic.
        self._lock = threading.RLock()
        # Trips the controller could not process. Non-empty means a real hazard was
        # detected and the safety controller did NOT act on it.
        self.undelivered = deque(maxlen=MAX_RECORDS)
        self._config_locked = False
        # last time each source was heard from: silence is not safety (a cut cable
        # simply stops producing readings, and the last NORMAL would otherwise stand
        # forever). `stale_sensors()` makes the difference visible.
        self.last_seen   = {}

    def register_sensor(
        self,
        source: str,
        sensor_type: SensorType,
        interface: InterfaceType,
        threshold: float,
        normally_closed=None,   # MUST be stated for EMERGENCY_STOP
        replace: bool = False,
        unit: str = "",
        location: str = "unknown",
    ):
        """
        Register a sensor so the hub knows what to do when it fires.

        Production examples:
          hub.register_sensor("gpio:17",             SensorType.SMOKE,         InterfaceType.GPIO,   threshold=1.0, location="kitchen")
          hub.register_sensor("mqtt/sensors/water/basement", SensorType.WATER_CONTACT, InterfaceType.MQTT, threshold=1.0, location="basement")
          hub.register_sensor("modbus:1:40001",      SensorType.VOLTAGE,       InterfaceType.MODBUS, threshold=260.0, unit="V", location="panel")
          hub.register_sensor("can:0x180",           SensorType.ENCODER,       InterfaceType.CANBUS, threshold=3000.0, unit="RPM", location="motor_1")
          hub.register_sensor("ros2:/joint_states",  SensorType.FORCE_TORQUE,  InterfaceType.ROS2,   threshold=50.0, unit="Nm", location="arm_joint_3")
        """
        # (red-team A6) Re-registering a source used to overwrite it SILENTLY. Raising
        # the threshold on a live smoke detector then reads real smoke as NORMAL, with
        # nothing in the output to show the sensor had been desensitised. Config drift
        # must be loud: an actual change requires replace=True.
        # (red-team A8) The READING was hardened but the DECISION BOUNDARY was not —
        # the exact mirror of A2. A NaN threshold makes every comparison False in BOTH
        # directions (`v >= nan` and `v < nan`), so the sensor NEVER trips: a raging
        # fire read NORMAL. +inf never trips, -inf always trips, and a string threshold
        # raised TypeError inside receive(). A corrupt boundary silently disables a
        # safety sensor, so it is refused at registration.
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
            raise ValueError(
                f"threshold for {source!r} must be a real number, got "
                f"{type(threshold).__name__}. A non-numeric boundary cannot decide "
                f"anything and would raise inside the receive path.")
        threshold = float(threshold)
        if threshold != threshold or threshold in (float("inf"), float("-inf")):
            raise ValueError(
                f"threshold for {source!r} must be FINITE, got {threshold}. NaN never "
                f"compares true in either direction, so the sensor would never trip; "
                f"infinities pin it permanently on or off. Either way the sensor is "
                f"silently disabled.")
        if not isinstance(sensor_type, SensorType):
            raise ValueError(f"sensor_type must be a SensorType, got {sensor_type!r}")
        if not isinstance(interface, InterfaceType):
            raise ValueError(f"interface must be an InterfaceType, got {interface!r}")
        # (red-team) bool("false") is True, so a config carrying the STRING "false"
        # silently inverted an e-stop's wiring. Only a real bool is accepted.
        if normally_closed is not None and not isinstance(normally_closed, bool):
            raise ValueError(
                f"normally_closed for {source!r} must be True or False, got "
                f"{normally_closed!r}. Truthy coercion would silently invert the "
                f"wiring (bool('false') is True).")
        # (red-team A11) check-then-act: the config-lock test, the prior-config
        # comparison and the map write must not interleave with another thread.
        with self._lock:
            if self._config_locked and not replace:
                raise PermissionError(
                    f"sensor configuration is LOCKED; refusing to register {source!r}. "
                    f"Configuration is a start-up phase: unlock deliberately to change it.")
            if self._config_locked and replace:
                raise PermissionError(
                    f"sensor configuration is LOCKED; refusing to REPLACE {source!r}. "
                    f"replace=True at runtime is how a live sensor gets desensitised.")
            if sensor_type is SensorType.EMERGENCY_STOP and normally_closed is None:
                raise ValueError(
                    "EMERGENCY_STOP requires an explicit normally_closed=True/False. Real "
                    "e-stops are wired normally-closed so a cut wire trips them; with "
                    "normally-open logic a severed line reads as NORMAL. State the wiring.")
            prior = self.sensor_map.get(source)
            cfg = {
                "sensor_type": sensor_type,
                "interface":   interface,
                "threshold":   threshold,
                "unit":        unit,
                "location":    location,
                "normally_closed": bool(normally_closed),
            }
            if prior is not None and prior != cfg and not replace:
                raise ValueError(
                    f"sensor {source!r} is already registered with different settings "
                    f"(threshold {prior['threshold']} -> {threshold}). Silently replacing it "
                    f"can desensitise a live sensor; pass replace=True to do it deliberately.")

            # (red-team A7) EMERGENCY_STOP wiring must be DECLARED, never guessed. Both
            # normally-open and normally-closed are legitimate installations, and the module
            # cannot know which is on the bench — so it refuses to assume for the one sensor
            # where guessing wrong means a cut wire reads as safe.
            self.sensor_map[source] = cfg

    def receive(self, source: str, value: float) -> dict | None:
        """
        Receive a sensor reading. If triggered, route to safety controller.
        This is the single entry point for all sensor data.
        """
        with self._lock:
            return self._receive_locked(source, value)

    def _receive_locked(self, source, value):
        config = self.sensor_map.get(source)
        if not config:
            # (red-team A1) This used to return {"warning": ...} and stop. A real smoke
            # reading arriving on an unregistered key — a typo, a sensor added to the
            # rig but not to the map, a source string that drifted — reached NO ONE:
            # zero events at the controller, and the returned dict is TRUTHY, so a
            # caller writing `if result:` sees success. An unroutable hazard is a
            # CONFIG FAULT, so it is recorded, announced, and reported under the same
            # "status" key every other path uses, instead of a soft key nobody reads.
            self.unrouted.append({"source": source, "value": value,
                                  "timestamp": datetime.now(timezone.utc).isoformat()})
            if len(self._unrouted_warned) >= MAX_WARN_SOURCES:
                self._unrouted_warned.popitem(last=False)     # evict oldest
            seen = self._unrouted_warned.get(source, 0) + 1
            self._unrouted_warned[source] = seen
            self._unrouted_warned.move_to_end(source)
            if seen <= 3 or seen % 100 == 0:
                print(f"  🚨 UNROUTED SENSOR READING from {source!r} "
                      f"(value={value!r}, occurrence {seen}) — not registered, so it "
                      f"reached no safety controller. Treat as a configuration fault.",
                      flush=True)
            return {"status": "UNROUTED", "source": source, "value": value,
                    "reason": "source is not registered; the reading reached no "
                              "safety controller"}

        reading = SensorReading(
            sensor_type = config["sensor_type"],
            interface   = config["interface"],
            source      = source,
            value       = value,
            threshold   = config["threshold"],
            unit        = config["unit"],
            location    = config["location"],
            normally_closed = config.get("normally_closed", False),
        )
        self.readings.append(reading)
        self.last_seen[source] = datetime.now(timezone.utc)

        if reading.triggered:
            event = reading.to_hardware_event()
            # (red-team A10) This used to `return controller.receive_event(event)`
            # bare, so ANY exception from the controller — a bug, a full log, a
            # downstream failure — propagated out of receive(). In a GPIO/MQTT/CAN
            # callback that kills the intake thread, and every LATER sensor goes
            # unread: one tripped sensor takes the whole sensor subsystem offline.
            # That is the same failure A2 exists to prevent, one layer up. The trip is
            # still reported, the failure is loud, and the loop stays alive.
            try:
                return self.controller.receive_event(event)
            except Exception as e:
                self.undelivered.append({
                    "source": source, "value": value, "error": repr(e)[:200],
                    "timestamp": datetime.now(timezone.utc).isoformat()})
                print(f"  🚨🚨 SENSOR TRIPPED BUT THE CONTROLLER FAILED for {source!r}: "
                      f"{type(e).__name__}: {e}. The hazard is REAL and the safety "
                      f"controller did not process it — intervene physically.",
                      flush=True)
                return {"status": "TRIP_UNDELIVERED", "source": source, "value": value,
                        "triggered": True, "quality": reading.quality,
                        "error": f"{type(e).__name__}: {e}"}

        return {"status": "NORMAL", "source": source, "value": value}

    def lock_configuration(self) -> None:
        """End the configuration phase. After this, registering or replacing a sensor
        is refused. (red-team) `replace=True` turned a SILENT unsafe mutation into an
        EXPLICIT one, which is better but is not a boundary: any caller reaching this
        method could still desensitise a live sensor. Locking makes configuration a
        start-up privilege rather than a runtime capability."""
        self._config_locked = True

    UNLOCK_TOKEN = "I-AM-RECONFIGURING-A-SAFETY-SENSOR"

    def unlock_configuration(self, token: str = "") -> None:
        """Deliberately re-open configuration.

        (red-team A13) A bare `unlock_configuration()` is one unrestricted call, so any
        path that can reach the hub — a debug endpoint, a hot-reload, a telemetry hook
        someone adds later — can re-open configuration and then raise a threshold. The
        token does not stop a determined caller; it stops an ACCIDENTAL one, and it
        makes every real unlock greppable in the source.
        """
        if token != self.UNLOCK_TOKEN:
            raise PermissionError(
                "unlock_configuration() requires the explicit token "
                f"{self.UNLOCK_TOKEN!r}. Re-opening a locked safety configuration must "
                "be a deliberate, visible act, not a stray method call.")
        with self._lock:
            self._config_locked = False

    def stale_sensors(self, max_age_seconds: float) -> list[dict]:
        """Sources that have not reported within `max_age_seconds`.

        (red-team) SILENCE IS NOT SAFETY. A cut cable, a dead adapter or a wedged
        network link simply stops producing readings; the hub's last value stays NORMAL
        forever, so a dead sensor is indistinguishable from a healthy quiet one. This
        does not alarm by itself — some sensors are legitimately event-driven — but it
        makes the difference VISIBLE so a deployment can decide. Registered sources
        never heard from at all are reported too.
        """
        now = datetime.now(timezone.utc)
        out = []
        for src in self.sensor_map:
            seen = self.last_seen.get(src)
            age = None if seen is None else (now - seen).total_seconds()
            if age is None or age > max_age_seconds:
                out.append({"source": src, "age_seconds": age,
                            "location": self.sensor_map[src]["location"],
                            "state": "NEVER_REPORTED" if age is None else "STALE"})
        return out

    def raise_stale_as_hazard(self, max_age_seconds: float,
                             hazard_sensor_type=None) -> list[dict]:
        """Turn silence into an actual event for sensors expected to report continuously.

        (red-team A12) `stale_sensors()` only made silence VISIBLE; nothing ever told
        the controller. A cut cable, dead sensor power or a wedged broker left the last
        NORMAL reading standing forever, and the higher-level code that was supposed to
        poll is exactly the code that gets forgotten or feature-flagged off. This
        synthesises a CORRUPT-quality trip per stale source so a dead sensor reaches the
        safety controller the same way a hazardous one does.

        Opt-in and explicit, because not every sensor is continuous — an event-driven
        contact switch is legitimately silent for months. Call it from a watchdog for
        the sensors a deployment declares continuous.
        """
        raised = []
        for entry in self.stale_sensors(max_age_seconds):
            src = entry["source"]
            cfg = self.sensor_map[src]
            if hazard_sensor_type is not None and cfg["sensor_type"] is not hazard_sensor_type:
                continue
            reading = SensorReading(
                sensor_type = cfg["sensor_type"],
                interface   = cfg["interface"],
                source      = src,
                value       = float("nan"),      # unreadable: no measurement exists
                threshold   = cfg["threshold"],
                unit        = cfg["unit"],
                location    = cfg["location"],
                normally_closed = cfg.get("normally_closed", False),
            )
            try:
                result = self.controller.receive_event(reading.to_hardware_event())
            except Exception as e:
                result = {"status": "TRIP_UNDELIVERED", "error": repr(e)[:200]}
            raised.append({"source": src, "state": entry["state"], "result": result})
        return raised

    def simulate_reading(self, source: str, value: float) -> dict | None:
        """
        Simulate a sensor reading for testing.
        Identical to receive() — used in demos and unit tests.
        """
        return self.receive(source, value)

    def all_sensor_status(self) -> list[dict]:
        """Return status of all registered sensors."""
        return [
            {
                "source":      src,
                "type":        cfg["sensor_type"].value,
                "interface":   cfg["interface"].value,
                "threshold":   cfg["threshold"],
                "location":    cfg["location"],
                "description": SENSOR_DESCRIPTIONS[cfg["sensor_type"]],
            }
            for src, cfg in self.sensor_map.items()
        ]
