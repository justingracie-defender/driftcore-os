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

from enum import Enum
from datetime import datetime
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
    ):
        self.sensor_type = sensor_type
        self.interface   = interface
        self.source      = source
        self.value       = value
        self.threshold   = threshold
        self.unit        = unit
        self.location    = location
        self.timestamp   = datetime.utcnow().isoformat()
        # Fail-safe: a corrupted reading (NaN) or impossible value means
        # the sensor cannot be trusted — treat as TRIGGERED. When in
        # doubt, stop. (value != value is the standard NaN check.)
        self.corrupted   = (value != value)
        self.triggered   = self.corrupted or value >= threshold

    def to_hardware_event(self) -> HardwareEvent:
        return HardwareEvent(
            hazard    = SENSOR_HAZARD_MAP[self.sensor_type],
            source    = self.source,
            interface = self.interface.value,
            reading   = self.value,
            threshold = self.threshold,
            location  = self.location,
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
        self.readings    = []
        self.sensor_map  = {}  # source → SensorType

    def register_sensor(
        self,
        source: str,
        sensor_type: SensorType,
        interface: InterfaceType,
        threshold: float,
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
        self.sensor_map[source] = {
            "sensor_type": sensor_type,
            "interface":   interface,
            "threshold":   threshold,
            "unit":        unit,
            "location":    location,
        }

    def receive(self, source: str, value: float) -> dict | None:
        """
        Receive a sensor reading. If triggered, route to safety controller.
        This is the single entry point for all sensor data.
        """
        config = self.sensor_map.get(source)
        if not config:
            return {"warning": f"Unregistered sensor source: {source}. Register it first."}

        reading = SensorReading(
            sensor_type = config["sensor_type"],
            interface   = config["interface"],
            source      = source,
            value       = value,
            threshold   = config["threshold"],
            unit        = config["unit"],
            location    = config["location"],
        )
        self.readings.append(reading)

        if reading.triggered:
            event = reading.to_hardware_event()
            return self.controller.receive_event(event)

        return {"status": "NORMAL", "source": source, "value": value}

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
