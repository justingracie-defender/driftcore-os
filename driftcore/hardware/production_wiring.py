"""
production_wiring.py — Real Hardware Connection Guide
DriftCore OS v3.1

═══════════════════════════════════════════════════════════════
THIS FILE IS FOR ENGINEERS AND NON-ENGINEERS BOTH
═══════════════════════════════════════════════════════════════

This file shows exactly what code to write to connect DriftCore
to real physical hardware. Each section covers one interface type.

For each interface:
  1. What hardware you need
  2. What Python library to install
  3. The exact code to wire it up
  4. What to test before going live

IMPORTANT: Never go live without testing the shutdown path first.
           Trigger the emergency stop. Watch it cut power.
           If it doesn't work in testing, it won't work in a fire.

═══════════════════════════════════════════════════════════════
"""


# ══════════════════════════════════════════════════════════════
# 1. GPIO — Raspberry Pi / Arduino
# ══════════════════════════════════════════════════════════════
GPIO_GUIDE = """
GPIO WIRING GUIDE
─────────────────
Hardware needed:
  - Raspberry Pi (any model) OR Arduino with PyFirmata
  - Safety relay module (SainSmart, Songle, or equivalent)
  - Smoke detector with relay output (not battery-only)
  - Water contact sensor (simple two-wire type)
  - Jumper wires

Install:
  pip install RPi.GPIO    # Raspberry Pi
  pip install pyserial    # Arduino via serial

Wiring:
  Sensor OUT → RPi GPIO Pin (e.g. Pin 17)
  Relay IN   → RPi GPIO Pin (e.g. Pin 27)
  Both share common GND

Production code (replace stubs in hardware_safety.py):

    import RPi.GPIO as GPIO

    SMOKE_PIN  = 17   # Input from smoke detector
    WATER_PIN  = 18   # Input from water sensor  
    HALT_PIN   = 27   # Output to halt relay
    POWER_PIN  = 22   # Output to main power relay

    GPIO.setmode(GPIO.BCM)
    GPIO.setup(SMOKE_PIN,  GPIO.IN,  pull_up_down=GPIO.PUD_DOWN)
    GPIO.setup(WATER_PIN,  GPIO.IN,  pull_up_down=GPIO.PUD_DOWN)
    GPIO.setup(HALT_PIN,   GPIO.OUT, initial=GPIO.HIGH)  # HIGH = relay closed = power ON
    GPIO.setup(POWER_PIN,  GPIO.OUT, initial=GPIO.HIGH)

    # Register with DriftCore sensor hub
    hub.register_sensor("gpio:17", SensorType.SMOKE,        InterfaceType.GPIO, threshold=1.0, location="server_room")
    hub.register_sensor("gpio:18", SensorType.WATER_CONTACT, InterfaceType.GPIO, threshold=1.0, location="floor_sensor")

    # Wire GPIO interrupts to DriftCore
    GPIO.add_event_detect(SMOKE_PIN, GPIO.RISING, callback=lambda ch: hub.receive("gpio:17", 1.0))
    GPIO.add_event_detect(WATER_PIN, GPIO.RISING, callback=lambda ch: hub.receive("gpio:18", 1.0))

    # Wire DriftCore shutdown to real relays.
    #
    # READ THIS BEFORE COPYING: the controller treats a relay callback that RETURNS
    # as a CONFIRMED stop, and sets power_cut/isolated on that basis. GPIO.output()
    # returns successfully even when the relay is welded shut, the coil is open, or
    # the wire fell off. A callback that only writes the pin therefore reports a stop
    # that may not have happened — the exact failure the confirmation exists to catch.
    #
    # So: drive the pin, then READ BACK a feedback contact and RAISE if it disagrees.
    # Safety relays (and contactors) provide a mirrored auxiliary contact for exactly
    # this. A callback that raises is recorded as an UNCONFIRMED STOP and the operator
    # is told to treat the machine as live.
    POWER_FB_PIN = 23   # aux contact: reads LOW when the main contact has OPENED
    HALT_FB_PIN  = 24
    GPIO.setup(POWER_FB_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(HALT_FB_PIN,  GPIO.IN, pull_up_down=GPIO.PUD_UP)

    import time as _time

    def _drive_and_confirm(drive_pin, feedback_pin, what):
        GPIO.output(drive_pin, GPIO.LOW)        # open the relay
        _time.sleep(0.05)                       # contact settling time
        if GPIO.input(feedback_pin) != GPIO.LOW:
            # The relay did not physically move. Raising is REQUIRED: it is what
            # turns "we commanded a stop" into "the stop was not confirmed".
            raise RuntimeError(
                f"{what}: relay did not open — feedback contact still reads closed. "
                f"Treat the machine as LIVE.")

    def real_power_cut():
        _drive_and_confirm(POWER_PIN, POWER_FB_PIN, "POWER_CUT")

    def real_hard_halt():
        _drive_and_confirm(HALT_PIN, HALT_FB_PIN, "HARD_HALT")

    controller.register_relay(ResponseLevel.POWER_CUT, real_power_cut)
    controller.register_relay(ResponseLevel.HARD_HALT, real_hard_halt)

    # EMERGENCY STOP — wire it NORMALLY CLOSED.
    #
    # A normally-closed e-stop holds its line HIGH while everything is healthy, so a
    # pressed button, a cut wire, a pulled connector or a dead supply all read LOW and
    # trip. Wired normally-open instead, a severed e-stop line reads exactly like an
    # unpressed button: NORMAL. The wiring must be declared, because the software
    # cannot see how the bench is built and refuses to guess for this one sensor.
    ESTOP_PIN = 19
    GPIO.setup(ESTOP_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    hub.register_sensor("gpio:19", SensorType.EMERGENCY_STOP, InterfaceType.GPIO,
                        threshold=1.0, location="front_panel",
                        normally_closed=True)      # REQUIRED for EMERGENCY_STOP
    GPIO.add_event_detect(ESTOP_PIN, GPIO.BOTH,
                          callback=lambda ch: hub.receive("gpio:19",
                                                          float(GPIO.input(ESTOP_PIN))))

    # Lock the configuration once every sensor is registered, so nothing at runtime
    # can raise a threshold or replace a live sensor.
    hub.lock_configuration()

Test procedure:
  1. Run: python main.py
  2. Trigger smoke sensor manually (or short GPIO pin 17 to 3.3V)
  3. Verify: relay clicks, power cuts, Fable narrates the event
  4. Verify the CONFIRMATION path: disconnect the relay's feedback contact and
     trigger again. The run must report stop_confirmed=False and print
     "UNCONFIRMED STOP". If it still reports a clean stop, your callback is not
     reading back and the system will believe a failed stop succeeded.
  5. Verify the E-STOP FAIL-SAFE: with the machine running, CUT or unplug the
     e-stop line (do not just press the button). It must trip. A normally-open
     e-stop will not, which is why this guide wires it normally-closed.
  4. Check audit log shows the event with timestamp
  5. Verify system cannot restart without human release command
"""


# ══════════════════════════════════════════════════════════════
# 2. MQTT — IoT Sensor Network
# ══════════════════════════════════════════════════════════════
MQTT_GUIDE = """
MQTT WIRING GUIDE
─────────────────
Hardware needed:
  - MQTT broker (Mosquitto — free, runs on Pi or cloud)
  - Any MQTT-capable sensor (Zigbee, Z-Wave, WiFi, ESP32)
  - Examples: Aqara smoke detector, Shelly water sensor,
              Tasmota flashed sensors, any Home Assistant device

Install:
  pip install paho-mqtt
  sudo apt install mosquitto mosquitto-clients   # broker

Production code:

    import paho.mqtt.client as mqtt

    BROKER = "localhost"   # or your cloud broker IP
    PORT   = 1883

    def on_message(client, userdata, msg):
        topic = msg.topic
        value = float(msg.payload.decode())
        hub.receive(topic, value)   # Route to DriftCore

    client = mqtt.Client()
    client.on_message = on_message
    client.connect(BROKER, PORT)

    # Subscribe to sensor topics
    client.subscribe("sensors/smoke/kitchen")
    client.subscribe("sensors/water/basement")
    client.subscribe("sensors/temp/server_room")
    client.subscribe("sensors/voltage/main_panel")

    # Register with DriftCore
    hub.register_sensor("sensors/smoke/kitchen",      SensorType.SMOKE,        InterfaceType.MQTT, threshold=1.0,   location="kitchen")
    hub.register_sensor("sensors/water/basement",     SensorType.WATER_CONTACT, InterfaceType.MQTT, threshold=1.0,  location="basement")
    hub.register_sensor("sensors/temp/server_room",   SensorType.TEMPERATURE,  InterfaceType.MQTT, threshold=45.0,  unit="C", location="server_room")
    hub.register_sensor("sensors/voltage/main_panel", SensorType.VOLTAGE,      InterfaceType.MQTT, threshold=260.0, unit="V", location="main_panel")

    client.loop_start()   # Run in background thread

Test procedure:
  1. Start Mosquitto broker
  2. Run DriftCore
  3. Publish test message: mosquitto_pub -t sensors/smoke/kitchen -m "1.0"
  4. Verify DriftCore fires FIRE response and narrates it
"""


# ══════════════════════════════════════════════════════════════
# 3. MODBUS — Industrial Equipment
# ══════════════════════════════════════════════════════════════
MODBUS_GUIDE = """
MODBUS WIRING GUIDE
───────────────────
Hardware needed:
  - Modbus RTU (RS-485) or Modbus TCP device
  - USB-to-RS485 adapter (for RTU)
  - Industrial sensors: Finder relay, Carlo Gavazzi monitor, etc.

Install:
  pip install pymodbus

Production code (Modbus TCP example):

    from pymodbus.client import ModbusTcpClient

    client = ModbusTcpClient("192.168.1.100", port=502)
    client.connect()

    hub.register_sensor("modbus:1:40001", SensorType.VOLTAGE, InterfaceType.MODBUS,
                        threshold=260.0, unit="V", location="main_panel")
    hub.register_sensor("modbus:1:40002", SensorType.CURRENT, InterfaceType.MODBUS,
                        threshold=20.0,  unit="A", location="motor_circuit")

    # Polling loop (run in thread)
    import threading, time

    def poll_modbus():
        while True:
            result = client.read_holding_registers(40001, count=2, slave=1)
            if not result.isError():
                hub.receive("modbus:1:40001", result.registers[0] * 0.1)  # scale factor
                hub.receive("modbus:1:40002", result.registers[1] * 0.01)
            time.sleep(0.5)   # Poll every 500ms

    threading.Thread(target=poll_modbus, daemon=True).start()
"""


# ══════════════════════════════════════════════════════════════
# 4. CAN BUS — Automotive / Heavy Machinery
# ══════════════════════════════════════════════════════════════
CANBUS_GUIDE = """
CAN BUS WIRING GUIDE
────────────────────
Hardware needed:
  - CAN interface (Peak PCAN-USB, Kvaser, or SocketCAN on Linux)
  - CAN-capable sensors/controllers (motor drives, PLCs)

Install:
  pip install python-can

Production code:

    import can

    bus = can.Bus(interface="socketcan", channel="can0", bitrate=500000)

    hub.register_sensor("can:0x180", SensorType.ENCODER,     InterfaceType.CANBUS, threshold=3000.0, unit="RPM", location="motor_1")
    hub.register_sensor("can:0x181", SensorType.FORCE_TORQUE, InterfaceType.CANBUS, threshold=50.0,  unit="Nm",  location="arm_joint")

    # Message listener (run in thread)
    def can_listener():
        for msg in bus:
            if msg.arbitration_id == 0x180:
                rpm = int.from_bytes(msg.data[0:2], 'big') * 0.1
                hub.receive("can:0x180", rpm)
            elif msg.arbitration_id == 0x181:
                torque = int.from_bytes(msg.data[0:2], 'big') * 0.01
                hub.receive("can:0x181", torque)

    import threading
    threading.Thread(target=can_listener, daemon=True).start()
"""


# ══════════════════════════════════════════════════════════════
# 5. ROS2 — Robotics
# ══════════════════════════════════════════════════════════════
ROS2_GUIDE = """
ROS2 WIRING GUIDE
─────────────────
Hardware needed:
  - ROS2 installed (Humble or Iron recommended)
  - Robot with ROS2 drivers (most modern robots)

Install:
  sudo apt install ros-humble-desktop
  pip install rclpy

Production code:

    import rclpy
    from rclpy.node import Node
    from sensor_msgs.msg import JointState
    from std_msgs.msg import Float32

    class DriftCoreSafetyNode(Node):
        def __init__(self, hub):
            super().__init__("driftcore_safety")
            self.hub = hub

            hub.register_sensor("ros2:/joint_torques", SensorType.FORCE_TORQUE, InterfaceType.ROS2, threshold=50.0, unit="Nm")
            hub.register_sensor("ros2:/motor_temp",    SensorType.TEMPERATURE,  InterfaceType.ROS2, threshold=80.0, unit="C")

            self.create_subscription(Float32, "/joint_torques", self.torque_callback, 10)
            self.create_subscription(Float32, "/motor_temp",    self.temp_callback,   10)

        def torque_callback(self, msg):
            self.hub.receive("ros2:/joint_torques", msg.data)

        def temp_callback(self, msg):
            self.hub.receive("ros2:/motor_temp", msg.data)

    rclpy.init()
    node = DriftCoreSafetyNode(hub)
    rclpy.spin(node)
"""


# ══════════════════════════════════════════════════════════════
# 6. SAFETY RELAY WIRING DIAGRAM (text)
# ══════════════════════════════════════════════════════════════
RELAY_DIAGRAM = """
PHYSICAL RELAY WIRING DIAGRAM
──────────────────────────────

MAINS POWER (240V/120V)
        │
    [MAIN FUSE]
        │
   [SAFETY RELAY] ◄──── GPIO/Modbus signal from DriftCore
        │                (LOW = relay opens = power cut)
        │
   [DISTRIBUTION]
    ┌───┴───┐
    │       │
[MOTORS] [COMPUTERS]
    │
[ACTUATOR RELAY] ◄──── Second relay for actuators only
    │                   (allows cutting motors while keeping AI running)
[ACTUATORS]

NOTES:
  ✅ Relay is NORMALLY CLOSED (NC) — power flows when relay is healthy
  ✅ If DriftCore crashes, relay loses signal → opens → power cut automatically
  ✅ This is called "fail-safe" — failure causes safe state, not dangerous state
  ✅ Add a manual bypass switch for maintenance (key-switch, not software)
  ✅ Always use certified safety relays for high-power applications
     (Pilz, Schmersal, SICK, or equivalent)

FAIL-SAFE PRINCIPLE:
  Normal:  GPIO HIGH → relay CLOSED → power flows → system runs
  Fault:   GPIO LOW  → relay OPEN   → power cut   → system stops
  Crash:   GPIO dead → relay OPEN   → power cut   → system stops

  The system stops itself when it can't prove it's safe.
  This is the same principle as a dead man's switch on a train.
"""


def print_all_guides():
    """Print the complete wiring guide for all interfaces."""
    guides = [
        ("GPIO — Raspberry Pi / Arduino", GPIO_GUIDE),
        ("MQTT — IoT Sensor Network",     MQTT_GUIDE),
        ("MODBUS — Industrial Equipment", MODBUS_GUIDE),
        ("CAN BUS — Heavy Machinery",     CANBUS_GUIDE),
        ("ROS2 — Robotics",               ROS2_GUIDE),
        ("Relay Wiring Diagram",          RELAY_DIAGRAM),
    ]
    for title, guide in guides:
        print(f"\n{'='*65}")
        print(f"  {title}")
        print(f"{'='*65}")
        print(guide)


if __name__ == "__main__":
    print_all_guides()
