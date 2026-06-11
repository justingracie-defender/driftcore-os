"""
hardware_isolation.py — Physical System Cutoff

When software safety fails, hardware must be able to stop the system.
This module simulates that boundary.
In real deployment: maps to physical relay/interlock signals.
"""

from datetime import datetime

_isolation_log = []


def isolate_energy_system() -> str:
    _isolation_log.append({
        "action": "ENERGY_ISOLATED",
        "timestamp": datetime.utcnow().isoformat()
    })
    return "ENERGY_ISOLATED"


def cutoff_actuators() -> str:
    _isolation_log.append({
        "action": "ACTUATORS_DISABLED",
        "timestamp": datetime.utcnow().isoformat()
    })
    return "ACTUATORS_DISABLED"


def full_isolation() -> dict:
    e = isolate_energy_system()
    a = cutoff_actuators()
    return {
        "energy": e,
        "actuators": a,
        "status": "FULLY_ISOLATED",
        "timestamp": datetime.utcnow().isoformat(),
        "note": "Human physical inspection required before any restart",
    }


def get_isolation_log() -> list:
    return list(_isolation_log)
