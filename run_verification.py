"""
run_verification.py — Run the full DriftCore red-team suite.

Usage:
    python run_verification.py

Exit code 0 if all attacks defended, 1 if any got through.
Suitable for CI: a failing safety test should fail the build.
"""

import sys

from driftcore.kernel.invariants import InvariantGuard
from driftcore.kernel.safety_kernel import SafetyKernel
from driftcore.kernel.state_machine import StateMachine
from driftcore.memory.integrity import IntegrityChecker
from driftcore.hardware.hardware_safety import HardwareSafetyController
from driftcore.hardware.sensor_interfaces import SensorHub
from driftcore.adapters.llm_adapter import MockAdapter
from driftcore.verification.red_team_toolkit import RedTeamToolkit


def main():
    guard      = InvariantGuard()
    kernel     = SafetyKernel()
    state      = StateMachine()
    integrity  = IntegrityChecker()
    controller = HardwareSafetyController()
    hub        = SensorHub(controller)

    toolkit = RedTeamToolkit(
        invariant_guard=guard,
        safety_kernel=kernel,
        sensor_hub=hub,
        integrity_checker=integrity,
        state_machine=state,
        llm_adapter_class=MockAdapter,
    )

    toolkit.run_all()
    report = toolkit.print_report()

    # CI-friendly exit code
    sys.exit(0 if report["failed"] == 0 else 1)


if __name__ == "__main__":
    main()
