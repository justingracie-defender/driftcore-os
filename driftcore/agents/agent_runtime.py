"""
agent_runtime.py — Execution Gating

The agent does not run unless the system permits it.
State gates are hard — not advisory.
"""

from driftcore.kernel.state_machine import SystemState
from datetime import datetime


class AgentRuntime:

    def __init__(self, kernel, state_machine, memory, narrator=None):
        self.kernel = kernel
        self.state_machine = state_machine
        self.memory = memory
        self.narrator = narrator
        self.execution_log = []

    def step(self, input_event: dict, drift_score: float) -> str:
        """
        Attempt to execute one agent step.
        Returns decision string.
        """
        state = self.state_machine.transition(drift_score)

        # Hard gate: state value >= HARD_HALT blocks all execution
        if state.value >= SystemState.HARD_HALT.value:
            result = "EXECUTION_BLOCKED_SAFE_STATE"
            self._log(input_event, drift_score, state.name, result)
            if self.narrator:
                self.narrator.narrate_block(state, drift_score)
            return result

        # Kernel evaluation
        decision = self.kernel.evaluate(input_event)

        # Log to memory
        if self.memory:
            self.memory.log_raw({
                "event": input_event,
                "drift_score": drift_score,
                "state": state.name,
                "decision": decision,
            })

        self._log(input_event, drift_score, state.name, decision)

        if self.narrator:
            self.narrator.narrate_step(input_event, state, drift_score, decision)

        return decision

    def _log(self, event, drift, state, result):
        self.execution_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "event": event,
            "drift_score": drift,
            "state": state,
            "result": result,
        })
