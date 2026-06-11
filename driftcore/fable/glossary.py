"""
glossary.py — Plain-Language Term Definitions

DriftCore uses technical terms. Fable defines them for everyone.
This glossary is part of the public interface.
"""

GLOSSARY = {
    "drift": (
        "Drift is when an AI system's behavior starts to diverge from what it's supposed to do. "
        "It's like a ship that slowly turns off course. Small drift is a warning. "
        "Large drift is an emergency."
    ),
    "drift_score": (
        "A number from 0.0 to 1.0 that measures how far the system has drifted. "
        "0.0 = perfectly on course. 1.0 = completely off course, emergency isolation required."
    ),
    "safe_halt": (
        "A safe halt is when the system stops itself because it detected something concerning. "
        "It's the AI equivalent of a circuit breaker. It's a safety feature, not a failure."
    ),
    "safety_kernel": (
        "The safety kernel is the part of the system that can never be overridden. "
        "Not by an agent, not by another AI, not by a clever argument. "
        "It is the last line of defense."
    ),
    "state_machine": (
        "The state machine tracks what mode the system is in: normal, monitoring, reduced autonomy, "
        "soft halt, hard halt, or isolation. Each mode has different rules about what the system can do."
    ),
    "autonomy_reduced": (
        "When autonomy is reduced, the system can still operate, but high-risk decisions "
        "require a human to approve them first. Think of it as a junior employee who needs "
        "sign-off for certain actions."
    ),
    "quarantine": (
        "When a memory entry or agent is quarantined, it's set aside for review. "
        "It's not deleted — it might contain useful information about what went wrong. "
        "But it can't influence the system until a human reviews it."
    ),
    "trust_model": (
        "The trust model tracks how reliable each agent has been. "
        "Trust starts in the middle, rises slowly with good behavior, "
        "and falls quickly with failures or safety violations."
    ),
    "fable": (
        "Fable is DriftCore's transparency layer. It translates every technical event "
        "into plain language so humans — not just engineers — can understand what the system is doing. "
        "Safety without legibility is not real safety."
    ),
    "hardware_isolation": (
        "In extreme cases, software alone isn't enough. Hardware isolation physically "
        "disconnects the AI system from energy sources and actuators. "
        "After hardware isolation, a human must physically inspect the system before restart."
    ),
    "audit_story": (
        "An audit story is an immutable, plain-language record of what the system did and why. "
        "Like a flight recorder, it cannot be erased. It's designed to be read by auditors, "
        "regulators, and the public."
    ),
}


def define(term: str) -> str:
    return GLOSSARY.get(term.lower().replace(" ", "_"), f"Term '{term}' not found in glossary.")


def all_terms() -> list[str]:
    return sorted(GLOSSARY.keys())
