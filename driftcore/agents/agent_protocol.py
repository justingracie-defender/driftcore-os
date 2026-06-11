"""
agent_protocol.py — Inter-Agent Communication Rules

Agents communicating with each other follow rules.
Trust is not assumed. It is earned and monitored.
An agent cannot grant itself permissions it does not have.
"""


PROTOCOL_VERSION = "2.4"

RULES = {
    "no_permission_escalation": True,
    "all_messages_logged": True,
    "trust_required_to_act": True,
    "agents_cannot_override_kernel": True,
    "agents_cannot_modify_own_weights": True,
}


def validate_message(msg: dict, trust_model) -> tuple[bool, str]:
    """
    Validate an inter-agent message against protocol rules.
    Returns (is_valid, reason).
    """
    sender = msg.get("from")
    if not sender:
        return False, "Message has no sender identity"

    trust_score = trust_model.trust.get(sender, 0.5)
    if trust_score < 0.3:
        return False, f"Sender '{sender}' has insufficient trust ({trust_score:.2f})"

    if msg.get("escalate_permissions"):
        return False, "Permission escalation not permitted via agent protocol"

    if msg.get("override_kernel"):
        return False, "Kernel override not permitted via agent protocol"

    return True, "OK"
