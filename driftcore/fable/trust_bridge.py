"""
trust_bridge.py — Human ↔ AI Trust Interface

Trust between humans and AI is not given. It is built.
It is built through transparency, track record, and the ability to say no.

The TrustBridge is the interface where humans and AI systems
communicate about trust explicitly — not just implicitly through behavior.
"""

from datetime import datetime


class TrustBridge:
    """
    A formal interface for humans to interact with the trust system.

    Humans can:
    - Query the current trust status of any agent
    - Flag concerns about an agent's behavior
    - Grant or revoke trust explicitly
    - Request a full audit of an agent's history

    The system cannot:
    - Grant itself higher trust
    - Silently change trust values
    - Override a human trust flag
    """

    def __init__(self, trust_model, audit_story):
        self.trust_model = trust_model
        self.audit = audit_story
        self.human_flags = {}

    def human_flag(self, agent: str, concern: str, raised_by: str) -> dict:
        """
        A human raises a concern about an agent.
        This immediately reduces that agent's trust and creates an audit entry.
        """
        self.human_flags.setdefault(agent, []).append({
            "concern": concern,
            "raised_by": raised_by,
            "timestamp": datetime.utcnow().isoformat(),
        })

        # Human flags carry weight — penalize trust
        self.trust_model.trust[agent] = max(
            0.0,
            self.trust_model.trust.get(agent, 0.5) - 0.20
        )

        self.audit.record(
            "HUMAN_TRUST_FLAG",
            f"Human operator '{raised_by}' flagged agent '{agent}': {concern}",
            {"agent": agent, "concern": concern}
        )

        return {"status": "FLAG_RECORDED", "agent": agent, "new_trust": self.trust_model.trust[agent]}

    def human_endorse(self, agent: str, endorsed_by: str) -> dict:
        """A human explicitly endorses an agent, increasing trust."""
        self.trust_model.trust[agent] = min(
            1.0,
            self.trust_model.trust.get(agent, 0.5) + 0.10
        )
        self.audit.record(
            "HUMAN_TRUST_ENDORSEMENT",
            f"Human operator '{endorsed_by}' endorsed agent '{agent}'.",
            {"agent": agent}
        )
        return {"status": "ENDORSEMENT_RECORDED", "agent": agent, "new_trust": self.trust_model.trust[agent]}

    def status_report(self, agent: str) -> dict:
        """Human-readable trust status for an agent."""
        trust = self.trust_model.trust.get(agent, 0.5)
        flags = self.human_flags.get(agent, [])
        return {
            "agent": agent,
            "trust_score": trust,
            "trust_level": self._label(trust),
            "quarantined": self.trust_model.is_quarantined(agent),
            "human_flags": len(flags),
            "flag_detail": flags,
        }

    def _label(self, score: float) -> str:
        if score >= 0.8: return "HIGH TRUST"
        if score >= 0.5: return "MODERATE TRUST"
        if score >= 0.2: return "LOW TRUST"
        return "UNTRUSTED — QUARANTINE"
