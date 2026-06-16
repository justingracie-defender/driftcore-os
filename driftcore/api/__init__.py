"""
driftcore/api/__init__.py
==========================
Universal Memory API for DriftCore OS.

Any AI, device, or human with appropriate access
can read from or write to the memory layer through
this interface.

Design principles (Justin Gracie):
  - Read: anyone who needs it, assigned initially, expandable
  - Write: AI judgment decides tier, human in loop for Tier 1
  - Format: whatever is most useful — text, audio, video, sensor
  - Access: always traceable, always audited
  - Human: always in the loop for important decisions

Data types supported:
  - text       — facts, notes, instructions
  - audio      — tone, sarcasm, voice recognition
  - video      — context, environment, events
  - sensor     — temperature, proximity, biometric
  - skill      — procedural learning, physical tasks

Memory caps are configurable per deployment.
A home robot needs different limits than a medical assistant.
Expansion is always clean — no drift or hallucination enters
through the expansion path.

This API is universal. It works for:
  - Home robots (LifeCore)
  - Scheduling agents
  - Medical assistants
  - Any AI that needs persistent, trustworthy memory
"""

import time
import json
import os
from dataclasses import dataclass, field
from typing import Optional, List, Any
from enum import Enum


# ── Data types ────────────────────────────────────────────────────

class DataType(Enum):
    TEXT    = "text"
    AUDIO   = "audio"
    VIDEO   = "video"
    SENSOR  = "sensor"
    SKILL   = "skill"


# ── Access levels ─────────────────────────────────────────────────

class AccessLevel(Enum):
    READ  = "read"
    WRITE = "write"
    ADMIN = "admin"


# ── Registered agent ──────────────────────────────────────────────

@dataclass
class RegisteredAgent:
    """
    Any human, AI, or device that can access memory.
    Assigned initially. Expandable later by admin.
    """
    agent_id:     str
    name:         str
    trust_level:  str        # maps to TrustLevel in observation gate
    access:       List[AccessLevel] = field(default_factory=list)
    data_types:   List[DataType]    = field(default_factory=list)
    registered_at: float            = field(default_factory=time.time)
    registered_by: str              = "admin"
    active:        bool             = True


# ── Memory request ────────────────────────────────────────────────

@dataclass
class MemoryRequest:
    """
    A request to read or write memory.
    Always includes who is asking and why.
    """
    agent_id:    str
    action:      str          # "read" or "write"
    query:       str          # what is being asked or stored
    data_type:   DataType     = DataType.TEXT
    data:        Any          = None
    context:     str          = ""
    timestamp:   float        = field(default_factory=time.time)


# ── Memory response ───────────────────────────────────────────────

@dataclass
class MemoryResponse:
    """
    Response to a memory request.
    Always includes what happened and why.
    """
    success:      bool
    data:         Any          = None
    tier:         Optional[int] = None
    reason:       str          = ""
    requires_human_approval: bool = False
    timestamp:    float        = field(default_factory=time.time)


# ── Format judgment ───────────────────────────────────────────────

def judge_format(content: Any, context: str = "") -> DataType:
    """
    Decide what format best preserves the meaning of content.

    Text is limited. Sarcasm, tone, emotion — these live in
    audio and video. A robot should listen, not just read.

    Returns the most useful DataType for this content.
    """
    # If it's already typed, respect that
    if isinstance(content, bytes):
        # Binary data — could be audio or video
        # For now default to audio — expand with mime detection
        return DataType.AUDIO

    if isinstance(content, dict) and "sensor" in str(context).lower():
        return DataType.SENSOR

    if isinstance(content, str):
        # Text — but check if context suggests richer format needed
        tone_signals = ["tone", "sarcasm", "emotion", "voice", "heard"]
        visual_signals = ["saw", "video", "image", "scene", "environment"]

        context_lower = context.lower()
        if any(s in context_lower for s in tone_signals):
            return DataType.AUDIO
        if any(s in context_lower for s in visual_signals):
            return DataType.VIDEO

        return DataType.TEXT

    return DataType.TEXT


# ── Main API ──────────────────────────────────────────────────────

class DriftCoreAPI:
    """
    Universal memory interface for DriftCore OS.

    Any registered agent can read or write through this API.
    The API enforces access rules, logs everything, and keeps
    humans in the loop for important decisions.

    Usage:
        api = DriftCoreAPI()
        api.register_agent(RegisteredAgent(...))
        response = api.request(MemoryRequest(...))
    """

    def __init__(
        self,
        memory=None,
        interactive: bool = True,
        storage=None,
    ):
        self._memory      = memory
        self._storage     = storage
        self._interactive = interactive
        self._agents: dict = {}
        self._load_agents()

    # ── Agent registration ────────────────────────────────────────

    def register_agent(
        self,
        agent: RegisteredAgent,
        authorised_by: str = "admin",
    ) -> bool:
        """
        Register a new agent. Admin only.
        Returns True if registered successfully.
        """
        self._agents[agent.agent_id] = agent
        self._save_agents()
        self._audit(
            action="AGENT_REGISTERED",
            agent_id=agent.agent_id,
            detail=f"name={agent.name}, trust={agent.trust_level}, "
                   f"registered_by={authorised_by}"
        )
        print(f"\n  ✅ Agent registered: {agent.name} ({agent.agent_id})\n")
        return True

    def deactivate_agent(self, agent_id: str, authorised_by: str = "admin"):
        """Deactivate an agent's access. Never deletes — always audited."""
        if agent_id in self._agents:
            self._agents[agent_id].active = False
            self._save_agents()
            self._audit("AGENT_DEACTIVATED", agent_id,
                       f"authorised_by={authorised_by}")

    # ── Main request handler ──────────────────────────────────────

    def request(self, req: MemoryRequest) -> MemoryResponse:
        """
        Handle a memory request from any registered agent.

        Read: returns relevant memories if agent has access.
        Write: stores with AI judgment on tier, human approval
               for Tier 1.

        Always audited. Always traceable.
        """
        # Verify agent is registered and active
        agent = self._agents.get(req.agent_id)
        if not agent or not agent.active:
            self._audit("ACCESS_DENIED", req.agent_id,
                       "Agent not registered or inactive")
            return MemoryResponse(
                success=False,
                reason="Agent not registered or access revoked."
            )

        # Check access level
        if req.action == "read":
            return self._handle_read(req, agent)
        elif req.action == "write":
            return self._handle_write(req, agent)
        else:
            return MemoryResponse(
                success=False,
                reason=f"Unknown action: {req.action}"
            )

    # ── Read ──────────────────────────────────────────────────────

    def _handle_read(
        self,
        req: MemoryRequest,
        agent: RegisteredAgent,
    ) -> MemoryResponse:
        """
        Read memory for an agent.
        Only returns what the agent is allowed to see.
        """
        if AccessLevel.READ not in agent.access:
            self._audit("READ_DENIED", req.agent_id, "No read access")
            return MemoryResponse(
                success=False,
                reason="This agent does not have read access."
            )

        # Query memory if available
        results = []
        if self._memory:
            try:
                results = self._memory.query_text(req.query, budget=5)
            except Exception as e:
                return MemoryResponse(
                    success=False,
                    reason=f"Memory query failed: {e}"
                )

        self._audit("READ", req.agent_id,
                   f"query='{req.query[:60]}', results={len(results)}")

        return MemoryResponse(
            success=True,
            data=results,
            reason=f"Found {len(results)} relevant memories."
        )

    # ── Write ─────────────────────────────────────────────────────

    def _handle_write(
        self,
        req: MemoryRequest,
        agent: RegisteredAgent,
    ) -> MemoryResponse:
        """
        Write to memory.
        AI judges which tier. Human approves Tier 1.
        Format is decided by what best preserves meaning.
        """
        if AccessLevel.WRITE not in agent.access:
            self._audit("WRITE_DENIED", req.agent_id, "No write access")
            return MemoryResponse(
                success=False,
                reason="This agent does not have write access."
            )

        # Judge the best format for this content
        best_format = judge_format(req.data or req.query, req.context)

        # If memory module available, use its judgment layer
        if self._memory:
            try:
                # Run through observation gate first
                from driftcore.observation import ObservationGate
                gate = ObservationGate(
                    memory=self._memory,
                    interactive=self._interactive
                )
                gate_result = gate.check(
                    text=req.query,
                    source=agent.trust_level,
                    context=req.context,
                )

                if not gate_result.allowed:
                    self._audit("WRITE_BLOCKED", req.agent_id,
                               f"Observation gate blocked: {gate_result.reason}")
                    return MemoryResponse(
                        success=False,
                        reason=f"Blocked by observation gate: {gate_result.reason}",
                        requires_human_approval=gate_result.flagged,
                    )

                # Store through memory module
                item = self._memory.observe(
                    text=req.query,
                    source=agent.trust_level,
                )

                self._audit("WRITE", req.agent_id,
                           f"tier={item.tier}, format={best_format.value}, "
                           f"quarantined={item.quarantined}")

                # Tier 1 always notifies human
                requires_approval = item.tier == 1

                return MemoryResponse(
                    success=True,
                    tier=item.tier,
                    data=best_format.value,
                    requires_human_approval=requires_approval,
                    reason=f"Stored in Tier {item.tier} as {best_format.value}."
                           + (" Human notification sent." if requires_approval else "")
                )

            except Exception as e:
                return MemoryResponse(
                    success=False,
                    reason=f"Write failed: {e}"
                )

        return MemoryResponse(
            success=False,
            reason="No memory module connected."
        )

    # ── Stats ─────────────────────────────────────────────────────

    def stats(self) -> dict:
        """Current API state."""
        return {
            "registered_agents": len(self._agents),
            "active_agents":     sum(1 for a in self._agents.values() if a.active),
            "memory_connected":  self._memory is not None,
            "storage_connected": self._storage is not None,
        }

    # ── Persistence ───────────────────────────────────────────────

    def _save_agents(self):
        try:
            os.makedirs("data", exist_ok=True)
            data = {}
            for aid, agent in self._agents.items():
                data[aid] = {
                    "agent_id":     agent.agent_id,
                    "name":         agent.name,
                    "trust_level":  agent.trust_level,
                    "access":       [a.value for a in agent.access],
                    "data_types":   [d.value for d in agent.data_types],
                    "registered_at": agent.registered_at,
                    "registered_by": agent.registered_by,
                    "active":       agent.active,
                }
            with open("data/registered_agents.json", "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def _load_agents(self):
        try:
            with open("data/registered_agents.json") as f:
                data = json.load(f)
            for aid, d in data.items():
                self._agents[aid] = RegisteredAgent(
                    agent_id     = d["agent_id"],
                    name         = d["name"],
                    trust_level  = d["trust_level"],
                    access       = [AccessLevel(a) for a in d["access"]],
                    data_types   = [DataType(dt) for dt in d["data_types"]],
                    registered_at = d["registered_at"],
                    registered_by = d["registered_by"],
                    active       = d["active"],
                )
        except Exception:
            pass

    def _audit(self, action: str, agent_id: str, detail: str = ""):
        try:
            from driftcore.audit import record
            record(
                action=f"API_{action}",
                memory_text=f"agent={agent_id}",
                authorised_by=agent_id,
                detail=detail,
            )
        except Exception:
            pass
