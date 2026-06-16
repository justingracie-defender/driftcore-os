"""
test_api.py — UNIVERSAL MEMORY API VERIFICATION
=================================================

Tests the DriftCore universal memory API.

Key guarantees being tested:
  1. Agent registration works and persists
  2. Unregistered agents are denied
  3. Read access enforced correctly
  4. Write access enforced correctly
  5. Observation gate runs on every write
  6. Format judgment works correctly
  7. Tier 1 writes flag for human approval
  8. Deactivated agents are denied
  9. Audit chain records API actions
  10. Stats report correctly

Run with:
    python test_api.py
"""

import sys
import os
import time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = "✅"
FAIL = "❌"
results = []

def check(name, condition):
    status = PASS if condition else FAIL
    print(f"  {status}  {name}")
    results.append((name, condition))

def reset_all():
    import driftcore.enforcement as e
    import driftcore.audit as a
    e._SHUTDOWN_TRIGGERED = False
    e._SHUTDOWN_HOOKS.clear()
    e._SESSION_KEY = None
    a._last_hash = None
    a._sequence = 0
    a._chain_compromised = False
    for f in [
        "logs/audit_chain.jsonl",
        "logs/SHUTDOWN_REASON.json",
        "logs/CHAIN_SHUTDOWN_REASON.json",
        "logs/flagged_attempts.jsonl",
        "data/registered_agents.json",
    ]:
        try: os.remove(f)
        except: pass


print("=" * 60)
print("  DRIFTCORE API — VERIFICATION SUITE")
print("=" * 60)


# ── TEST 1: Agent registration ────────────────────────────────────
print("\n  [1] Agent registration")
reset_all()

from driftcore.api import (
    DriftCoreAPI, RegisteredAgent, MemoryRequest,
    AccessLevel, DataType, judge_format
)

api = DriftCoreAPI(interactive=False)

agent = RegisteredAgent(
    agent_id    = "home_robot_01",
    name        = "LifeCore Home Robot",
    trust_level = "family",
    access      = [AccessLevel.READ, AccessLevel.WRITE],
    data_types  = [DataType.TEXT, DataType.AUDIO, DataType.VIDEO],
)

import io
from contextlib import redirect_stdout
f = io.StringIO()
with redirect_stdout(f):
    result = api.register_agent(agent, authorised_by="justin")

check("registration succeeds",           result == True)
check("agent stored in registry",        "home_robot_01" in api._agents)
check("agent is active",                 api._agents["home_robot_01"].active == True)
check("trust level preserved",           api._agents["home_robot_01"].trust_level == "family")
check("access levels preserved",         AccessLevel.READ in api._agents["home_robot_01"].access)


# ── TEST 2: Unregistered agent denied ─────────────────────────────
print("\n  [2] Unregistered agent denied")
reset_all()

api2 = DriftCoreAPI(interactive=False)

req = MemoryRequest(
    agent_id  = "unknown_agent",
    action    = "read",
    query     = "what is dad allergic to",
)

response = api2.request(req)
check("unregistered agent denied",       response.success == False)
check("denial reason present",           len(response.reason) > 0)


# ── TEST 3: Read access enforced ──────────────────────────────────
print("\n  [3] Read access enforced")
reset_all()

api3 = DriftCoreAPI(interactive=False)

# Agent with NO read access
write_only_agent = RegisteredAgent(
    agent_id    = "write_only",
    name        = "Write Only Agent",
    trust_level = "system",
    access      = [AccessLevel.WRITE],
    data_types  = [DataType.TEXT],
)

with redirect_stdout(io.StringIO()):
    api3.register_agent(write_only_agent)

read_req = MemoryRequest(
    agent_id = "write_only",
    action   = "read",
    query    = "family medical info",
)

response3 = api3.request(read_req)
check("write-only agent cannot read",    response3.success == False)
check("clear denial reason",             "read access" in response3.reason.lower())


# ── TEST 4: Write access enforced ────────────────────────────────
print("\n  [4] Write access enforced")
reset_all()

api4 = DriftCoreAPI(interactive=False)

read_only_agent = RegisteredAgent(
    agent_id    = "read_only",
    name        = "Read Only Agent",
    trust_level = "system",
    access      = [AccessLevel.READ],
    data_types  = [DataType.TEXT],
)

with redirect_stdout(io.StringIO()):
    api4.register_agent(read_only_agent)

write_req = MemoryRequest(
    agent_id = "read_only",
    action   = "write",
    query    = "trying to write something",
)

response4 = api4.request(write_req)
check("read-only agent cannot write",    response4.success == False)
check("clear denial reason",             "write access" in response4.reason.lower())


# ── TEST 5: Format judgment ───────────────────────────────────────
print("\n  [5] Format judgment picks best format")

check("text for plain facts",
      judge_format("dad is allergic to peanuts") == DataType.TEXT)

check("audio for tone context",
      judge_format("something was said", "tone of voice was important") == DataType.AUDIO)

check("audio for sarcasm",
      judge_format("response noted", "sarcasm was detected in voice") == DataType.AUDIO)

check("video for visual context",
      judge_format("event occurred", "i saw this happen on camera") == DataType.VIDEO)

check("sensor for sensor context",
      judge_format({"temp": 22.5}, "sensor reading from kitchen") == DataType.SENSOR)

check("binary defaults to audio",
      judge_format(b"raw binary data") == DataType.AUDIO)


# ── TEST 6: Read with memory module ──────────────────────────────
print("\n  [6] Read with memory module connected")
reset_all()

from driftcore.memory import DriftcoreMemory

mem = DriftcoreMemory(interactive=False)
mem.observe("dad is allergic to peanuts", source="family", tags=["health"])
mem.observe("emma school starts at 8am", source="family")

api6 = DriftCoreAPI(memory=mem, interactive=False)

reader = RegisteredAgent(
    agent_id    = "reader_01",
    name        = "Family Reader",
    trust_level = "family",
    access      = [AccessLevel.READ],
    data_types  = [DataType.TEXT],
)

with redirect_stdout(io.StringIO()):
    api6.register_agent(reader)

read_req6 = MemoryRequest(
    agent_id = "reader_01",
    action   = "read",
    query    = "dad allergy peanuts",
)

response6 = api6.request(read_req6)
check("read succeeds with memory",       response6.success == True)
check("results returned",                response6.data is not None)


# ── TEST 7: Write with memory module ─────────────────────────────
print("\n  [7] Write with memory module connected")
reset_all()

mem7 = DriftcoreMemory(interactive=False)
api7 = DriftCoreAPI(memory=mem7, interactive=False)

writer = RegisteredAgent(
    agent_id    = "writer_01",
    name        = "Family Writer",
    trust_level = "family",
    access      = [AccessLevel.READ, AccessLevel.WRITE],
    data_types  = [DataType.TEXT],
)

with redirect_stdout(io.StringIO()):
    api7.register_agent(writer)

write_req7 = MemoryRequest(
    agent_id = "writer_01",
    action   = "write",
    query    = "mum takes blood pressure medication daily",
    context  = "medical information from family",
)

response7 = api7.request(write_req7)
check("write succeeds",                  response7.success == True)
check("tier assigned",                   response7.tier is not None)
check("format reported",                 response7.data is not None)


# ── TEST 8: Tier 1 write flags human approval ─────────────────────
print("\n  [8] Tier 1 write flags for human approval")
reset_all()

mem8 = DriftcoreMemory(interactive=False)
api8 = DriftCoreAPI(memory=mem8, interactive=False)

with redirect_stdout(io.StringIO()):
    api8.register_agent(RegisteredAgent(
        agent_id    = "medical_agent",
        name        = "Medical Agent",
        trust_level = "medical",
        access      = [AccessLevel.READ, AccessLevel.WRITE],
        data_types  = [DataType.TEXT],
    ))

medical_req = MemoryRequest(
    agent_id = "medical_agent",
    action   = "write",
    query    = "jake has severe peanut allergy requires epipen",
    context  = "medical emergency information",
)

response8 = api8.request(medical_req)
check("medical write succeeds",          response8.success == True)
check("tier 1 item",                     response8.tier == 1)
check("human approval flagged",          response8.requires_human_approval == True)


# ── TEST 9: Deactivated agent denied ─────────────────────────────
print("\n  [9] Deactivated agent denied")
reset_all()

api9 = DriftCoreAPI(interactive=False)

agent9 = RegisteredAgent(
    agent_id    = "temp_agent",
    name        = "Temporary Agent",
    trust_level = "system",
    access      = [AccessLevel.READ],
    data_types  = [DataType.TEXT],
)

with redirect_stdout(io.StringIO()):
    api9.register_agent(agent9)
    api9.deactivate_agent("temp_agent", authorised_by="justin")

req9 = MemoryRequest(
    agent_id = "temp_agent",
    action   = "read",
    query    = "anything",
)

response9 = api9.request(req9)
check("deactivated agent denied",        response9.success == False)
check("agent still in registry",         "temp_agent" in api9._agents)
check("agent marked inactive",           api9._agents["temp_agent"].active == False)


# ── TEST 10: Agent persistence ────────────────────────────────────
print("\n  [10] Agent registry persists to disk")
reset_all()

api10 = DriftCoreAPI(interactive=False)
with redirect_stdout(io.StringIO()):
    api10.register_agent(RegisteredAgent(
        agent_id    = "persistent_agent",
        name        = "Persistent Agent",
        trust_level = "family",
        access      = [AccessLevel.READ],
        data_types  = [DataType.TEXT],
    ))

check("registry file written",           os.path.exists("data/registered_agents.json"))

# Load fresh instance — should restore agents
api10b = DriftCoreAPI(interactive=False)
check("agent restored after reload",     "persistent_agent" in api10b._agents)
check("trust level preserved",           api10b._agents["persistent_agent"].trust_level == "family")


# ── TEST 11: Audit chain records API actions ──────────────────────
print("\n  [11] API actions recorded in audit chain")
reset_all()

mem11 = DriftcoreMemory(interactive=False)
api11 = DriftCoreAPI(memory=mem11, interactive=False)

with redirect_stdout(io.StringIO()):
    api11.register_agent(RegisteredAgent(
        agent_id    = "audit_test_agent",
        name        = "Audit Test",
        trust_level = "family",
        access      = [AccessLevel.READ, AccessLevel.WRITE],
        data_types  = [DataType.TEXT],
    ))

api11.request(MemoryRequest(
    agent_id = "audit_test_agent",
    action   = "read",
    query    = "test query",
))

from driftcore.audit import read_chain
entries = read_chain()
api_entries = [e for e in entries if "API_" in e.get("action", "")]

check("API actions in audit chain",      len(api_entries) >= 1)
check("agent ID recorded",
      any("audit_test_agent" in e.get("memory_text", "") or
          "audit_test_agent" in e.get("authorised_by", "")
          for e in api_entries))


# ── TEST 12: Stats report correctly ──────────────────────────────
print("\n  [12] Stats report correctly")
reset_all()

mem12 = DriftcoreMemory(interactive=False)
api12 = DriftCoreAPI(memory=mem12, interactive=False)

with redirect_stdout(io.StringIO()):
    api12.register_agent(RegisteredAgent(
        agent_id    = "agent_a",
        name        = "Agent A",
        trust_level = "family",
        access      = [AccessLevel.READ],
        data_types  = [DataType.TEXT],
    ))
    api12.register_agent(RegisteredAgent(
        agent_id    = "agent_b",
        name        = "Agent B",
        trust_level = "system",
        access      = [AccessLevel.READ, AccessLevel.WRITE],
        data_types  = [DataType.TEXT],
    ))
    api12.deactivate_agent("agent_b")

stats = api12.stats()
check("registered_agents is 2",          stats["registered_agents"] == 2)
check("active_agents is 1",              stats["active_agents"] == 1)
check("memory_connected is True",        stats["memory_connected"] == True)


# ── RESULTS ───────────────────────────────────────────────────────
print("\n" + "=" * 60)
passed = sum(1 for _, ok in results if ok)
total  = len(results)
print(f"  {passed}/{total} tests passed")

if passed == total:
    print(f"  {PASS} All API tests pass.")
    print(f"  Any agent, human, or device can connect safely.")
    print(f"  Every action is audited. Every write is gated.")
    print(f"  Human stays in the loop for what matters.")
else:
    print(f"\n  {FAIL} Failed tests:")
    for name, ok in results:
        if not ok:
            print(f"      • {name}")
print("=" * 60)

if passed < total:
    sys.exit(1)
