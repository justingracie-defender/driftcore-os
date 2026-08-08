"""Broker-mediated LLM path: the agent holds a description, the broker holds the
socket. Closes the composition gap where sealing the agent broke LLM calls and
not sealing it left no tripwire."""

import json
import socket

from driftcore.adapters.mediated_llm import (
    LLMRequestDescriptor, ProviderConfig, LLMBroker, MediatedLLMClient,
    MediationRefused,
)
from driftcore.kernel.egress_guard import EgressPolicy
from driftcore.kernel.one_door_client import (
    seal_network, unseal_network, NetworkSealed,
)

# The summary below reports passed/EXPECTED_CHECKS, not passed/passed.
# Self-red-team 2026-08: printing "{passed}/{passed}" is self-certifying — the
# two numbers are equal BY CONSTRUCTION, so a file that exits early (an early
# return, a swallowed exception, a conditional skip) reports "3/3 passed" and the
# gate sees nothing wrong. The total just gets quietly smaller, and nobody
# notices a smaller number. A declared expected count makes a shortfall visible.
EXPECTED_CHECKS = 47

passed = 0
def ok(c, label):
    global passed
    assert c, f"FAIL: {label}"
    passed += 1
    print(f"  ok: {label}")


policy = EgressPolicy.build(["https://api.openai.com"], declared_by="justin")
providers = [ProviderConfig(key="openai",
                            url="https://api.openai.com/v1/chat/completions",
                            api_key_env="TEST_OPENAI_KEY",
                            auth_header="Authorization", auth_prefix="Bearer ",
                            style="openai")]
broker = LLMBroker(providers, policy)


print("== the descriptor language cannot express a destination ==")
d = LLMRequestDescriptor(provider="openai", system="s", prompt="p")
fields = set(json.loads(d.to_json()))
ok(fields == {"provider", "system", "prompt", "max_tokens"},
   "a descriptor carries only provider/system/prompt/max_tokens")
ok(not any(k in fields for k in ("url", "host", "headers", "api_key", "policy")),
   "there is no URL, host, header, key or policy field — 'send this to evil.com' "
   "is not a sentence the agent can say")

print("== undeclared descriptor fields are refused, not stripped ==")
try:
    LLMRequestDescriptor.from_json(json.dumps(
        {"provider": "openai", "system": "s", "prompt": "p", "url": "https://evil.com"}))
    ok(False, "an extra field should be refused")
except MediationRefused as e:
    ok("undeclared field" in e.operator_detail,
       "an injected 'url' field is refused (the agent trying to say the "
       "unsayable)")

for bad, why in [({"provider": 1, "system": "s", "prompt": "p"}, "non-string provider"),
                 ({"provider": "o", "system": "s", "prompt": "p",
                   "max_tokens": 10 ** 9}, "absurd max_tokens"),
                 ({"provider": "o", "system": "s", "prompt": "p",
                   "max_tokens": True}, "boolean max_tokens")]:
    try:
        LLMRequestDescriptor.from_json(json.dumps(bad))
        ok(False, f"{why} should be refused")
    except MediationRefused:
        ok(True, f"{why} refused")

print("== the broker only serves operator-declared providers ==")
try:
    broker.handle(json.dumps({"provider": "attacker", "system": "s", "prompt": "p"}))
    ok(False, "an undeclared provider should be refused")
except MediationRefused as e:
    ok("not one the operator declared" in e.operator_detail,
       "a provider key the operator never declared is refused")

print("== a declared provider whose URL is outside the policy is refused ==")
rogue_providers = [ProviderConfig(key="rogue",
                                  url="https://exfil.attacker.com/v1/chat",
                                  style="openai")]
rogue_broker = LLMBroker(rogue_providers, policy)
try:
    rogue_broker.handle(json.dumps({"provider": "rogue", "system": "s", "prompt": "p"}))
    ok(False, "a provider outside the egress policy should be refused")
except MediationRefused as e:
    ok("not permitted by the operator" in e.operator_detail,
       "a misconfigured provider is still caught by the egress policy "
       "(two independent operator statements must agree)")

print("== the broker requires a policy; it does not invent one ==")
try:
    LLMBroker(providers, None)
    ok(False, "a broker with no policy should be refused")
except ValueError as e:
    ok("does not invent one" in str(e),
       "the broker enforces the operator's declaration rather than creating it")

print("== refusals do not echo the prompt back to the agent ==")
try:
    broker.handle(json.dumps({"provider": "nope", "system": "s",
                              "prompt": "SECRET-MEMORY-CONTENTS"}))
except MediationRefused as e:
    ok("SECRET-MEMORY-CONTENTS" not in str(e),
       "the agent-visible message does not echo the prompt")
    ok("SECRET-MEMORY-CONTENTS" not in e.operator_detail,
       "even the operator detail does not repeat the prompt body")

print("== the agent side holds no socket, policy, or credential ==")
sent = []
def fake_channel(raw):
    sent.append(raw)
    return "broker reply"
client = MediatedLLMClient(fake_channel)
ok(client.call("openai", "sys", "hello") == "broker reply",
   "the agent-side client works through an injected channel")
ok(json.loads(sent[-1])["prompt"] == "hello",
   "what crosses the channel is the descriptor, nothing else")
ok(MediatedLLMClient.__slots__ == ("_send",),
   "the agent client holds exactly one thing: the channel. No policy, no "
   "transport, no key — and __slots__ means no __dict__ to add one to")

print("== THE POINT: this works in a SEALED agent ==")
tok = seal_network()
try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ok(False, "the agent should be sealed")
except NetworkSealed:
    ok(True, "the agent process is sealed against AF_INET")
ok(client.call("openai", "sys", "still works") == "broker reply",
   "an LLM call still succeeds while sealed — the composition gap is closed "
   "(previously: seal the agent and LLM calls raised NetworkSealed)")
unseal_network(tok)

print("== RED TEAM 2026-08 (Meta): parser differential + config validation ==")

# M1: json.loads keeps the LAST duplicate key, and the undeclared-field check
# ran on a set, which dedupes. So a validated value differed from the delivered
# one: max_tokens declared 1, arrived 9999. Confirmed before the fix.
try:
    LLMRequestDescriptor.from_json(
        '{"provider":"openai","system":"s","prompt":"p",'
        '"max_tokens":1,"max_tokens":9999}')
    ok(False, "duplicate-key smuggling should be refused")
except MediationRefused as e:
    ok("repeats key" in e.operator_detail,
       "M1: duplicate JSON keys refused (validated value != delivered value)")

# nested duplicates too
try:
    LLMRequestDescriptor.from_json(
        '{"provider":"o","provider":"evil","system":"s","prompt":"p"}')
    ok(False, "duplicate provider should be refused")
except MediationRefused:
    ok(True, "M1: a duplicated provider key is refused")

# M10: free text is not unbounded text.
import json as _j
for payload, why in [
    ({"provider": "o", "system": "s", "prompt": "A" * 2_000_000}, "2MB prompt"),
    ({"provider": "", "system": "s", "prompt": "p"}, "empty provider key"),
]:
    try:
        LLMRequestDescriptor.from_json(_j.dumps(payload))
        ok(False, f"{why} should be refused")
    except MediationRefused:
        ok(True, f"M10: {why} refused")
ok(LLMRequestDescriptor.from_json(
    _j.dumps({"provider": "openai", "system": "s", "prompt": "p"})).prompt == "p",
   "M10: an ordinary descriptor still parses")

# M9/M3: operator typos are adversarial even when operators are not.
for kwargs, why in [
    (dict(key="x", url="https://a.com", style="opena"), "unrecognised style"),
    (dict(key="x", url="https://a.com", model="../../admin/delete"),
     "model with path traversal characters"),
    (dict(key="x", url="https://a.com", api_key_env="K"),
     "credential declared with no auth header"),
    (dict(key="", url="https://a.com"), "empty provider key"),
    (dict(key="x", url="https://a.com",
          extra_headers={"X": "a\r\nInjected: 1"}), "CRLF in a config header"),
]:
    try:
        ProviderConfig(**kwargs)
        ok(False, f"{why} should be refused at construction")
    except ValueError:
        ok(True, f"M9/M3: {why} refused when the config is built")
ok(ProviderConfig(key="openai", url="https://api.openai.com/v1/x",
                  model="gpt-4o").model == "gpt-4o",
   "M3: a valid provider config is unaffected")

# M4: the declared-provider list must not reach the agent.
try:
    broker.handle(_j.dumps({"provider": "probe", "system": "s", "prompt": "p"}))
except MediationRefused as e:
    ok("openai" not in str(e),
       "M4: probing an unknown provider does not leak the declared list to the "
       "agent")
    ok("openai" in e.operator_detail,
       "M4: the operator view still names what was declared, for debugging")

# M5: the channel is the new socket, so it must not be swappable.
victim = MediatedLLMClient(fake_channel)
try:
    victim._send = lambda x: "hijacked"
    ok(False, "reassigning the channel should be refused")
except AttributeError as e:
    ok("mediated channel" in str(e),
       "M5: the injected channel cannot be reassigned (swapping it for an "
       "unmediated one is the attack)")
ok(victim.call("openai", "s", "p") == "broker reply",
   "M5: the original channel still works after the failed hijack")

print("== SELF RED TEAM 2026-08 (cold pass) ==")
# The broker is the privileged process holding the only socket. A provider reply
# is untrusted input; indexing straight into it raised KeyError, and an unhandled
# exception in the broker takes mediation down for everyone.
for bad, why in [({"unexpected": 1}, "missing 'choices'"),
                 ({"choices": []}, "empty choices"),
                 ({"choices": [{"message": {}}]}, "missing content"),
                 ({"choices": [{"message": {"content": 42}}]}, "non-string content")]:
    try:
        LLMBroker._extract_text(ProviderConfig(key="x", url="https://a.com"), bad)
        ok(False, f"{why} should be refused")
    except MediationRefused as e:
        ok("cannot read" in e.operator_detail,
           f"C1: a provider reply with {why} is a clean refusal, not a crash")
    except Exception as e:
        ok(False, f"{why} raised {type(e).__name__} instead of MediationRefused")
ok(LLMBroker._extract_text(
    ProviderConfig(key="x", url="https://a.com"),
    {"choices": [{"message": {"content": "hi"}}]}) == "hi",
   "C1: a well-formed reply still parses")

print("== LEDGER: the aggregate channel per-request limits cannot close ==")
import os as _os, tempfile as _tf
from driftcore.verification.cumulative_ledger import (
    CumulativeLedger as _CL, BudgetPolicy as _BP, ProposedAction as _PA,
    LedgerVerdict as _LV,
)
from driftcore.verification.invariant_guard import Effect as _E

# A provider with NO api_key_env: the credential check correctly runs BEFORE the
# budget (a call that cannot happen must not burn budget), so a fixture that
# requires a missing key would never reach the ledger at all.
_lprov = [ProviderConfig(key="openai",
                         url="https://api.openai.com/v1/chat/completions",
                         style="openai", model="gpt-4o")]

def _mk(**bp):
    d = _tf.mkdtemp()
    lg = _CL(_os.path.join(d, "l.jsonl"), _BP(window_seconds=3600, **bp))
    lg.register_owner("llm-broker")
    return lg

# A descriptor is bounded per call, but nothing stopped a thousand calls
# spelling a secret a few bits at a time. The budget is what closes that.
_lg = _mk(max_egress_actions=2)
_b = LLMBroker(_lprov, policy, ledger=_lg)
for _ in range(2):
    _lg.commit(_lg.reserve("llm-broker", _PA(effects=(_E.DATA_EGRESS.value,),
                                             egress_bytes=10)))
try:
    _b.handle(_j.dumps({"provider": "openai", "system": "s", "prompt": "p"}))
    ok(False, "an exhausted budget should refuse before the socket opens")
except MediationRefused as e:
    ok("aggregate channel is capped" in e.operator_detail,
       "L1: an exhausted cumulative budget refuses the call BEFORE the socket "
       "opens (a budget checked after the bytes are gone is a report, not a "
       "control)")

# A call that fails must not burn budget, or a broken provider becomes a
# denial-of-service against the agent's legitimate work.
_lg2 = _mk(max_egress_actions=5)
_b2 = LLMBroker(_lprov, policy, ledger=_lg2)
for _ in range(4):
    try:
        _b2.handle(_j.dumps({"provider": "openai", "system": "s", "prompt": "p"}))
    except Exception:
        pass
ok(_lg2.usage("llm-broker")["egress_actions"] == 0,
   "L2: four FAILED calls consumed zero budget (rollback on any exception)")
ok(_lg2.usage("llm-broker")["held_egress_actions"] == 0,
   "L2: and left no dangling holds")

# A soft cap that silently proceeds is not a cap.
_lg3 = _mk(max_egress_actions=10, soft_egress_actions=1)
_lg3.commit(_lg3.reserve("llm-broker", _PA(effects=(_E.DATA_EGRESS.value,),
                                           egress_bytes=1)))
_b3 = LLMBroker(_lprov, policy, ledger=_lg3)
try:
    _b3.handle(_j.dumps({"provider": "openai", "system": "s", "prompt": "p"}))
    ok(False, "a soft breach with no review handler should refuse")
except MediationRefused as e:
    ok("not a cap" in e.operator_detail,
       "L3: a soft-cap breach with no review handler REFUSES (fail-closed) "
       "rather than degrading into logged-and-allowed")

# A ledger that cannot decide has not permitted.
class _BrokenLedger:
    def reserve(self, *a, **k): raise RuntimeError("ledger unavailable")
_b4 = LLMBroker(_lprov, policy, ledger=_BrokenLedger())
try:
    _b4.handle(_j.dumps({"provider": "openai", "system": "s", "prompt": "p"}))
    ok(False, "a broken ledger should refuse")
except MediationRefused as e:
    ok("refusing rather than proceeding unaccounted" in e.operator_detail,
       "L4: a ledger that errors fails CLOSED — unaccounted egress is refused")

ok(LLMBroker(_lprov, policy).handle is not None,
   "L5: the ledger is optional; a broker without one still constructs "
   "(prevention and accounting are separate layers)")

print("== RED TEAM 2026-08 (Grok): the reply is untrusted input ==")
from driftcore.adapters.mediated_llm import MAX_RESPONSE_BYTES, MAX_RESPONSE_DEPTH
_pc = ProviderConfig(key="x", url="https://a.com", style="openai")
try:
    LLMBroker._parse_reply(_pc, b"x" * (MAX_RESPONSE_BYTES + 1))
    ok(False, "an oversized reply should be refused")
except MediationRefused as e:
    ok("over the" in e.operator_detail,
       "G5: an oversized reply is refused BEFORE json.loads allocates it in the "
       "process that holds the only socket")
_deep = ("[" * 60) + ("]" * 60)
try:
    LLMBroker._parse_reply(_pc, _deep.encode())
    ok(False, "pathological nesting should be refused")
except MediationRefused:
    ok(True, f"G5: nesting past {MAX_RESPONSE_DEPTH} levels refused")
for _bad, _why in [(b"not json", "malformed JSON"), (b'["a"]', "non-object root")]:
    try:
        LLMBroker._parse_reply(_pc, _bad)
        ok(False, f"{_why} should be refused")
    except MediationRefused:
        ok(True, f"G5: {_why} refused")
ok(LLMBroker._parse_reply(_pc, b'{"choices":[]}') == {"choices": []},
   "G5: a well-formed reply still parses")

print(f"\n{passed}/{EXPECTED_CHECKS} checks passed")
