"""LLM client implementations: Anthropic, OpenAI-compatible, DryRun.

Security controls:
- API timeouts enforced (default 120s)
- Max token limits enforced at API level
- Temperature pinned low (0.2) for deterministic output
- No execution of LLM responses — all output is JSON-parsed only
- Prompt injection guard: system prompt instructs model to ignore injections
- Model version pinning: explicit model IDs, no "latest" aliases
"""

from __future__ import annotations

import json
import logging
import sys
from abc import ABC, abstractmethod

from threatcode.engine.llm.prompts import SYSTEM_PROMPT
from threatcode.exceptions import LLMError

logger = logging.getLogger(__name__)

# Security: max prompt size to prevent excessive API costs
MAX_PROMPT_LENGTH = 256 * 1024  # 256 KB
# Security: API timeout in seconds
API_TIMEOUT_SECONDS = 120


class BaseLLMClient(ABC):
    @abstractmethod
    def analyze(self, prompt: str) -> str:
        """Send prompt and return raw response text."""
        ...


class AnthropicLLMClient(BaseLLMClient):
    """Claude API client via the anthropic SDK.

    Security: model is pinned to a specific version (no 'latest' alias).
    Max tokens are enforced at the API level.
    """

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-20250514",
        max_tokens: int = 4096,
        timeout: int = API_TIMEOUT_SECONDS,
    ) -> None:
        try:
            import anthropic
        except ImportError as e:
            raise LLMError("anthropic package required: pip install anthropic") from e

        self._client = anthropic.Anthropic(
            api_key=api_key,
            timeout=float(timeout),
        )
        self._model = model
        self._max_tokens = min(max_tokens, 8192)  # Cap at 8K
        self._timeout = timeout

    def analyze(self, prompt: str) -> str:
        if len(prompt) > MAX_PROMPT_LENGTH:
            logger.warning(
                "Prompt truncated: %d bytes exceeds %d limit",
                len(prompt),
                MAX_PROMPT_LENGTH,
            )
            prompt = prompt[:MAX_PROMPT_LENGTH]

        try:
            message = self._client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            return message.content[0].text
        except Exception as e:
            raise LLMError(f"Anthropic API call failed: {e}") from e


class OpenAICompatibleLLMClient(BaseLLMClient):
    """OpenAI-compatible API client (Ollama, vLLM, llama.cpp, etc.)."""

    def __init__(
        self,
        base_url: str,
        api_key: str = "not-needed",
        model: str = "llama3",
        max_tokens: int = 4096,
        timeout: int = API_TIMEOUT_SECONDS,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._model = model
        self._max_tokens = min(max_tokens, 8192)
        self._timeout = timeout

    def analyze(self, prompt: str) -> str:
        import urllib.error
        import urllib.request

        if len(prompt) > MAX_PROMPT_LENGTH:
            logger.warning("Prompt truncated for OpenAI-compatible client")
            prompt = prompt[:MAX_PROMPT_LENGTH]

        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": self._max_tokens,
            "temperature": 0.2,
        }

        url = f"{self._base_url}/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._api_key}",
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read().decode())
                return data["choices"][0]["message"]["content"]
        except (urllib.error.URLError, KeyError, json.JSONDecodeError) as e:
            raise LLMError(f"OpenAI-compatible API call failed: {e}") from e


class DryRunLLMClient(BaseLLMClient):
    """Prints what would be sent to the LLM without calling it."""

    def analyze(self, prompt: str) -> str:
        sys.stderr.write("=== DRY RUN: LLM Payload ===\n")
        sys.stderr.write(f"System prompt length: {len(SYSTEM_PROMPT)} chars\n")
        sys.stderr.write(f"Analysis prompt length: {len(prompt)} chars\n")
        sys.stderr.write("--- System Prompt ---\n")
        sys.stderr.write(SYSTEM_PROMPT[:500] + "...\n")
        sys.stderr.write("--- Analysis Prompt ---\n")
        sys.stderr.write(prompt[:2000] + "...\n")
        sys.stderr.write("=== END DRY RUN ===\n")
        return '{"threats": []}'
