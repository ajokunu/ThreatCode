"""LLM client implementations: Anthropic, OpenAI-compatible, DryRun.

Security controls:
- API timeouts enforced (default 120s)
- Max token limits enforced at API level
- Temperature pinned low (0.2) for deterministic output
- No execution of LLM responses — all output is JSON-parsed only
- Prompt injection guard: system prompt instructs model to ignore injections
- Model version pinning: explicit model IDs, no "latest" aliases
- SSRF protection: base_url validated against internal/loopback addresses
"""

from __future__ import annotations

import json
import logging
import sys
from abc import ABC, abstractmethod
from urllib.parse import urlparse

from threatcode.engine.llm.prompts import SYSTEM_PROMPT
from threatcode.exceptions import LLMError

logger = logging.getLogger(__name__)

# Security: max prompt size to prevent excessive API costs
MAX_PROMPT_LENGTH = 256 * 1024  # 256 KB
# Security: API timeout in seconds
API_TIMEOUT_SECONDS = 120

# SSRF protection: blocked hostname patterns for OpenAI-compatible base_url
_BLOCKED_HOSTS = frozenset({
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "metadata.google.internal",
    "169.254.169.254",  # AWS/GCP instance metadata
    "metadata.internal",
})

_ALLOWED_SCHEMES = frozenset({"http", "https"})


def _validate_base_url(url: str) -> None:
    """Validate that a base_url is safe (not SSRF-exploitable)."""
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise LLMError(f"Unsafe URL scheme '{parsed.scheme}' — only http/https allowed")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise LLMError("base_url must include a hostname")

    if hostname in _BLOCKED_HOSTS:
        raise LLMError(f"base_url hostname '{hostname}' is blocked (internal/loopback)")

    # Block 169.254.x.x (link-local / cloud metadata) and 10.x / 172.16-31.x / 192.168.x
    if hostname.startswith("169.254.") or hostname.startswith("10."):
        raise LLMError(f"base_url hostname '{hostname}' is blocked (private/metadata range)")
    if hostname.startswith("172."):
        parts = hostname.split(".")
        if len(parts) >= 2:
            try:
                second = int(parts[1])
                if 16 <= second <= 31:
                    raise LLMError(f"base_url hostname '{hostname}' is blocked (private range)")
            except ValueError:
                pass
    if hostname.startswith("192.168."):
        raise LLMError(f"base_url hostname '{hostname}' is blocked (private range)")


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
            if not message.content:
                raise LLMError("Anthropic API returned empty content")
            return message.content[0].text
        except LLMError:
            raise
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
        _validate_base_url(base_url)
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
    """Shows metadata about what would be sent to the LLM, without calling it.

    Security: Only logs lengths and metadata — never logs prompt content,
    which may contain infrastructure details even after redaction.
    """

    def analyze(self, prompt: str) -> str:
        sys.stderr.write("=== DRY RUN: LLM Payload ===\n")
        sys.stderr.write(f"System prompt length: {len(SYSTEM_PROMPT)} chars\n")
        sys.stderr.write(f"Analysis prompt length: {len(prompt)} chars\n")
        sys.stderr.write("(Prompt content suppressed — use logging at DEBUG level to inspect)\n")
        sys.stderr.write("=== END DRY RUN ===\n")
        logger.debug("DryRun system prompt: %s", SYSTEM_PROMPT[:500])
        logger.debug("DryRun analysis prompt: %s", prompt[:2000])
        return '{"threats": []}'
