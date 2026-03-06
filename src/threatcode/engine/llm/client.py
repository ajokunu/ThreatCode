"""LLM client implementations: Anthropic, OpenAI-compatible, DryRun.

Security controls:
- API timeouts enforced (default 120s)
- Max token limits enforced at API level
- Temperature pinned low (0.2) for deterministic output
- No execution of LLM responses — all output is JSON-parsed only
- Prompt injection guard: system prompt instructs model to ignore injections
- Model version pinning: explicit model IDs, no "latest" aliases
- SSRF protection: base_url validated via DNS resolution + ipaddress checks
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
import sys
import urllib.request
from abc import ABC, abstractmethod
from typing import IO, Any
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler

from threatcode.engine.llm.prompts import SYSTEM_PROMPT
from threatcode.exceptions import LLMError

logger = logging.getLogger(__name__)

# Security: max prompt size (in chars) to prevent excessive API costs
MAX_PROMPT_LENGTH = 256 * 1024  # 256K chars
# Security: API timeout in seconds
API_TIMEOUT_SECONDS = 120

_ALLOWED_SCHEMES = frozenset({"https"})
# Security: max response body size to prevent memory abuse
MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10 MB


def _validate_base_url(url: str, *, allow_http: bool = False) -> None:
    """Validate that a base_url is safe (not SSRF-exploitable).

    Resolves hostname via DNS and checks ALL resolved IPs against the
    ipaddress module — blocks loopback, private, link-local, reserved,
    and IPv4-mapped IPv6 addresses.
    """
    parsed = urlparse(url)
    allowed = _ALLOWED_SCHEMES | ({"http"} if allow_http else set())
    if parsed.scheme not in allowed:
        raise LLMError(f"Unsafe URL scheme '{parsed.scheme}' — only http/https allowed")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise LLMError("base_url must include a hostname")

    # Warn when sending API key over plain HTTP
    if parsed.scheme == "http":
        logger.warning(
            "base_url uses plain HTTP — API key will be sent unencrypted. "
            "Use HTTPS for production deployments."
        )

    # Resolve hostname to IP addresses and validate each one
    default_port = 443 if parsed.scheme == "https" else 80
    try:
        addrinfo = socket.getaddrinfo(
            hostname, parsed.port or default_port, proto=socket.IPPROTO_TCP
        )
    except socket.gaierror as e:
        raise LLMError(f"Cannot resolve hostname '{hostname}': {e}") from e

    if not addrinfo:
        raise LLMError(f"Hostname '{hostname}' resolved to no addresses")

    for family, _type, _proto, _canonname, sockaddr in addrinfo:
        ip_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError as e:
            raise LLMError(f"base_url resolved to invalid IP: {ip_str}") from e

        # Unwrap IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped

        if addr.is_unspecified:
            raise LLMError(f"base_url resolves to unspecified address ({ip_str})")
        if addr.is_loopback:
            raise LLMError(f"base_url resolves to loopback address ({ip_str})")
        if addr.is_private:
            raise LLMError(f"base_url resolves to private address ({ip_str})")
        if addr.is_link_local:
            raise LLMError(f"base_url resolves to link-local address ({ip_str})")
        if addr.is_reserved:
            raise LLMError(f"base_url resolves to reserved address ({ip_str})")


class _SafeRedirectHandler(HTTPRedirectHandler):
    """HTTP redirect handler that validates redirect targets against SSRF."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        _validate_base_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


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
        temperature: float = 0.2,
    ) -> None:
        try:
            import anthropic
        except ImportError as e:
            raise LLMError("anthropic package required: pip install anthropic") from e

        # Validate max_tokens range
        if not 1 <= max_tokens <= 8192:
            logger.warning("max_tokens %d out of range [1, 8192], clamping", max_tokens)
        max_tokens = max(1, min(max_tokens, 8192))

        self._client = anthropic.Anthropic(
            api_key=api_key,
            timeout=float(timeout),
        )
        self._model = model
        self._max_tokens = max_tokens
        self._timeout = timeout
        self._temperature = max(0.0, min(temperature, 1.0))

    def analyze(self, prompt: str) -> str:
        if len(prompt) > MAX_PROMPT_LENGTH:
            logger.warning(
                "Prompt truncated: %d chars exceeds %d limit",
                len(prompt),
                MAX_PROMPT_LENGTH,
            )
            prompt = prompt[:MAX_PROMPT_LENGTH]

        try:
            message = self._client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                temperature=self._temperature,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            if not message.content:
                raise LLMError("Anthropic API returned empty content")
            block = message.content[0]
            if not hasattr(block, "text"):
                raise LLMError("Anthropic API returned non-text content block")
            return str(block.text)
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
        temperature: float = 0.2,
        allow_insecure: bool = False,
    ) -> None:
        _validate_base_url(base_url, allow_http=allow_insecure)
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._model = model

        # Validate max_tokens range
        if not 1 <= max_tokens <= 8192:
            logger.warning("max_tokens %d out of range [1, 8192], clamping", max_tokens)
        self._max_tokens = max(1, min(max_tokens, 8192))

        self._timeout = timeout
        self._temperature = max(0.0, min(temperature, 1.0))

    def analyze(self, prompt: str) -> str:
        import urllib.error

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
            "temperature": self._temperature,
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
            opener = urllib.request.build_opener(_SafeRedirectHandler)
            with opener.open(req, timeout=self._timeout) as resp:
                raw_bytes = resp.read(MAX_RESPONSE_SIZE + 1)
                if len(raw_bytes) > MAX_RESPONSE_SIZE:
                    raise LLMError(f"Response body exceeds {MAX_RESPONSE_SIZE} byte limit")
                raw = raw_bytes.decode("utf-8")
                data = json.loads(raw)
                return str(data["choices"][0]["message"]["content"])
        except (
            urllib.error.URLError,
            KeyError,
            IndexError,
            json.JSONDecodeError,
            UnicodeDecodeError,
        ) as e:
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
        sys.stderr.write("(Prompt content suppressed for security)\n")
        sys.stderr.write("=== END DRY RUN ===\n")
        logger.debug(
            "DryRun: system_prompt_len=%d, analysis_prompt_len=%d",
            len(SYSTEM_PROMPT),
            len(prompt),
        )
        return '{"threats": []}'
