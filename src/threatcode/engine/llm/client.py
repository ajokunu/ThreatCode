"""LLM client implementations: Anthropic, OpenAI-compatible, DryRun.

Security controls:
- API timeouts enforced (default 120s) and retries bounded
- Max token limits enforced at API level
- A prompt that is too large is refused, never sliced, so the model never sees corrupt JSON
- No execution of LLM responses - all output is JSON-parsed only
- Prompt injection guard: system prompt instructs model to ignore injections
- Explicit model IDs, no "latest" aliases; ``DEPRECATED_MODELS`` names the ones that are retired
- SSRF protection: every base_url (config, ``ANTHROPIC_BASE_URL``) is validated via DNS resolution
  and ipaddress checks, and a redirect to another origin is refused so the API key and the request
  body are never forwarded
- Temperature is sent only when configured: current models reject it
"""

from __future__ import annotations

import inspect
import ipaddress
import json
import logging
import math
import os
import random
import socket
import sys
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from pathlib import Path
from typing import IO, Any
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler

from threatcode.config import DEFAULT_LLM_MAX_RETRIES, DEFAULT_LLM_MODEL
from threatcode.engine.llm.prompts import SYSTEM_PROMPT
from threatcode.exceptions import LLMError

logger = logging.getLogger(__name__)

# Security: max prompt size (in chars) to prevent excessive API costs. A larger prompt is refused.
MAX_PROMPT_LENGTH = 256 * 1024  # 256K chars
# Security: API timeout in seconds
API_TIMEOUT_SECONDS = 120

# Security: max response body size to prevent memory abuse
MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10 MB

# Characters per token used to estimate the size of a request without calling a tokenizer.
CHARS_PER_TOKEN = 3.5

# Model ids that are retired or deprecated; the default must never be one of them.
DEPRECATED_MODELS: tuple[str, ...] = (
    "claude-sonnet-4-20250514",
    "claude-opus-4-20250514",
    "claude-3-7-sonnet-20250219",
    "claude-3-5-sonnet-20241022",
    "claude-3-5-sonnet-20240620",
    "claude-3-5-haiku-20241022",
    "claude-3-opus-20240229",
    "claude-3-sonnet-20240229",
    "claude-3-haiku-20240307",
)

# The OpenAI-compatible client retries these statuses, at most three attempts in all.
_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
_MAX_ATTEMPTS = 3
_BACKOFF_BASE_SECONDS = 1.0
_RETRY_AFTER_CAP_SECONDS = 30.0

# Shared address space (RFC 6598), used by carrier-grade NAT and overlay
# networks such as Tailscale. Not routable on the public internet.
_SHARED_ADDRESS_SPACE = ipaddress.IPv4Network("100.64.0.0/10")

_LOCAL_NETWORK_HINT = (
    "local model servers need provider 'ollama' or 'local' with llm.allow_local_network: true"
)

_MAX_TOKENS_LIMIT = 8192


def estimate_tokens(text: str) -> int:
    """A cheap token estimate: characters divided by 3.5, rounded up."""
    return math.ceil(len(text) / CHARS_PER_TOKEN)


def _validate_base_url(url: str, *, allow_local_network: bool = False) -> None:
    """Validate that a base_url is safe (not SSRF-exploitable).

    Resolves hostname via DNS and checks ALL resolved IPs against the
    ipaddress module. By default only https URLs that resolve to public
    addresses are accepted.

    With ``allow_local_network`` (the explicit opt-in for the ollama and
    local providers), loopback, private and shared (RFC 6598) addresses
    are also accepted, and plain http is allowed for them. Link-local
    (cloud metadata), unspecified, multicast and reserved addresses stay
    blocked either way, and plain http to a public address is rejected.
    """
    parsed = urlparse(url)
    if parsed.scheme == "http" and not allow_local_network:
        raise LLMError(f"Unsafe URL scheme 'http' - only https is allowed; {_LOCAL_NETWORK_HINT}")
    if parsed.scheme not in ("http", "https"):
        allowed = "http/https" if allow_local_network else "https"
        raise LLMError(f"Unsafe URL scheme '{parsed.scheme}' - only {allowed} is allowed")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise LLMError("base_url must include a hostname")

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

    for _family, _type, _proto, _canonname, sockaddr in addrinfo:
        ip_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError as e:
            raise LLMError(f"base_url resolved to invalid IP: {ip_str}") from e

        # Unwrap IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped

        # Order matters: CPython also reports 169.254.0.0/16 and 240.0.0.0/4
        # as private, and ::1 as reserved (it sits in ::/8).
        if addr.is_unspecified:
            raise LLMError(f"base_url resolves to unspecified address ({ip_str})")
        if addr.is_link_local:
            raise LLMError(f"base_url resolves to link-local address ({ip_str})")
        if addr.is_multicast:
            raise LLMError(f"base_url resolves to multicast address ({ip_str})")
        kind: str | None
        if addr.is_loopback:
            kind = "loopback"
        elif addr.is_reserved:
            raise LLMError(f"base_url resolves to reserved address ({ip_str})")
        elif addr.is_private:
            kind = "private"
        elif isinstance(addr, ipaddress.IPv4Address) and addr in _SHARED_ADDRESS_SPACE:
            kind = "shared (RFC 6598)"
        elif not addr.is_global:
            raise LLMError(f"base_url resolves to non-public address ({ip_str})")
        else:
            kind = None  # public

        if kind is None:
            if parsed.scheme == "http":
                raise LLMError(
                    f"plain http is only allowed for loopback or private addresses; "
                    f"'{hostname}' resolves to public address {ip_str} - use https"
                )
        elif not allow_local_network:
            raise LLMError(f"base_url resolves to {kind} address ({ip_str}); {_LOCAL_NETWORK_HINT}")


def _origin(url: str) -> tuple[str, str, int]:
    """Scheme, host and effective port: the unit a redirect must stay inside."""
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    try:
        port = parsed.port
    except ValueError:
        port = None
    return scheme, (parsed.hostname or "").lower(), port or (443 if scheme == "https" else 80)


class _SafeRedirectHandler(HTTPRedirectHandler):
    """Redirect handler that keeps the request, its API key and its body on one origin.

    A redirect to another scheme, host or port is refused: the 307 and 308 codes replay the POST
    body, which holds the redacted but still sensitive infrastructure prompt, and every redirect
    could carry the Authorization header along.
    A redirect inside the original origin (a trailing-slash 308, say) is followed after the same
    SSRF validation the base_url got.
    """

    def __init__(self, origin_url: str, allow_local_network: bool = False) -> None:
        super().__init__()
        self._origin = _origin(origin_url)
        self._allow_local_network = allow_local_network

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        target = _origin(newurl)
        if target != self._origin:
            logger.warning(
                "Refusing redirect from %s://%s:%d to %s://%s:%d: the API key and the request "
                "stay on the configured origin",
                *self._origin,
                *target,
            )
            return None
        _validate_base_url(newurl, allow_local_network=self._allow_local_network)
        new_request: urllib.request.Request | None
        if code in (307, 308) and req.get_method() == "POST":
            # The stdlib never follows these for a POST; inside one origin the call (method and
            # body) is repeated as the server asked, so a local server that redirects to itself
            # keeps working.
            new_request = urllib.request.Request(
                newurl,
                data=req.data,
                headers={k: v for k, v in req.headers.items() if k.lower() != "content-length"},
                origin_req_host=req.origin_req_host,
                unverifiable=True,
                method="POST",
            )
        else:
            new_request = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_request is not None and target != _origin(req.full_url):
            # Unreachable while the origin is fixed; kept so a future relaxation cannot leak it.
            new_request.headers.pop("Authorization", None)
            new_request.unredirected_hdrs.pop("Authorization", None)
        return new_request


def _clamp_max_tokens(max_tokens: int) -> int:
    if not 1 <= max_tokens <= _MAX_TOKENS_LIMIT:
        logger.warning(
            "max_tokens %d out of range [1, %d], clamping", max_tokens, _MAX_TOKENS_LIMIT
        )
    return max(1, min(max_tokens, _MAX_TOKENS_LIMIT))


def _check_prompt_size(prompt: str) -> None:
    """Refuse an oversized prompt instead of cutting it: a sliced JSON payload is corrupt."""
    if len(prompt) > MAX_PROMPT_LENGTH:
        raise LLMError(
            f"The prompt is {len(prompt)} characters, over the {MAX_PROMPT_LENGTH} limit; "
            "the infrastructure is too large to send in one request"
        )


class BaseLLMClient(ABC):
    """What the LLM phase needs from a client.

    ``provider`` and ``model`` name the backend in the report; a client that does not set them
    leaves the names from the configuration in place.
    """

    provider: str = ""
    model: str = ""

    @abstractmethod
    def analyze(self, prompt: str) -> str:
        """Send prompt and return raw response text."""
        ...


def _is_temperature_rejection(error: Exception) -> bool:
    """Whether the API refused the request because it names a temperature."""
    status = getattr(error, "status_code", None)
    return status == 400 and "temperature" in str(error).lower()


class AnthropicLLMClient(BaseLLMClient):
    """Claude API client via the anthropic SDK.

    The default model is ``claude-sonnet-5-5``.
    Temperature is sent only when configured, and a 400 that names it is retried once without it.
    The reply is the joined text of every text block (thinking blocks are skipped); a refusal or
    a reply without text raises ``LLMError``.
    ``ANTHROPIC_BASE_URL`` and ``base_url`` go through the SSRF validator before the SDK sees them.
    """

    provider = "anthropic"

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_LLM_MODEL,
        max_tokens: int = 4096,
        timeout: int = API_TIMEOUT_SECONDS,
        temperature: float | None = None,
        max_retries: int = DEFAULT_LLM_MAX_RETRIES,
        base_url: str = "",
        allow_local_network: bool = False,
    ) -> None:
        try:
            import anthropic
        except ImportError as e:
            raise LLMError(
                "The anthropic SDK is not installed. Install it with: pip install 'threatcode[llm]'"
            ) from e

        if model in DEPRECATED_MODELS:
            logger.warning(
                "Model '%s' is deprecated; set llm.model to a current one such as '%s'",
                model,
                DEFAULT_LLM_MODEL,
            )

        # The SDK reads ANTHROPIC_BASE_URL itself, so the value is validated here and passed on
        # explicitly: nothing reaches the SDK unchecked.
        resolved_url = base_url or os.environ.get("ANTHROPIC_BASE_URL", "").strip()
        if resolved_url:
            _validate_base_url(resolved_url, allow_local_network=allow_local_network)

        self._client = anthropic.Anthropic(
            api_key=api_key,
            timeout=float(timeout),
            max_retries=max_retries,
            base_url=resolved_url or None,
        )
        self.model = model
        self._model = model
        self._max_tokens = _clamp_max_tokens(max_tokens)
        self._timeout = timeout
        self._temperature = None if temperature is None else max(0.0, min(temperature, 1.0))
        self._temperature_as_kwarg = _create_accepts_temperature(self._client)

    def analyze(self, prompt: str) -> str:
        _check_prompt_size(prompt)

        send_temperature = self._temperature is not None
        for _attempt in range(2):
            kwargs: dict[str, Any] = {
                "model": self._model,
                "max_tokens": self._max_tokens,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": prompt}],
            }
            if send_temperature:
                if self._temperature_as_kwarg:
                    kwargs["temperature"] = self._temperature
                else:
                    # Current SDK signatures no longer list temperature; the API still takes it.
                    kwargs["extra_body"] = {"temperature": self._temperature}
            try:
                message = self._client.messages.create(**kwargs)
            except Exception as e:
                if send_temperature and _is_temperature_rejection(e):
                    logger.warning(
                        "The model rejected the temperature setting; retrying once without it. "
                        "Remove llm.temperature to stop sending it."
                    )
                    send_temperature = False
                    continue
                raise LLMError(f"Anthropic API call failed: {e}") from e
            return self._text_of(message)
        raise LLMError("Anthropic API call failed: the temperature retry did not complete")

    def _text_of(self, message: Any) -> str:
        stop_reason = getattr(message, "stop_reason", None)
        if stop_reason == "refusal":
            raise LLMError("The model refused the request (stop_reason: refusal)")

        texts: list[str] = []
        for block in getattr(message, "content", None) or []:
            block_type = getattr(block, "type", None)
            text = getattr(block, "text", None)
            if isinstance(text, str) and (block_type == "text" or block_type is None):
                texts.append(text)
        if not texts:
            raise LLMError("Anthropic API returned no text content block")

        if stop_reason == "max_tokens":
            logger.warning(
                "The model reply was cut off at max_tokens (%d); complete findings are kept, "
                "raise llm.max_tokens for the rest",
                self._max_tokens,
            )
        return "".join(texts)


def _create_accepts_temperature(client: Any) -> bool:
    """Whether ``messages.create`` takes ``temperature`` by name (older SDKs) or **kwargs."""
    try:
        parameters = inspect.signature(client.messages.create).parameters
    except (TypeError, ValueError, AttributeError):
        return True
    return "temperature" in parameters or any(
        p.kind is inspect.Parameter.VAR_KEYWORD for p in parameters.values()
    )


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


def _retry_delay(attempt: int, retry_after: str | None) -> float:
    """Seconds to wait before attempt ``attempt + 1``: Retry-After when sent, else backoff."""
    if retry_after:
        try:
            return max(0.0, min(float(retry_after.strip()), _RETRY_AFTER_CAP_SECONDS))
        except ValueError:
            pass
    base = _BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
    delay: float = base + random.uniform(0.0, base / 2)
    return min(delay, _RETRY_AFTER_CAP_SECONDS)


class OpenAICompatibleLLMClient(BaseLLMClient):
    """OpenAI-compatible API client (OpenAI, Ollama, vLLM, llama.cpp, etc.).

    A request without an API key carries no Authorization header.
    HTTP 429 and 5xx are retried with exponential backoff and jitter (Retry-After honored within a
    cap), at most three attempts in all and no more than ``max_retries`` retries.
    A redirect to another origin is refused, so the key and the body are never forwarded.
    """

    provider = "openai"

    def __init__(
        self,
        base_url: str,
        api_key: str = "",
        model: str = "llama3",
        max_tokens: int = 4096,
        timeout: int = API_TIMEOUT_SECONDS,
        temperature: float | None = None,
        allow_local_network: bool = False,
        max_retries: int = DEFAULT_LLM_MAX_RETRIES,
        provider: str = "openai",
    ) -> None:
        _validate_base_url(base_url, allow_local_network=allow_local_network)
        # The name the report shows: "ollama" or "local" for a self-hosted server.
        self.provider = provider
        # "not-needed" was the placeholder an older version sent; it still means no key.
        self._api_key = "" if api_key == "not-needed" else api_key
        if urlparse(base_url).scheme == "http" and self._api_key:
            logger.warning(
                "base_url uses plain http - the API key will be sent unencrypted. "
                "Use https if the server needs a key."
            )
        # Accept base_url with or without the /v1 suffix: OpenAI and Ollama both
        # document theirs as ending in /v1.
        self._base_url = base_url.rstrip("/").removesuffix("/v1")
        self._allow_local_network = allow_local_network
        self._model = model
        self.model = model
        self._max_tokens = _clamp_max_tokens(max_tokens)
        self._timeout = timeout
        self._temperature = None if temperature is None else max(0.0, min(temperature, 2.0))
        self._attempts = 1 + max(0, min(max_retries, _MAX_ATTEMPTS - 1))
        # OpenAI's own endpoint takes max_completion_tokens; servers that mimic it take max_tokens.
        self._token_parameter = (
            "max_completion_tokens"
            if (urlparse(base_url).hostname or "").lower() == "api.openai.com"
            else "max_tokens"
        )

    def analyze(self, prompt: str) -> str:
        _check_prompt_size(prompt)

        payload: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            self._token_parameter: self._max_tokens,
        }
        if self._temperature is not None:
            payload["temperature"] = self._temperature
        body = json.dumps(payload).encode()

        url = f"{self._base_url}/v1/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        for attempt in range(1, self._attempts + 1):
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            try:
                return self._send(req)
            except urllib.error.HTTPError as e:
                status = e.code
                retry_after = e.headers.get("Retry-After") if e.headers else None
                e.close()
                if status in _RETRY_STATUSES and attempt < self._attempts:
                    delay = _retry_delay(attempt, retry_after)
                    logger.warning(
                        "The model server answered HTTP %d; retrying in %.1fs (attempt %d of %d)",
                        status,
                        delay,
                        attempt + 1,
                        self._attempts,
                    )
                    _sleep(delay)
                    continue
                raise LLMError(
                    f"OpenAI-compatible API call failed: HTTP {status} {e.reason}"
                ) from e
            except (TimeoutError, OSError) as e:
                # URLError is an OSError, so a timeout, a refused connection and a reset all land
                # here and none escapes as a bare exception.
                raise LLMError(f"OpenAI-compatible API call failed: {e}") from e
            except (KeyError, IndexError, TypeError, json.JSONDecodeError, UnicodeDecodeError) as e:
                raise LLMError(f"OpenAI-compatible API call failed: {e}") from e
        raise LLMError("OpenAI-compatible API call failed: no attempt completed")

    def _send(self, req: urllib.request.Request) -> str:
        opener = urllib.request.build_opener(
            _SafeRedirectHandler(self._base_url, self._allow_local_network)
        )
        with opener.open(req, timeout=self._timeout) as resp:
            raw_bytes = resp.read(MAX_RESPONSE_SIZE + 1)
        if len(raw_bytes) > MAX_RESPONSE_SIZE:
            raise LLMError(f"Response body exceeds {MAX_RESPONSE_SIZE} byte limit")
        data = json.loads(raw_bytes.decode("utf-8"))
        choice = data["choices"][0]
        content = choice["message"]["content"]
        if not isinstance(content, str):
            raise LLMError("OpenAI-compatible API returned no text content")
        if choice.get("finish_reason") == "length":
            logger.warning(
                "The model reply was cut off at max tokens (%d); complete findings are kept, "
                "raise llm.max_tokens for the rest",
                self._max_tokens,
            )
        return content


class DryRunLLMClient(BaseLLMClient):
    """Writes the exact request that would be sent, then returns no threats.

    The payload is already pseudonymized and redacted when it gets here, so it is safe to show:
    printing it is how a person audits what would leave the machine.
    It goes to ``output`` when given, else to stderr (stdout carries the report), as JSON with the
    system prompt and the user message.
    A summary of sizes and the token estimate goes to stderr either way.
    Nothing touches the network.
    """

    provider = "dry-run"

    def __init__(self, output: str | None = None) -> None:
        self._output = output

    def analyze(self, prompt: str) -> str:
        request = {
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": prompt}],
        }
        text = json.dumps(request, indent=2, ensure_ascii=False) + "\n"
        if self._output:
            try:
                Path(self._output).write_text(text, encoding="utf-8")
            except OSError as e:
                raise LLMError(f"Cannot write the dry-run request to {self._output}: {e}") from e
            where = f"The exact request was written to {self._output}; none was sent\n"
        else:
            sys.stderr.write(text)
            where = "The exact request is printed above; none was sent\n"

        estimate = estimate_tokens(SYSTEM_PROMPT) + estimate_tokens(prompt)
        sys.stderr.write("=== DRY RUN: LLM request ===\n")
        sys.stderr.write(f"System prompt length: {len(SYSTEM_PROMPT)} chars\n")
        sys.stderr.write(f"Analysis prompt length: {len(prompt)} chars\n")
        sys.stderr.write(f"Estimated input size: about {estimate} tokens\n")
        sys.stderr.write(where)
        sys.stderr.write("=== END DRY RUN ===\n")
        logger.debug(
            "DryRun: system_prompt_len=%d, analysis_prompt_len=%d",
            len(SYSTEM_PROMPT),
            len(prompt),
        )
        return '{"threats": []}'
