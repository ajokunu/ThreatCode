"""Build the LLM client a scan uses.

``build_client(settings)`` is called only when the LLM is requested: ``--llm``, ``llm.enabled`` in
an explicit config, ``THREATCODE_LLM=1``, or ``--dry-run``.
A scan that does not ask for the LLM never reaches this module, so nothing is sent anywhere and no
API key is read.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

from threatcode.config import DEFAULT_LLM_MODEL
from threatcode.exceptions import LLMError

if TYPE_CHECKING:
    from threatcode.config import LLMConfig, ResolvedSettings
    from threatcode.engine.llm.client import BaseLLMClient

logger = logging.getLogger(__name__)

__all__ = ["build_client", "resolve_api_key"]


OPENAI_DEFAULT_BASE_URL = "https://api.openai.com"


def resolve_api_key(llm: LLMConfig) -> str:
    """The key for ``llm``: ``llm.api_key``, else the variable ``llm.api_key_env`` names.

    The variable defaults to ANTHROPIC_API_KEY for anthropic and OPENAI_API_KEY for openai; the
    ollama and local providers read none unless ``api_key_env`` is set.
    """
    if llm.api_key:
        return llm.api_key
    variable = llm.api_key_variable()
    return os.environ.get(variable, "").strip() if variable else ""


def build_client(settings: ResolvedSettings) -> BaseLLMClient | None:
    """Build the client for the provider in ``settings.config.llm``.

    Returns the dry-run client when ``settings.dry_run`` is set, so the request is built and
    nothing leaves the machine; it writes the request to ``settings.dry_run_output`` when that is
    given.
    Returns None (after a warning) when the provider needs an API key that is not set or the
    provider is unknown, so the scan continues with rules only.

    Raises:
        LLMError: The provider configuration is invalid or the SDK is not installed.
    """
    from threatcode.engine.llm.client import (
        AnthropicLLMClient,
        DryRunLLMClient,
        OpenAICompatibleLLMClient,
    )

    config = settings.config
    llm = config.llm
    if settings.dry_run:
        return DryRunLLMClient(output=settings.dry_run_output)

    if llm.provider == "anthropic":
        api_key = resolve_api_key(llm)
        if not api_key:
            variable = llm.api_key_variable()
            logger.warning(
                "No Anthropic API key: set %s or drop --llm. Continuing with rules only.", variable
            )
            return None
        return AnthropicLLMClient(
            api_key=api_key,
            model=llm.model,
            max_tokens=llm.max_tokens,
            timeout=llm.timeout,
            temperature=llm.temperature,
            max_retries=llm.max_retries,
            base_url=llm.base_url,
            allow_local_network=llm.allow_local_network,
        )

    if llm.provider in ("openai", "ollama", "local"):
        base_url = llm.base_url
        if not base_url and llm.provider == "openai":
            base_url = OPENAI_DEFAULT_BASE_URL
        if not base_url:
            raise LLMError(f"provider '{llm.provider}' requires llm.base_url")
        api_key = resolve_api_key(llm)
        if (
            llm.provider == "openai"
            and not api_key
            and base_url.startswith(OPENAI_DEFAULT_BASE_URL)
        ):
            logger.warning(
                "No OpenAI API key: set %s or drop --llm. Continuing with rules only.",
                llm.api_key_variable(),
            )
            return None
        if llm.model == DEFAULT_LLM_MODEL:
            logger.warning(
                "llm.model is '%s', a Claude model, but the provider is '%s'; "
                "set llm.model to a model that server serves",
                llm.model,
                llm.provider,
            )
        return OpenAICompatibleLLMClient(
            base_url=base_url,
            api_key=api_key,
            model=llm.model,
            max_tokens=llm.max_tokens,
            timeout=llm.timeout,
            temperature=llm.temperature,
            # Config validation already limits this to ollama, local and anthropic.
            allow_local_network=llm.allow_local_network,
            max_retries=llm.max_retries,
        )

    logger.warning(
        "Unknown LLM provider '%s'. Supported: anthropic, openai, ollama, local. "
        "Continuing with rules only.",
        llm.provider,
    )
    return None
