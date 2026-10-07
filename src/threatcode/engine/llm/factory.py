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

from threatcode.exceptions import LLMError

if TYPE_CHECKING:
    from threatcode.config import ResolvedSettings
    from threatcode.engine.llm.client import BaseLLMClient

logger = logging.getLogger(__name__)

__all__ = ["build_client"]


def build_client(settings: ResolvedSettings) -> BaseLLMClient | None:
    """Build the client for the provider in ``settings.config.llm``.

    Returns the dry-run client when ``settings.dry_run`` is set, so the request is built and
    nothing leaves the machine.
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
    if settings.dry_run:
        return DryRunLLMClient()

    if config.llm.provider == "anthropic":
        api_key = config.llm.api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            logger.warning(
                "No Anthropic API key: set ANTHROPIC_API_KEY or drop --llm. "
                "Continuing with rules only."
            )
            return None
        return AnthropicLLMClient(
            api_key=api_key,
            model=config.llm.model,
            max_tokens=config.llm.max_tokens,
            temperature=config.llm.temperature,
        )

    if config.llm.provider in ("openai", "ollama", "local"):
        if not config.llm.base_url:
            raise LLMError(f"provider '{config.llm.provider}' requires llm.base_url")
        return OpenAICompatibleLLMClient(
            base_url=config.llm.base_url,
            api_key=config.llm.api_key,
            model=config.llm.model,
            max_tokens=config.llm.max_tokens,
            temperature=config.llm.temperature,
            # Config validation already limits this to ollama and local.
            allow_local_network=config.llm.allow_local_network,
        )

    logger.warning(
        "Unknown LLM provider '%s'. Supported: anthropic, openai, ollama, local. "
        "Continuing with rules only.",
        config.llm.provider,
    )
    return None
