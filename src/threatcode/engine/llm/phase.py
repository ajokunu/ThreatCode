"""LLM phase of the analysis pipeline.

``run_llm_phase`` serializes the graph into a pseudonymous, redacted, budgeted context, asks the
model for additional threats, parses and merges what comes back and reports how the phase went.
It never raises: a failed call returns no threats and a ``failed`` status, so rule results are
always kept.

The status mapping holds ``provider``, ``model``, ``status`` (``ran``, ``skipped`` or ``failed``),
``error``, ``threat_count`` and, once a request was built, the redaction strategy, a hash of the
prompt (with the per-request delimiter held constant, so the same input hashes the same), the
estimated input size, what the budget summarized or dropped, how many items were skipped,
salvaged, deduplicated or left unattributed, and the unattributed items themselves.
"""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING, Any

from threatcode.config import LLMConfig, RedactionConfig
from threatcode.engine.llm.client import CHARS_PER_TOKEN, estimate_tokens
from threatcode.engine.llm.context import build_context
from threatcode.engine.llm.merge import merge_llm_threats
from threatcode.engine.llm.parser import parse_llm_response
from threatcode.engine.llm.prompts import (
    SYSTEM_PROMPT,
    build_analysis_prompt,
    new_delimiter,
    prompt_overhead_chars,
)
from threatcode.engine.llm.redactor import Redactor
from threatcode.exceptions import LLMError
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import Threat

if TYPE_CHECKING:
    from threatcode.config import ThreatCodeConfig
    from threatcode.engine.llm.client import BaseLLMClient

logger = logging.getLogger(__name__)

_MAX_ERROR_LENGTH = 500
# Below this many characters of JSON there is no room for even one resource.
_MIN_CONTEXT_CHARS = 2_000
_CANONICAL_DELIMITER = "infrastructure_data_0000000000000000"


def run_llm_phase(
    graph: InfraGraph,
    threats: list[Threat],
    client: BaseLLMClient | None,
    config: ThreatCodeConfig | None,
) -> tuple[list[Threat], dict[str, Any]]:
    """Run LLM-augmented threat analysis.

    ``threats`` are the findings gathered before this phase; the ids of the rules that fired on
    each resource are shown to the model so it does not repeat them, and a model finding that
    restates one is dropped.
    Returns the new LLM threats and a status mapping (see the module docstring).
    """
    provider, model = _describe_client(client, config)
    status: dict[str, Any] = {
        "provider": provider,
        "model": model,
        "status": "skipped",
        "error": "",
        "threat_count": 0,
    }
    if client is None:
        return [], status

    try:
        llm_threats = _analyze(graph, threats, client, config, status)
    except LLMError as e:
        # Expected failures (server down, bad response): one line, no traceback.
        logger.warning("LLM analysis failed (%s) - returning rule-based results only", e)
        status["status"] = "failed"
        status["error"] = str(e)[:_MAX_ERROR_LENGTH]
        status["threat_count"] = 0
        return [], status
    except Exception as e:
        logger.exception("LLM analysis failed - returning rule-based results only")
        status["status"] = "failed"
        status["error"] = f"{type(e).__name__}: {e}"[:_MAX_ERROR_LENGTH]
        status["threat_count"] = 0
        return [], status

    status["status"] = "ran"
    status["threat_count"] = len(llm_threats)
    return llm_threats, status


def _describe_client(
    client: BaseLLMClient | None, config: ThreatCodeConfig | None
) -> tuple[str, str]:
    """Provider and model names for the status block: the client's own, else the configuration's."""
    config_provider = config.llm.provider if config else ""
    config_model = config.llm.model if config else ""
    if client is None:
        return config_provider, config_model

    provider = getattr(client, "provider", "")
    if not isinstance(provider, str) or not provider:
        provider = config_provider
    model = getattr(client, "model", "")
    if not isinstance(model, str) or not model:
        model = "" if provider == "dry-run" else config_model
    return provider, model


def _analyze(
    graph: InfraGraph,
    existing_threats: list[Threat],
    client: BaseLLMClient,
    config: ThreatCodeConfig | None,
    status: dict[str, Any],
) -> list[Threat]:
    llm_config = config.llm if config else LLMConfig()
    redaction = config.redaction if config else RedactionConfig()
    redactor = Redactor(strategy=redaction.strategy, extra_fields=redaction.fields)
    status["redaction"] = redaction.strategy

    # The token limit covers the system prompt and the text around the JSON as well.
    limit = llm_config.max_input_tokens
    budget_chars = int(limit * CHARS_PER_TOKEN) - len(SYSTEM_PROMPT) - prompt_overhead_chars()
    if budget_chars < _MIN_CONTEXT_CHARS:
        raise LLMError(
            f"llm.max_input_tokens ({limit}) leaves no room for the infrastructure context"
        )

    context = build_context(graph, existing_threats, redactor, max_chars=budget_chars)
    status["context"] = context.stats.to_dict()

    prompt = build_analysis_prompt(context.data, delimiter=new_delimiter())
    canonical = build_analysis_prompt(context.data, delimiter=_CANONICAL_DELIMITER)
    status["prompt_hash"] = hashlib.sha256((SYSTEM_PROMPT + "\n" + canonical).encode()).hexdigest()[
        :16
    ]
    estimate = estimate_tokens(SYSTEM_PROMPT) + estimate_tokens(prompt)
    status["input_tokens_estimate"] = estimate
    if estimate > limit:
        raise LLMError(
            f"The request is about {estimate} tokens, over llm.max_input_tokens ({limit}); "
            "nothing was sent"
        )
    logger.info("Sending about %d input tokens to the model", estimate)

    response = client.analyze(prompt)

    parsed = parse_llm_response(response)
    merged = merge_llm_threats(parsed.threats, graph, existing_threats, context.addresses, redactor)
    status["parsed_count"] = len(parsed.threats)
    status["skipped_items"] = parsed.skipped
    status["salvaged_items"] = parsed.salvaged
    status["duplicate_count"] = merged.duplicates
    status["unattributed_count"] = merged.unattributed_count
    status["unattributed"] = merged.unattributed
    if merged.unattributed_count:
        logger.warning(
            "%d LLM finding(s) named no resource in the scan and were set aside "
            "(see llm.unattributed in the report)",
            merged.unattributed_count,
        )
    return merged.threats
