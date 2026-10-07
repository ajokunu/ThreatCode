"""LLM phase of the analysis pipeline.

``run_llm_phase`` redacts the graph, asks the model for additional threats,
validates what comes back and reports how the phase went. It never raises: a
failed call returns no threats and a ``failed`` status, so rule results are
always kept.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from threatcode.engine.mitre import tactics_for_techniques
from threatcode.exceptions import LLMError
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import Severity, Threat, ThreatSource, hash_id

if TYPE_CHECKING:
    from threatcode.config import ThreatCodeConfig
    from threatcode.engine.llm.client import BaseLLMClient

logger = logging.getLogger(__name__)

_MAX_ERROR_LENGTH = 500


def run_llm_phase(
    graph: InfraGraph,
    threats: list[Threat],
    client: BaseLLMClient | None,
    config: ThreatCodeConfig | None,
) -> tuple[list[Threat], dict[str, Any]]:
    """Run LLM-augmented threat analysis.

    ``threats`` are the findings gathered before this phase; their rule ids are
    passed to the model so it does not repeat them. Returns the new LLM threats
    and a status mapping with ``provider``, ``model``, ``status`` (``ran``,
    ``skipped`` or ``failed``), ``error`` and ``threat_count``.
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
        llm_threats = _analyze(graph, threats, client, config)
    except LLMError as e:
        # Expected failures (server down, bad response): one line, no traceback.
        logger.warning("LLM analysis failed (%s) - returning rule-based results only", e)
        status["status"] = "failed"
        status["error"] = str(e)[:_MAX_ERROR_LENGTH]
        return [], status
    except Exception as e:
        logger.exception("LLM analysis failed - returning rule-based results only")
        status["status"] = "failed"
        status["error"] = f"{type(e).__name__}: {e}"[:_MAX_ERROR_LENGTH]
        return [], status

    status["status"] = "ran"
    status["threat_count"] = len(llm_threats)
    return llm_threats, status


def _describe_client(
    client: BaseLLMClient | None, config: ThreatCodeConfig | None
) -> tuple[str, str]:
    """Best-effort provider and model names for the status block."""
    config_provider = config.llm.provider if config else ""
    config_model = config.llm.model if config else ""
    if client is None:
        return config_provider, config_model

    class_name = type(client).__name__
    provider = getattr(client, "provider", None)
    if not isinstance(provider, str) or not provider:
        if class_name == "DryRunLLMClient":
            provider = "dry-run"
        elif class_name == "AnthropicLLMClient":
            provider = "anthropic"
        else:
            provider = config_provider
    model = getattr(client, "model", None)
    if not isinstance(model, str) or not model:
        model = getattr(client, "_model", None)
    if not isinstance(model, str) or not model:
        model = "" if provider == "dry-run" else config_model
    return provider, model


def _analyze(
    graph: InfraGraph,
    existing_threats: list[Threat],
    client: BaseLLMClient,
    config: ThreatCodeConfig | None,
) -> list[Threat]:
    from threatcode.engine.llm.parser import parse_llm_threats
    from threatcode.engine.llm.prompts import build_analysis_prompt
    from threatcode.engine.llm.redactor import Redactor

    strategy = "placeholder"
    if config and config.redaction:
        strategy = config.redaction.strategy
    redactor = Redactor(strategy=strategy)
    graph_data = graph.to_dict()
    redacted_data = redactor.redact(graph_data)
    existing_ids = {t.rule_id for t in existing_threats if t.rule_id}

    prompt = build_analysis_prompt(redacted_data, existing_ids)
    response = client.analyze(prompt)

    raw_threats = parse_llm_threats(response)

    # Build set of known resource addresses for validation
    known_addresses = set(graph.nodes.keys())

    threats: list[Threat] = []
    for raw in raw_threats:
        # Unredact LLM-sourced fields that may contain redacted placeholders
        address = redactor.unredact_string(raw.get("resource_address", ""))
        raw["title"] = redactor.unredact_string(raw.get("title", ""))
        raw["description"] = redactor.unredact_string(raw.get("description", ""))
        raw["mitigation"] = redactor.unredact_string(raw.get("mitigation", ""))
        confidence = raw.get("confidence", 0.7)

        # Cap confidence if resource_address is not in the graph
        if address and address not in known_addresses:
            logger.debug(
                "LLM threat references unknown resource '%s' — capping confidence at 0.5",
                address,
            )
            confidence = min(confidence, 0.5)

        techniques = raw.get("mitre_techniques", [])
        tactics = raw.get("mitre_tactics", [])
        if techniques and not tactics:
            tactics = tactics_for_techniques(techniques)
        try:
            sev = Severity(raw.get("severity", "medium"))
        except ValueError:
            sev = Severity.MEDIUM
        try:
            threat = Threat(
                id=hash_id(f"LLM_{address}_{raw.get('title', '')}"),
                title=raw.get("title", "LLM-identified threat"),
                description=raw.get("description", ""),
                stride_category=raw.get("stride_category", "tampering"),
                severity=sev,
                source=ThreatSource.LLM,
                resource_type=raw.get("resource_type", ""),
                resource_address=address,
                mitigation=raw.get("mitigation", ""),
                confidence=confidence,
                mitre_techniques=techniques,
                mitre_tactics=tactics,
            )
        except ValueError as e:
            # The parser already filters unknown STRIDE categories; a bad item
            # that gets through anyway is dropped rather than failing the phase.
            logger.warning("Dropping invalid LLM threat: %s", e)
            continue
        threats.append(threat)
    return threats
