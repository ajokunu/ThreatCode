"""Structured JSON response parser for LLM output.

Security: All LLM output is parsed as JSON only, never executed.
Response length is bounded. Schema validation is strict — unknown
keys are silently dropped, invalid values get safe defaults.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from threatcode.constants import VALID_SEVERITIES, VALID_STRIDE_CATEGORIES

logger = logging.getLogger(__name__)

# Security: reject LLM responses over 512 KB to prevent memory abuse
MAX_RESPONSE_LENGTH = 512 * 1024
# Security: cap the number of threats from a single LLM response
MAX_LLM_THREATS = 100

# Known threat fields — anything else is dropped
_ALLOWED_THREAT_KEYS = {
    "title",
    "description",
    "stride_category",
    "severity",
    "resource_type",
    "resource_address",
    "mitigation",
    "confidence",
    "mitre_techniques",
    "mitre_tactics",
}


def parse_llm_threats(response: str) -> list[dict[str, Any]]:
    """Parse and validate LLM response into threat dicts.

    Security controls:
    - Response length bounded by MAX_RESPONSE_LENGTH
    - JSON-only parsing (no eval, no exec)
    - Strict schema validation — unknown keys dropped
    - Output count bounded by MAX_LLM_THREATS
    """
    if len(response) > MAX_RESPONSE_LENGTH:
        logger.warning(
            "LLM response truncated: %d bytes exceeds %d byte limit",
            len(response),
            MAX_RESPONSE_LENGTH,
        )
        response = response[:MAX_RESPONSE_LENGTH]

    data = _extract_json(response)
    if not isinstance(data, dict) or "threats" not in data:
        return []

    raw_list = data["threats"]
    if not isinstance(raw_list, list):
        return []

    threats: list[dict[str, Any]] = []
    for raw in raw_list[:MAX_LLM_THREATS]:
        if not isinstance(raw, dict):
            continue
        threat = _validate_threat(raw)
        if threat:
            threats.append(threat)

    if len(raw_list) > MAX_LLM_THREATS:
        logger.warning(
            "LLM returned %d threats, capped at %d", len(raw_list), MAX_LLM_THREATS
        )

    return threats


def _extract_json(text: str) -> Any:
    """Extract JSON from LLM response, handling markdown code blocks.

    Security: only json.loads() is used — never eval(), yaml.load(), or exec().
    """
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try extracting from ```json ... ``` blocks
    match = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1).strip())
        except json.JSONDecodeError:
            pass

    # Try finding first { ... } block
    brace_start = text.find("{")
    brace_end = text.rfind("}")
    if brace_start != -1 and brace_end > brace_start:
        try:
            return json.loads(text[brace_start : brace_end + 1])
        except json.JSONDecodeError:
            pass

    return {}


def _validate_threat(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Validate and normalize a single threat dict."""
    title = raw.get("title", "").strip()
    if not title:
        return None

    stride = raw.get("stride_category", "").lower().strip()
    if stride not in VALID_STRIDE_CATEGORIES:
        stride = "tampering"

    severity = raw.get("severity", "medium").lower().strip()
    if severity not in VALID_SEVERITIES:
        severity = "medium"

    confidence = raw.get("confidence", 0.7)
    if not isinstance(confidence, int | float) or not 0 <= confidence <= 1:
        confidence = 0.7

    techniques = raw.get("mitre_techniques", [])
    if not isinstance(techniques, list):
        techniques = []
    techniques = [t for t in techniques if isinstance(t, str) and t.startswith("T")]

    tactics = raw.get("mitre_tactics", [])
    if not isinstance(tactics, list):
        tactics = []
    tactics = [t for t in tactics if isinstance(t, str) and t.startswith("TA")]

    return {
        "title": title,
        "description": raw.get("description", "").strip(),
        "stride_category": stride,
        "severity": severity,
        "resource_type": raw.get("resource_type", "").strip(),
        "resource_address": raw.get("resource_address", "").strip(),
        "mitigation": raw.get("mitigation", "").strip(),
        "confidence": confidence,
        "mitre_techniques": techniques,
        "mitre_tactics": tactics,
    }
