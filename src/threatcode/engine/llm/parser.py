"""Structured JSON response parser for LLM output."""

from __future__ import annotations

import json
import re
from typing import Any

VALID_STRIDE = {
    "spoofing",
    "tampering",
    "repudiation",
    "information_disclosure",
    "denial_of_service",
    "elevation_of_privilege",
}
VALID_SEVERITY = {"critical", "high", "medium", "low", "info"}


def parse_llm_threats(response: str) -> list[dict[str, Any]]:
    """Parse and validate LLM response into threat dicts."""
    data = _extract_json(response)
    if not isinstance(data, dict) or "threats" not in data:
        return []

    threats: list[dict[str, Any]] = []
    for raw in data["threats"]:
        if not isinstance(raw, dict):
            continue
        threat = _validate_threat(raw)
        if threat:
            threats.append(threat)
    return threats


def _extract_json(text: str) -> Any:
    """Extract JSON from LLM response, handling markdown code blocks."""
    # Try direct parse
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
    if stride not in VALID_STRIDE:
        stride = "tampering"

    severity = raw.get("severity", "medium").lower().strip()
    if severity not in VALID_SEVERITY:
        severity = "medium"

    confidence = raw.get("confidence", 0.7)
    if not isinstance(confidence, int | float) or not 0 <= confidence <= 1:
        confidence = 0.7

    return {
        "title": title,
        "description": raw.get("description", "").strip(),
        "stride_category": stride,
        "severity": severity,
        "resource_type": raw.get("resource_type", "").strip(),
        "resource_address": raw.get("resource_address", "").strip(),
        "mitigation": raw.get("mitigation", "").strip(),
        "confidence": confidence,
    }
