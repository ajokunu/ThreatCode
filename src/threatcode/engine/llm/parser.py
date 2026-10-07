"""Structured JSON response parser for LLM output.

Security: All LLM output is parsed as JSON only, never executed.
Response length is bounded. Schema validation is strict: unknown keys are silently dropped,
invalid values get safe defaults, and every item is validated on its own so one malformed item
never costs the rest of the batch.
Text fields are cleaned before they reach a report: links, code blocks and shell metacharacter
runs are removed and lengths are capped.
MITRE IDs are normalized (a revoked ID maps to its successor) and validated against the known
technique and tactic databases.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from threatcode.constants import VALID_SEVERITIES, VALID_STRIDE_CATEGORIES
from threatcode.engine.mitre import (
    TACTIC_DB,
    TECHNIQUE_DB,
    is_deprecated,
    is_revoked,
    normalize_technique,
)

logger = logging.getLogger(__name__)

# Security: reject LLM responses over 512 KB to prevent memory abuse
MAX_RESPONSE_LENGTH = 512 * 1024
# Security: cap the number of threats from a single LLM response
MAX_LLM_THREATS = 100

# Length caps on model-written text, so one reply cannot flood a report.
MAX_TITLE_LENGTH = 200
MAX_DESCRIPTION_LENGTH = 2000
MAX_MITIGATION_LENGTH = 1000
MAX_FIELD_LENGTH = 200

_THREATS_KEY = re.compile(r'"threats"\s*:\s*\[')
_CODE_BLOCK = re.compile(r"```.*?```", re.DOTALL)
_MARKDOWN_LINK = re.compile(r"\[([^\]\n]*)\]\([^)\n]*\)")
_URL = re.compile(r"(?:\b[a-zA-Z][a-zA-Z0-9+.\-]{1,15}://|\bwww\.)[^\s<>\"')\]]+")
# Runs of shell operators ("&&", "||", "; rm", "$(") are never prose.
_SHELL_RUN = re.compile(r"[;&|`$<>\\]{2,}|\$[({]")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Bidi overrides can disguise the direction of text.
_BIDI = re.compile(r"[‎‏‪-‮⁦-⁩]")
_SPACES = re.compile(r"[ \t]{2,}")
_BLANK_LINES = re.compile(r"\n{3,}")


@dataclass
class ParseResult:
    """What a response held: the valid items and how the rest went."""

    threats: list[dict[str, Any]] = field(default_factory=list)
    # Items that were not usable (wrong type, no title, failed validation).
    skipped: int = 0
    # Items recovered from a reply that was cut off before its closing brackets.
    salvaged: int = 0
    # False when no JSON could be read at all.
    parsed: bool = True


def parse_llm_threats(response: str) -> list[dict[str, Any]]:
    """Parse and validate LLM response into threat dicts.

    Security controls:
    - Response length bounded by MAX_RESPONSE_LENGTH
    - JSON-only parsing (no eval, no exec)
    - Strict schema validation - unknown keys dropped, every field type-checked
    - Output count bounded by MAX_LLM_THREATS
    - MITRE IDs normalized and validated against known databases
    """
    return parse_llm_response(response).threats


def parse_llm_response(response: str) -> ParseResult:
    """Like ``parse_llm_threats``, also reporting skipped and salvaged items."""
    result = ParseResult()
    if len(response) > MAX_RESPONSE_LENGTH:
        logger.warning(
            "LLM response truncated: %d chars exceeds %d char limit - output may be incomplete",
            len(response),
            MAX_RESPONSE_LENGTH,
        )
        response = response[:MAX_RESPONSE_LENGTH]

    raw_list = _threat_list(response, result)
    if raw_list is None:
        return result

    for index, raw in enumerate(raw_list[:MAX_LLM_THREATS]):
        if not isinstance(raw, dict):
            result.skipped += 1
            logger.warning("LLM threat %d is not an object; skipped", index)
            continue
        try:
            threat = _validate_threat(raw)
        except (AttributeError, TypeError, ValueError) as e:
            result.skipped += 1
            logger.warning("LLM threat %d could not be validated (%s); skipped", index, e)
            continue
        if threat is None:
            result.skipped += 1
            logger.debug("LLM threat %d has no title; skipped", index)
            continue
        result.threats.append(threat)

    if len(raw_list) > MAX_LLM_THREATS:
        logger.warning("LLM returned %d threats, capped at %d", len(raw_list), MAX_LLM_THREATS)
    return result


def _threat_list(response: str, result: ParseResult) -> list[Any] | None:
    """The ``threats`` array of a reply, whole or salvaged, or None when there is none."""
    data = _extract_json(response)
    if isinstance(data, dict) and "threats" in data:
        threats = data["threats"]
        if isinstance(threats, list):
            return threats
        logger.warning("LLM response 'threats' is not a list; 0 threats parsed")
        result.parsed = False
        return None

    salvaged = _salvage_items(response)
    if salvaged:
        result.salvaged = len(salvaged)
        logger.warning(
            "LLM response was not complete JSON (cut off?); salvaged %d complete threat(s)",
            len(salvaged),
        )
        return salvaged

    if response.strip():
        if data is None:
            logger.warning("LLM response was not valid JSON, 0 threats parsed")
        else:
            logger.warning("LLM response has no 'threats' list; 0 threats parsed")
        result.parsed = False
    return None


def _extract_json(text: str) -> Any:
    """Extract JSON from LLM response, handling markdown code blocks.

    Security: only json.loads() is used - never eval(), yaml.load(), or exec().
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

    return None


def _salvage_items(text: str) -> list[Any]:
    """Complete objects of a ``threats`` array whose reply stops before the array closes."""
    match = _THREATS_KEY.search(text)
    if match is None:
        return []
    decoder = json.JSONDecoder()
    position = match.end()
    items: list[Any] = []
    length = len(text)
    while position < length:
        while position < length and text[position] in " \t\r\n,":
            position += 1
        if position >= length or text[position] == "]":
            break
        try:
            item, position = decoder.raw_decode(text, position)
        except json.JSONDecodeError:
            break
        items.append(item)
    return items


def _s(value: Any) -> str:
    """The stripped string, or '' for anything that is not one."""
    return value.strip() if isinstance(value, str) else ""


def clean_text(text: str, max_length: int, *, single_line: bool = False) -> str:
    """Make model-written text safe for a report.

    Removes code blocks, links and URLs, shell operator runs, control characters and bidi
    overrides, then caps the length.
    """
    cleaned = _CONTROL.sub("", _BIDI.sub("", text))
    cleaned = _CODE_BLOCK.sub(" ", cleaned)
    cleaned = _MARKDOWN_LINK.sub(r"\1", cleaned)
    cleaned = _URL.sub("[link removed]", cleaned)
    cleaned = _SHELL_RUN.sub(" ", cleaned)
    cleaned = cleaned.replace("`", "")
    if single_line:
        cleaned = " ".join(cleaned.split())
    else:
        cleaned = _BLANK_LINES.sub("\n\n", _SPACES.sub(" ", cleaned))
    cleaned = cleaned.strip()
    if len(cleaned) > max_length:
        cleaned = cleaned[: max_length - 3].rstrip() + "..."
    return cleaned


def _identifier(value: Any) -> str:
    """A resource type or address: one line, no control characters, capped."""
    text = _CONTROL.sub("", _BIDI.sub("", _s(value)))
    return " ".join(text.split())[:MAX_FIELD_LENGTH]


def _id_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _techniques(value: Any) -> list[str]:
    """Technique IDs the model gave, normalized to current IDs and checked against the database."""
    valid: list[str] = []
    for item in _id_list(value):
        technique = normalize_technique(item.upper())
        if technique not in TECHNIQUE_DB:
            if technique.startswith("T"):
                logger.debug("Dropping unknown MITRE technique ID from LLM: %s", item)
            continue
        if is_revoked(technique) or is_deprecated(technique):
            logger.debug("Dropping revoked or deprecated MITRE technique ID from LLM: %s", item)
            continue
        if technique not in valid:
            valid.append(technique)
    return valid


def _tactics(value: Any) -> list[str]:
    valid: list[str] = []
    for item in _id_list(value):
        tactic = item.upper()
        if tactic in TACTIC_DB:
            if tactic not in valid:
                valid.append(tactic)
        elif tactic.startswith("TA"):
            logger.debug("Dropping unknown MITRE tactic ID from LLM: %s", item)
    return valid


def _validate_threat(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Validate and normalize a single threat dict."""
    title = clean_text(_s(raw.get("title")), MAX_TITLE_LENGTH, single_line=True)
    if not title:
        return None

    stride = _s(raw.get("stride_category")).lower().replace(" ", "_").replace("-", "_")
    if stride not in VALID_STRIDE_CATEGORIES:
        logger.debug(
            "LLM threat '%s': invalid stride_category '%s', defaulting to 'tampering'",
            title,
            stride,
        )
        stride = "tampering"

    severity = _s(raw.get("severity")).lower()
    if severity not in VALID_SEVERITIES:
        logger.debug(
            "LLM threat '%s': invalid severity '%s', defaulting to 'medium'", title, severity
        )
        severity = "medium"

    confidence = raw.get("confidence", 0.7)
    if isinstance(confidence, bool) or not isinstance(confidence, int | float):
        confidence = 0.7
    elif not 0 <= confidence <= 1:
        confidence = 0.7

    return {
        "title": title,
        "description": clean_text(_s(raw.get("description")), MAX_DESCRIPTION_LENGTH),
        "stride_category": stride,
        "severity": severity,
        "resource_type": _identifier(raw.get("resource_type")),
        "resource_address": _identifier(raw.get("resource_address")),
        "mitigation": clean_text(_s(raw.get("mitigation")), MAX_MITIGATION_LENGTH),
        "confidence": float(confidence),
        "mitre_techniques": _techniques(raw.get("mitre_techniques")),
        "mitre_tactics": _tactics(raw.get("mitre_tactics")),
    }
