"""SARIF 2.1.0 output formatter for GitHub Code Scanning."""

from __future__ import annotations

import json
import re
from typing import Any

from threatcode.models.report import ThreatReport
from threatcode.models.threat import Severity, Threat


def _safe_uri(address: str) -> str:
    """Strip non-URI characters from a resource address for use as artifact URI."""
    return re.sub(r"[^A-Za-z0-9_./:@\-]", "", address)


def format_sarif(report: ThreatReport, indent: int = 2) -> str:
    """Format threat report as SARIF 2.1.0 JSON."""
    sarif = _build_sarif(report)
    return json.dumps(sarif, indent=indent, sort_keys=False)


def _build_sarif(report: ThreatReport) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    rule_id_to_index: dict[str, int] = {}

    for threat in report.threats:
        # Add rule definition (deduplicate by rule_id or threat id)
        rule_key = threat.rule_id or threat.id
        if rule_key not in rule_id_to_index:
            rule_id_to_index[rule_key] = len(rules)
            rules.append(_threat_to_rule(threat, rule_key))

        rule_index = rule_id_to_index[rule_key]
        results.append(_threat_to_result(threat, rule_key, rule_index))

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ThreatCode",
                        "version": report.version,
                        "informationUri": "https://github.com/ajokunu/ThreatCode",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": [],
                    }
                ],
            }
        ],
    }


def _threat_to_rule(threat: Threat, rule_id: str) -> dict[str, Any]:
    return {
        "id": rule_id,
        "name": _to_pascal_case(threat.title),
        "shortDescription": {"text": threat.title},
        "fullDescription": {"text": threat.description.strip()},
        "help": {
            "text": threat.mitigation.strip() if threat.mitigation else "See description.",
            "markdown": f"**Mitigation**: {threat.mitigation.strip()}" if threat.mitigation else "",
        },
        "defaultConfiguration": {
            "level": _severity_to_sarif_level(threat.severity),
        },
        "properties": {
            "tags": [
                "security",
                f"stride/{threat.stride_category}",
                f"source/{threat.source.value}",
                *[f"mitre/{tid}" for tid in threat.mitre_techniques],
            ],
        },
    }


def _threat_to_result(threat: Threat, rule_id: str, rule_index: int) -> dict[str, Any]:
    return {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": _severity_to_sarif_level(threat.severity),
        "message": {
            "text": (
                f"[{threat.stride_category.upper()}] {threat.title}\n\n"
                f"{threat.description.strip()}\n\n"
                f"Resource: {threat.resource_address} ({threat.resource_type})"
            ),
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": _safe_uri(threat.resource_address),
                        "uriBaseId": "%SRCROOT%",
                    },
                },
                "logicalLocations": [
                    {
                        "fullyQualifiedName": _safe_uri(threat.resource_address),
                        "kind": "resource",
                    }
                ],
            }
        ],
        "properties": {
            "severity": threat.severity.value,
            "stride_category": threat.stride_category,
            "source": threat.source.value,
            "confidence": threat.confidence,
            "resource_type": threat.resource_type,
        },
    }


_SARIF_LEVELS: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _severity_to_sarif_level(severity: Severity) -> str:
    return _SARIF_LEVELS.get(severity, "warning")


def _to_pascal_case(text: str) -> str:
    return "".join(
        word.capitalize() for word in re.split(r"[\s_\-]+", text) if word
    )
