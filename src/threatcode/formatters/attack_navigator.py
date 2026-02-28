"""ATT&CK Navigator layer JSON formatter.

Produces a layer file compatible with https://mitre-attack.github.io/attack-navigator/
"""

from __future__ import annotations

import json
from typing import Any

from threatcode.engine.mitre import TECHNIQUE_DB
from threatcode.models.report import ThreatReport
from threatcode.models.threat import Severity

# Severity -> Navigator color score (0-100 scale)
_SEVERITY_SCORE: dict[Severity, int] = {
    Severity.CRITICAL: 100,
    Severity.HIGH: 75,
    Severity.MEDIUM: 50,
    Severity.LOW: 25,
    Severity.INFO: 10,
}

_SEVERITY_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "#ff0000",
    Severity.HIGH: "#ff6600",
    Severity.MEDIUM: "#ffcc00",
    Severity.LOW: "#66ccff",
    Severity.INFO: "#cccccc",
}


def format_attack_navigator(report: ThreatReport, indent: int = 2) -> str:
    """Format threat report as an ATT&CK Navigator layer JSON."""
    layer = _build_layer(report)
    return json.dumps(layer, indent=indent, sort_keys=False)


def _build_layer(report: ThreatReport) -> dict[str, Any]:
    # Group findings by technique ID, track highest severity per technique
    technique_map: dict[str, dict[str, Any]] = {}

    for threat in report.threats:
        for tid in threat.mitre_techniques:
            if tid not in TECHNIQUE_DB:
                continue
            if tid not in technique_map:
                technique_map[tid] = {
                    "severity": threat.severity,
                    "count": 0,
                    "threats": [],
                }
            entry = technique_map[tid]
            entry["count"] += 1
            entry["threats"].append(threat.title)
            if threat.severity > entry["severity"]:
                entry["severity"] = threat.severity

    techniques: list[dict[str, Any]] = []
    for tid, info in sorted(technique_map.items()):
        sev = info["severity"]
        comment = f"{info['count']} finding(s): " + "; ".join(info["threats"][:5])
        techniques.append({
            "techniqueID": tid,
            "tactic": "",
            "score": _SEVERITY_SCORE.get(sev, 10),
            "color": _SEVERITY_COLOR.get(sev, "#cccccc"),
            "comment": comment,
            "enabled": True,
            "metadata": [
                {"name": "findings", "value": str(info["count"])},
                {"name": "max_severity", "value": sev.value},
            ],
        })

    return {
        "name": "ThreatCode Threat Model",
        "versions": {
            "attack": "16",
            "navigator": "5.1",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": (
            f"Auto-generated from ThreatCode scan of {report.input_file}. "
            f"{len(report.threats)} threats mapped to {len(techniques)} ATT&CK techniques."
        ),
        "filters": {
            "platforms": ["IaaS"],
        },
        "sorting": 3,
        "layout": {
            "layout": "side",
            "aggregateFunction": "max",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#cccccc", "#ffcc00", "#ff6600", "#ff0000"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Critical", "color": "#ff0000"},
            {"label": "High", "color": "#ff6600"},
            {"label": "Medium", "color": "#ffcc00"},
            {"label": "Low", "color": "#66ccff"},
            {"label": "Info", "color": "#cccccc"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#205b8f",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": True,
        "selectVisibleTechniques": False,
    }
