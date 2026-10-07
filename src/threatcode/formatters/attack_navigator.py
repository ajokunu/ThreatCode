"""ATT&CK Navigator layer JSON formatter.

Produces a layer file (layer format 4.5) that loads in
https://mitre-attack.github.io/attack-navigator/.

The Navigator places a technique in a tactic column, and a technique with no tactic lands in
none of them or all of them depending on the version.
So there is one entry per (technique, tactic), with the tactic written as its shortname
(``initial-access``), and an entry never has an empty tactic: when no tactic can be found the key
is left out.
The layer does not filter by platform, so every technique a finding names stays visible.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from threatcode.engine.mitre import (
    ATTACK_VERSION,
    TACTIC_SHORTNAME,
    TECHNIQUE_DB,
    normalize_technique,
)
from threatcode.formatters._utils import collapse_whitespace, truncate
from threatcode.models.report import ThreatReport, threat_severity
from threatcode.models.threat import Severity

logger = logging.getLogger(__name__)

__all__ = ["LAYER_VERSION", "NAVIGATOR_VERSION", "format_attack_navigator"]

# Layer file format and the Navigator release the layer is written for (a full semantic version,
# at least 4.9.0, as the format document requires).
LAYER_VERSION = "4.5"
NAVIGATOR_VERSION = "5.1.0"

_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
_COMMENT_TITLES = 5

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


@dataclass
class _Entry:
    """What the layer knows about one (technique, tactic)."""

    severity: Severity
    findings: int = 0
    titles: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)

    def add(self, severity: Severity) -> None:
        if severity > self.severity:
            self.severity = severity


def format_attack_navigator(report: ThreatReport, indent: int = 2) -> str:
    """Format threat report as an ATT&CK Navigator layer JSON."""
    layer = _build_layer(report)
    return json.dumps(layer, indent=indent, sort_keys=False)


def _tactic_shortnames(technique_id: str, preferred: list[str]) -> list[str]:
    """Navigator tactic shortnames a technique belongs to, narrowed by the finding's tactics.

    ``preferred`` are the TA ids the finding names.
    The ones the technique really belongs to are used; when none is, every tactic of the
    technique is.
    A technique ATT&CK does not know has no tactic of its own, so the finding's tactics stand.
    """
    entry = TECHNIQUE_DB.get(technique_id)
    known = list(entry["tactic_ids"]) if entry is not None else []
    wanted = [t for t in preferred if t in known] if known else list(preferred)
    chosen = wanted or known
    names = [TACTIC_SHORTNAME[t] for t in chosen if t in TACTIC_SHORTNAME]
    return sorted(dict.fromkeys(names))


def _build_layer(report: ThreatReport) -> dict[str, Any]:
    entries: dict[tuple[str, str], _Entry] = {}
    unknown: set[str] = set()

    def record(technique: str, tactic_ids: list[str], severity: Severity) -> list[_Entry]:
        current = normalize_technique(technique)
        if not _TECHNIQUE_ID.match(current):
            logger.warning(
                "Navigator layer: '%s' is not an ATT&CK technique id; left out", technique
            )
            return []
        if current not in TECHNIQUE_DB:
            unknown.add(current)
        touched = []
        for tactic in _tactic_shortnames(current, tactic_ids) or [""]:
            entry = entries.setdefault((current, tactic), _Entry(severity=severity))
            entry.add(severity)
            touched.append(entry)
        return touched

    for threat in report.threats:
        severity = threat_severity(threat)
        for technique in threat.mitre_techniques:
            for entry in record(technique, threat.mitre_tactics, severity):
                entry.findings += 1
                entry.titles.append(collapse_whitespace(threat.title))

    for path in report.attack_paths:
        label = f"{path.entry} to {path.target}"
        hop_techniques = [t for hop in path.hops for t in hop.techniques]
        for technique in dict.fromkeys([*path.techniques, *hop_techniques]):
            for entry in record(technique, path.tactics, path.severity):
                entry.paths.append(label)

    if unknown:
        logger.warning(
            "Navigator layer: %d technique id(s) are not in the bundled ATT&CK data (%s); kept",
            len(unknown),
            ", ".join(sorted(unknown)),
        )

    techniques = [_technique(tid, tactic, info) for (tid, tactic), info in sorted(entries.items())]
    description = (
        f"Auto-generated from ThreatCode scan of {report.input_file}. "
        f"{len(report.threats)} threats mapped to {len({t['techniqueID'] for t in techniques})} "
        f"ATT&CK techniques."
    )
    layer: dict[str, Any] = {
        "name": "ThreatCode Threat Model",
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": "enterprise-attack",
        "description": truncate(collapse_whitespace(description), 1000),
        "filters": {},
        "sorting": 3,
        "layout": {
            "layout": "side",
            "aggregateFunction": "max",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
            "expandedSubtechniques": "annotated",
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
    if unknown:
        layer["metadata"] = [
            {
                "name": "techniques not in the bundled ATT&CK data",
                "value": ", ".join(sorted(unknown)),
            }
        ]
    return layer


def _technique(technique_id: str, tactic: str, info: _Entry) -> dict[str, Any]:
    parts = []
    if info.findings:
        titles = "; ".join(list(dict.fromkeys(info.titles))[:_COMMENT_TITLES])
        parts.append(f"{info.findings} finding(s): {titles}")
    if info.paths:
        paths = "; ".join(list(dict.fromkeys(info.paths))[:_COMMENT_TITLES])
        parts.append(f"{len(set(info.paths))} attack path(s): {paths}")
    entry: dict[str, Any] = {"techniqueID": technique_id}
    if tactic:
        entry["tactic"] = tactic
    entry.update(
        {
            "score": _SEVERITY_SCORE.get(info.severity, 10),
            "color": _SEVERITY_COLOR.get(info.severity, "#cccccc"),
            "comment": truncate(" | ".join(parts), 1000),
            "enabled": True,
            "metadata": [
                {"name": "findings", "value": str(info.findings)},
                {"name": "attack_paths", "value": str(len(set(info.paths)))},
                {"name": "max_severity", "value": info.severity.value},
            ],
        }
    )
    return entry
