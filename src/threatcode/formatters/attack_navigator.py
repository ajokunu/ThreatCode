"""ATT&CK Navigator layer JSON formatter.

Produces a layer file (layer format 4.5) that loads in
https://mitre-attack.github.io/attack-navigator/.

The Navigator places a technique in a tactic column, and a technique with no tactic lands in
none of them or all of them depending on the version.
So there is one entry per (technique, tactic), with the tactic written as its shortname
(``initial-access``), and an entry never has an empty tactic: when no tactic can be found the key
is left out.
The layer does not filter by platform, so every technique a finding names stays visible.

A technique that ATT&CK files under several tactics (valid cloud accounts are initial access,
persistence, privilege escalation and stealth) is placed in the tactic the finding names.
An attack path does not name one, so the layer picks the tactic the step plays: initial access
for the entry step, and mid-path the one that moves the attacker closest to the target.
Painting a technique in every column of the matrix would claim the path does four things where
it does one.
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
from threatcode.formatters._utils import collapse_whitespace, input_summary, plural, truncate
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

# The gradient the Navigator shades an unscored cell range with: five stops spread evenly over
# 0 to 100, which are 0, 25, 50, 75 and 100, so the stops of low, medium, high and critical are
# the colors of the legend and a score between two severities blends the two.
_GRADIENT = [
    _SEVERITY_COLOR[Severity.INFO],
    _SEVERITY_COLOR[Severity.LOW],
    _SEVERITY_COLOR[Severity.MEDIUM],
    _SEVERITY_COLOR[Severity.HIGH],
    _SEVERITY_COLOR[Severity.CRITICAL],
]

# Where an attack-path step puts a technique that has several tactics, after the entry step
# (which takes initial access): the tactic that moves the attacker closest to the target first,
# the one that only describes the path's start last.
_MID_PATH_TACTICS = (
    "privilege-escalation",
    "lateral-movement",
    "credential-access",
    "collection",
    "exfiltration",
    "impact",
    "persistence",
    "execution",
    "discovery",
    "stealth",
    "defense-evasion",
    "initial-access",
)


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


def _path_tactic(technique_id: str, path_tactics: list[str], *, entry: bool) -> list[str]:
    """The one tactic an attack-path step plays, as a list (empty when none can be found).

    ``entry`` is the first step that uses a technique: it is how the attacker gets in.
    Any other step moves along the path, so it never takes initial access when another tactic
    fits.
    """
    names = _tactic_shortnames(technique_id, path_tactics)
    if len(names) <= 1:
        return names
    if entry and "initial-access" in names:
        return ["initial-access"]
    ranked = [name for name in _MID_PATH_TACTICS if name in names]
    return [ranked[0] if ranked else names[0]]


@dataclass
class _Entries:
    """The layer's (technique, tactic) cells, filled by findings and attack paths."""

    cells: dict[tuple[str, str], _Entry] = field(default_factory=dict)
    unknown: set[str] = field(default_factory=set)

    def record(
        self,
        technique: str,
        tactic_ids: list[str],
        severity: Severity,
        *,
        path_step: bool | None = None,
    ) -> list[_Entry]:
        """Add ``technique``; ``path_step`` is set (True for the entry step) for a path's step."""
        current = normalize_technique(technique)
        if not _TECHNIQUE_ID.match(current):
            logger.warning(
                "Navigator layer: '%s' is not an ATT&CK technique id; left out", technique
            )
            return []
        if current not in TECHNIQUE_DB:
            self.unknown.add(current)
        if path_step is None:
            tactics = _tactic_shortnames(current, tactic_ids)
        else:
            tactics = _path_tactic(current, tactic_ids, entry=path_step)
        touched = []
        for tactic in tactics or [""]:
            entry = self.cells.setdefault((current, tactic), _Entry(severity=severity))
            entry.add(severity)
            touched.append(entry)
        return touched

    def add_findings(self, report: ThreatReport) -> int:
        """Record every finding's techniques; returns how many findings named a valid one."""
        mapped = 0
        for threat in report.threats:
            severity = threat_severity(threat)
            recorded = False
            for technique in threat.mitre_techniques:
                for entry in self.record(technique, threat.mitre_tactics, severity):
                    recorded = True
                    entry.findings += 1
                    entry.titles.append(collapse_whitespace(threat.title))
            mapped += recorded
        return mapped

    def add_paths(self, report: ThreatReport) -> None:
        """Record the technique of every attack-path step, each in the one tactic it plays."""
        for path in report.attack_paths:
            label = f"{path.entry} to {path.target}"
            first = next((i for i, hop in enumerate(path.hops) if hop.techniques), None)
            stepped: set[str] = set()
            for index, hop in enumerate(path.hops):
                for technique in hop.techniques:
                    stepped.add(technique)
                    for entry in self.record(
                        technique, path.tactics, path.severity, path_step=index == first
                    ):
                        entry.paths.append(label)
            for technique in path.techniques:
                if technique not in stepped:
                    for entry in self.record(
                        technique, path.tactics, path.severity, path_step=False
                    ):
                        entry.paths.append(label)


def _build_layer(report: ThreatReport) -> dict[str, Any]:
    collected = _Entries()
    mapped = collected.add_findings(report)
    collected.add_paths(report)
    unknown = collected.unknown
    if unknown:
        logger.warning(
            "Navigator layer: %d technique id(s) are not in the bundled ATT&CK data (%s); kept",
            len(unknown),
            ", ".join(sorted(unknown)),
        )

    techniques = [
        _technique(tid, tactic, info) for (tid, tactic), info in sorted(collected.cells.items())
    ]
    distinct = len({t["techniqueID"] for t in techniques})
    layer: dict[str, Any] = {
        "name": "ThreatCode Threat Model",
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": "enterprise-attack",
        "description": truncate(collapse_whitespace(_description(report, mapped, distinct)), 1000),
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
            "colors": list(_GRADIENT),
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Critical", "color": _SEVERITY_COLOR[Severity.CRITICAL]},
            {"label": "High", "color": _SEVERITY_COLOR[Severity.HIGH]},
            {"label": "Medium", "color": _SEVERITY_COLOR[Severity.MEDIUM]},
            {"label": "Low", "color": _SEVERITY_COLOR[Severity.LOW]},
            {"label": "Info", "color": _SEVERITY_COLOR[Severity.INFO]},
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


_INPUT_NAMES = {"": "the scan", ".": "the current directory", "..": "the parent directory"}


def _description(report: ThreatReport, mapped: int, techniques: int) -> str:
    """Two sentences, each ending in one period, whatever the input is called."""
    summary = input_summary(report.input_file)
    where = _INPUT_NAMES.get(summary, summary)
    first = f"Auto-generated from ThreatCode scan of {where}"
    if not first.endswith("."):
        first += "."
    return f"{first} {plural(mapped, 'threat')} mapped to {plural(techniques, 'ATT&CK technique')}."


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
