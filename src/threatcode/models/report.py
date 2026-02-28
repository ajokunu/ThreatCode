"""Threat report aggregate."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from threatcode.models.threat import Severity, Threat


@dataclass
class ThreatReport:
    threats: list[Threat] = field(default_factory=list)
    scanned_resources: int = 0
    input_file: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    version: str = ""

    def add(self, threat: Threat) -> None:
        self.threats.append(threat)

    def filter_by_severity(self, min_severity: Severity) -> list[Threat]:
        return [t for t in self.threats if t.severity >= min_severity]

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for t in self.threats:
            counts[t.severity.value] = counts.get(t.severity.value, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "timestamp": self.timestamp,
            "input_file": self.input_file,
            "scanned_resources": self.scanned_resources,
            "summary": self.summary,
            "total_threats": len(self.threats),
            "threats": [t.to_dict() for t in self.threats],
        }
