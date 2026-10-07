"""Threat report aggregate."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, ClassVar

from threatcode.models.attack_path import AttackPath
from threatcode.models.threat import Severity, Threat


@dataclass
class ThreatReport:
    # Version of the report document contract. It is not part of the serialized
    # output yet; formatters start emitting it when the first output change of
    # the schema 2 contract lands.
    SCHEMA_VERSION: ClassVar[str] = "2"

    threats: list[Threat] = field(default_factory=list)
    scanned_resources: int = 0
    input_file: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    version: str = ""
    attack_paths: list[AttackPath] = field(default_factory=list)
    # LLM phase status: provider, model, status (ran, skipped or failed), error
    # and threat_count. None until the LLM phase has been evaluated.
    llm: dict[str, Any] | None = None
    # Rule evaluations that raised: {rule_id, node_id, error}.
    rule_errors: list[dict[str, str]] = field(default_factory=list)

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
        data: dict[str, Any] = {
            "version": self.version,
            "timestamp": self.timestamp,
            "input_file": self.input_file,
            "scanned_resources": self.scanned_resources,
            "summary": self.summary,
            "total_threats": len(self.threats),
            "threats": [t.to_dict() for t in self.threats],
        }
        # New keys are emitted only when they carry something, so reports that
        # do not use them stay byte-identical to the previous schema.
        if self.attack_paths:
            data["attack_paths"] = [p.to_dict() for p in self.attack_paths]
        # A skipped LLM phase is tracked in memory but not serialized yet.
        if self.llm is not None and self.llm.get("status") != "skipped":
            data["llm"] = dict(self.llm)
        if self.rule_errors:
            data["rule_errors"] = [dict(e) for e in self.rule_errors]
        return data
