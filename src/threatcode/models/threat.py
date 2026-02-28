"""Threat model data structures."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


class ThreatSource(str, Enum):
    RULE = "rule"
    LLM = "llm"
    BOUNDARY = "boundary"


@dataclass
class Threat:
    id: str
    title: str
    description: str
    stride_category: str
    severity: Severity
    source: ThreatSource
    resource_type: str
    resource_address: str
    mitigation: str = ""
    rule_id: str = ""
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)
    mitre_techniques: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "stride_category": self.stride_category,
            "severity": self.severity.value,
            "source": self.source.value,
            "resource_type": self.resource_type,
            "resource_address": self.resource_address,
            "mitigation": self.mitigation,
            "rule_id": self.rule_id,
            "confidence": self.confidence,
            "metadata": self.metadata,
            "mitre_techniques": self.mitre_techniques,
            "mitre_tactics": self.mitre_tactics,
        }
