"""Threat model data structures."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from threatcode.constants import VALID_STRIDE_CATEGORIES

logger = logging.getLogger(__name__)


_SEVERITY_RANKS: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANKS[self.value]

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank == other.rank
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.value)

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

    def __post_init__(self) -> None:
        if self.stride_category not in VALID_STRIDE_CATEGORIES:
            logger.warning(
                "Unknown stride_category '%s' on threat '%s' — defaulting",
                self.stride_category,
                self.title,
            )
            self.stride_category = "information_disclosure"

        # Validate and clamp confidence to valid range
        if not isinstance(self.confidence, (int, float)):
            logger.warning(
                "Invalid confidence type %s, defaulting to 1.0",
                type(self.confidence).__name__,
            )
            self.confidence = 1.0
        self.confidence = max(0.0, min(1.0, float(self.confidence)))

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
