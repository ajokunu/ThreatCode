"""Threat model data structures."""

from __future__ import annotations

import functools
import hashlib
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

VALID_EVIDENCE: frozenset[str] = frozenset({"config", "design", "scanner"})
"""Where the facts behind a finding came from.

``config`` is a configuration file read as written, ``design`` is a declared
design input (a diagram or an architecture description) and ``scanner`` is a
result ingested from another tool.
"""


@functools.total_ordering
class _RankOrdered:
    """Orders members by ``rank``.

    ``Severity`` mixes in ``str``, which already defines all four rich
    comparison operators on the string value. ``functools.total_ordering``
    only fills in operators a class does not define, so it has to run on a
    plain base class that comes first in the MRO instead of on ``Severity``
    itself, or the inherited string comparisons would win.
    """

    @property
    def rank(self) -> int:
        raise NotImplementedError

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _RankOrdered):
            return self.rank == other.rank
        return NotImplemented

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, _RankOrdered):
            return NotImplemented
        return self.rank < other.rank

    def __hash__(self) -> int:
        return hash(self.rank)


class Severity(_RankOrdered, str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANKS[self.value]

    def __hash__(self) -> int:
        return hash(self.value)


class ThreatSource(str, Enum):
    RULE = "rule"
    LLM = "llm"
    BOUNDARY = "boundary"
    SECRET = "secret"
    SCANNER = "scanner"


def hash_id(seed: str) -> str:
    """Stable 12 hex character identifier derived from a seed string."""
    return hashlib.sha256(seed.encode()).hexdigest()[:12]


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
    # Source location of the evidence in the scanned file.
    location_file: str = ""
    location_start_line: int | None = None
    location_end_line: int | None = None
    # Stable identity of the finding across runs, set by the producer.
    fingerprint: str = ""
    # One of VALID_EVIDENCE.
    evidence: str = "config"
    # Name of the tool an ingested finding came from.
    tool: str = ""
    # Other identifiers of the same issue, such as CVE and GHSA ids.
    aliases: list[str] = field(default_factory=list)
    # The other endpoint of a boundary or flow finding.
    target_address: str = ""
    # Severity after context (internet reachability, data classification,
    # intentional exposure); ``severity`` stays the base severity of the rule.
    effective_severity: Severity | None = None
    severity_reason: str = ""
    # Ids of the attack paths this finding enables.
    path_ids: list[str] = field(default_factory=list)
    root_cause: str = ""

    def __post_init__(self) -> None:
        if self.stride_category not in VALID_STRIDE_CATEGORIES:
            raise ValueError(
                f"Unknown stride_category '{self.stride_category}' on threat '{self.title}'; "
                f"expected one of {sorted(VALID_STRIDE_CATEGORIES)}"
            )
        if self.evidence not in VALID_EVIDENCE:
            raise ValueError(
                f"Unknown evidence '{self.evidence}' on threat '{self.title}'; "
                f"expected one of {sorted(VALID_EVIDENCE)}"
            )

        # Validate and clamp confidence to valid range
        if not isinstance(self.confidence, (int, float)):
            logger.warning(
                "Invalid confidence type %s, defaulting to 1.0",
                type(self.confidence).__name__,
            )
            self.confidence = 1.0
        self.confidence = max(0.0, min(1.0, float(self.confidence)))

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
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
        # Contract fields are emitted only when they differ from their defaults,
        # so output that does not use them stays byte-identical.
        if self.location_file:
            data["location_file"] = self.location_file
        if self.location_start_line is not None:
            data["location_start_line"] = self.location_start_line
        if self.location_end_line is not None:
            data["location_end_line"] = self.location_end_line
        if self.fingerprint:
            data["fingerprint"] = self.fingerprint
        if self.evidence != "config":
            data["evidence"] = self.evidence
        if self.tool:
            data["tool"] = self.tool
        if self.aliases:
            data["aliases"] = list(self.aliases)
        if self.target_address:
            data["target_address"] = self.target_address
        if self.effective_severity is not None:
            data["effective_severity"] = self.effective_severity.value
        if self.severity_reason:
            data["severity_reason"] = self.severity_reason
        if self.path_ids:
            data["path_ids"] = list(self.path_ids)
        if self.root_cause:
            data["root_cause"] = self.root_cause
        return data
