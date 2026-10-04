"""Base parser types and abstract class."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal

# Where a resource's properties come from; see ParsedResource.evidence
Evidence = Literal["config", "design"]


@dataclass
class ParsedResource:
    resource_type: str
    address: str
    name: str
    provider: str
    properties: dict[str, Any] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    module: str = ""
    source_location: str = ""
    # A TrustZone value declared by the input (a design's trust zone); None infers it
    trust_zone: str | None = None
    # A declared boundary id, finer than the zone class; crossing between two
    # different boundaries counts as a trust-boundary crossing
    boundary: str = ""
    # "config" when properties come from deployable configuration (IaC), where a
    # missing property is a fact; "design" when they come from a diagram or
    # threat model, where a missing property is unknown
    evidence: Evidence = "config"


@dataclass
class ParsedEdge:
    """An edge the input states explicitly, such as a data flow in a design."""

    source: str
    target: str
    edge_type: str = "data_flow"  # an EdgeType value
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ParsedOutput:
    resources: list[ParsedResource] = field(default_factory=list)
    source_path: str = ""
    format_type: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    edges: list[ParsedEdge] = field(default_factory=list)


class BaseParser(ABC):
    @abstractmethod
    def parse(self, data: Any, source_path: str = "") -> ParsedOutput: ...
