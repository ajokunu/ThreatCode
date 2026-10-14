"""Base parser types and abstract class."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal

from threatcode._paths import posix_separators
from threatcode.diagnostics import Diagnostic

# Where a resource's properties come from; see ParsedResource.evidence
Evidence = Literal["config", "design"]

# "managed" resources are created by the input; "data" resources are looked up
# (a Terraform data source) and give context rather than being deployed
Mode = Literal["managed", "data"]


@dataclass
class ParsedResource:
    resource_type: str
    address: str
    name: str
    provider: str
    properties: dict[str, Any] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    module: str = ""
    # The file the resource comes from, written with forward slashes on every platform.
    # A legacy trailing ":N" is accepted and read as the start line by the graph builder;
    # parsers should set start_line
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
    # Attribute path -> the raw reference strings the format expresses there.
    # Paths use "." for nesting and "[]" for every list level, for example
    # "vpc_id" or "ingress[].security_groups". The graph resolves them to edges
    references: dict[str, list[str]] = field(default_factory=dict)
    # 1-based, inclusive; None when the format cannot say
    start_line: int | None = None
    end_line: int | None = None
    mode: Mode = "managed"
    # Bookkeeping about how the resource was expressed (count, for_each,
    # depends_on, provider alias, lifecycle). Never visible to rules
    meta: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Windows paths come from pathlib with backslashes; no report or address carries them
        self.source_location = posix_separators(self.source_location)


@dataclass
class ParsedEdge:
    """An edge the input states explicitly, such as a data flow in a design."""

    source: str
    target: str
    edge_type: str = "data_flow"  # an EdgeType value
    # Parser-supplied attributes (protocol, ports, authenticated, ...). The graph
    # keeps them apart from the fields it computes, so they cannot forge a crossing
    metadata: dict[str, Any] = field(default_factory=dict)
    # True when the input states the edge; a parser that infers an edge sets False,
    # and such an edge to an unknown node is skipped instead of being an error
    declared: bool = True


@dataclass
class ParsedOutput:
    resources: list[ParsedResource] = field(default_factory=list)
    # The input the resources were read from, written with forward slashes on every platform
    source_path: str = ""
    format_type: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    edges: list[ParsedEdge] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.source_path = posix_separators(self.source_path)


class BaseParser(ABC):
    @abstractmethod
    def parse(self, data: Any, source_path: str = "") -> ParsedOutput: ...
