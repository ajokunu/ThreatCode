"""Diagnostics: the channel for coverage gaps that are not errors.

A parser or the graph builder that skips, approximates or cannot resolve
something records a `Diagnostic` instead of logging at debug level, so every
output can report what the scan did not analyse.

Codes form a closed registry (`DIAGNOSTIC_CODES`).
Constructing a `Diagnostic` with a code that is not registered raises
`ValueError`, which keeps the set of codes reviewable and stops typos from
creating silent new categories.
A module that emits a code of its own registers it at import time with
`register_code`; it never edits this file.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal, get_args

from threatcode._paths import posix_separators

Level = Literal["info", "warning", "error"]
LEVELS: tuple[str, ...] = get_args(Level)

_CODE_SHAPE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")

_CODES: dict[str, str] = {
    "parse.failed": "A file a parser claims could not be parsed",
    "parse.zero_resources": "An input was parsed but produced no resources to model",
    "cfn.skipped_resource": "A CloudFormation resource entry was skipped",
    "cfn.unmapped_type": "A CloudFormation resource type has no mapping to a modelled type",
    "cfn.nested_stack": "A CloudFormation nested stack was not expanded",
    "cfn.unresolved_intrinsic": "A CloudFormation intrinsic function could not be resolved",
    "hcl.module_call_skipped": "A Terraform module call was not expanded, so it is not analysed",
    "hcl.unresolved_reference": "A Terraform expression could not be resolved to a value",
    "hcl.dynamic_block": "A Terraform dynamic block was not expanded",
    "hcl.count_zero": "A Terraform resource with count 0 creates no instances",
    "plan.data_source": "A Terraform plan data source was added as a context node",
    "plan.unknown_values": "A Terraform plan holds values that are unknown until apply",
    "helm.fallback_render": "A Helm chart was rendered without helm, so values may be approximated",
    "k8s.skipped_document": "A Kubernetes manifest document was skipped",
    "mcp.unknown_entry": "An MCP configuration entry has an unrecognised shape",
    "mcp.unknown_capability": "The capabilities of an MCP server are unknown",
    "graph.duplicate_address": "Two resources share an address, so the later one was renamed",
    "graph.dangling_declared_edge": "A declared edge names a node that does not exist",
    "graph.edge_cap": "The graph reached its edge limit and skipped further edges",
    "graph.ambiguous_reference": "A reference matches several nodes, so no edge was added",
    "graph.unit_superseded": "An input unit was replaced by a more complete one",
    "ingest.unattached": "An ingested scanner finding matched no node in the graph",
    "ingest.duplicate": "An ingested scanner finding duplicates one already present",
}

# A read-only view: codes are added only through register_code
DIAGNOSTIC_CODES: Mapping[str, str] = MappingProxyType(_CODES)


def register_code(code: str, description: str) -> None:
    """Register a diagnostic code of the form `area.name`.

    Registering the same code with the same description again is a no-op, so a
    module can register at import time without caring about import order.
    Registering an existing code with a different description raises.
    """
    if not _CODE_SHAPE.match(code):
        raise ValueError(f"Invalid diagnostic code '{code}': use lowercase 'area.name'")
    if not description.strip():
        raise ValueError(f"Diagnostic code '{code}' needs a description")
    existing = _CODES.get(code)
    if existing is not None:
        if existing != description:
            raise ValueError(f"Diagnostic code '{code}' is already registered")
        return
    _CODES[code] = description


@dataclass(frozen=True)
class Diagnostic:
    level: Level
    code: str
    message: str
    # The file the diagnostic is about, written with forward slashes on every platform
    file: str = ""
    line: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "file", posix_separators(self.file))
        if self.level not in LEVELS:
            raise ValueError(f"Invalid diagnostic level '{self.level}': use one of {LEVELS}")
        if self.code not in _CODES:
            raise ValueError(
                f"Unregistered diagnostic code '{self.code}'; register it with register_code"
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize, leaving out the location parts that are unset."""
        data: dict[str, Any] = {"level": self.level, "code": self.code, "message": self.message}
        if self.file:
            data["file"] = self.file
        if self.line is not None:
            data["line"] = self.line
        return data
