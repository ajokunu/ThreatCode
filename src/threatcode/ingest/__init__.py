"""Scanner result ingestion: Trivy, Grype, OSV-Scanner and SARIF findings joined to graph nodes.

This module is the seam between the scan pipeline and the ingesters.
The pipeline calls ``load_and_attach(paths, graph, root)`` once per scan with the files named by
``--ingest`` and merges ``IngestResult.threats`` into the analysis context and
``IngestResult.diagnostics`` into the graph diagnostics.
``IngestResult.sources`` lists one mapping per ingested file (tool, version, file, counts) for the
report.

The implementation arrives with the ingestion package.
Until then ``load_and_attach`` accepts no files: naming one is a usage error that names it, so a
scan never looks clean because a scanner result was silently dropped.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from threatcode.diagnostics import Diagnostic
from threatcode.exceptions import UsageError
from threatcode.models.threat import Threat

if TYPE_CHECKING:
    from threatcode.ir.graph import InfraGraph

__all__ = ["IngestResult", "load_and_attach"]


@dataclass
class IngestResult:
    """Findings, diagnostics and per-file source records of one ingestion."""

    threats: list[Threat] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    sources: list[dict[str, Any]] = field(default_factory=list)


def load_and_attach(paths: Sequence[Path], graph: InfraGraph, root: Path) -> IngestResult:
    """Read the scanner result files in ``paths`` and attach their findings to ``graph``.

    ``root`` is the scan root; locations in the returned threats are relative to it.

    Raises:
        UsageError: A file is unreadable or not a recognized scanner result.
    """
    if paths:
        raise UsageError(
            f"cannot ingest {paths[0]}: scanner result ingestion is not available in this build"
        )
    return IngestResult()
