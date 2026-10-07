"""Run input through the library path the way ``threatcode scan`` does.

``scan_text`` and ``scan_files`` call ``detect_and_parse``, ``InfraGraph.from_parsed`` and
``HybridEngine`` with no LLM, so a test exercises the real parser, graph and rules
instead of hand-building property dictionaries. One call yields a ``ScanResult`` with
the graph, the parse outputs and the report.

The file name decides the parser, as it does for the CLI, so ``scan_text(text, "main.tf")``
parses HCL, ``scan_text(text, "Dockerfile")`` a Dockerfile and ``scan_text(text, ".mcp.json")``
an MCP config.
"""

from __future__ import annotations

import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import cache, lru_cache
from pathlib import Path
from typing import Any

from threatcode.engine.hybrid import HybridEngine
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import Threat
from threatcode.parsers import detect_and_parse
from threatcode.parsers.base import ParsedOutput

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
REAL_SHAPES_DIR = FIXTURES_DIR / "real_shapes"


def real_shape(relative: str) -> Path:
    """Path of a file or directory in the real-shape corpus; fails loudly when it is absent."""
    path = REAL_SHAPES_DIR / relative
    if not path.exists():
        raise FileNotFoundError(f"no real-shape fixture {relative} under {REAL_SHAPES_DIR}")
    return path


@dataclass
class ScanResult:
    """What one scan produced: parse outputs, the graph and the engine report."""

    parsed: list[ParsedOutput]
    graph: InfraGraph
    report: Any
    input_files: list[str] = field(default_factory=list)

    @property
    def threats(self) -> list[Threat]:
        return list(self.report.threats)

    @property
    def rule_ids(self) -> set[str]:
        """Ids of the rules that fired anywhere."""
        return {t.rule_id for t in self.threats if getattr(t, "rule_id", None)}

    def threats_for(self, address: str) -> list[Threat]:
        return [t for t in self.threats if t.resource_address == address]

    def rule_ids_for(self, address: str) -> set[str]:
        return {t.rule_id for t in self.threats_for(address) if getattr(t, "rule_id", None)}

    def fired(self, rule_id: str, address: str | None = None) -> bool:
        """True when a rule fired, optionally on one resource address."""
        return any(
            t.rule_id == rule_id and (address is None or t.resource_address == address)
            for t in self.threats
        )


@lru_cache(maxsize=1)
def _engine() -> HybridEngine:
    # Loading every rule file takes a noticeable fraction of a scan; the engine keeps no
    # per-scan state, so one instance serves every call in the test session.
    return HybridEngine()


def merge_parsed(outputs: list[ParsedOutput]) -> ParsedOutput:
    """Fold several parse outputs into one, the way a multi-file scan feeds one graph."""
    if len(outputs) == 1:
        return outputs[0]
    merged = ParsedOutput(
        source_path=", ".join(o.source_path for o in outputs),
        format_type="+".join(sorted({o.format_type for o in outputs})),
    )
    for output in outputs:
        merged.resources.extend(output.resources)
        merged.edges.extend(output.edges)
        merged.metadata.update(output.metadata)
    return merged


def build_graph(outputs: list[ParsedOutput]) -> InfraGraph:
    """One graph across all inputs; uses ``from_units`` when the graph provides it."""
    from_units = getattr(InfraGraph, "from_units", None)
    if from_units is not None and len(outputs) > 1:
        return from_units(outputs)  # type: ignore[no-any-return]
    return InfraGraph.from_parsed(merge_parsed(outputs))


def scan_files(paths: Iterable[str | Path]) -> ScanResult:
    """Parse each path, build one graph across them and analyze it without an LLM."""
    resolved = [Path(p) for p in paths]
    if not resolved:
        raise ValueError("scan_files needs at least one path")
    outputs = [detect_and_parse(p) for p in resolved]
    graph = build_graph(outputs)
    result = _engine().analyze(graph, input_file=str(resolved[0]))
    report = getattr(result, "report", result)
    return ScanResult(
        parsed=outputs, graph=graph, report=report, input_files=[str(p) for p in resolved]
    )


@cache
def scan_real_shape(*relatives: str) -> ScanResult:
    """Scan fixtures of the real-shape corpus, caching the result for the test session.

    Tests only read the result. A test that mutates the graph must call ``scan_files``.
    """
    return scan_files([real_shape(r) for r in relatives])


def scan_text(text: str, filename: str, directory: Path | None = None) -> ScanResult:
    """Write ``text`` to ``filename`` and scan it.

    The directory defaults to a temporary one that is removed afterwards; the result
    holds no reference to the file, so nothing needs the path to outlive the call.
    """
    name = Path(filename)
    if name.is_absolute() or ".." in name.parts:
        raise ValueError(f"filename must be a relative name inside the scan directory: {filename}")
    if directory is not None:
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return scan_files([path])
    with tempfile.TemporaryDirectory(prefix="threatcode-scan-") as tmp:
        path = Path(tmp) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return scan_files([path])
