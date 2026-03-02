"""ThreatCode — STRIDE threat model generator from Infrastructure-as-Code."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from threatcode.models.analysis import AnalysisResult

__version__ = "0.4.1"


def scan(
    input_path: str | Path,
    *,
    no_llm: bool = True,
    output_format: str = "json",
    min_severity: str = "info",
    config_path: str | Path | None = None,
    extra_rule_paths: list[str | Path] | None = None,
) -> dict[str, Any]:
    """Public API: scan an IaC file and return a threat report dict.

    Args:
        input_path: Path to terraform plan JSON, .tf file, or CFN template.
        no_llm: If True, skip LLM analysis and use rules only.
        output_format: Output format (json, sarif, markdown, bitbucket).
        min_severity: Minimum severity to include (critical, high, medium, low, info).
        config_path: Optional path to .threatcode.yml config file.
        extra_rule_paths: Additional YAML rule files to load.

    Returns:
        Threat report as a dictionary.
    """
    from threatcode.config import load_config
    from threatcode.engine.hybrid import HybridEngine
    from threatcode.ir.graph import InfraGraph
    from threatcode.models.threat import Severity
    from threatcode.parsers import detect_and_parse

    cfg_path = Path(config_path) if config_path else None
    config = load_config(cfg_path)
    config.no_llm = no_llm

    parsed = detect_and_parse(input_path)
    graph = InfraGraph.from_parsed(parsed)

    extra = [Path(p) for p in (extra_rule_paths or [])]
    engine = HybridEngine(config=config, extra_rule_paths=extra)
    report = engine.analyze(graph, input_file=str(input_path))

    if min_severity != "info":
        report.threats = report.filter_by_severity(Severity(min_severity))

    return report.to_dict()


def analyze(
    input_path: str | Path,
    *,
    no_llm: bool = True,
    min_severity: str = "info",
    config_path: str | Path | None = None,
    extra_rule_paths: list[str | Path] | None = None,
) -> AnalysisResult:
    """Public API: scan an IaC file and return graph + threat report.

    Like scan(), but preserves the infrastructure graph for diagram rendering
    and topology analysis.

    Args:
        input_path: Path to terraform plan JSON, .tf file, or CFN template.
        no_llm: If True, skip LLM analysis and use rules only.
        min_severity: Minimum severity to include (critical, high, medium, low, info).
        config_path: Optional path to .threatcode.yml config file.
        extra_rule_paths: Additional YAML rule files to load.

    Returns:
        AnalysisResult with .graph (InfraGraph) and .report (ThreatReport).
    """
    from threatcode.config import load_config
    from threatcode.engine.hybrid import HybridEngine
    from threatcode.ir.graph import InfraGraph
    from threatcode.models.analysis import AnalysisResult
    from threatcode.models.threat import Severity
    from threatcode.parsers import detect_and_parse

    cfg_path = Path(config_path) if config_path else None
    config = load_config(cfg_path)
    config.no_llm = no_llm

    parsed = detect_and_parse(input_path)
    graph = InfraGraph.from_parsed(parsed)

    extra = [Path(p) for p in (extra_rule_paths or [])]
    engine = HybridEngine(config=config, extra_rule_paths=extra)
    report = engine.analyze(graph, input_file=str(input_path))

    if min_severity != "info":
        report.threats = report.filter_by_severity(Severity(min_severity))

    return AnalysisResult(graph=graph, report=report)
