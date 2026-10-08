"""ThreatCode: STRIDE threat models and attack paths from infrastructure code and agent configs.

The public API is ``scan`` (a report as a dict), ``analyze`` (the report and its graph) and
``run_scan`` (everything, including the exit code and the coverage).
All three go through the same pipeline as ``threatcode scan``, so a Python call and the command
line cannot disagree.
Names are loaded on first use, which keeps ``import threatcode`` and the CLI start-up fast.
"""

from __future__ import annotations

import importlib
import os
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from threatcode.exceptions import (
    ConfigError,
    LLMError,
    ParseError,
    RuleLoadError,
    ThreatCodeError,
    UnsupportedFormatError,
    UsageError,
)

if TYPE_CHECKING:
    from threatcode.models.analysis import AnalysisResult as AnalysisResult
    from threatcode.models.report import ThreatReport as ThreatReport
    from threatcode.models.threat import Severity as Severity
    from threatcode.models.threat import Threat as Threat
    from threatcode.pipeline import ScanRequest as ScanRequest
    from threatcode.pipeline import ScanResult as ScanResult
    from threatcode.pipeline import run_scan as run_scan

__version__ = "0.9.1"

__all__ = [
    "AnalysisResult",
    "ConfigError",
    "LLMError",
    "ParseError",
    "RuleLoadError",
    "ScanRequest",
    "ScanResult",
    "Severity",
    "Threat",
    "ThreatCodeError",
    "ThreatReport",
    "UnsupportedFormatError",
    "UsageError",
    "__version__",
    "analyze",
    "run_scan",
    "scan",
]

# Names loaded on first access: public name -> (module, attribute).
_LAZY: dict[str, tuple[str, str]] = {
    "AnalysisResult": ("threatcode.models.analysis", "AnalysisResult"),
    "ThreatReport": ("threatcode.models.report", "ThreatReport"),
    "Severity": ("threatcode.models.threat", "Severity"),
    "Threat": ("threatcode.models.threat", "Threat"),
    "ScanRequest": ("threatcode.pipeline", "ScanRequest"),
    "ScanResult": ("threatcode.pipeline", "ScanResult"),
    "run_scan": ("threatcode.pipeline", "run_scan"),
}


def __getattr__(name: str) -> Any:
    target = _LAZY.get(name)
    if target is None:
        raise AttributeError(f"module 'threatcode' has no attribute '{name}'")
    value = getattr(importlib.import_module(target[0]), target[1])
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))


def _run(
    paths: str | os.PathLike[str] | Sequence[str | os.PathLike[str]],
    options: dict[str, Any],
) -> ScanResult:
    import logging

    from threatcode.pipeline import prepare_request, run_scan

    if "output_format" in options:
        raise TypeError(
            "scan() and analyze() take no output_format: scan() returns a dict, and "
            "threatcode.formatters.render(name, analysis) renders any other format"
        )
    named = [paths] if isinstance(paths, (str, os.PathLike)) else list(paths)
    prepared = prepare_request(named, **options)
    for notice in prepared.config.notices:
        logging.getLogger("threatcode").warning("%s", notice)
    result = run_scan(prepared.request)
    coverage = result.coverage
    if coverage.errors:
        shown = "; ".join(
            f"{e.get('file') or '.'}: {(str(e.get('message', '')).splitlines() or [''])[0]}"
            for e in coverage.errors[:3]
        )
        more = len(coverage.errors) - 3
        suffix = f" (and {more} more)" if more > 0 else ""
        raise ThreatCodeError(
            f"the scan could not analyse its input: {shown}{suffix}. "
            "Use run_scan() to get the partial result with its coverage block."
        )
    if result.exit_code == 2:
        # No input error, so this is strict mode with a coverage gap.
        first = coverage.gaps[0] if coverage.gaps else {}
        raise ThreatCodeError(
            f"strict mode: the scan has {len(coverage.gaps) + coverage.rule_errors} coverage "
            f"gap(s), the first is [{first.get('code', 'rule.error')}] "
            f"{str(first.get('message', 'a rule failed')).splitlines()[0]}. "
            "Use run_scan() to get the result with its coverage block."
        )
    return result


def scan(
    paths: str | os.PathLike[str] | Sequence[str | os.PathLike[str]],
    **settings: Any,
) -> dict[str, Any]:
    """Scan files and directories and return the threat report as a dict.

    The dict is exactly what ``threatcode scan -f json`` prints: ``schema_version``, ``threats``,
    ``attack_paths`` and a ``coverage`` block that says what was not analysed.
    A finding never raises; an input that could not be analysed does.

    Args:
        paths: A file or directory path, or several, or ``-`` for standard input.
        **settings: ``fail_on``, ``min_severity``, ``strict``, ``config_path``,
            ``extra_rule_paths``, ``llm`` (False unless set), ``dry_run``, ``ignore_file``,
            ``no_ignore``, ``baseline``, ``write_baseline``, ``ingest``, ``stdin_name``,
            ``no_timestamp``, ``max_nodes`` and ``max_edges``, each as the CLI flag of the same
            name.

    Raises:
        ThreatCodeError: An input could not be analysed, or a setting is invalid.
        UsageError: A named path does not exist.
    """
    return _run(paths, settings).to_dict()


def analyze(
    paths: str | os.PathLike[str] | Sequence[str | os.PathLike[str]],
    **settings: Any,
) -> AnalysisResult:
    """Like ``scan``, but return the graph and the report together.

    The result has ``.graph`` (the infrastructure graph), ``.report`` and ``.attack_paths``, and
    renders to SVG with ``.to_svg()``. Accepts the same settings as ``scan``.
    """
    return _run(paths, settings).analysis
