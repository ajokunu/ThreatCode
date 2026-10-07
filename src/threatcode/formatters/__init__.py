"""Output formats: one registry for the CLI, the Python API and the config file.

``FORMATTERS`` maps a format name to a ``FormatterSpec``: the function that renders an
``AnalysisResult`` to text, the file extension of its output and a one-line description.
The CLI builds its ``--format`` choices from it, the config validates ``output_format`` against it
and ``render`` is the one call that turns an analysis into text.
Formatter modules are imported on first use, so listing the formats costs nothing.

``write_text_file`` is the one way output reaches a file: it rejects a directory and turns every
``OSError`` into a single ``ThreatCodeError`` line that names the absolute path and the reason.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

from threatcode.exceptions import ThreatCodeError, UsageError

if TYPE_CHECKING:
    from threatcode.models.analysis import AnalysisResult

__all__ = [
    "FORMATTERS",
    "FormatterSpec",
    "RenderOptions",
    "format_names",
    "get_formatter",
    "render",
    "write_text_file",
]


@dataclass(frozen=True)
class RenderOptions:
    """Presentation switches a renderer may honor; formats that are data ignore them."""

    # Use ANSI colors. The CLI sets it for a terminal when NO_COLOR is unset and --no-color is off.
    color: bool = False
    # Terminal width for the text report; 0 means find it (COLUMNS, else the terminal, else 100).
    width: int = 0
    # Put the graph (nodes and edges, no properties), the summary by base severity and the ingested
    # sources in the JSON report. Off by default so the JSON is exactly the report.
    include_graph: bool = False


class FormatterSpec(NamedTuple):
    render: Callable[[AnalysisResult, RenderOptions], str]
    extension: str
    description: str


def _json(analysis: AnalysisResult, options: RenderOptions) -> str:
    from threatcode.formatters.json_out import format_json

    return format_json(analysis, include_graph=options.include_graph)


def _sarif(analysis: AnalysisResult, options: RenderOptions) -> str:
    from threatcode.formatters.sarif import format_sarif

    return format_sarif(analysis.report, analysis.graph, source_root=analysis.root)


def _markdown(analysis: AnalysisResult, options: RenderOptions) -> str:
    from threatcode.formatters.markdown import format_markdown

    return format_markdown(analysis.report, analysis.graph)


def _bitbucket(analysis: AnalysisResult, options: RenderOptions) -> str:
    from threatcode.formatters.bitbucket import format_bitbucket

    return format_bitbucket(analysis.report, analysis.graph, source_root=analysis.root)


def _navigator(analysis: AnalysisResult, options: RenderOptions) -> str:
    from threatcode.formatters.attack_navigator import format_attack_navigator

    return format_attack_navigator(analysis.report)


def _mermaid(analysis: AnalysisResult, options: RenderOptions) -> str:
    from threatcode.formatters.mermaid import format_mermaid

    return format_mermaid(analysis)


def _diagram(analysis: AnalysisResult, options: RenderOptions) -> str:
    from threatcode.formatters.diagram import format_diagram

    return format_diagram(analysis.report, analysis.graph)


def _text(analysis: AnalysisResult, options: RenderOptions) -> str:
    from threatcode.formatters.text import format_text

    return format_text(analysis, options)


FORMATTERS: dict[str, FormatterSpec] = {
    "json": FormatterSpec(_json, ".json", "Machine-readable report with coverage"),
    "sarif": FormatterSpec(_sarif, ".sarif", "SARIF 2.1.0 for GitHub code scanning"),
    "markdown": FormatterSpec(_markdown, ".md", "Markdown for pull request comments"),
    "bitbucket": FormatterSpec(_bitbucket, ".json", "Bitbucket Code Insights report"),
    "navigator": FormatterSpec(_navigator, ".json", "MITRE ATT&CK Navigator layer"),
    "mermaid": FormatterSpec(_mermaid, ".mmd", "Mermaid flowchart by trust zone with attack paths"),
    "diagram": FormatterSpec(_diagram, ".svg", "SVG diagram of the infrastructure"),
    "text": FormatterSpec(_text, ".txt", "Human summary for a terminal"),
    # The old name of "navigator", kept so scripts and configs that use it keep working.
    "matrix": FormatterSpec(_navigator, ".json", "Deprecated alias of navigator"),
}


def format_names() -> list[str]:
    """The format names, in display order."""
    return list(FORMATTERS)


def get_formatter(name: str) -> FormatterSpec:
    """The spec of format ``name``.

    Raises:
        UsageError: ``name`` is not a registered format.
    """
    try:
        return FORMATTERS[name]
    except KeyError:
        raise UsageError(
            f"unknown output format '{name}'; choose one of {', '.join(FORMATTERS)}"
        ) from None


def render(name: str, analysis: AnalysisResult, options: RenderOptions | None = None) -> str:
    """Render ``analysis`` in format ``name``."""
    return get_formatter(name).render(analysis, options or RenderOptions())


def write_text_file(path: str | os.PathLike[str], text: str) -> Path:
    """Write ``text`` to ``path`` (UTF-8), creating parent directories; return the absolute path.

    Raises:
        ThreatCodeError: ``path`` is a directory or cannot be written. The message is one line:
            ``cannot write <absolute path>: <reason>``.
    """
    target = Path(os.path.abspath(path))
    try:
        if target.is_dir():
            raise ThreatCodeError(f"cannot write {target}: it is a directory, not a file")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise ThreatCodeError(f"cannot write {target}: {exc.strerror or exc}") from exc
    return target
