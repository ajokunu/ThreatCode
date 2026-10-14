"""The verdict of the terminal report when part of a Helm chart was not analysed.

A Helm chart whose templates could not be rendered is modelled from the templates that could.
The findings of those are real, but a verdict that counts only them (``5 medium, 9 low``, or
worse ``no findings``) reads as a statement about the whole chart.
So the terminal says ``incomplete`` and how many templates were left out, the way it does for an
input error.

The rule is deliberately narrow.
It looks at the gaps the parsers recorded: a ``helm.render_warning`` or a gap of level ``error``.
Gaps that only approximate (a chart rendered without helm, an unknown plan value) or that
describe a module the scan was never asked to read do not change the verdict; the coverage block
lists them.

Nothing here prints; it returns the phrases the report flows into a line.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Mapping, Sequence
from typing import Any

from threatcode.formatters._utils import plural
from threatcode.formatters._utils import verdict_items as shared_verdict_items
from threatcode.formatters.terminal_coverage import unique_gaps
from threatcode.formatters.terminal_layout import TIE
from threatcode.models.report import ThreatReport

__all__ = ["incomplete_phrase", "unanalysed_templates", "verdict_items"]

HELM_WARNING = "helm.render_warning"
# ``..., worst critical``: the severity is not left alone at the start of the next line
_WORST = re.compile(r"(, worst) (\w+)$")
# A warning about the chart as a whole is filed under its Chart.yaml; one about a template that
# rendered to nothing usable is filed under that template.
_CHART_FILES = frozenset({"chart.yaml", "chart.yml"})


def _is_chart_file(path: str) -> bool:
    return posixpath.basename(path.replace("\\", "/")).lower() in _CHART_FILES


def unanalysed_templates(gaps: Sequence[Mapping[str, Any]]) -> list[str]:
    """The templates a Helm render warning says were left out, without repeats, in order.

    A template is named by the file its warning is filed under.
    A warning filed under the chart itself (a dependency that is not vendored, a subchart that
    cannot be rendered) does not say which templates it affects and is not counted here.
    """
    seen: dict[str, None] = {}
    for gap in unique_gaps(gaps):
        file = str(gap.get("file") or "")
        if gap.get("code") == HELM_WARNING and file and not _is_chart_file(file):
            seen.setdefault(file, None)
    return list(seen)


def incomplete_phrase(gaps: Sequence[Mapping[str, Any]]) -> str:
    """``2 templates not analysed``: why a scan with these gaps is incomplete, or ``""``.

    Empty when no gap is a Helm render warning or an error, which is the case for a clean scan
    and for gaps that only approximate.
    """
    unique = unique_gaps(gaps)
    templates = unanalysed_templates(unique)
    warned = any(g.get("code") == HELM_WARNING for g in unique)
    errors = sum(1 for g in unique if g.get("level") == "error")
    parts: list[str] = []
    if templates:
        parts.append(f"{plural(len(templates), 'template')} not analysed")
    elif warned:
        parts.append("Helm chart not fully analysed")
    if errors:
        parts.append(plural(errors, "error"))
    return ", ".join(parts)


def verdict_items(report: ThreatReport) -> list[tuple[str, str]]:
    """The verdict as phrases: ``incomplete (2 templates not analysed); in the rest: ...``.

    It is the shared verdict, with the gaps above put in front of it.
    A report that already says ``incomplete`` or ``no result`` because of an input error is left
    alone: it has said so, and the coverage block lists the gaps.
    The one phrase it changes is the bare ``no findings``, which after the prefix would read as
    a statement about the whole chart; the rest of the chart had ``nothing found``.
    A ``worst critical`` at the end of a phrase is kept on one line.
    """
    items = [(_keep_worst(text), style) for text, style in shared_verdict_items(report)]
    problem = incomplete_phrase(report.coverage.gaps)
    if not problem or report.coverage.errors:
        return items
    if items and items[0][0].startswith(("incomplete", "no result")):
        return items
    rest = [
        ("nothing found", "") if text == "no findings" else (text, style) for text, style in items
    ]
    return [(f"incomplete ({problem}); in the rest:", "high"), *rest]


def _keep_worst(text: str) -> str:
    return _WORST.sub(rf"\1{TIE}\2", text)
