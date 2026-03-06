"""Threat model diff between two runs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from threatcode.exceptions import ThreatCodeError
from threatcode.formatters._utils import escape_md as _escape_md


def _load_report(path: str) -> dict[str, Any]:
    """Load and validate a threat report JSON file."""
    file_path = Path(path)
    if not file_path.exists():
        raise ThreatCodeError(f"Report file not found: {file_path.name}")
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ThreatCodeError(f"Invalid JSON in report file {file_path.name}: {e}") from e
    if not isinstance(data, dict):
        raise ThreatCodeError(f"Report file {file_path.name} must contain a JSON object")
    return data


def compute_diff(baseline_path: str, current_path: str) -> dict[str, Any]:
    """Compare two threat report JSON files."""
    baseline = _load_report(baseline_path)
    current = _load_report(current_path)

    baseline_threats = {t["id"]: t for t in baseline.get("threats", [])}
    current_threats = {t["id"]: t for t in current.get("threats", [])}

    baseline_ids = set(baseline_threats.keys())
    current_ids = set(current_threats.keys())

    added = [current_threats[tid] for tid in sorted(current_ids - baseline_ids)]
    removed = [baseline_threats[tid] for tid in sorted(baseline_ids - current_ids)]
    unchanged = [current_threats[tid] for tid in sorted(baseline_ids & current_ids)]

    return {
        "baseline_file": baseline.get("input_file", ""),
        "current_file": current.get("input_file", ""),
        "baseline_total": len(baseline_threats),
        "current_total": len(current_threats),
        "added": added,
        "removed": removed,
        "unchanged_count": len(unchanged),
    }


def format_diff(diff_result: dict[str, Any], output_format: str = "json") -> str:
    if output_format == "markdown":
        return _format_diff_markdown(diff_result)
    return json.dumps(diff_result, indent=2)


def _format_diff_markdown(diff: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Threat Model Diff")
    lines.append("")
    lines.append(f"**Baseline:** {diff['baseline_total']} threats")
    lines.append(f"**Current:** {diff['current_total']} threats")
    lines.append(f"**Unchanged:** {diff['unchanged_count']}")
    lines.append("")

    added = diff.get("added", [])
    if added:
        lines.append(f"## New Threats (+{len(added)})")
        lines.append("")
        for t in added:
            if not isinstance(t, dict) or "id" not in t:
                continue
            title = _escape_md(t.get("title", ""))
            addr = _escape_md(t.get("resource_address", ""))
            lines.append(f"- **{title}** ({t.get('severity', 'unknown')}) — `{addr}`")
        lines.append("")

    removed = diff.get("removed", [])
    if removed:
        lines.append(f"## Resolved Threats (-{len(removed)})")
        lines.append("")
        for t in removed:
            if not isinstance(t, dict) or "id" not in t:
                continue
            title = _escape_md(t.get("title", ""))
            addr = _escape_md(t.get("resource_address", ""))
            lines.append(f"- ~~{title}~~ ({t.get('severity', 'unknown')}) — `{addr}`")
        lines.append("")

    if not added and not removed:
        lines.append("No changes detected.")

    return "\n".join(lines)
