"""Threat model diff between two scan reports.

Both inputs must be the JSON reports ``threatcode scan -f json`` writes: a ``threats`` list whose
items carry an ``id`` and a ``severity``, and a ``schema_version`` or ``version``.
Anything else is an error that says what the file is, so a diff of the wrong files can never read
as "no changes".

Threat ids are compared as multisets: an id that appears twice in one report and once in the other
is one added or removed threat.
A threat present in both with a different severity or title is *changed*.
A severity is the effective severity when the report has one, else the base severity.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from threatcode.exceptions import ThreatCodeError
from threatcode.formatters._utils import escape_md as _escape_md

SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
_RANK = {name: len(SEVERITY_ORDER) - index for index, name in enumerate(SEVERITY_ORDER)}
_HINT = "diff compares the JSON reports written by `threatcode scan -f json`"


def _severity(threat: dict[str, Any]) -> str:
    return str(threat.get("effective_severity") or threat.get("severity"))


def _sort_key(threat: dict[str, Any]) -> tuple[int, str, str]:
    return (-_RANK.get(_severity(threat), 0), str(threat.get("title", "")), str(threat["id"]))


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def load_report(path: str) -> dict[str, Any]:
    """Load a scan report and check that it is one.

    Raises:
        ThreatCodeError: The file is missing, is not JSON, or is not a ThreatCode scan report.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise ThreatCodeError(f"Report file not found: {path}")
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ThreatCodeError(f"{path} is not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise ThreatCodeError(f"{path} is not a ThreatCode scan report: expected a JSON object")
    schema = data.get("$schema")
    if isinstance(data.get("runs"), list) or (
        isinstance(schema, str) and "sarif" in schema.lower()
    ):
        raise ThreatCodeError(f"{path} is a SARIF file, not a ThreatCode report; {_HINT}")
    threats = data.get("threats")
    if not isinstance(threats, list):
        raise ThreatCodeError(
            f"{path} is not a ThreatCode scan report (no 'threats' list); {_HINT}"
        )
    if "schema_version" not in data and "version" not in data:
        raise ThreatCodeError(
            f"{path} is not a ThreatCode scan report (no schema_version or version); {_HINT}"
        )
    for index, threat in enumerate(threats, start=1):
        valid = (
            isinstance(threat, dict)
            and isinstance(threat.get("id"), str)
            and threat.get("id")
            and _severity(threat) in _RANK
        )
        if not valid:
            raise ThreatCodeError(
                f"{path}: threat {index} must be an object with an 'id' and a 'severity' "
                f"({', '.join(SEVERITY_ORDER)}); {_HINT}"
            )
    return data


def _by_id(threats: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for threat in threats:
        grouped[str(threat["id"])].append(threat)
    return grouped


def compute_diff(baseline_path: str, current_path: str) -> dict[str, Any]:
    """Compare two scan reports: added, removed, changed and the count left unchanged."""
    baseline = load_report(baseline_path)
    current = load_report(current_path)
    base_groups = _by_id(baseline["threats"])
    cur_groups = _by_id(current["threats"])
    base_counts = Counter({k: len(v) for k, v in base_groups.items()})
    cur_counts = Counter({k: len(v) for k, v in cur_groups.items()})

    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    unchanged = 0
    for threat_id in sorted(set(base_counts) | set(cur_counts)):
        before, after = base_groups.get(threat_id, []), cur_groups.get(threat_id, [])
        paired = min(len(before), len(after))
        for old, new in zip(before[:paired], after[:paired], strict=True):
            if _severity(old) != _severity(new) or old.get("title") != new.get("title"):
                changed.append(
                    {
                        "id": threat_id,
                        "title": new.get("title", ""),
                        "resource_address": new.get("resource_address", ""),
                        "severity_before": _severity(old),
                        "severity_after": _severity(new),
                        "title_before": old.get("title", ""),
                        "title_after": new.get("title", ""),
                    }
                )
            else:
                unchanged += 1
        added.extend(after[paired:])
        removed.extend(before[paired:])

    changed.sort(
        key=lambda c: (-_RANK[c["severity_after"]], str(c["title"]), str(c["id"])),
    )
    return {
        "baseline_file": baseline.get("input_file", ""),
        "current_file": current.get("input_file", ""),
        "baseline_total": len(baseline["threats"]),
        "current_total": len(current["threats"]),
        "added": sorted(added, key=_sort_key),
        "removed": sorted(removed, key=_sort_key),
        "changed": changed,
        "unchanged_count": unchanged,
    }


def gating_threats(diff_result: dict[str, Any], threshold: str) -> list[dict[str, Any]]:
    """The added threats, and the worsened ones, whose severity is at or above ``threshold``."""
    floor = _RANK[threshold]
    offenders = [t for t in diff_result["added"] if _RANK.get(_severity(t), 0) >= floor]
    for change in diff_result["changed"]:
        after = _RANK[change["severity_after"]]
        if after > _RANK[change["severity_before"]] and after >= floor:
            offenders.append(change)
    return offenders


def format_diff(diff_result: dict[str, Any], output_format: str = "json") -> str:
    if output_format == "markdown":
        return _format_diff_markdown(diff_result)
    if output_format == "text":
        return _format_diff_text(diff_result)
    return json.dumps(diff_result, indent=2)


def _severity_breakdown(threats: list[dict[str, Any]]) -> str:
    counts = Counter(_severity(t) for t in threats)
    return ", ".join(f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts.get(s))


def _format_diff_markdown(diff: dict[str, Any]) -> str:
    lines: list[str] = ["# Threat Model Diff", ""]
    lines.append(f"**Baseline:** {_plural(diff['baseline_total'], 'threat')}")
    lines.append(f"**Current:** {_plural(diff['current_total'], 'threat')}")
    lines.append(f"**Unchanged:** {diff['unchanged_count']}")
    lines.append("")

    added, removed, changed = diff["added"], diff["removed"], diff["changed"]
    if added:
        breakdown = _severity_breakdown(added)
        suffix = f" - {breakdown}" if breakdown else ""
        lines.append(f"## New Threats (+{len(added)}){suffix}")
        lines.append("")
        for t in added:
            title = _escape_md(str(t.get("title", "")))
            addr = _escape_md(str(t.get("resource_address", "")))
            lines.append(f"- **{title}** ({_severity(t)}) - `{addr}`")
        lines.append("")
    if removed:
        lines.append(f"## Resolved Threats (-{len(removed)})")
        lines.append("")
        for t in removed:
            title = _escape_md(str(t.get("title", "")))
            addr = _escape_md(str(t.get("resource_address", "")))
            lines.append(f"- ~~{title}~~ ({_severity(t)}) - `{addr}`")
        lines.append("")
    if changed:
        lines.append(f"## Changed Threats ({len(changed)})")
        lines.append("")
        for c in changed:
            title = _escape_md(str(c["title_after"]))
            addr = _escape_md(str(c["resource_address"]))
            detail = f"{c['severity_before']} -> {c['severity_after']}"
            if c["title_before"] != c["title_after"]:
                detail += f", was titled {_escape_md(str(c['title_before']))}"
            lines.append(f"- **{title}** ({detail}) - `{addr}`")
        lines.append("")
    if not (added or removed or changed):
        lines.append("No changes detected.")
    return "\n".join(lines)


def _format_diff_text(diff: dict[str, Any]) -> str:
    added, removed, changed = diff["added"], diff["removed"], diff["changed"]
    lines = [
        f"Baseline {_plural(diff['baseline_total'], 'threat')}, "
        f"current {_plural(diff['current_total'], 'threat')}, "
        f"{diff['unchanged_count']} unchanged"
    ]
    for t in added:
        lines.append(f"+ {_severity(t):<8} {t.get('resource_address', '')}  {t.get('title', '')}")
    for t in removed:
        lines.append(f"- {_severity(t):<8} {t.get('resource_address', '')}  {t.get('title', '')}")
    for c in changed:
        lines.append(
            f"~ {c['severity_before']} -> {c['severity_after']}  "
            f"{c['resource_address']}  {c['title_after']}"
        )
    if not (added or removed or changed):
        lines.append("No changes detected.")
    return "\n".join(lines) + "\n"
