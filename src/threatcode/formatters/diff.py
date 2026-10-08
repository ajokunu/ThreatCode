"""Threat model diff between two scan reports.

Both inputs must be the JSON reports ``threatcode scan -f json`` writes: a ``threats`` list whose
items carry an ``id`` and a ``severity``, and a ``schema_version`` or ``version``.
Anything else is an error that says what the file is, so a diff of the wrong files can never read
as "no changes".

Attack paths are compared by id, which hashes the node sequence, so a path is added when a new
route to a target opens and removed when the last hop that made it possible is fixed.
They come first in every format, because a new path to a data store matters more than one more
finding.
A report from before attack paths existed has none.

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
from threatcode.formatters._utils import md_code, md_inline, terminal_safe

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
    paths = data.get("attack_paths", [])
    if not isinstance(paths, list) or not all(
        isinstance(p, dict) and isinstance(p.get("id"), str) and p.get("id") for p in paths
    ):
        raise ThreatCodeError(
            f"{path}: 'attack_paths' must be a list of objects that each have an 'id'; {_HINT}"
        )
    return data


def _by_id(threats: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for threat in threats:
        grouped[str(threat["id"])].append(threat)
    return grouped


def _path_severity(path: dict[str, Any]) -> str:
    value = str(path.get("severity", "")).lower()
    return value if value in _RANK else "medium"


def _path_sort_key(path: dict[str, Any]) -> tuple[int, float, str]:
    score = path.get("score", 0)
    number = (
        float(score) if isinstance(score, (int, float)) and not isinstance(score, bool) else 0.0
    )
    return (-_RANK[_path_severity(path)], -number, str(path["id"]))


def _path_summary(path: dict[str, Any]) -> dict[str, Any]:
    """The part of an attack path a diff reports: its id, ends, severity and hop count."""
    hops = path.get("hops")
    return {
        "id": path["id"],
        "entry": str(path.get("entry", "")),
        "target": str(path.get("target", "")),
        "severity": _path_severity(path),
        "score": path.get("score", 0),
        "hops": max(len(hops) - 1, 0) if isinstance(hops, list) else 0,
    }


def compute_diff(baseline_path: str, current_path: str) -> dict[str, Any]:
    """Compare two scan reports: attack paths and threats added, removed or changed."""
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
    base_paths = {str(p["id"]): p for p in baseline.get("attack_paths", [])}
    cur_paths = {str(p["id"]): p for p in current.get("attack_paths", [])}
    return {
        "baseline_file": baseline.get("input_file", ""),
        "current_file": current.get("input_file", ""),
        "baseline_total": len(baseline["threats"]),
        "current_total": len(current["threats"]),
        "attack_paths_added": [
            _path_summary(cur_paths[i])
            for i in sorted(cur_paths, key=lambda i: _path_sort_key(cur_paths[i]))
            if i not in base_paths
        ],
        "attack_paths_removed": [
            _path_summary(base_paths[i])
            for i in sorted(base_paths, key=lambda i: _path_sort_key(base_paths[i]))
            if i not in cur_paths
        ],
        "added": sorted(added, key=_sort_key),
        "removed": sorted(removed, key=_sort_key),
        "changed": changed,
        "unchanged_count": unchanged,
    }


def gating_threats(diff_result: dict[str, Any], threshold: str) -> list[dict[str, Any]]:
    """What a CI gate fails on: new paths, new and worsened threats at or above ``threshold``."""
    floor = _RANK[threshold]
    offenders = [
        p for p in diff_result.get("attack_paths_added", []) if _RANK[_path_severity(p)] >= floor
    ]
    offenders += [t for t in diff_result["added"] if _RANK.get(_severity(t), 0) >= floor]
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


def _any_change(diff: dict[str, Any]) -> bool:
    return bool(
        diff["added"]
        or diff["removed"]
        or diff["changed"]
        or diff.get("attack_paths_added")
        or diff.get("attack_paths_removed")
    )


def _path_line(path: dict[str, Any], *, struck: bool = False) -> str:
    entry, target = md_code(path["entry"]), md_code(path["target"])
    text = f"{entry} to {target}"
    if struck:
        text = f"~~{text}~~"
    return (
        f"- **{path['severity']}** {text} ({_plural(int(path['hops']), 'hop')}) - "
        f"{md_code(str(path['id']))}"
    )


def _format_diff_markdown(diff: dict[str, Any]) -> str:
    lines: list[str] = ["# Threat Model Diff", ""]
    lines.append(f"**Baseline:** {_plural(diff['baseline_total'], 'threat')}")
    lines.append(f"**Current:** {_plural(diff['current_total'], 'threat')}")
    lines.append(f"**Unchanged:** {diff['unchanged_count']}")
    lines.append("")

    new_paths = diff.get("attack_paths_added", [])
    gone_paths = diff.get("attack_paths_removed", [])
    if new_paths:
        lines.append(f"## New Attack Paths (+{len(new_paths)})")
        lines.append("")
        lines += [_path_line(p) for p in new_paths]
        lines.append("")
    if gone_paths:
        lines.append(f"## Closed Attack Paths (-{len(gone_paths)})")
        lines.append("")
        lines += [_path_line(p, struck=True) for p in gone_paths]
        lines.append("")

    added, removed, changed = diff["added"], diff["removed"], diff["changed"]
    if added:
        breakdown = _severity_breakdown(added)
        suffix = f" - {breakdown}" if breakdown else ""
        lines.append(f"## New Threats (+{len(added)}){suffix}")
        lines.append("")
        for t in added:
            title = md_inline(str(t.get("title", "")), limit=300)
            addr = md_code(str(t.get("resource_address", "")))
            lines.append(f"- **{title}** ({_severity(t)}) - {addr}")
        lines.append("")
    if removed:
        lines.append(f"## Resolved Threats (-{len(removed)})")
        lines.append("")
        for t in removed:
            title = md_inline(str(t.get("title", "")), limit=300)
            addr = md_code(str(t.get("resource_address", "")))
            lines.append(f"- ~~{title}~~ ({_severity(t)}) - {addr}")
        lines.append("")
    if changed:
        lines.append(f"## Changed Threats ({len(changed)})")
        lines.append("")
        for c in changed:
            title = md_inline(str(c["title_after"]), limit=300)
            addr = md_code(str(c["resource_address"]))
            detail = f"{c['severity_before']} -> {c['severity_after']}"
            if c["title_before"] != c["title_after"]:
                detail += f", was titled {md_inline(str(c['title_before']), limit=300)}"
            lines.append(f"- **{title}** ({detail}) - {addr}")
        lines.append("")
    if not _any_change(diff):
        lines.append("No changes detected.")
    return "\n".join(lines)


def _format_diff_text(diff: dict[str, Any]) -> str:
    added, removed, changed = diff["added"], diff["removed"], diff["changed"]

    def safe(value: object) -> str:
        """Report text is untrusted: it may carry a control sequence meant for the terminal."""
        return terminal_safe(str(value))

    lines = [
        f"Baseline {_plural(diff['baseline_total'], 'threat')}, "
        f"current {_plural(diff['current_total'], 'threat')}, "
        f"{diff['unchanged_count']} unchanged"
    ]
    for p in diff.get("attack_paths_added", []):
        lines.append(
            f"+ {safe(p['severity']):<8} attack path {safe(p['entry'])} -> {safe(p['target'])} "
            f"({_plural(int(p['hops']), 'hop')})"
        )
    for p in diff.get("attack_paths_removed", []):
        lines.append(
            f"- {safe(p['severity']):<8} attack path {safe(p['entry'])} -> {safe(p['target'])} "
            f"({_plural(int(p['hops']), 'hop')})"
        )
    for t in added:
        lines.append(
            f"+ {safe(_severity(t)):<8} {safe(t.get('resource_address', ''))}  "
            f"{safe(t.get('title', ''))}"
        )
    for t in removed:
        lines.append(
            f"- {safe(_severity(t)):<8} {safe(t.get('resource_address', ''))}  "
            f"{safe(t.get('title', ''))}"
        )
    for c in changed:
        lines.append(
            f"~ {safe(c['severity_before'])} -> {safe(c['severity_after'])}  "
            f"{safe(c['resource_address'])}  {safe(c['title_after'])}"
        )
    if not _any_change(diff):
        lines.append("No changes detected.")
    return "\n".join(lines) + "\n"
