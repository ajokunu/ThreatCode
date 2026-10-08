"""Markdown report, written to be posted as a pull request comment.

The report reads in the order a reviewer needs it:

1. a title, a hidden marker line (so a CI step can find its own comment and edit it in place) and
   a one-line verdict;
2. the severity table;
3. the attack paths, each as ordered hops, with a Mermaid flowchart of the hops;
4. a table of the top risks across all categories;
5. the findings, one section per STRIDE category with the category that holds the worst finding
   first, and findings that share a root cause on one resource collapsed into one entry;
6. what the scan could not analyse, and the state of the LLM phase.

An attack path says what each hop does in words (``sends traffic on HTTPS 443``, ``assumes the
role``), lists the findings that enable it once (a finding that enabled the hop before is not
repeated) and, when it starts with hops an earlier path already lists, says so instead of
repeating them.

GitHub rejects a comment over 65,536 characters, so the report is capped at ``MAX_CHARS`` (60,000).
When findings do not fit, the most severe are kept and a footer says how many were left out.
The report has no timestamp when the scan was run without one, so two runs over the same input
produce the same comment and an update in place shows no change.

Everything that comes from the scanned input goes through ``md_inline`` or ``md_code``, so a
hostile resource name or model output cannot start a heading, a list, a table row or an
@-mention.
A URL in running text becomes a code span rather than carrying an invisible character, so it can
be copied as it is and never turns into a link.
Severities are plain text labels such as ``[HIGH]``.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from threatcode.engine.mitre import TECHNIQUE_DB
from threatcode.formatters._utils import (
    STRIDE_ORDER,
    collapse_whitespace,
    md_code,
    md_inline,
    plural,
    severity_counts,
    severity_label,
    stride_label,
    technique_url,
    threat_source,
    truncate,
    verdict_line,
)
from threatcode.formatters.diagram_labels import (
    Enabler,
    edge_phrase,
    hop_enablers,
    humanize_tokens,
    shared_prefix_length,
)
from threatcode.formatters.mermaid import attack_path_flowchart
from threatcode.models.attack_path import AttackPath
from threatcode.models.report import ThreatReport, threat_severity
from threatcode.models.threat import Severity, Threat, ThreatSource

if TYPE_CHECKING:
    from threatcode.ir.graph import InfraGraph

__all__ = ["MARKER", "MAX_CHARS", "format_markdown"]

MARKER = "<!-- threatcode-report -->"
# GitHub's limit for a comment is 65,536 characters; the rest is headroom.
MAX_CHARS = 60_000
TOP_RISKS = 10
MAX_PATHS = 10
MAX_PATH_DIAGRAMS = 5
MAX_LISTED = 10
_TITLE_LIMIT = 200
_DESCRIPTION_LIMIT = 1500
_MITIGATION_LIMIT = 800
_SUB_BULLET_LIMIT = 300
# A severity reason can name the whole route from the internet; cutting it leaves an open bracket
_REASON_LIMIT = 600
_RESERVE = 200
# Fewer leading hops than this are not worth collapsing into a reference to an earlier path
_MIN_SHARED_HOPS = 2


# Where each finding sits: threat id -> (file, start line); "" when nothing knows.
_Places = dict[str, tuple[str, int | None]]

# A web address in running text, up to the first character that ends it
_URL = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"'`|]+")
_URL_TRAILING = ".,;:!?)]}"
_URL_MARK = "\ue000{}\ue001"
_URL_SLOT = re.compile("\ue000(\\d+)\ue001")
_PRIVATE_USE = re.compile("[\ue000-\uf8ff]")


def _prose(text: str, *, limit: int | None = None) -> str:
    """Untrusted running text as inline Markdown, with each web address in a code span.

    ``md_inline`` keeps a bare address from becoming a link by putting an invisible character
    inside ``://``, which breaks the address for anyone who copies it.
    A code span is inert for the same reason and copies exactly, so addresses go there and the
    rest of the text goes through ``md_inline``.
    The engine's edge type tokens (``network_flow``) read as words.
    """
    flat = _PRIVATE_USE.sub("", collapse_whitespace(humanize_tokens(text)))
    if limit is not None:
        flat = truncate(flat, limit)
    urls: list[str] = []

    def slot(match: re.Match[str]) -> str:
        url = match.group(0)
        tail = ""
        while url and url[-1] in _URL_TRAILING:
            tail = url[-1] + tail
            url = url[:-1]
        if not url:
            return match.group(0)
        urls.append(url)
        return _URL_MARK.format(len(urls) - 1) + tail

    marked = _URL.sub(slot, flat)
    return _URL_SLOT.sub(lambda m: md_code(urls[int(m.group(1))]), md_inline(marked))


@dataclass
class _Entry:
    """One finding, or the findings of one resource that share a root cause."""

    threats: list[Threat]
    grouped: bool = False
    places: _Places = field(default_factory=dict)

    @property
    def first(self) -> Threat:
        return self.threats[0]

    @property
    def severity(self) -> Severity:
        return max(threat_severity(t) for t in self.threats)

    @property
    def sort_key(self) -> tuple[int, str, str, str]:
        first = self.first
        return (-self.severity.rank, first.resource_address, first.title, first.id)


def format_markdown(
    report: ThreatReport,
    graph: InfraGraph | None = None,
    *,
    max_chars: int = MAX_CHARS,
    top_risks: int = TOP_RISKS,
) -> str:
    """Format a report as Markdown for a pull request comment, at most ``max_chars`` long."""
    places: _Places = {}
    for threat in report.threats:
        file, line, _end = threat_source(threat, graph)
        places[threat.id] = (file, line)
    entries = _entries(report.threats, places)
    head = _head(report, entries, top_risks)
    tail = _coverage(report)
    budget = max_chars - len(head) - len(tail) - _RESERVE
    chosen, omitted = _select(entries, budget)
    body = _sections(chosen)
    footer = ""
    if omitted:
        footer = (
            f"_{plural(omitted, 'more threat')} omitted to keep this report under "
            f"{max_chars:,} characters; see the full report artifact._\n"
        )
    out = head + body + tail + footer
    if len(out) > max_chars:
        out = _hard_cap(head + tail, max_chars)
    return out


# ── grouping and selection ────────────────────────────────────────────


def _entries(threats: Sequence[Threat], places: _Places) -> list[_Entry]:
    """Findings as entries, most severe first; a shared root cause on one resource is one entry."""
    groups: dict[tuple[str, str], list[Threat]] = {}
    singles: list[Threat] = []
    for threat in threats:
        if threat.root_cause:
            groups.setdefault((threat.resource_address, threat.root_cause), []).append(threat)
        else:
            singles.append(threat)
    entries = [_Entry([t], places=places) for t in singles]
    for members in groups.values():
        ordered = sorted(members, key=lambda t: (-threat_severity(t).rank, t.title, t.id))
        entries.append(_Entry(ordered, grouped=len(ordered) > 1, places=places))
    entries.sort(key=lambda e: e.sort_key)
    return entries


def _select(entries: list[_Entry], budget: int) -> tuple[list[_Entry], int]:
    """The leading entries (most severe first) that fit ``budget``, and the threats left over."""
    chosen: list[_Entry] = []
    used = 0
    opened: set[str] = set()
    for index, entry in enumerate(entries):
        category = entry.first.stride_category
        cost = sum(len(line) + 1 for line in _entry_lines(entry))
        if category not in opened:
            cost += len(_section_heading(category)) + 2
        if used + cost > budget:
            return chosen, sum(len(e.threats) for e in entries[index:])
        used += cost
        opened.add(category)
        chosen.append(entry)
    return chosen, 0


def _hard_cap(rest: str, max_chars: int) -> str:
    """Last resort when the fixed parts alone are too long: cut at a line and close any fence."""
    note = f"\n_Report cut at {max_chars:,} characters; see the full report artifact._\n"
    cut = rest[: max(max_chars - len(note) - 8, 0)]
    cut = cut[: cut.rfind("\n")] if "\n" in cut else cut
    if cut.count("```") % 2:
        cut += "\n```"
    return cut + note


# ── head ──────────────────────────────────────────────────────────────


def _head(report: ThreatReport, entries: list[_Entry], top_risks: int) -> str:
    lines: list[str] = ["# ThreatCode Threat Model Report", MARKER, ""]
    lines.append(f"- **Verdict:** {verdict_line(report)}")
    if report.input_file:
        lines.append(f"- **Input:** {md_code(report.input_file)}")
    lines.append(f"- **Scanned resources:** {report.scanned_resources}")
    total = f"{len(report.threats)}"
    if entries and len(entries) < len(report.threats):
        total += f" ({plural(len(entries), 'entry', 'entries')} after grouping by root cause)"
    lines.append(f"- **Total threats:** {total}")
    if report.timestamp:
        lines.append(f"- **Timestamp:** {md_inline(report.timestamp)}")
    lines.append("")

    counts = severity_counts(report.threats)
    if counts:
        lines += ["## Summary", "", "| Severity | Count |", "|----------|-------|"]
        lines += [f"| {severity_label(name)} | {count} |" for name, count in counts.items()]
        lines.append("")

    lines += _attack_path_section(report)
    if not report.threats:
        lines += ["No threats detected.", ""]
    elif entries:
        lines += _top_risks(entries[:top_risks])
    return "\n".join(lines) + "\n"


def _attack_path_section(report: ThreatReport) -> list[str]:
    paths = sorted(report.attack_paths, key=lambda p: (-p.severity.rank, -p.score, p.id))
    if not paths:
        return []
    by_id = {t.id: t for t in report.threats}
    lines = ["## Attack paths", ""]
    lines.append(
        f"{plural(len(paths), 'path')} from an exposed entry point to a sensitive target, "
        "most severe first."
    )
    lines.append("")
    shown = paths[:MAX_PATHS]
    for number, path in enumerate(shown, start=1):
        lines += _path_lines(number, path, by_id, shown[: number - 1])
    if len(paths) > len(shown):
        lines += [f"_{len(paths) - len(shown)} more attack paths are in the JSON report._", ""]
    diagram = attack_path_flowchart(shown, limit=MAX_PATH_DIAGRAMS)
    if diagram:
        lines += [
            "_The diagram draws the hops of these paths only. "
            "`threatcode scan -f mermaid` draws the whole graph._",
            "",
            "```mermaid",
            diagram.rstrip("\n"),
            "```",
            "",
        ]
    return lines


def _path_lines(
    number: int, path: AttackPath, by_id: dict[str, Threat], earlier: Sequence[AttackPath] = ()
) -> list[str]:
    hops = path.hops
    lines = [
        f"### {number}. {severity_label(path.severity)} {md_code(path.entry)} to "
        f"{md_code(path.target)} ({plural(max(len(hops) - 1, 0), 'hop')})",
        "",
    ]
    if path.rationale:
        lines += [_prose(path.rationale, limit=_DESCRIPTION_LIMIT), ""]
    shared, source = shared_prefix_length(path, earlier)
    if shared < _MIN_SHARED_HOPS:
        shared = 0
    if shared:
        named = ", ".join(md_code(hop.node_id) for hop in hops[:shared])
        span = "Hop 1" if shared == 1 else f"Hops 1 to {shared}"
        lines += [f"{span} are the same as in path {source + 1}: {named}.", ""]
    enablers = hop_enablers(path, by_id)
    for index, hop in enumerate(hops, start=1):
        if index <= shared:
            continue
        zone = f" ({md_inline(hop.zone)} zone)" if hop.zone else ""
        line = f"{index}. {md_code(hop.node_id)}{zone}"
        if hop.edge_type_to_next:
            target_type = hops[index].resource_type if index < len(hops) else ""
            phrase = edge_phrase(hop.edge_type_to_next, via=hop.via, target_type=target_type)
            line += f", then {_prose(phrase)}"
        if hop.techniques:
            line += f"; ATT&CK {_technique_links(hop.techniques)}"
        lines.append(line)
        lines += [_enabler_line(enabler) for enabler in enablers[index - 1]]
    lines.append("")
    return lines


def _enabler_line(enabler: Enabler) -> str:
    if not enabler.known or enabler.severity is None:
        return f"   - enabled by finding {md_code(enabler.threat_id)}"
    return (
        f"   - enabled by {severity_label(enabler.severity)} "
        f"{_prose(enabler.title, limit=_TITLE_LIMIT)} ({md_code(enabler.label)})"
    )


def _top_risks(entries: list[_Entry]) -> list[str]:
    lines = [
        f"## Top risks ({len(entries)})",
        "",
        "| # | Severity | Finding | Resource | ATT&CK |",
        "|---|----------|---------|----------|--------|",
    ]
    for number, entry in enumerate(entries, start=1):
        first = entry.first
        techniques = _technique_links(_techniques(entry))
        lines.append(
            f"| {number} | {severity_label(entry.severity)} | {_entry_title(entry)} | "
            f"{md_code(first.resource_address, table=True)} | {techniques} |"
        )
    lines.append("")
    return lines


# ── findings ──────────────────────────────────────────────────────────


def _section_heading(category: str) -> str:
    return f"## {stride_label(category)}"


def _sections(entries: list[_Entry]) -> str:
    by_category: dict[str, list[_Entry]] = {}
    for entry in entries:
        by_category.setdefault(entry.first.stride_category, []).append(entry)
    lines: list[str] = []
    for category in _category_order(by_category):
        lines += [_section_heading(category), ""]
        for entry in by_category[category]:
            lines += _entry_lines(entry)
    return "\n".join(lines) + "\n" if lines else ""


def _category_order(by_category: dict[str, list[_Entry]]) -> list[str]:
    """STRIDE categories with the worst finding first, then in the order STRIDE names them.

    A reader of a pull request comment looks for what to fix first, and the only critical finding
    of a scan should not be in the last section.
    """

    def key(category: str) -> tuple[int, int, str]:
        worst = max(entry.severity.rank for entry in by_category[category])
        place = STRIDE_ORDER.index(category) if category in STRIDE_ORDER else len(STRIDE_ORDER)
        return (-worst, place, category)

    return sorted(by_category, key=key)


def _entry_title(entry: _Entry) -> str:
    if entry.grouped:
        cause = entry.first.root_cause.replace("_", " ").replace("-", " ").strip()
        return (
            f"{md_inline(cause[:1].upper() + cause[1:], limit=80)} ({len(entry.threats)} findings)"
        )
    return _prose(entry.first.title, limit=_TITLE_LIMIT)


def _entry_heading(entry: _Entry) -> str:
    """The heading of a finding: its severity and title, and the resource unless the title names it.

    A boundary crossing is titled with both of its resources, so repeating one of them at the end
    only makes the heading longer; the facts line under it names the resource anyway.
    """
    first = entry.first
    heading = f"### {severity_label(entry.severity)} {_entry_title(entry)}"
    if not entry.grouped and first.resource_address and first.resource_address in first.title:
        return heading
    return f"{heading} - {md_code(first.resource_address)}"


def _entry_lines(entry: _Entry) -> list[str]:
    first = entry.first
    lines = [_entry_heading(entry), ""]
    if entry.grouped:
        facts = (
            f"**Severity:** {entry.severity.value.capitalize()} | "
            f"**Resource:** {md_code(first.resource_address)} | "
            f"**Findings:** {len(entry.threats)} sharing one root cause"
        )
        lines += [facts + _location_part(first, entry.places), ""]
        for threat in entry.threats:
            lines.append(_sub_bullet(threat))
        lines.append("")
        return lines

    lines += [_facts_line(first, entry.places), ""]
    techniques = _techniques(entry)
    if techniques:
        lines += [f"**MITRE ATT&CK:** {_technique_links(techniques)}", ""]
    if first.description.strip():
        lines += [_prose(first.description, limit=_DESCRIPTION_LIMIT), ""]
    if first.mitigation.strip():
        mitigation = _prose(first.mitigation, limit=_MITIGATION_LIMIT)
        lines += [f"> **Mitigation:** {mitigation}", ""]
    return lines


def _severity_text(threat: Threat) -> str:
    """``Medium (base low, raised one level because the data store is tagged ...)``.

    The engine words a reason as ``raised one level: <why>``; written out after the base severity
    that is a second colon in one line, so it becomes a clause with ``because``.
    """
    effective = threat_severity(threat)
    text = effective.value.capitalize()
    if effective == threat.severity:
        return text
    reasons = [_because(part) for part in threat.severity_reason.split("; ") if part.strip()]
    reason = f", {_prose('; '.join(reasons), limit=_REASON_LIMIT)}" if reasons else ""
    return f"{text} (base {threat.severity.value}{reason})"


def _because(reason: str) -> str:
    """``raised one level: marked intentional: tag x`` as ``raised one level because ...``."""
    change, _, why = reason.partition(": ")
    if not why:
        return change
    head, _, rest = why.partition(": ")
    return f"{change} because {head}" + (f" ({rest})" if rest else "")


def _facts_line(threat: Threat, places: _Places) -> str:
    severity = _severity_text(threat)
    source = threat.source.value
    if threat.source is ThreatSource.LLM:
        source += " (advisory)"
    parts = [
        f"**Severity:** {severity}",
        f"**Resource:** {md_code(threat.resource_address)}",
        f"**Source:** {md_inline(source)}",
    ]
    if threat.rule_id:
        parts.append(f"**Rule:** {md_code(threat.rule_id)}")
    return " | ".join(parts) + _location_part(threat, places)


def _location_part(threat: Threat, places: _Places) -> str:
    file, line = places.get(threat.id, (threat.location_file, threat.location_start_line))
    if not file:
        return ""
    where = f"{file}:{line}" if line else file
    return f" | **Location:** {md_code(where)}"


def _sub_bullet(threat: Threat) -> str:
    label = f" ({md_code(threat.rule_id)})" if threat.rule_id else ""
    title = _prose(threat.title, limit=_TITLE_LIMIT)
    text = f"- {severity_label(threat_severity(threat))} {title}{label}"
    if threat.mitigation.strip():
        text += f": {_prose(threat.mitigation, limit=_SUB_BULLET_LIMIT)}"
    return text


def _techniques(entry: _Entry) -> list[str]:
    seen: dict[str, None] = {}
    for threat in entry.threats:
        for technique in threat.mitre_techniques:
            seen.setdefault(technique, None)
    return list(seen)


def _technique_links(technique_ids: Sequence[str]) -> str:
    """ATT&CK ids as links to attack.mitre.org; an id the data does not know stays plain text."""
    links: list[str] = []
    for technique in technique_ids:
        url = technique_url(technique)
        if url and technique in TECHNIQUE_DB:
            links.append(f"[{technique}]({url})")
        else:
            links.append(md_inline(technique, limit=40))
    return ", ".join(links)


# ── coverage ──────────────────────────────────────────────────────────


def _coverage(report: ThreatReport) -> str:
    cov = report.coverage
    lines = ["## Coverage", ""]
    head = (
        f"{plural(cov.files_discovered, 'file')} discovered, {plural(cov.units_parsed, 'unit')} "
        f"parsed"
    )
    if cov.not_iac_count:
        head += f", {cov.not_iac_count} not infrastructure"
    lines.append(f"- {head}")
    if cov.suppressed or cov.baselined:
        lines.append(f"- Set aside: {cov.suppressed} suppressed, {cov.baselined} baselined")
    if cov.errors:
        lines.append(f"- **Input errors ({len(cov.errors)}):**")
        for err in cov.errors[:MAX_LISTED]:
            where = md_code(err.get("file", "")) + ": " if err.get("file") else ""
            lines.append(f"  - {where}{_prose(err.get('message', ''), limit=300)}")
        _more(lines, len(cov.errors))
    if cov.gaps:
        lines.append(f"- **Coverage gaps ({len(cov.gaps)}):** part of the input was not analysed")
        for gap in cov.gaps[:MAX_LISTED]:
            where = md_code(str(gap["file"])) + ": " if gap.get("file") else ""
            code = md_code(str(gap.get("code", "")))
            lines.append(f"  - {code} {where}{_prose(str(gap.get('message', '')), limit=300)}")
        _more(lines, len(cov.gaps))
    if cov.rule_errors:
        lines.append(f"- Rule errors: {plural(cov.rule_errors, 'rule evaluation')} failed")
    if not (cov.errors or cov.gaps or cov.rule_errors):
        lines.append("- No input errors or coverage gaps were recorded.")
    lines += _llm_lines(report)
    lines.append("")
    return "\n".join(lines) + "\n"


def _more(lines: list[str], total: int) -> None:
    if total > MAX_LISTED:
        lines.append(f"  - ... and {total - MAX_LISTED} more (see coverage in the JSON report)")


def _llm_lines(report: ThreatReport) -> list[str]:
    llm = report.llm
    if not llm:
        return []
    status = str(llm.get("status", ""))
    where = "/".join(str(llm[k]) for k in ("provider", "model") if llm.get(k))
    where = f" ({md_inline(where)})" if where else ""
    if status == "ran":
        count = int(llm.get("threat_count", 0) or 0)
        return [
            f"- LLM analysis ran{where}: {plural(count, 'advisory finding')}. "
            "LLM findings never fail the gate."
        ]
    if status == "failed":
        error = _prose(str(llm.get("error", "")), limit=300)
        return [f"- **LLM analysis failed**{where}: {error}. Only rule-based findings are shown."]
    return []
