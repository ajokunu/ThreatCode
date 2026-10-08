"""Secret findings placed on the resources of a scan.

``find_secrets(units, graph)`` is the call the scan pipeline makes once per scan, after the graph is
built.
``units`` are the ``ScanUnit`` objects of ``threatcode.discovery``: each carries the absolute
``path`` to read, the root-relative POSIX ``relpath``, its ``kind`` and, once parsed, the
``ParsedOutput`` in ``parsed``.
Files are read only through these units, so a symlinked or special file the walker skipped is never
opened.

What is scanned
---------------
The text of the files the scan models: Terraform ``.tf`` and ``.tf.json`` files (plus the
``*.tfvars`` and ``*.tfvars.json`` files beside them), Terraform plan JSON, CloudFormation
templates, Kubernetes manifests (including the base64 ``data`` of a Secret, which is decoded and
scanned) and Helm charts (``values*.yaml`` and the raw ``templates/``, where a hardcoded literal is
found and ``{{ .Values.x }}`` is not).

Dockerfiles and MCP configs are not scanned here.
``DOCKER_ENV_SECRET``, ``DOCKER_ARG_SECRET`` and ``MCP_SECRET_IN_CONFIG`` already cover them with
the same detectors, so scanning them again would report one secret twice.

What a finding is
-----------------
Each match becomes a ``Threat`` with ``source=SECRET`` and ``rule_id`` ``SECRET_<KIND>``.
Its ``resource_address`` is the innermost resource whose lines contain the match, or empty when no
resource does (a variable default, a file-level value), so the finding joins the graph and the
attack paths through the resource that exposes the secret.
``metadata`` holds the ``attribute`` (the key the value sits under, when known), the ``preview``
(``[REDACTED <rule> len=<n>]``, never a character of the secret) and ``fingerprint_hint``.
The hint is built from the rule, file, address and attribute, or from the line with the secret
masked, and never from the value, so a fingerprint cannot be used to confirm a guessed password.
"""

from __future__ import annotations

import base64
import binascii
import logging
import os
import re
import stat
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from threatcode.diagnostics import Diagnostic, register_code
from threatcode.engine.mitre import tactics_for_techniques
from threatcode.engine.secrets.config import SecretScanConfig
from threatcode.engine.secrets.scanner import SecretMatch, SecretScanner, decode_secret_text
from threatcode.models.threat import Severity, Threat, ThreatSource, hash_id

if TYPE_CHECKING:
    from threatcode.discovery import ScanUnit
    from threatcode.ir.graph import InfraGraph
    from threatcode.ir.nodes import InfraNode
    from threatcode.parsers.base import ParsedOutput

__all__ = ["find_secrets", "find_secrets_in_file"]

logger = logging.getLogger(__name__)

register_code(
    "secrets.file_skipped",
    "A file was not scanned for secrets because it was too large, binary or unreadable",
)
register_code(
    "secrets.truncated",
    "A file holds more secrets than the report limit, so the rest were not listed",
)

# Formats whose secrets are already reported by their own rules
_COVERED_ELSEWHERE = frozenset({"dockerfile", "mcp_config"})
_YAML_LIKE = frozenset({".yaml", ".yml", ".tpl"})
_TECHNIQUES = ["T1552.001"]
_CONFIDENCE = {"provider": 0.95, "structure": 0.85, "generic": 0.6}
_MAX_HELM_FILES = 2000
_MAX_SECRET_DATA_BYTES = 64 * 1024
_MAX_PROPERTY_NODES = 5000
_ADDRESS_LOOKBACK = 400

_SKIP_DIRS = frozenset({".git", "node_modules", ".terraform", "__pycache__"})
_HELM_SUFFIXES = frozenset({".yaml", ".yml", ".tpl", ".json"})
_ADDRESS_LINE = re.compile(r'"address"\s*:\s*"([^"]+)"')
_DATA_HEADER = re.compile(r"""^(\s*)"?data"?\s*:\s*\{?\s*$""")
_DATA_ENTRY = re.compile(r"""^\s*"?([^"\s:]{1,253})"?\s*:\s*"?([A-Za-z0-9+/=]{4,})"?\s*,?\s*$""")
_TFVARS = (".tfvars", ".tfvars.json")


@dataclass
class _SourceFile:
    """One file to read: where it is, what to call it, and whether the user named it."""

    path: Path
    relpath: str
    explicit: bool = False


@dataclass
class _Located:
    node: InfraNode | None = None
    attribute: str = ""


@dataclass
class _FileScan:
    """The graph facts about one file that attribution needs."""

    relpath: str
    nodes: list[InfraNode] = field(default_factory=list)
    lines: list[str] = field(default_factory=list)
    format_type: str = ""
    ends: dict[str, int] = field(default_factory=dict)


# -- entry points ------------------------------------------------------------------------------


def find_secrets(
    units: Sequence[ScanUnit],
    graph: InfraGraph,
    config: SecretScanConfig | None = None,
) -> list[Threat]:
    """Return the secret findings in the text of the modeled files of ``units``.

    ``config`` carries the ``secrets`` section of an explicitly named configuration file.
    A configuration found inside the scanned tree must not be passed here: a repository must not
    be able to turn off its own secret detection.
    """
    scanner = SecretScanner(config)
    cfg = scanner.config
    abs_to_rel: dict[str, str] = {}
    sources: list[tuple[ScanUnit, _SourceFile]] = []
    for unit in units:
        if unit.parsed is None or unit.parsed.format_type in _COVERED_ELSEWHERE:
            continue
        for source in _unit_sources(unit):
            abs_to_rel[str(source.path)] = source.relpath
            sources.append((unit, source))
    by_file = _nodes_by_file(graph, abs_to_rel)

    findings: list[Threat] = []
    seen_ids: set[str] = set()
    for unit, source in sources:
        text = _read_source(source, cfg.max_file_size, graph)
        if text is None:
            continue
        format_type = unit.parsed.format_type if unit.parsed is not None else ""
        findings.extend(_scan_source(scanner, source, text, format_type, by_file, graph, seen_ids))
    return findings


def find_secrets_in_file(
    path: Path,
    text: str,
    parsed: ParsedOutput,
    graph: InfraGraph,
    root: Path,
    config: SecretScanConfig | None = None,
) -> list[Threat]:
    """Secret findings for one parsed file whose ``text`` the caller already holds.

    The golden recordings and library callers that parse a single file use this form.
    A Helm ``Chart.yaml`` also pulls in the chart's values and templates, as the pipeline does.
    """
    if parsed.format_type in _COVERED_ELSEWHERE:
        return []
    scanner = SecretScanner(config)
    try:
        relpath = Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        relpath = Path(path).name
    sources: list[tuple[_SourceFile, str | None]] = [
        (_SourceFile(Path(path), relpath, explicit=True), text)
    ]
    if parsed.format_type == "helm":
        chart_dir = Path(path).parent
        base = PurePosixPath(relpath).parent
        sources.extend(
            (src, None) for src in _helm_sources(chart_dir, base) if src.relpath != relpath
        )
    abs_to_rel = {str(src.path): src.relpath for src, _ in sources}
    abs_to_rel[str(Path(path).resolve())] = relpath
    by_file = _nodes_by_file(graph, abs_to_rel)
    findings: list[Threat] = []
    seen_ids: set[str] = set()
    for source, preloaded in sources:
        body = (
            preloaded
            if preloaded is not None
            else _read_source(source, scanner.config.max_file_size, graph)
        )
        if body is None:
            continue
        findings.extend(
            _scan_source(scanner, source, body, parsed.format_type, by_file, graph, seen_ids)
        )
    return findings


# -- which files ---------------------------------------------------------------------------------


def _unit_sources(unit: ScanUnit) -> list[_SourceFile]:
    from threatcode.discovery import HCL_MODULE, HELM_CHART

    if unit.kind == HCL_MODULE:
        sources = [
            _SourceFile(unit.path / PurePosixPath(rel).name, rel, explicit=False)
            for rel in unit.files
        ]
        sources.extend(_tfvars_sources(unit))
        return sources
    if unit.kind == HELM_CHART:
        return _helm_sources(unit.path.parent, unit.base_rel)
    return [_SourceFile(unit.path, unit.relpath, explicit=unit.explicit or unit.stdin)]


def _tfvars_sources(unit: ScanUnit) -> list[_SourceFile]:
    """The variable files beside a module's ``.tf`` files; Terraform loads them with the module."""
    try:
        names = sorted(os.listdir(unit.path))
    except OSError:
        return []
    base = unit.base_rel
    return [
        _SourceFile(unit.path / name, (base / name).as_posix())
        for name in names
        if name.lower().endswith(_TFVARS)
    ]


def _helm_sources(chart_dir: Path, base: PurePosixPath) -> list[_SourceFile]:
    """Chart.yaml, values files and templates of a chart, without following links."""
    sources: list[_SourceFile] = []
    for current, dirs, files in os.walk(chart_dir, followlinks=False):
        dirs[:] = sorted(
            d for d in dirs if d not in _SKIP_DIRS and not os.path.islink(os.path.join(current, d))
        )
        for name in sorted(files):
            if Path(name).suffix.lower() not in _HELM_SUFFIXES:
                continue
            full = Path(current) / name
            rel = (base / PurePosixPath(full.relative_to(chart_dir).as_posix())).as_posix()
            sources.append(_SourceFile(full, rel))
            if len(sources) >= _MAX_HELM_FILES:
                return sources
    return sources


# -- reading -------------------------------------------------------------------------------------


def _read_source(source: _SourceFile, max_size: int, graph: InfraGraph) -> str | None:
    """Read one file as text, or record why it was not scanned.

    Only a regular file is opened.
    A file found by walking is opened without following a link (``O_NOFOLLOW``), so a link created
    after discovery cannot send the read outside the tree.
    """
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if not source.explicit:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source.path, flags)
    except OSError as exc:
        _skipped(graph, source, f"cannot be opened ({exc.strerror or exc})", "warning")
        return None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            return None
        if info.st_size > max_size:
            mib = info.st_size / (1024 * 1024)
            _skipped(
                graph,
                source,
                f"is {mib:.1f} MB, over the {max_size // (1024 * 1024)} MB secret scan limit "
                "(raise secrets.max_file_size in an explicit --config)",
                "warning",
            )
            return None
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(max_size + 1)
    except OSError as exc:
        _skipped(graph, source, f"cannot be read ({exc.strerror or exc})", "warning")
        return None
    finally:
        os.close(descriptor)
    if len(raw) > max_size:
        _skipped(graph, source, "grew past the secret scan size limit while it was read", "warning")
        return None
    text = decode_secret_text(raw)
    if text is None:
        _skipped(graph, source, "looks binary", "info")
    return text


def _skipped(graph: InfraGraph, source: _SourceFile, why: str, level: str) -> None:
    graph.diagnostics.append(
        Diagnostic(
            "warning" if level == "warning" else "info",
            "secrets.file_skipped",
            f"{source.relpath} {why}, so it was not scanned for secrets",
            source.relpath,
        )
    )


# -- the graph side ------------------------------------------------------------------------------


def _nodes_by_file(graph: InfraGraph, abs_to_rel: Mapping[str, str]) -> dict[str, list[InfraNode]]:
    by_file: dict[str, list[InfraNode]] = {}
    for node in graph.nodes.values():
        if not node.source_file:
            continue
        key = abs_to_rel.get(node.source_file) or node.source_file.replace("\\", "/")
        by_file.setdefault(key, []).append(node)
    for nodes in by_file.values():
        nodes.sort(key=lambda n: (n.start_line or 0, n.id))
    return by_file


def _scan_source(
    scanner: SecretScanner,
    source: _SourceFile,
    text: str,
    format_type: str,
    by_file: Mapping[str, list[InfraNode]],
    graph: InfraGraph,
    seen_ids: set[str],
) -> list[Threat]:
    # A Helm chart's templates are Go templates: a match inside a {{ }} action is code
    outcome = scanner.scan_text(text, path=source.relpath, templated=format_type == "helm")
    context = _FileScan(
        relpath=source.relpath,
        nodes=list(by_file.get(source.relpath, ())),
        lines=text.split("\n"),
        format_type=format_type,
    )
    plain = list(outcome.matches)
    decoded: list[tuple[SecretMatch, _Located]] = []
    if format_type in ("kubernetes", "helm") and Path(source.relpath).suffix.lower() in (
        _YAML_LIKE | {".json"}
    ):
        # The encoded text of a Secret's data is not itself the secret, the decoded value is
        encoded_lines, decoded = _secret_data_matches(scanner, context)
        plain = [m for m in plain if m.line not in encoded_lines]
    entries = [(match, _locate(context, match)) for match in plain]
    entries.extend(decoded)
    entries.sort(key=lambda e: (e[0].line, e[0].column, e[0].rule.id))
    threats = _to_threats(context.relpath, entries, seen_ids)
    if outcome.truncated:
        graph.diagnostics.append(
            Diagnostic(
                "warning",
                "secrets.truncated",
                f"{context.relpath} holds more secrets than the report limit, so only the first "
                f"{len(outcome.matches)} are listed",
                context.relpath,
            )
        )
        if threats:
            threats[-1].metadata["truncated"] = True
    return threats


def _end_line(context: _FileScan, node: InfraNode) -> int:
    """The last line of a node: its own, else the line before the next node or document."""
    if node.end_line is not None:
        return node.end_line
    cached = context.ends.get(node.id)
    if cached is not None:
        return cached
    start = node.start_line or 1
    end = len(context.lines)
    for other in context.nodes:
        if (other.start_line or 0) > start:
            end = min(end, (other.start_line or end + 1) - 1)
            break
    if context.relpath.lower().endswith((".yaml", ".yml", ".tpl")):
        for number in range(start + 1, end + 1):
            if context.lines[number - 1].startswith("---"):
                end = number - 1
                break
    context.ends[node.id] = end
    return end


def _locate(context: _FileScan, match: SecretMatch) -> _Located:
    """Find the resource whose lines contain the match, innermost first."""
    nodes = context.nodes
    if not nodes:
        return _Located()
    line = match.line
    if context.format_type == "terraform_plan":
        node = _plan_node(context, match)
        return _Located(node, _property_path(node, match.value) if node else "")
    inside = [
        (node, _end_line(context, node))
        for node in nodes
        if node.start_line is not None and node.start_line <= line <= _end_line(context, node)
    ]
    if not inside:
        return _Located()
    node, _end = min(inside, key=lambda pair: (pair[1] - (pair[0].start_line or 0), pair[0].id))
    return _Located(node, _property_path(node, match.value))


def _plan_node(context: _FileScan, match: SecretMatch) -> InfraNode | None:
    """Plan JSON repeats a resource in several sections, so the nearest ``address`` decides."""
    ids = {node.id: node for node in context.nodes}
    start = max(0, match.line - 1)
    for index in range(start, max(-1, start - _ADDRESS_LOOKBACK), -1):
        found = _ADDRESS_LINE.search(context.lines[index])
        if found and found.group(1) in ids:
            return ids[found.group(1)]
    holders = [n for n in context.nodes if _holds_value(n.properties, match.value)]
    return holders[0] if len(holders) == 1 else None


def _holds_value(properties: Mapping[str, Any], value: str) -> bool:
    return bool(value) and _find_path(properties, value) is not None


def _property_path(node: InfraNode | None, value: str) -> str:
    if node is None or not value:
        return ""
    return _find_path(node.properties, value) or ""


def _find_path(properties: Mapping[str, Any], value: str) -> str | None:
    """Dotted path of the first string property that holds ``value``; None when none does."""
    budget = [_MAX_PROPERTY_NODES]

    def walk(item: Any, path: str, depth: int) -> str | None:
        budget[0] -= 1
        if budget[0] < 0 or depth > 8:
            return None
        if isinstance(item, str):
            return path if value in item else None
        if isinstance(item, Mapping):
            for key, child in item.items():
                found = walk(child, f"{path}.{key}" if path else str(key), depth + 1)
                if found is not None:
                    return found
        elif isinstance(item, (list, tuple)):
            for child in item:
                found = walk(child, f"{path}[]" if path else "[]", depth + 1)
                if found is not None:
                    return found
        return None

    return walk(properties, "", 0)


# -- Kubernetes Secret data ----------------------------------------------------------------------


def _secret_data_matches(
    scanner: SecretScanner, context: _FileScan
) -> tuple[set[int], list[tuple[SecretMatch, _Located]]]:
    """Decode the base64 ``data`` of each Secret manifest and scan what it holds.

    Returns the lines that held encoded entries, so the caller can drop matches on the encoded
    text, and the matches found in the decoded values.
    """
    encoded_lines: set[int] = set()
    results: list[tuple[SecretMatch, _Located]] = []
    for node in context.nodes:
        if node.resource_type != "kubernetes_secret" or node.start_line is None:
            continue
        for number, key, encoded in _data_entries(context, node):
            encoded_lines.add(number)
            decoded = _decode_value(encoded)
            if decoded is None:
                continue
            body = (
                f'{key}: "{decoded}"'
                if "\n" not in decoded and '"' not in decoded
                else f"{key}: {decoded}"
            )
            for found in scanner.scan_text(body).matches:
                first = SecretMatch(
                    rule=found.rule,
                    line=number,
                    column=1,
                    length=found.length,
                    attribute=f"data.{key}",
                    preview=found.preview,
                    masked_line=f"data.{key}",
                    value=found.value,
                )
                results.append((first, _Located(node, f"data.{key}")))
    return encoded_lines, results


def _data_entries(context: _FileScan, node: InfraNode) -> Iterable[tuple[int, str, str]]:
    start = node.start_line or 1
    end = _end_line(context, node)
    data_indent: int | None = None
    for number in range(start, min(end, len(context.lines)) + 1):
        raw = context.lines[number - 1].rstrip("\r")
        if data_indent is None:
            header = _DATA_HEADER.match(raw)
            if header:
                data_indent = len(header.group(1))
            continue
        if not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip())
        if indent <= data_indent:
            data_indent = None
            header = _DATA_HEADER.match(raw)
            if header:
                data_indent = len(header.group(1))
            continue
        entry = _DATA_ENTRY.match(raw)
        if entry:
            yield number, entry.group(1), entry.group(2)


def _decode_value(encoded: str) -> str | None:
    if len(encoded) > _MAX_SECRET_DATA_BYTES * 2:
        return None
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw or len(raw) > _MAX_SECRET_DATA_BYTES:
        return None
    text = decode_secret_text(raw)
    return text.strip("\r\n") if text is not None else None


# -- findings ------------------------------------------------------------------------------------


def _to_threats(
    relpath: str, entries: Sequence[tuple[SecretMatch, _Located]], seen_ids: set[str]
) -> list[Threat]:
    threats: list[Threat] = []
    collapsed: dict[tuple[str, str, str, str], Threat] = {}
    ordinals: dict[tuple[str, int], int] = {}
    for match, located in entries:
        node = located.node
        address = node.id if node else ""
        attribute = match.attribute or located.attribute
        if address:
            key = (match.rule.id, address, attribute, match.value)
            earlier = collapsed.get(key)
            if earlier is not None:
                earlier.metadata["occurrences"] = int(earlier.metadata["occurrences"]) + 1
                continue
        ordinal_key = (match.rule.id, match.line)
        ordinal = ordinals.get(ordinal_key, 0)
        ordinals[ordinal_key] = ordinal + 1
        threat = _threat(relpath, match, node, address, attribute, ordinal)
        if threat.id in seen_ids:
            continue
        seen_ids.add(threat.id)
        threats.append(threat)
        if address:
            collapsed[(match.rule.id, address, attribute, match.value)] = threat
    return threats


def _threat(
    relpath: str,
    match: SecretMatch,
    node: InfraNode | None,
    address: str,
    attribute: str,
    ordinal: int,
) -> Threat:
    rule = match.rule
    where = f"{relpath}:{match.line}"
    on = f" on {address}" if address else ""
    attr = f" (attribute {attribute})" if attribute else ""
    hint_tail = attribute or match.masked_line
    metadata: dict[str, Any] = {
        "preview": match.preview,
        "category": rule.category,
        "fingerprint_hint": hash_id(f"{rule.id}\x00{relpath}\x00{address}\x00{hint_tail}"),
        "occurrences": 1,
    }
    if attribute:
        metadata["attribute"] = attribute
    return Threat(
        id=hash_id(f"secret\x00{rule.id}\x00{relpath}\x00{match.line}\x00{ordinal}"),
        title=f"Hardcoded secret: {rule.title}",
        description=(
            f"A credential ({rule.title}) is written in plain text at {where}{on}{attr}. "
            "Anyone who can read the repository, a plan, a state file or the deployed template "
            f"can use it. The value is not shown here ({match.preview})."
        ),
        stride_category="information_disclosure",
        severity=Severity(rule.severity),
        source=ThreatSource.SECRET,
        resource_type=node.resource_type if node else "",
        resource_address=address,
        mitigation=(
            "Remove the value from the file and rotate the credential, because it is already in "
            "version control history. Read it at deploy time from a secrets manager or a "
            "parameter store instead of writing it in code."
        ),
        rule_id=rule.id,
        confidence=_CONFIDENCE.get(rule.kind, 0.6),
        metadata=metadata,
        mitre_techniques=list(_TECHNIQUES),
        mitre_tactics=tactics_for_techniques(_TECHNIQUES),
        location_file=relpath,
        location_start_line=match.line,
        location_end_line=match.line,
    )
