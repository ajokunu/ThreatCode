"""SARIF 2.1.0 output for GitHub code scanning.

GitHub binds an alert to a file and a line, remembers it across runs by its fingerprint and
ranks it by ``security-severity``, so the report is written for that:

- Every result points at the file the resource is defined in (a root-relative, percent-encoded
  ``uri`` with ``uriBaseId`` ``%SRCROOT%``) and a ``region``.
  The input file and line 1 stand in when no line is known.
  The resource address never becomes a URI; it is a ``logicalLocation`` of kind ``resource``.
- ``partialFingerprints`` carry the finding's stable fingerprint, so editing a file does not
  close one alert and open another.
- Rules are stable.
  A rule-based finding uses its rule id, a secret its ``SECRET_*`` id, an ingested scanner finding
  ``<tool>:<id>``.
  The findings that have no rule (a trust boundary crossing, a model's suggestion) share one rule
  per zone pair (``THREATCODE_BOUNDARY_<SOURCE>_<TARGET>``) or one rule (``THREATCODE_LLM``), and
  the resource-specific text lives in the result message.
- Each attack path is one result (``THREATCODE_ATTACK_PATH``) with related locations for every hop
  and a code flow over the hops' definitions.
- ``invocations`` say whether the scan completed and carry the input errors, coverage gaps and
  LLM failure as notifications, so a partial scan never looks like a clean one.

Everything that comes from the scanned input is data: the Markdown in ``help`` and
``message.markdown`` is built with the escaping helpers, and the text a model wrote is always
escaped.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from threatcode.engine.mitre import TECHNIQUE_DB
from threatcode.fingerprint import compute_fingerprint
from threatcode.formatters._utils import (
    collapse_whitespace,
    md_inline,
    root_prefix,
    source_uri,
    stride_label,
    technique_url,
    threat_source,
    truncate,
)
from threatcode.models.report import ThreatReport, threat_severity
from threatcode.models.threat import Severity, Threat, ThreatSource

if TYPE_CHECKING:
    from threatcode.ir.graph import InfraGraph
    from threatcode.ir.nodes import InfraNode
    from threatcode.models.attack_path import AttackHop, AttackPath

__all__ = [
    "ATTACK_PATH_RULE",
    "FINGERPRINT_KEY",
    "LLM_RULE",
    "SCHEMA_URL",
    "format_sarif",
    "rule_key",
]

SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/ajokunu/ThreatCode"
FINGERPRINT_KEY = "threatcode/v1"
SRCROOT = "%SRCROOT%"

ATTACK_PATH_RULE = "THREATCODE_ATTACK_PATH"
LLM_RULE = "THREATCODE_LLM"
BOUNDARY_RULE_PREFIX = "THREATCODE_BOUNDARY_"

# GitHub accepts at most this many results in one run and shows ten tags per rule.
MAX_RESULTS = 25_000
MAX_TAGS = 10
MAX_NOTIFICATIONS = 200

# critical 9.5, high 8.0, medium 5.5, low 3.0; GitHub bands: 9.0 and up critical, 7.0 high,
# 4.0 medium, below that low.
# Info has no score: a rule without one shows as a plain note.
_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
}
_SARIF_LEVELS: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_PRECISION_BY_LEVEL = {"definitive": "high", "heuristic": "medium", "absence": "low"}

_ACRONYMS = {
    word.lower(): word
    for word in (  # noqa: SIM905 - one string reads and diffs better than 40 quoted words
        "IAM RDS EC2 S3 VPC KMS EBS EKS ECS SNS SQS TLS SSH RDP API DNS MFA RBAC MCP LLM SQL SSL "
        "ACL CIDR IMDS IMDSv1 IMDSv2 ARN URL JSON AWS GCP CDN ALB WAF SSM ECR NSG AKS CVE IP"
    ).split()
}
_CWE = re.compile(r"^(?:CWE-)?(\d{1,5})$", re.IGNORECASE)
_MAX_MESSAGE = 1500


# ── paths ─────────────────────────────────────────────────────────────


def _input_paths(report: ThreatReport) -> list[str]:
    """The inputs relative to the scan root: ``input_paths``, else the ones ``input_file`` lists."""
    return report.input_paths or [p.strip() for p in report.input_file.split(",")]


def _input_file(report: ThreatReport) -> str:
    """The first path the report names as its input, for a result with no location of its own."""
    first = _input_paths(report)[0]
    return first or "."


# ── entry point ───────────────────────────────────────────────────────


def format_sarif(
    report: ThreatReport,
    graph: InfraGraph | None = None,
    *,
    source_root: str | os.PathLike[str] | None = None,
    indent: int = 2,
) -> str:
    """Format a report as SARIF 2.1.0 JSON.

    ``graph`` gives attack paths and flow targets the file and line of the resources they name.
    ``source_root`` is the directory the report's relative paths are relative to; when it is
    below the current directory, the paths are written relative to the current directory
    instead, which is what GitHub resolves ``%SRCROOT%`` against.
    """
    sarif = _build_sarif(report, graph, root_prefix(source_root))
    return json.dumps(sarif, indent=indent, sort_keys=False)


@dataclass
class _Context:
    report: ThreatReport
    graph: InfraGraph | None
    prefix: str
    path_ids_by_node: dict[str, list[str]] = field(default_factory=dict)

    def node(self, address: str) -> InfraNode | None:
        return self.graph.get_node(address) if self.graph is not None else None

    def location(self, uri: str, start: int | None, end: int | None) -> dict[str, Any]:
        region: dict[str, Any] = {"startLine": max(start or 1, 1)}
        if start and end and end >= start:
            region["endLine"] = end
        return {
            "artifactLocation": {"uri": uri, "uriBaseId": SRCROOT},
            "region": region,
        }

    def threat_location(self, threat: Threat) -> dict[str, Any]:
        file, start, end = threat_source(threat, self.graph)
        if not file:
            file, start, end = _input_file(self.report), None, None
        return self.location(source_uri(file, self.prefix), start, end)

    def node_location(self, node_id: str) -> dict[str, Any] | None:
        node = self.node(node_id)
        if node is None or not node.source_file:
            return None
        return self.location(
            source_uri(node.source_file, self.prefix), node.start_line, node.end_line
        )


def _build_sarif(report: ThreatReport, graph: InfraGraph | None, prefix: str) -> dict[str, Any]:
    ctx = _Context(report, graph, prefix)
    threats = sorted(report.threats, key=_threat_order)
    paths = sorted(report.attack_paths, key=lambda p: (-p.severity.rank, -p.score, p.id))
    for path in paths:
        for hop in path.hops:
            ctx.path_ids_by_node.setdefault(hop.node_id, []).append(path.id)

    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    truncated = 0

    grouped: dict[str, list[Threat]] = {}
    for threat in threats:
        grouped.setdefault(rule_key(threat), []).append(threat)

    def register(key: str, rule: dict[str, Any]) -> int:
        if key not in rule_index:
            rule_index[key] = len(rules)
            rules.append(rule)
        return rule_index[key]

    if paths:
        index = register(ATTACK_PATH_RULE, _attack_path_rule(paths))
        results.extend(_attack_path_result(ctx, path, index) for path in paths)

    fingerprints = _fingerprints(threats)
    for threat in threats:
        key = rule_key(threat)
        index = register(key, _threat_rule(key, grouped[key]))
        if len(results) >= MAX_RESULTS:
            truncated += 1
            continue
        results.append(_threat_result(ctx, threat, key, index, fingerprints[threat.id]))

    driver: dict[str, Any] = {
        "name": "ThreatCode",
        "version": report.version,
        "informationUri": INFORMATION_URI,
        "rules": rules,
    }
    if report.version:
        driver["semanticVersion"] = report.version
    run: dict[str, Any] = {
        "tool": {"driver": driver},
        "automationDetails": {"id": _automation_id(report)},
        "results": results,
        "invocations": [_invocation(ctx, truncated)],
    }
    return {"$schema": SCHEMA_URL, "version": "2.1.0", "runs": [run]}


def _threat_order(threat: Threat) -> tuple[int, str, str, str]:
    return (-threat_severity(threat).rank, threat.resource_address, threat.rule_id, threat.id)


def _automation_id(report: ThreatReport) -> str:
    """``threatcode/<input>/``: the category GitHub keeps one alert set for, per scanned input."""
    joined = "+".join(part.strip() for part in _input_paths(report))
    label = re.sub(r"[^A-Za-z0-9._+-]+", "-", joined).strip("-.")
    return f"threatcode/{label[:80] or 'root'}/"


# ── rules ─────────────────────────────────────────────────────────────


def rule_key(threat: Threat) -> str:
    """The SARIF rule id of a finding.

    A finding with a rule uses it.
    A boundary crossing uses one id per zone pair, a model suggestion one id, an ingested scanner
    finding ``<tool>:<id>``, so a scan with hundreds of crossings has a handful of rules.
    """
    if threat.source is ThreatSource.BOUNDARY:
        meta = threat.metadata
        source, target = meta.get("source_zone"), meta.get("target_zone")
        if isinstance(source, str) and isinstance(target, str) and source and target:
            return f"{BOUNDARY_RULE_PREFIX}{source.upper()}_{target.upper()}"
        return f"{BOUNDARY_RULE_PREFIX}CROSSING"
    if threat.source is ThreatSource.LLM:
        return LLM_RULE
    if threat.source is ThreatSource.SCANNER and threat.tool and threat.rule_id:
        return f"{threat.tool}:{threat.rule_id}"
    return threat.rule_id or threat.id


def _zones(threat: Threat) -> tuple[str, str]:
    meta = threat.metadata
    return str(meta.get("source_zone", "")), str(meta.get("target_zone", ""))


def _threat_rule(key: str, threats: Sequence[Threat]) -> dict[str, Any]:
    first = threats[0]
    severity = max(threat_severity(t) for t in threats)
    if first.source is ThreatSource.BOUNDARY:
        source_zone, target_zone = _zones(first)
        where = f" from the {source_zone} zone to the {target_zone} zone" if source_zone else ""
        title = f"Trust boundary crossing{where}"
        description = (
            f"Traffic crosses a trust boundary{where}. "
            "Each result names the two resources and what the input says about the flow: "
            "whether it is authenticated and whether it is encrypted."
        )
        mitigation = (
            "Authenticate the caller at the receiving end, encrypt the flow in transit "
            "(TLS or mutual TLS) and validate what crosses the boundary."
        )
    elif first.source is ThreatSource.LLM:
        title = "Advisory finding from the LLM analysis"
        description = (
            "A language model proposed this finding from a redacted view of the infrastructure "
            "graph. It is advisory: it is not checked against a rule, it never fails the gate, "
            "and it can be wrong. Each result carries the model's reasoning."
        )
        mitigation = "Review the finding against the configuration and decide whether it applies."
    else:
        title, description, mitigation = first.title, first.description, first.mitigation
    one_line = collapse_whitespace(description)
    help_text = collapse_whitespace(mitigation) or "See the description."
    rule: dict[str, Any] = {
        "id": key,
        "name": _to_pascal_case(title or key),
        "shortDescription": {"text": truncate(collapse_whitespace(title), 200) or key},
        "fullDescription": {"text": one_line or title or key},
        "help": {"text": help_text},
        "defaultConfiguration": {"level": _SARIF_LEVELS[severity]},
        "properties": {"tags": _tags(threats), "precision": _precision(threats)},
    }
    score = _SECURITY_SEVERITY.get(severity)
    if score:
        rule["properties"]["security-severity"] = score
    markdown = _help_markdown(mitigation, _techniques(threats), advisory=False)
    if markdown:
        rule["help"]["markdown"] = markdown
    return rule


def _techniques(threats: Iterable[Threat]) -> list[str]:
    seen: dict[str, None] = {}
    for threat in threats:
        for technique in threat.mitre_techniques:
            seen.setdefault(technique, None)
    return sorted(seen)


def _help_markdown(mitigation: str, techniques: Sequence[str], *, advisory: bool) -> str:
    """Help in Markdown: the mitigation as escaped text and links to the ATT&CK techniques."""
    parts: list[str] = []
    if collapse_whitespace(mitigation):
        parts.append(f"**Mitigation**: {md_inline(mitigation)}")
    links = [
        f"[{t}]({technique_url(t)})" for t in techniques if technique_url(t) and t in TECHNIQUE_DB
    ]
    if links:
        parts.append(f"**ATT&CK**: {', '.join(links)}")
    if advisory and parts:
        parts.append("This finding is advisory.")
    return "\n\n".join(parts)


def _tags(threats: Sequence[Threat]) -> list[str]:
    """At most ten tags, most useful first: STRIDE, source, CWE, OWASP, then ATT&CK."""
    stride = sorted({t.stride_category for t in threats})
    sources = sorted({t.source.value for t in threats})
    cwes = sorted({tag for t in threats for tag in _cwe_tags(t.metadata)})
    owasp = sorted({tag for t in threats for tag in _owasp_tags(t.metadata)})
    techniques = _techniques(threats)
    tags = ["security"]
    tags += [f"stride/{s}" for s in stride]
    tags += [f"source/{s}" for s in sources]
    if any(t.source is ThreatSource.LLM for t in threats):
        tags.append("advisory")
    tags += cwes
    tags += owasp
    tags += [f"mitre/{t}" for t in techniques]
    return list(dict.fromkeys(tags))[:MAX_TAGS]


def _cwe_tags(metadata: dict[str, Any]) -> list[str]:
    value = metadata.get("cwe") if isinstance(metadata, dict) else None
    items = value if isinstance(value, list) else [value]
    tags = []
    for item in items:
        match = _CWE.match(str(item).strip()) if item is not None else None
        if match:
            tags.append(f"external/cwe/cwe-{int(match.group(1))}")
    return tags


def _owasp_tags(metadata: dict[str, Any]) -> list[str]:
    """Return SARIF tags for OWASP IDs a rule declares under metadata.owasp."""
    owasp = metadata.get("owasp") if isinstance(metadata, dict) else None
    if not isinstance(owasp, dict):
        return []
    tags: list[str] = []
    for list_name in ("mcp_top_10", "agentic_top_10"):
        ids = owasp.get(list_name)
        if isinstance(ids, list):
            tags.extend(f"owasp-{list_name.replace('_', '-')}/{i}" for i in ids)
    return tags


def _precision(threats: Sequence[Threat]) -> str:
    """GitHub's ``precision``: how often a result of this rule is right.

    A rule that proves the condition from the configuration is high, one that infers it from
    names or partial data medium, and one that fires because something is missing low.
    Model suggestions are always low.
    The rule's confidence reaches a finding as ``Threat.confidence`` (1.0, 0.7, 0.5), so the
    least certain finding of the rule decides.
    """
    if any(t.source is ThreatSource.LLM for t in threats):
        return "low"
    level = min(t.confidence for t in threats)
    if level >= 0.9:
        return _PRECISION_BY_LEVEL["definitive"]
    if level >= 0.6:
        return _PRECISION_BY_LEVEL["heuristic"]
    return _PRECISION_BY_LEVEL["absence"]


def _to_pascal_case(text: str) -> str:
    """``Public S3 bucket`` is ``PublicS3Bucket``: letters and digits only, acronyms kept."""
    words = [w for w in re.split(r"[^A-Za-z0-9]+", text) if w]
    parts = []
    for word in words:
        known = _ACRONYMS.get(word.lower())
        if known:
            parts.append(known)
        elif word.isupper() and len(word) > 1:
            parts.append(word)
        else:
            parts.append(word[0].upper() + word[1:])
    return "".join(parts)[:120] or "Finding"


def _attack_path_rule(paths: Sequence[AttackPath]) -> dict[str, Any]:
    severity = max(p.severity for p in paths)
    techniques = sorted({t for p in paths for t in p.techniques})
    links = _help_markdown(
        "Close any hop of the path: remove the exposure at its entry, restrict the network flow or "
        "the IAM permission on a hop, or protect the target with its own access control.",
        techniques,
        advisory=False,
    )
    tags = ["security", "attack-path"] + [f"mitre/{t}" for t in techniques]
    rule: dict[str, Any] = {
        "id": ATTACK_PATH_RULE,
        "name": "AttackPath",
        "shortDescription": {
            "text": "Attack path from an exposed entry point to a sensitive target"
        },
        "fullDescription": {
            "text": (
                "A chain of resources an attacker can follow from an exposed entry point, usually "
                "the internet, to a data store, a secret or an admin identity. Each hop is a "
                "modelled network flow, data flow or IAM binding, and the findings that make the "
                "hop possible are listed in the code flow."
            )
        },
        "help": {
            "text": (
                "Close any hop of the path: remove the exposure at its entry, restrict the "
                "network flow or the IAM permission on a hop, or protect the target with its "
                "own access control."
            ),
            "markdown": links,
        },
        "defaultConfiguration": {"level": _SARIF_LEVELS[severity]},
        "properties": {"tags": tags[:MAX_TAGS], "precision": "medium"},
    }
    score = _SECURITY_SEVERITY.get(severity)
    if score:
        rule["properties"]["security-severity"] = score
    return rule


# ── results ───────────────────────────────────────────────────────────


def _fingerprints(threats: Sequence[Threat]) -> dict[str, str]:
    """A fingerprint per finding id; findings that would share one are told apart by their id.

    Two crossings from one resource to two others in the same zone pair have the same rule key,
    address and file.
    GitHub treats results with one fingerprint as one alert, so the second would vanish.
    """
    base = {t.id: t.fingerprint or compute_fingerprint(t) for t in threats}
    counts: dict[str, int] = {}
    for fingerprint in base.values():
        counts[fingerprint] = counts.get(fingerprint, 0) + 1
    return {
        threat_id: fingerprint if counts[fingerprint] == 1 else f"{fingerprint}.{threat_id}"
        for threat_id, fingerprint in base.items()
    }


def _threat_result(
    ctx: _Context, threat: Threat, key: str, index: int, fingerprint: str
) -> dict[str, Any]:
    severity = threat_severity(threat)
    node = ctx.node(threat.resource_address)
    location: dict[str, Any] = {
        "physicalLocation": ctx.threat_location(threat),
        "logicalLocations": [_logical(threat.resource_address, node)],
    }
    result: dict[str, Any] = {
        "ruleId": key,
        "ruleIndex": index,
        "level": _SARIF_LEVELS[severity],
        "message": _message(threat),
        "locations": [location],
        "partialFingerprints": {FINGERPRINT_KEY: fingerprint},
        "properties": _result_properties(ctx, threat, severity),
    }
    related = _related(ctx, threat)
    if related:
        result["relatedLocations"] = related
    return result


def _message(threat: Threat) -> dict[str, str]:
    """The resource-specific text of a result.

    ``text`` is plain and one line.
    A model's mitigation is not in it; it is in ``markdown``, escaped, and marked advisory.
    """
    label = stride_label(threat.stride_category)
    detail = collapse_whitespace(threat.description)
    text = f"{collapse_whitespace(threat.title)} ({label}) on {threat.resource_address}"
    if detail:
        text += f": {detail}"
    message = {"text": truncate(text, _MAX_MESSAGE)}
    if threat.source is ThreatSource.LLM:
        parts = [
            f"**Advisory (LLM)** {md_inline(threat.title, limit=200)} ({label}) on "
            f"{md_inline(threat.resource_address, limit=200)}"
        ]
        if detail:
            parts.append(md_inline(threat.description, limit=_MAX_MESSAGE))
        if collapse_whitespace(threat.mitigation):
            parts.append(f"**Suggested mitigation**: {md_inline(threat.mitigation, limit=800)}")
        message["markdown"] = "\n\n".join(parts)
    return message


def _logical(address: str, node: InfraNode | None) -> dict[str, str]:
    return {
        "name": node.name if node is not None and node.name else address,
        "fullyQualifiedName": address,
        "kind": "resource",
    }


def _related(ctx: _Context, threat: Threat) -> list[dict[str, Any]]:
    """The other end of a flow, as a related location."""
    if not threat.target_address:
        return []
    node = ctx.node(threat.target_address)
    entry: dict[str, Any] = {
        "id": 1,
        "message": {"text": f"Target of the flow: {threat.target_address}"},
        "logicalLocations": [_logical(threat.target_address, node)],
    }
    physical = ctx.node_location(threat.target_address)
    if physical is not None:
        entry["physicalLocation"] = physical
    return [entry]


def _result_properties(ctx: _Context, threat: Threat, severity: Severity) -> dict[str, Any]:
    props: dict[str, Any] = {
        "severity": severity.value,
        "stride_category": threat.stride_category,
        "source": threat.source.value,
        "confidence": threat.confidence,
        "resource_type": threat.resource_type,
    }
    if severity != threat.severity:
        props["base_severity"] = threat.severity.value
    if threat.severity_reason:
        props["severity_reason"] = collapse_whitespace(threat.severity_reason)
    if threat.root_cause:
        props["root_cause"] = threat.root_cause
    if threat.evidence != "config":
        props["evidence"] = threat.evidence
    if threat.tool:
        props["tool"] = threat.tool
    if threat.aliases:
        props["aliases"] = list(threat.aliases)
    path_ids = sorted(
        set(threat.path_ids) | set(ctx.path_ids_by_node.get(threat.resource_address, ()))
    )
    if path_ids:
        props["attack_path_ids"] = path_ids
    if threat.source is ThreatSource.LLM:
        props["advisory"] = True
    return props


# ── attack paths ──────────────────────────────────────────────────────


def _attack_path_result(ctx: _Context, path: AttackPath, index: int) -> dict[str, Any]:
    hops = path.hops
    steps: list[dict[str, Any]] = []
    related: list[dict[str, Any]] = []
    for number, hop in enumerate(hops, start=1):
        location = _hop_location(ctx, hop)
        text = f"Hop {number}: {hop.node_id}"
        if hop.edge_type_to_next:
            text += f", then {hop.edge_type_to_next} to the next hop"
        steps.append(
            {"location": {**location, "message": {"text": text}}, "executionOrder": number}
        )
        related.append({"id": number, **location, "message": {"text": text}})

    primary = next(
        (
            {
                "physicalLocation": ctx.node_location(h.node_id),
                "logicalLocations": [_logical(h.node_id, ctx.node(h.node_id))],
            }
            for h in reversed(hops)
            if ctx.node_location(h.node_id) is not None
        ),
        None,
    )
    if primary is None:
        primary = {
            "physicalLocation": ctx.location(
                source_uri(_input_file(ctx.report), ctx.prefix), None, None
            ),
            "logicalLocations": [_logical(path.target, None)],
        }
    flow_text = f"{path.entry} to {path.target}"
    text = f"Attack path from {path.entry} to {path.target} in {max(len(hops) - 1, 0)} hops"
    if path.rationale:
        text += f": {collapse_whitespace(path.rationale)}"
    fingerprint = hashlib.sha256(f"attack_path\x1f{path.id}".encode()).hexdigest()[:16]
    properties: dict[str, Any] = {
        "severity": path.severity.value,
        "score": path.score,
        "source": "attack_path",
        "attack_path_id": path.id,
        "techniques": list(path.techniques),
        "tactics": list(path.tactics),
    }
    return {
        "ruleId": ATTACK_PATH_RULE,
        "ruleIndex": index,
        "level": _SARIF_LEVELS[path.severity],
        "message": {"text": truncate(text, _MAX_MESSAGE)},
        "locations": [primary],
        "relatedLocations": related,
        "codeFlows": [
            {"message": {"text": flow_text}, "threadFlows": [{"locations": steps}]},
        ],
        "partialFingerprints": {FINGERPRINT_KEY: fingerprint},
        "properties": properties,
    }


def _hop_location(ctx: _Context, hop: AttackHop) -> dict[str, Any]:
    """A hop's definition: file and line when the graph knows them, else the resource alone."""
    location: dict[str, Any] = {"logicalLocations": [_logical(hop.node_id, ctx.node(hop.node_id))]}
    physical = ctx.node_location(hop.node_id)
    if physical is not None:
        location["physicalLocation"] = physical
    return location


# ── invocation ────────────────────────────────────────────────────────


def _invocation(ctx: _Context, truncated: int) -> dict[str, Any]:
    """Whether the scan completed, with the errors and gaps as notifications."""
    report = ctx.report
    cov = report.coverage
    notes: list[dict[str, Any]] = []

    def note(level: str, code: str, text: str, file: str = "", line: int | None = None) -> None:
        entry: dict[str, Any] = {
            "level": level,
            "message": {"text": truncate(collapse_whitespace(text), 1000)},
            "descriptor": {"id": code or "threatcode.notice"},
        }
        if file:
            entry["locations"] = [
                {"physicalLocation": ctx.location(source_uri(file, ctx.prefix), line, None)}
            ]
        notes.append(entry)

    for error in cov.errors:
        note("error", error.get("code", ""), error.get("message", ""), error.get("file", ""))
    for gap in cov.gaps:
        level = {"error": "error", "warning": "warning"}.get(str(gap.get("level")), "note")
        line = gap.get("line")
        note(
            level,
            str(gap.get("code", "")),
            str(gap.get("message", "")),
            str(gap.get("file") or ""),
            line if isinstance(line, int) else None,
        )
    if cov.rule_errors:
        note(
            "warning",
            "rules.failed",
            f"{cov.rule_errors} rule evaluation(s) failed, so some findings may be missing",
        )
    llm = report.llm or {}
    llm_failed = llm.get("status") == "failed"
    if llm_failed:
        note(
            "warning",
            "llm.failed",
            f"LLM analysis failed, only rule-based findings are reported: {llm.get('error', '')}",
        )
    if truncated:
        note(
            "warning",
            "sarif.truncated",
            f"{truncated} lower-severity result(s) were left out to stay under "
            f"{MAX_RESULTS} results",
        )
    if len(notes) > MAX_NOTIFICATIONS:
        omitted = len(notes) - MAX_NOTIFICATIONS
        notes = notes[:MAX_NOTIFICATIONS]
        note("note", "sarif.notifications_omitted", f"{omitted} more notification(s) omitted")
    return {
        "executionSuccessful": not (cov.errors or llm_failed or cov.rule_errors),
        "toolExecutionNotifications": notes,
    }
