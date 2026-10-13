"""SARIF 2.1.0 output for GitHub code scanning.

GitHub binds an alert to a file and a line, remembers it across runs by its fingerprint and
ranks it by ``security-severity``, so the report is written for that:

- Every result points at the file the resource is defined in (a percent-encoded ``uri`` relative
  to the repository root, with ``uriBaseId`` ``%SRCROOT%``) and a ``region``.
  The repository root is the git top level of the scan root, whatever directory the scan was
  started from, because that is what GitHub resolves ``%SRCROOT%`` against.
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
- GitHub ranks an alert by the ``security-severity`` of its rule, never of its result, so a rule
  has one severity.
  A finding whose effective severity differs from its rule's (internet reachability raised it,
  an intentional-exposure tag lowered it) belongs to a variant rule, ``<id>/<severity>``.
  The rule's own id keeps the findings at the rule's reference severity, so a finding that
  context did not change keeps its id from run to run.
  Every result also carries its own ``security-severity``.
- A message is one sentence of instance detail ("<title> on <address>"); the explanation that is
  the same for every instance is in the rule's ``fullDescription`` and ``help``, which GitHub
  shows once.
- Each attack path is one result (``THREATCODE_ATTACK_PATH``) anchored at the first resource of
  the path that has a file, the entry point where a fix goes.
  Its code flow has a step for every hop, each with a file and line (the internet has no file and
  is shown at the resource it enters), and a step says which findings enable the hop.
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
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from threatcode.engine.mitre import TECHNIQUE_DB
from threatcode.fingerprint import compute_fingerprint
from threatcode.formatters import RepoPaths
from threatcode.formatters._utils import (
    collapse_whitespace,
    md_inline,
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
    from threatcode.models.report import Coverage

__all__ = [
    "ATTACK_PATH_RULE",
    "FINGERPRINT_KEY",
    "LLM_RULE",
    "SCHEMA_URL",
    "first_sentence",
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
        "ACL CIDR IMDS IMDSv1 IMDSv2 ARN URL JSON AWS GCP CDN ALB WAF SSM ECR NSG AKS CVE IP K8S SA"
    ).split()
}
_CWE = re.compile(r"^(?:CWE-)?(\d{1,5})$", re.IGNORECASE)
# An advisory id from a scanner: CVE-2022-37434, GHSA-xxxx-xxxx-xxxx, GO-2023-1234, AVD-AWS-0086.
_ADVISORY_ID = re.compile(
    r"(?:CVE|GHSA|GO|OSV|PYSEC|RUSTSEC|AVD|DLA|DSA|USN|RHSA|ALAS|ELSA|GMS|MAL)-[A-Za-z0-9-]+",
    re.IGNORECASE,
)
_SENTENCE_END = re.compile(r"[.!?](?=\s|$)")
_MAX_MESSAGE = 600
# The instance detail a message adds to a title: one sentence.
_MAX_DETAIL = 240
MAX_NAME = 64


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
    repo_root: str | os.PathLike[str] | None = None,
    ingest_sources: Sequence[Mapping[str, Any]] = (),
    indent: int = 2,
) -> str:
    """Format a report as SARIF 2.1.0 JSON.

    ``graph`` gives attack paths and flow targets the file and line of the resources they name.
    ``source_root`` is the directory the report's relative paths are relative to (the current
    directory when it is None).
    Paths are written relative to the repository root, which GitHub resolves ``%SRCROOT%``
    against: ``repo_root`` when given, else the git top level above ``source_root``.
    A scan root that is in no checkout, and a file outside the repository, are reported as
    notifications so a run whose alerts GitHub cannot place never looks right.
    ``ingest_sources`` (``AnalysisResult.ingest_sources``) become one notification each, and what
    suppressions, the baseline and ``--min-severity`` left out is counted in notifications, so a
    report that hides findings says so.
    """
    paths = RepoPaths.resolve(source_root, repo_root)
    sarif = _build_sarif(report, graph, paths, list(ingest_sources))
    return json.dumps(sarif, indent=indent, sort_keys=False)


@dataclass
class _Context:
    report: ThreatReport
    graph: InfraGraph | None
    paths: RepoPaths
    ingest_sources: list[Mapping[str, Any]] = field(default_factory=list)
    path_ids_by_node: dict[str, list[str]] = field(default_factory=dict)
    # The SARIF rule id each finding's result carries, by finding id.
    rule_id_by_threat: dict[str, str] = field(default_factory=dict)

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
        return self.location(self.paths.uri(file), start, end)

    def node_location(self, node_id: str) -> dict[str, Any] | None:
        node = self.node(node_id)
        if node is None or not node.source_file:
            return None
        return self.location(self.paths.uri(node.source_file), node.start_line, node.end_line)


def _build_sarif(
    report: ThreatReport,
    graph: InfraGraph | None,
    paths: RepoPaths,
    ingest_sources: list[Mapping[str, Any]],
) -> dict[str, Any]:
    ctx = _Context(report, graph, paths, ingest_sources)
    threats = sorted(report.threats, key=_threat_order)
    attack_paths = sorted(report.attack_paths, key=lambda p: (-p.severity.rank, -p.score, p.id))
    for path in attack_paths:
        for hop in path.hops:
            ctx.path_ids_by_node.setdefault(hop.node_id, []).append(path.id)

    reference: dict[str, Severity] = {}
    for threat in threats:
        key = rule_key(threat)
        reference[key] = max(reference.get(key, threat.severity), threat.severity)
    grouped: dict[str, list[Threat]] = {}
    for threat in threats:
        rule_id = _variant_id(rule_key(threat), threat_severity(threat), reference)
        ctx.rule_id_by_threat[threat.id] = rule_id
        grouped.setdefault(rule_id, []).append(threat)

    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    truncated = 0

    def register(rule_id: str, rule: dict[str, Any]) -> int:
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rules.append(rule)
        return rule_index[rule_id]

    paths_by_severity: dict[Severity, list[AttackPath]] = {}
    for path in attack_paths:
        paths_by_severity.setdefault(path.severity, []).append(path)
    for severity, same in paths_by_severity.items():
        rule_id = _variant_id(ATTACK_PATH_RULE, severity, {ATTACK_PATH_RULE: Severity.CRITICAL})
        index = register(rule_id, _attack_path_rule(rule_id, severity, same))
        results.extend(_attack_path_result(ctx, path, rule_id, index) for path in same)

    fingerprints = _fingerprints(threats)
    for threat in threats:
        rule_id = ctx.rule_id_by_threat[threat.id]
        index = register(rule_id, _threat_rule(rule_id, grouped[rule_id]))
        if len(results) >= MAX_RESULTS:
            truncated += 1
            continue
        results.append(_threat_result(ctx, threat, rule_id, index, fingerprints[threat.id]))

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


def _variant_id(key: str, severity: Severity, reference: dict[str, Severity]) -> str:
    """The rule id of a finding: ``key``, or ``key/<severity>`` when context moved its severity.

    GitHub ranks an alert by its rule's ``security-severity``, so findings of one rule at two
    severities need two rules.
    The findings at the rule's reference severity (the highest base severity the rule has) keep
    the bare id, so context changing one finding does not rename the alerts of the others.
    """
    if severity == reference.get(key, severity):
        return key
    return f"{key}/{severity.value}"


def _threat_order(threat: Threat) -> tuple[int, str, str, str]:
    return (-threat_severity(threat).rank, threat.resource_address, threat.rule_id, threat.id)


def _automation_id(report: ThreatReport) -> str:
    """``threatcode/<input>/``: the category GitHub keeps one alert set for, per scanned input."""
    joined = "+".join(part.strip() for part in _input_paths(report))
    label = re.sub(r"[^A-Za-z0-9._+-]+", "-", joined).strip("-.")
    return f"threatcode/{label[:80] or 'root'}/"


# ── rules ─────────────────────────────────────────────────────────────


def rule_key(threat: Threat) -> str:
    """The SARIF rule id of a finding, before it is split by severity.

    A finding with a rule uses it.
    A boundary crossing uses one id per zone pair, a model suggestion one id, an ingested scanner
    finding ``<tool>:<id>`` (the tool prefix is added once: a reader that already prefixed the
    id keeps it), so a scan with hundreds of crossings has a handful of rules.
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
        if threat.rule_id.startswith(f"{threat.tool}:"):
            return threat.rule_id
        return f"{threat.tool}:{threat.rule_id}"
    return threat.rule_id or threat.id


def _zones(threat: Threat) -> tuple[str, str]:
    meta = threat.metadata
    return str(meta.get("source_zone", "")), str(meta.get("target_zone", ""))


def _base_key(rule_id: str) -> str:
    """The rule id without a severity suffix (``K8S_NO_SECCOMP_PROFILE/low`` is the rule)."""
    head, _, tail = rule_id.rpartition("/")
    return head if head and tail in {s.value for s in Severity} else rule_id


def _threat_rule(rule_id: str, threats: Sequence[Threat]) -> dict[str, Any]:
    """One rule; every finding in ``threats`` has the same effective severity."""
    first = threats[0]
    severity = threat_severity(first)
    key = _base_key(rule_id)
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
        "id": rule_id,
        "name": _rule_name(key),
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


def _to_pascal_case(text: str, *, limit: int = MAX_NAME) -> str:
    """``Public S3 bucket`` is ``PublicS3Bucket``: letters and digits only, acronyms kept.

    Words are added whole until ``limit`` characters, so a long title is cut at a word boundary
    and never mid-word.
    """
    words = [w for w in re.split(r"[^A-Za-z0-9]+", text) if w]
    parts: list[str] = []
    used = 0
    for word in words:
        known = _ACRONYMS.get(word.lower())
        if known:
            part = known
        elif word.isupper() and len(word) > 1:
            part = word
        else:
            part = word[0].upper() + word[1:]
        if parts and used + len(part) > limit:
            break
        parts.append(part[:limit])
        used += len(part)
    return "".join(parts) or "Finding"


def _rule_name(key: str) -> str:
    """A short, stable name for a rule, made from its id and not from its title.

    An advisory id (``CVE-2022-37434``, ``GHSA-xxxx-xxxx-xxxx``) is its own name, without the
    tool prefix; any other id becomes PascalCase words (``K8S_NO_SECCOMP_PROFILE`` is
    ``K8SNoSeccompProfile``).
    """
    bare = key.split(":", 1)[1] if ":" in key else key
    if _ADVISORY_ID.fullmatch(bare):
        return bare
    return _to_pascal_case(bare.removeprefix("THREATCODE_").lower())


def _attack_path_rule(
    rule_id: str, severity: Severity, paths: Sequence[AttackPath]
) -> dict[str, Any]:
    techniques = sorted({t for p in paths for t in p.techniques})
    mitigation = (
        "Close any hop of the path: remove the exposure at its entry, restrict the network flow or "
        "the IAM permission on a hop, or protect the target with its own access control."
    )
    tags = ["security", "attack-path"] + [f"mitre/{t}" for t in techniques]
    rule: dict[str, Any] = {
        "id": rule_id,
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
            "text": mitigation,
            "markdown": _help_markdown(mitigation, techniques, advisory=False),
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
    ctx: _Context, threat: Threat, rule_id: str, index: int, fingerprint: str
) -> dict[str, Any]:
    severity = threat_severity(threat)
    node = ctx.node(threat.resource_address)
    location: dict[str, Any] = {
        "physicalLocation": ctx.threat_location(threat),
        "logicalLocations": [_logical(threat.resource_address, node)],
    }
    result: dict[str, Any] = {
        "ruleId": rule_id,
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


def first_sentence(text: str, limit: int) -> str:
    """The first sentence of ``text`` on one line, at most ``limit`` characters."""
    flat = collapse_whitespace(text)
    match = _SENTENCE_END.search(flat)
    return truncate(flat[: match.start() + 1] if match else flat, limit)


def _message(threat: Threat) -> dict[str, str]:
    """The instance-specific headline of a result: one sentence on one line.

    A rule finding reads ``<title> on <address>``: what the rule says in general is in the
    rule's description and help, which GitHub shows once, not in every alert.
    Findings whose description is about this instance (a crossing, a scanner's package and
    version, a secret, a model's reasoning) add its first sentence.
    A model's mitigation is not in ``text``; it is in ``markdown``, escaped, and marked advisory.
    """
    label = stride_label(threat.stride_category)
    title = collapse_whitespace(threat.title)
    address = threat.resource_address
    if threat.source is ThreatSource.RULE:
        text = f"{title} on {address}" if address and address not in title else title
    else:
        detail = first_sentence(threat.description, _MAX_DETAIL)
        head = title if not address or address in title else f"{title} on {address}"
        if threat.source is ThreatSource.BOUNDARY and detail:
            text = detail
        else:
            text = f"{head}. {detail}" if detail else head
    message = {"text": truncate(text, _MAX_MESSAGE)}
    if threat.source is ThreatSource.LLM:
        parts = [
            f"**Advisory (LLM)** {md_inline(threat.title, limit=200)} ({label}) on "
            f"{md_inline(threat.resource_address, limit=200)}"
        ]
        if collapse_whitespace(threat.description):
            parts.append(md_inline(threat.description, limit=_MAX_DETAIL * 4))
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
    score = _SECURITY_SEVERITY.get(severity)
    if score:
        props["security-severity"] = score
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


def _attack_path_result(
    ctx: _Context, path: AttackPath, rule_id: str, index: int
) -> dict[str, Any]:
    hops = path.hops
    locations = _hop_locations(ctx, hops)
    steps: list[dict[str, Any]] = []
    related: list[dict[str, Any]] = []
    for number, hop in enumerate(hops, start=1):
        borrowed = locations[number - 1]
        text = _hop_text(ctx, number, hop, hops[number] if number < len(hops) else None, borrowed)
        location: dict[str, Any] = {
            "logicalLocations": [_logical(hop.node_id, ctx.node(hop.node_id))]
        }
        if borrowed is not None:
            location["physicalLocation"] = borrowed[0]
        steps.append(
            {"location": {**location, "message": {"text": text}}, "executionOrder": number}
        )
        related.append({"id": number, **location, "message": {"text": text}})

    anchor = next((h for h in hops if ctx.node_location(h.node_id) is not None), None)
    if anchor is not None:
        primary: dict[str, Any] = {
            "physicalLocation": ctx.node_location(anchor.node_id),
            "logicalLocations": [_logical(anchor.node_id, ctx.node(anchor.node_id))],
        }
    else:
        primary = {
            "physicalLocation": ctx.location(ctx.paths.uri(_input_file(ctx.report)), None, None),
            "logicalLocations": [_logical(path.target, None)],
        }
    flow_text = f"{path.entry} to {path.target}"
    if path.rationale:
        flow_text += f": {collapse_whitespace(path.rationale)}"
    text = f"Attack path from {path.entry} to {path.target} in {max(len(hops) - 1, 0)} hops"
    if anchor is not None and anchor.node_id != path.entry:
        text += f", entering at {anchor.node_id}"
    fingerprint = hashlib.sha256(f"attack_path\x1f{path.id}".encode()).hexdigest()[:16]
    properties: dict[str, Any] = {
        "severity": path.severity.value,
        "score": path.score,
        "source": "attack_path",
        "attack_path_id": path.id,
        "techniques": list(path.techniques),
        "tactics": list(path.tactics),
    }
    score = _SECURITY_SEVERITY.get(path.severity)
    if score:
        properties["security-severity"] = score
    return {
        "ruleId": rule_id,
        "ruleIndex": index,
        "level": _SARIF_LEVELS[path.severity],
        "message": {"text": truncate(text, _MAX_MESSAGE)},
        "locations": [primary],
        "relatedLocations": related,
        "codeFlows": [
            {
                "message": {"text": truncate(flow_text, _MAX_MESSAGE)},
                "threadFlows": [{"locations": steps}],
            },
        ],
        "partialFingerprints": {FINGERPRINT_KEY: fingerprint},
        "properties": properties,
    }


def _hop_locations(
    ctx: _Context, hops: Sequence[AttackHop]
) -> list[tuple[dict[str, Any], str] | None]:
    """The file and line to show each hop at, with the resource that lends it when it is not own.

    A hop with a resource in the scanned files is shown there.
    One without (the internet) is shown at the next hop that has one, because that is the
    resource it enters; failing that, at the nearest earlier one.
    Only when no hop has a file is the entry None.
    """
    own = [ctx.node_location(hop.node_id) for hop in hops]
    result: list[tuple[dict[str, Any], str] | None] = []
    for i, location in enumerate(own):
        if location is not None:
            result.append((location, hops[i].node_id))
            continue
        order = [*range(i + 1, len(hops)), *range(i - 1, -1, -1)]
        lent = next(((own[j], hops[j].node_id) for j in order if own[j] is not None), None)
        result.append(lent)
    return result


def _hop_text(
    ctx: _Context,
    number: int,
    hop: AttackHop,
    following: AttackHop | None,
    shown: tuple[dict[str, Any], str] | None,
) -> str:
    """``Hop 3: aws_instance.app[0] -> aws_iam_role.app (iam_binding); enabled by EC2_IMDSV1``."""
    text = f"Hop {number}: {hop.node_id}"
    if following is not None:
        text += f" -> {following.node_id}"
        if hop.edge_type_to_next:
            text += f" ({hop.edge_type_to_next}{_via_detail(hop.via)})"
    enabling = list(
        dict.fromkeys(
            ctx.rule_id_by_threat[t] for t in hop.enabled_by if t in ctx.rule_id_by_threat
        )
    )
    if enabling:
        text += f"; enabled by {', '.join(enabling)}"
    if shown is not None and shown[1] != hop.node_id:
        text += f"; no file of its own, shown at {shown[1]}"
    return truncate(collapse_whitespace(text), _MAX_MESSAGE)


def _via_detail(via: dict[str, Any]) -> str:
    """`` tcp/443`` for a flow edge that names a protocol and ports, else nothing."""
    ports = via.get("ports")
    protocol = via.get("protocol")
    if isinstance(ports, list) and ports and isinstance(protocol, str) and protocol:
        return f" {protocol}/{','.join(str(p) for p in ports[:5])}"
    return ""


# ── invocation ────────────────────────────────────────────────────────


def _counted(findings: int, paths: int) -> str:
    """``2 findings and 1 attack path``, leaving out a zero."""
    parts = []
    if findings:
        parts.append(f"{findings} finding{'' if findings == 1 else 's'}")
    if paths:
        parts.append(f"{paths} attack path{'' if paths == 1 else 's'}")
    return " and ".join(parts)


def _set_aside_notes(cov: Coverage, note: Callable[..., None]) -> None:
    """Say what the report leaves out on purpose, so a smaller report never reads as a safer one."""
    suppressed = _counted(cov.suppressed - cov.suppressed_paths, cov.suppressed_paths)
    if suppressed:
        note(
            "note",
            "suppressions.applied",
            f"{suppressed} suppressed by the ignore file and not in this report",
        )
    baselined = _counted(cov.baselined - cov.baselined_paths, cov.baselined_paths)
    if baselined:
        note(
            "note",
            "baseline.applied",
            f"{baselined} already in the baseline and not in this report",
        )
    hidden = _counted(cov.hidden_findings, cov.hidden_paths)
    if hidden:
        note(
            "note",
            "min_severity.hidden",
            f"{hidden} below {cov.min_severity or 'the minimum severity'} left out of this report; "
            "the gate counted them",
        )


def _count(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _llm_note(llm: Mapping[str, Any], note: Callable[..., None]) -> None:
    """What the model phase did: its findings are advisory and the rest of the report is not."""
    found = _count(llm.get("threat_count"))
    text = (
        f"LLM analysis ran ({llm.get('provider', '')}/{llm.get('model', '')}): {found} advisory "
        f"finding{'' if found == 1 else 's'}, not checked against a rule and never failing the gate"
    )
    context = llm.get("context")
    if isinstance(context, dict) and context.get("reduced"):
        dropped = _count(context.get("nodes_dropped"))
        text += f"; the graph was reduced to fit the token limit ({dropped} nodes left out)"
    unattributed = _count(llm.get("unattributed_count"))
    if unattributed:
        text += f"; {unattributed} named no resource in the scan and were set aside"
    note("note", "llm.ran", text)


def _ingest_notes(ctx: _Context, note: Callable[..., None]) -> None:
    """One notification per scanner result that was joined to the graph."""
    for source in ctx.ingest_sources:
        tool = str(source.get("tool") or source.get("format") or "scanner")
        findings = int(source.get("findings") or 0)
        attached = int(source.get("attached") or 0)
        unattached = int(source.get("unattached") or 0)
        duplicates = int(source.get("duplicates") or 0)
        text = (
            f"ingested {findings} {tool} finding{'' if findings == 1 else 's'} from "
            f"{source.get('file') or 'a file'}: {attached} attached to a resource, "
            f"{unattached} not attached"
        )
        if duplicates:
            text += f", {duplicates} dropped as already reported"
        note("note", "ingest.source", text)


def _path_notes(ctx: _Context, note: Callable[..., None]) -> None:
    """Say so when GitHub cannot place the alerts: no checkout around the scan, files outside it."""
    paths = ctx.paths
    if not paths.anchored:
        note(
            "warning",
            "sarif.paths.unanchored",
            "the scanned path is in no git checkout and not below the current directory, so file "
            "paths are relative to the scanned path, not to a repository root; GitHub cannot place "
            "the alerts. Run from the repository, or pass the repository root.",
        )
    if paths.outside:
        count = len(paths.outside)
        note(
            "warning",
            "sarif.paths.outside_repository",
            f"{count} file(s) are outside the repository root, so they are named by file name "
            "only and GitHub cannot place their alerts.",
        )


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
                {"physicalLocation": ctx.location(ctx.paths.uri(file), line, None)}
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
    if llm.get("status") == "ran":
        _llm_note(llm, note)
    _path_notes(ctx, note)
    _set_aside_notes(cov, note)
    _ingest_notes(ctx, note)
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
