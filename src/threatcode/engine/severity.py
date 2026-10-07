"""Contextual severity phase.

The base severity of a finding comes from its rule. This phase is where the
engine records an effective severity and the reason for it when context changes
the picture. It sets ``Threat.effective_severity`` and ``Threat.severity_reason``
and never touches ``Threat.severity``.
The gate, SARIF and the reports read the effective severity when it is set.

Three facts change a severity, each by one level, and the changes add up:

- **Reachable from the internet.**
  A finding on a resource the internet reaches over network flows (the reachability edges of
  `threatcode.ir.reachability`, from the `internet` node) is one level higher when it is a
  spoofing, tampering, information disclosure or elevation of privilege finding: a weakness an
  outsider can reach is worse than the same weakness behind the network.
  A finding that states the exposure itself (a world-open group, a public bucket) is not raised,
  because its base severity already is about being reachable.
- **Sensitive data.**
  A finding on a data store tagged `DataClassification` or `Compliance` with `confidential`,
  `restricted`, `pci`, `phi`, `hipaa` or `pii` is one level higher.
  Keys and values are matched without regard to case; a value such as `PCI-DSS, HIPAA` holds
  several classes.
- **Intentional exposure.**
  An exposure finding on a resource tagged `Public=true`, `Intent=public` or
  `threatcode:intent=public` is one level lower, never below `info` and never silenced, and its
  reason says `marked intentional`.
  To remove a finding altogether, use a suppression.

The severity never goes above `critical`, and a finding whose severity would not change gets no
effective severity.
`severity_reason` names the route from the internet or the tag that caused each change, so a
reviewer can check it.

Findings of the boundary phase and of the LLM are left alone: the first are about flows the
reachability edges already describe, the second are advisory.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Iterator, Mapping
from typing import Any

from threatcode.engine.stride import StrideCategory
from threatcode.ir.edges import EdgeType
from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import DATA_CATEGORIES, INTERNET_ID, InfraNode
from threatcode.models.report import ThreatReport
from threatcode.models.threat import Severity, Threat, ThreatSource
from threatcode.values import is_unknown

SENSITIVE_CLASSES: frozenset[str] = frozenset(
    {"confidential", "restricted", "pci", "phi", "hipaa", "pii"}
)
# Tag keys compared after removing case and punctuation
CLASSIFICATION_KEYS: frozenset[str] = frozenset({"dataclassification", "compliance"})
# The (key, value) pairs that mark an exposure as intended, compared without case
INTENT_TAGS: tuple[tuple[str, str], ...] = (
    ("public", "true"),
    ("intent", "public"),
    ("threatcode:intent", "public"),
)
# The categories of weakness an outsider who can reach the resource can use
REACHABLE_RAISES: frozenset[str] = frozenset(
    {
        StrideCategory.SPOOFING.value,
        StrideCategory.TAMPERING.value,
        StrideCategory.INFORMATION_DISCLOSURE.value,
        StrideCategory.ELEVATION_OF_PRIVILEGE.value,
    }
)
# Findings that the context may change: the others are about flows or advisory
CONTEXT_SOURCES: frozenset[ThreatSource] = frozenset(
    {ThreatSource.RULE, ThreatSource.SECRET, ThreatSource.SCANNER}
)
# Words of a rule id that say the finding is about exposure
_EXPOSURE_WORDS = frozenset(
    {"PUBLIC", "WORLD", "OPEN", "UNRESTRICTED", "EXPOSED", "ANONYMOUS", "INTERNET"}
)
# ATT&CK techniques of initial access through an exposed service
_EXPOSURE_TECHNIQUES = frozenset({"T1190", "T1133"})
_SEVERITY_ORDER = (
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)
_TOKEN = re.compile(r"[a-z0-9]+")
_MAX_TAG_DEPTH = 4


def apply(report: ThreatReport, graph: InfraGraph) -> None:
    """Set effective severities on the findings of ``report``, in place."""
    routes = _routes_from_internet(graph)
    for threat in report.threats:
        if threat.source not in CONTEXT_SOURCES:
            continue
        node = graph.get_node(threat.resource_address)
        if node is None:
            continue
        exposure_finding = is_exposure_finding(threat)
        level = _SEVERITY_ORDER.index(threat.severity)
        reasons: list[str] = []
        route = routes.get(node.id)
        if (
            route is not None
            and not exposure_finding
            and threat.stride_category in REACHABLE_RAISES
        ):
            level += 1
            reasons.append(
                f"raised one level: {node.id} is reachable from the internet ({' -> '.join(route)})"
            )
        if node.category in DATA_CATEGORIES:
            tag = sensitive_classification(node)
            if tag:
                level += 1
                reasons.append(f"raised one level: the data store is tagged {tag}")
        if exposure_finding:
            intent = intentional_tag(node)
            if intent:
                level -= 1
                reasons.append(f"lowered one level: marked intentional: {intent}")
        level = max(0, min(len(_SEVERITY_ORDER) - 1, level))
        effective = _SEVERITY_ORDER[level]
        if effective == threat.severity or not reasons:
            continue
        threat.effective_severity = effective
        threat.severity_reason = "; ".join(reasons)


def is_exposure_finding(threat: Threat) -> bool:
    """Whether a finding is about the resource being exposed, by its rule or its technique.

    A rule id such as ``S3_PUBLIC_ACCESS`` or ``SG_UNRESTRICTED_INGRESS`` names the exposure in
    one of its words, and exposure rules map to the initial access techniques ``T1190`` and
    ``T1133``.
    """
    if _EXPOSURE_WORDS & set(threat.rule_id.upper().split("_")):
        return True
    return bool(_EXPOSURE_TECHNIQUES & set(threat.mitre_techniques))


def _routes_from_internet(graph: InfraGraph) -> dict[str, list[str]]:
    """For each node the internet reaches over network flows, the shortest route to it."""
    if graph.internet_node is None:
        return {}
    routes: dict[str, list[str]] = {INTERNET_ID: [INTERNET_ID]}
    queue: deque[str] = deque([INTERNET_ID])
    while queue:
        current = queue.popleft()
        for target in sorted(
            {e.target for e in graph.edges_from(current) if e.edge_type is EdgeType.NETWORK_FLOW}
        ):
            if target not in routes:
                routes[target] = [*routes[current], target]
                queue.append(target)
    del routes[INTERNET_ID]
    return routes


# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------


def node_tags(node: InfraNode) -> dict[str, str]:
    """The tags and labels of a node as lower-case keys and string values.

    Terraform and Kubernetes give a mapping, CloudFormation a list of ``Key`` and ``Value``
    entries; a value that is not known is left out.
    """
    found: dict[str, str] = {}
    for name in ("tags", "tags_all", "Tags", "labels", "Labels"):
        for key, value in _tag_pairs(node.properties.get(name)):
            found.setdefault(key, value)
    return found


def _tag_pairs(value: Any, depth: int = 0) -> Iterator[tuple[str, str]]:
    if depth > _MAX_TAG_DEPTH or is_unknown(value):
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            text = _scalar(item)
            if text is not None and not is_unknown(key):
                yield str(key).strip().lower(), text
    elif isinstance(value, (list, tuple)):
        for entry in value:
            if not isinstance(entry, Mapping):
                continue
            key = next((entry[k] for k in ("key", "Key") if k in entry), None)
            item = next((entry[k] for k in ("value", "Value") if k in entry), None)
            text = _scalar(item)
            if isinstance(key, str) and not is_unknown(key) and text is not None:
                yield key.strip().lower(), text


def _scalar(value: Any) -> str | None:
    if is_unknown(value) or value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)):
        return str(value).strip()
    return None


def sensitive_classification(node: InfraNode) -> str:
    """The first sensitive classification tag of a node as ``Key=value``, else the empty string."""
    for key, value in sorted(node_tags(node).items()):
        if re.sub(r"[^a-z0-9]", "", key) not in CLASSIFICATION_KEYS:
            continue
        if SENSITIVE_CLASSES & set(_TOKEN.findall(value.lower())):
            return f"{key}={value}"
    return ""


def intentional_tag(node: InfraNode) -> str:
    """The tag that marks a node's exposure as intended as ``Key=value``, else the empty string."""
    tags = node_tags(node)
    for key, wanted in INTENT_TAGS:
        value = tags.get(key)
        if value is not None and value.lower() == wanted:
            return f"{key}={value}"
    return ""


def is_sensitive_data_store(node: InfraNode) -> bool:
    """Whether a node is a data store tagged with a sensitive classification."""
    return node.category in DATA_CATEGORIES and bool(sensitive_classification(node))
