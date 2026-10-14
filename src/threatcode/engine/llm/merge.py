"""Turn what the model said into findings that can sit beside the rule results.

``merge_llm_threats`` takes the parsed items and decides, for each, whether it is a finding:

- it must name a resource in the graph (a handle or a real address); an item with an empty or
  unknown address is not attributable and goes to the ``unattributed`` list of the LLM status,
  not into the findings, so the model cannot invent a resource and have it reported;
- ``resource_type`` comes from the graph node, never from the model;
- tactics are derived from the techniques (the model's own tactics are used only when it gave no
  technique);
- a finding that restates a rule, boundary, secret or scanner finding on the same resource and
  STRIDE category, with a shared technique or a similar title, is dropped, and so is a repeat of
  an earlier model finding;
- the id hashes the address, the category and the sorted techniques, so rewording a title between
  runs does not change it and a baseline diff stays quiet.

Handles in the text are written back as real addresses, and redaction placeholders only for the
finding's own resource and only for labels that name a location, never a secret.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from threatcode.engine.llm.context import AddressMap
from threatcode.engine.llm.redactor import RESTORABLE_LABELS, Redactor
from threatcode.engine.mitre import tactics_for_techniques
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import VALID_EVIDENCE, Severity, Threat, ThreatSource, hash_id

logger = logging.getLogger(__name__)

# Two titles with at least this share of their words in common say the same thing.
TITLE_SIMILARITY = 0.6
MAX_UNATTRIBUTED = 50
_WORD = re.compile(r"[a-z0-9]{3,}")


@dataclass
class MergeResult:
    threats: list[Threat] = field(default_factory=list)
    # Items that named no resource of the graph, as short mappings for the report.
    unattributed: list[dict[str, Any]] = field(default_factory=list)
    unattributed_count: int = 0
    # Items dropped because a rule or an earlier item already said the same.
    duplicates: int = 0
    # Items the model gave that were not usable at all (invalid after conversion).
    invalid: int = 0


def merge_llm_threats(
    raw_threats: Sequence[dict[str, Any]],
    graph: InfraGraph,
    existing: Sequence[Threat],
    addresses: AddressMap,
    redactor: Redactor,
) -> MergeResult:
    """Validate, attribute and deduplicate parsed model items into ``Threat`` objects."""
    result = MergeResult()
    by_key: dict[tuple[str, str], list[Threat]] = {}
    for threat in existing:
        for address in {threat.resource_address, threat.target_address}:
            if address:
                by_key.setdefault((address, threat.stride_category), []).append(threat)
    used_ids = {t.id for t in existing}

    for raw in raw_threats:
        given = str(raw.get("resource_address", ""))
        node_id = addresses.resolve(given) if given else None
        if node_id is None or node_id not in graph.nodes:
            reason = "no resource address" if not given else "address is not in the graph"
            result.unattributed_count += 1
            if len(result.unattributed) < MAX_UNATTRIBUTED:
                result.unattributed.append(_unattributed(raw, reason))
            continue
        node = graph.nodes[node_id]

        techniques = list(raw.get("mitre_techniques") or [])
        tactics = (
            tactics_for_techniques(techniques)
            if techniques
            else list(raw.get("mitre_tactics") or [])
        )
        stride = str(raw.get("stride_category", "tampering"))
        title = _restore(str(raw.get("title", "")), addresses, redactor, node_id)
        if not title:
            result.invalid += 1
            continue

        key = (node_id, stride)
        if any(_same_finding(title, techniques, other) for other in by_key.get(key, [])):
            result.duplicates += 1
            continue

        try:
            severity = Severity(str(raw.get("severity", "medium")))
        except ValueError:
            severity = Severity.MEDIUM
        seed = f"LLM_{node_id}_{stride}_{','.join(sorted(techniques))}"
        threat_id = hash_id(seed)
        counter = 1
        while threat_id in used_ids:
            counter += 1
            threat_id = hash_id(f"{seed}#{counter}")
        try:
            threat = Threat(
                id=threat_id,
                title=title,
                description=_restore(str(raw.get("description", "")), addresses, redactor, node_id),
                stride_category=stride,
                severity=severity,
                source=ThreatSource.LLM,
                resource_type=node.resource_type,
                resource_address=node_id,
                mitigation=_restore(str(raw.get("mitigation", "")), addresses, redactor, node_id),
                confidence=float(raw.get("confidence", 0.7)),
                mitre_techniques=techniques,
                mitre_tactics=tactics,
                evidence=node.evidence if node.evidence in VALID_EVIDENCE else "config",
            )
        except ValueError as e:
            # The parser already filters unknown STRIDE categories; a bad item that gets
            # through anyway is dropped rather than failing the phase.
            logger.warning("Dropping invalid LLM threat: %s", e)
            result.invalid += 1
            continue
        used_ids.add(threat_id)
        by_key.setdefault(key, []).append(threat)
        result.threats.append(threat)
    return result


def _restore(text: str, addresses: AddressMap, redactor: Redactor, node_id: str) -> str:
    """Handles back to addresses; location placeholders back to values for this resource only."""
    text = addresses.restore_text(text)
    return redactor.unredact_string(text, scope=node_id, labels=RESTORABLE_LABELS)


def _unattributed(raw: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "title": str(raw.get("title", ""))[:200],
        "severity": str(raw.get("severity", "")),
        "stride_category": str(raw.get("stride_category", "")),
        "resource_address": str(raw.get("resource_address", ""))[:200],
        "reason": reason,
    }


def _same_finding(title: str, techniques: Sequence[str], other: Threat) -> bool:
    """Whether ``other`` already says what a model item with this title and techniques says."""
    if set(techniques) & set(other.mitre_techniques):
        return True
    return _similarity(title, other.title) >= TITLE_SIMILARITY


def _similarity(a: str, b: str) -> float:
    first = set(_WORD.findall(a.lower()))
    second = set(_WORD.findall(b.lower()))
    if not first or not second:
        return 0.0
    return len(first & second) / len(first | second)
