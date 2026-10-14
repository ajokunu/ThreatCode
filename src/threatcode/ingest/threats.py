"""Turning a placed scanner finding into a ``Threat``.

Every finding becomes one ``Threat`` per node it joined, or one threat with no resource address when
it joined none.
The threat has ``source`` ``scanner``, ``evidence`` ``scanner``, the tool name, and a rule id of the
form ``<tool>:<id>`` (``trivy:CVE-2022-37434``).

``aliases`` hold the finding's own id first, then every other identifier of the issue (CVE, GHSA,
the scanner's second id for a rule), so a ``.threatcodeignore`` line with a bare CVE id suppresses
it whichever tool reported it.

STRIDE follows the kind: a vulnerability is elevation of privilege, a secret information
disclosure, a misconfiguration tampering, and anything else tampering.
``mitre_techniques`` stay empty: an attack path adds the technique of the step a finding enables.

``metadata`` records how the finding was joined (``join``: ``image``, ``file_line``, ``directory``
or ``unattached``), the scanner's ``target``, the package, versions, CVSS, references and the
ingested file.
It also carries ``fingerprint_hint``, built from the address, the scanner target and the package,
so two unattached findings with the same rule never share a fingerprint.
"""

from __future__ import annotations

from typing import Any

from threatcode.ingest.attach import Placement
from threatcode.ingest.model import ExternalFinding
from threatcode.ir.nodes import InfraNode
from threatcode.models.threat import Severity, Threat, ThreatSource, hash_id

__all__ = ["STRIDE_BY_KIND", "to_threats"]

STRIDE_BY_KIND: dict[str, str] = {
    "vulnerability": "elevation_of_privilege",
    "secret": "information_disclosure",
    "misconfiguration": "tampering",
    "other": "tampering",
}

# How sure the join is: the exact keys are certain, a directory match is a guess about ownership.
_CONFIDENCE = {"image": 1.0, "file_line": 1.0, "directory": 0.7, "unattached": 1.0}


_DISPLAY_NAMES = {
    "trivy": "Trivy",
    "grype": "Grype",
    "osv-scanner": "OSV-Scanner",
    "checkov": "Checkov",
    "gitleaks": "Gitleaks",
}


def _display(tool: str) -> str:
    return _DISPLAY_NAMES.get(tool, tool)


def rule_id_of(finding: ExternalFinding) -> str:
    return f"{finding.tool}:{finding.id}"


def all_ids(finding: ExternalFinding) -> list[str]:
    """The finding's own id followed by its other identifiers, without repeats."""
    return list(dict.fromkeys([finding.id, *finding.aliases]))


def to_threats(finding: ExternalFinding, placement: Placement, ingest_file: str) -> list[Threat]:
    """The threats for one placed finding, one per joined node."""
    targets: list[InfraNode | None] = list(placement.nodes) or [None]
    return [_threat(finding, placement, node, ingest_file) for node in targets]


def _threat(
    finding: ExternalFinding, placement: Placement, node: InfraNode | None, ingest_file: str
) -> Threat:
    address = node.id if node is not None else ""
    package = finding.package
    seed = "|".join(
        [
            "scanner",
            finding.tool,
            finding.id,
            package.name if package else "",
            package.version if package else "",
            finding.target,
            finding.file,
            str(finding.line or ""),
            address,
        ]
    )
    hint = "|".join([address, finding.target, package.name if package else ""])
    metadata: dict[str, Any] = {
        "kind": finding.kind,
        "join": placement.join,
        "target": finding.target,
        "ingest_file": ingest_file,
        "fingerprint_hint": hint,
    }
    if package is not None:
        metadata["package"] = package.to_dict()
    if finding.fixed_version:
        metadata["fixed_version"] = finding.fixed_version
    if finding.status:
        metadata["status"] = finding.status
    if finding.cvss_score is not None:
        metadata["cvss_score"] = finding.cvss_score
    if finding.cvss_vector:
        metadata["cvss_vector"] = finding.cvss_vector
    if finding.references:
        metadata["references"] = list(finding.references)
    if finding.scope == "image" and finding.image_refs:
        metadata["image"] = finding.image_refs[0]
    location_file = placement.location_file
    start = placement.line
    end = placement.end_line
    if node is not None and placement.join == "image":
        # The finding is about the image, so it is reported where the workload names it.
        location_file, start, end = "", None, None
    return Threat(
        id=hash_id(seed),
        title=_title(finding),
        description=_description(finding),
        stride_category=STRIDE_BY_KIND[finding.kind],
        severity=Severity(finding.severity),
        source=ThreatSource.SCANNER,
        resource_type=node.resource_type if node is not None else "",
        resource_address=address,
        mitigation=_mitigation(finding),
        rule_id=rule_id_of(finding),
        confidence=_CONFIDENCE[placement.join],
        metadata=metadata,
        location_file=location_file,
        location_start_line=start,
        location_end_line=end,
        evidence="scanner",
        tool=finding.tool,
        aliases=all_ids(finding),
    )


def _title(finding: ExternalFinding) -> str:
    package = finding.package
    if finding.title:
        return f"{finding.id}: {finding.title}"
    if package is not None and package.name:
        return f"{finding.id} in {package.name}"
    return finding.id


def _description(finding: ExternalFinding) -> str:
    parts: list[str] = []
    package = finding.package
    if finding.kind == "vulnerability" and package is not None and package.name:
        text = f"{_display(finding.tool)} reports {finding.id} in package {package.name}"
        if package.version:
            text += f" {package.version}"
        parts.append(text + ".")
        if finding.fixed_version:
            parts.append(f"Fixed in {finding.fixed_version}.")
        else:
            parts.append("No fixed version is reported.")
        if finding.cvss_score is not None:
            vector = f" ({finding.cvss_vector})" if finding.cvss_vector else ""
            parts.append(f"CVSS base score {finding.cvss_score:g}{vector}.")
    else:
        parts.append(f"{_display(finding.tool)} reports {finding.id}.")
    where = _where(finding)
    if where:
        parts.append(where)
    if finding.description:
        parts.append(finding.description)
    return " ".join(parts)


def _where(finding: ExternalFinding) -> str:
    if finding.scope == "image" and finding.image_refs:
        return f"Image: {finding.image_refs[0]}."
    if finding.file:
        line = f":{finding.line}" if finding.line else ""
        return f"Location: {finding.file}{line}."
    return ""


def _mitigation(finding: ExternalFinding) -> str:
    package = finding.package
    if finding.kind == "vulnerability":
        if package is not None and package.name and finding.fixed_version:
            return (
                f"Upgrade {package.name} to {finding.fixed_version}, "
                "or rebuild the image on a patched base."
            )
        return (
            "No fixed version is reported: follow the advisory, apply the vendor mitigation "
            "or replace the package."
        )
    if finding.kind == "secret":
        return "Revoke and rotate the credential, then remove it from the source and its history."
    return finding.mitigation or (
        f"Follow the guidance of {_display(finding.tool)} for {finding.id}."
    )
