"""OSV-Scanner JSON reports (``osv-scanner --format json``).

Detected by a ``results`` list whose entries hold ``source`` and ``packages``.
An empty ``results`` list is an OSV-Scanner report with zero findings, but only when the file also
carries ``experimental_config`` or ``license_summary`` (an empty ``{"results": []}`` alone is
ambiguous and is reported as unrecognized).

How a finding is built
----------------------
Each vulnerable package lists its ``vulnerabilities`` (OSV records) and ``groups``: ids that name
the same issue, with the ``max_severity`` of the group as a CVSS score string.
A group is one finding.
Its id is the first id of the group that has a record, the other ids of the group
and the aliases of its records are the finding's aliases, and its severity is the group's
``max_severity``, else the record's CVSS v3 vector (scored here), else its
``database_specific.severity`` label, else ``info``.
A package with no groups yields one finding per record.

How a finding is joined
-----------------------
A result whose ``source.type`` is ``image``, ``docker`` or ``container`` is of image scope and
``source.path`` is the image reference.
Any other source is a lockfile or SBOM: the finding is of path scope at ``source.path``, which joins
the workloads in the directory of that file.
"""

from __future__ import annotations

from typing import Any

from threatcode.ingest.cvss import cvss3_base_score
from threatcode.ingest.model import (
    ExternalFinding,
    PackageInfo,
    ScannerReport,
    clean_text,
    severity_from_label,
    severity_from_score,
    to_float,
)

TOOL = "osv-scanner"
_IMAGE_SOURCES = frozenset({"image", "docker", "container"})
_DESCRIPTION_LIMIT = 700
_MAX_FIXED = 5


def detect(data: object) -> bool:
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return False
    results = data["results"]
    if not results:
        return "experimental_config" in data or "license_summary" in data
    return all(
        isinstance(r, dict)
        and isinstance(r.get("source"), dict)
        and isinstance(r.get("packages"), list)
        for r in results
    )


def load(data: dict[str, Any]) -> list[ScannerReport]:
    report = ScannerReport(tool=TOOL)
    for result in data["results"]:
        source = result["source"]
        path = clean_text(source.get("path"))
        image_scope = clean_text(source.get("type")).lower() in _IMAGE_SOURCES
        for package in result["packages"]:
            if not isinstance(package, dict):
                continue
            for finding in _package_findings(package, path, image_scope):
                report.findings.append(finding)
    return [report]


def _package_findings(entry: dict[str, Any], path: str, image_scope: bool) -> list[ExternalFinding]:
    info = entry.get("package")
    info = info if isinstance(info, dict) else {}
    package = PackageInfo(
        name=clean_text(info.get("name")),
        version=clean_text(info.get("version")),
        purl=clean_text(info.get("purl")),
        ecosystem=clean_text(info.get("ecosystem")),
    )
    records = [v for v in entry.get("vulnerabilities") or [] if isinstance(v, dict)]
    by_id = {clean_text(r.get("id")): r for r in records if clean_text(r.get("id"))}
    groups = [g for g in entry.get("groups") or [] if isinstance(g, dict)]
    findings: list[ExternalFinding] = []
    claimed: set[str] = set()
    for group in groups:
        ids = [clean_text(i) for i in group.get("ids") or [] if isinstance(i, str)]
        members = [by_id[i] for i in ids if i in by_id]
        if not members:
            continue
        claimed.update(clean_text(m.get("id")) for m in members)
        findings.append(
            _finding(members, ids, to_float(group.get("max_severity")), package, path, image_scope)
        )
    for record in records:
        if clean_text(record.get("id")) not in claimed:
            findings.append(_finding([record], [], None, package, path, image_scope))
    return findings


def _finding(
    members: list[dict[str, Any]],
    group_ids: list[str],
    group_score: float | None,
    package: PackageInfo,
    path: str,
    image_scope: bool,
) -> ExternalFinding:
    primary = members[0]
    identifier = clean_text(primary.get("id")) or "unknown"
    related: list[str] = list(group_ids)
    for member in members:
        related.append(clean_text(member.get("id")))
        related.extend(clean_text(a) for a in member.get("aliases") or [] if isinstance(a, str))
    score = group_score
    vector = ""
    if score is None:
        score, vector = _record_score(members)
    severity = severity_from_score(score, default="")
    if not severity:
        severity = _label_severity(members)
    references = [
        clean_text(ref.get("url"))
        for ref in primary.get("references") or []
        if isinstance(ref, dict) and ref.get("url")
    ][:5]
    return ExternalFinding(
        tool=TOOL,
        kind="vulnerability",
        id=identifier,
        severity=severity,
        title=clean_text(primary.get("summary"), 300),
        description=clean_text(primary.get("details"), _DESCRIPTION_LIMIT),
        aliases=[a for a in dict.fromkeys(related) if a and a != identifier],
        cvss_score=score,
        cvss_vector=vector,
        package=package,
        fixed_version=_fixed_versions(members, package),
        target=path,
        file="" if image_scope else path,
        scope="image" if image_scope else "path",
        image_refs=(path,) if image_scope and path else (),
        references=references,
    )


def _record_score(members: list[dict[str, Any]]) -> tuple[float | None, str]:
    best: tuple[float | None, str] = (None, "")
    for member in members:
        for entry in member.get("severity") or []:
            if not isinstance(entry, dict):
                continue
            vector = clean_text(entry.get("score"))
            score = cvss3_base_score(vector)
            if score is not None and (best[0] is None or score > best[0]):
                best = (score, vector)
    return best


def _label_severity(members: list[dict[str, Any]]) -> str:
    best = "info"
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for member in members:
        labels: list[object] = []
        specific = member.get("database_specific")
        if isinstance(specific, dict):
            labels.append(specific.get("severity"))
        for affected in member.get("affected") or []:
            if isinstance(affected, dict) and isinstance(affected.get("database_specific"), dict):
                labels.append(affected["database_specific"].get("severity"))
        for label in labels:
            candidate = severity_from_label(label)
            if rank[candidate] > rank[best]:
                best = candidate
    return best


def _fixed_versions(members: list[dict[str, Any]], package: PackageInfo) -> str:
    fixed: list[str] = []
    for member in members:
        for affected in member.get("affected") or []:
            if not isinstance(affected, dict):
                continue
            named = affected.get("package")
            if (
                isinstance(named, dict)
                and package.name
                and clean_text(named.get("name")).lower() != package.name.lower()
            ):
                continue
            for rng in affected.get("ranges") or []:
                if not isinstance(rng, dict):
                    continue
                for event in rng.get("events") or []:
                    if isinstance(event, dict) and event.get("fixed"):
                        fixed.append(clean_text(event.get("fixed")))
    return ", ".join(list(dict.fromkeys(f for f in fixed if f))[:_MAX_FIXED])
