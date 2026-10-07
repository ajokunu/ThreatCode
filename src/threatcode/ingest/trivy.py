"""Trivy JSON reports (``trivy ... --format json``, schema version 2).

Detected by ``SchemaVersion`` together with ``Results`` or ``ArtifactName``.
A clean scan has ``Results`` null or missing, which is still a Trivy report with zero findings.

What becomes a finding
----------------------
``Results[].Vulnerabilities`` are vulnerabilities, ``Misconfigurations`` with status ``FAIL`` are
misconfigurations and ``Secrets`` are secrets.
Passed and excepted misconfiguration checks and ``Licenses`` are counted in ``skipped``.
The matched text of a secret is never copied: Trivy masks it only in part.

How a finding is joined
-----------------------
A report whose ``ArtifactType`` is ``container_image`` is of image scope: every finding belongs to
the image, named by ``ArtifactName`` and ``Metadata.RepoTags`` and ``Metadata.RepoDigests``.
Every other artifact type (``filesystem``, ``repository``, ``cyclonedx`` and so on) is of path
scope: the finding sits in ``Results[].Target``, with the line of ``CauseMetadata`` for a
misconfiguration and of ``StartLine`` for a secret.
The target of an operating system package result (``Class`` ``os-pkgs``) is a description, not a
file, so those findings have no file.
"""

from __future__ import annotations

from typing import Any

from threatcode.ingest.model import (
    ExternalFinding,
    PackageInfo,
    ScannerReport,
    clean_text,
    severity_from_label,
    to_float,
)

TOOL = "trivy"
_DESCRIPTION_LIMIT = 700


def detect(data: object) -> bool:
    if not isinstance(data, dict) or not isinstance(data.get("SchemaVersion"), int):
        return False
    return "Results" in data or "ArtifactName" in data


def load(data: dict[str, Any]) -> list[ScannerReport]:
    artifact_type = clean_text(data.get("ArtifactType"))
    image_scope = artifact_type == "container_image"
    refs = _image_refs(data) if image_scope else ()
    report = ScannerReport(tool=TOOL)
    for result in _dicts(data.get("Results")):
        target = clean_text(result.get("Target"))
        klass = clean_text(result.get("Class"))
        rtype = clean_text(result.get("Type"))
        file = "" if image_scope or klass == "os-pkgs" else target
        for vuln in _dicts(result.get("Vulnerabilities")):
            report.findings.append(
                _vulnerability(vuln, target, file, rtype, image_scope=image_scope, refs=refs)
            )
        for misconf in _dicts(result.get("Misconfigurations")):
            status = clean_text(misconf.get("Status")).upper()
            if status and status != "FAIL":
                report.skip("passed_checks")
                continue
            report.findings.append(
                _misconfiguration(misconf, target, file, image_scope=image_scope, refs=refs)
            )
        for secret in _dicts(result.get("Secrets")):
            report.findings.append(
                _secret(secret, target, file, image_scope=image_scope, refs=refs)
            )
        licenses = result.get("Licenses")
        if isinstance(licenses, list) and licenses:
            report.skip("licenses", len(licenses))
    return [report]


def _dicts(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _image_refs(data: dict[str, Any]) -> tuple[str, ...]:
    refs: list[str] = []
    name = clean_text(data.get("ArtifactName"))
    if name:
        refs.append(name)
    metadata = data.get("Metadata")
    if isinstance(metadata, dict):
        for key in ("RepoTags", "RepoDigests"):
            values = metadata.get(key)
            if isinstance(values, list):
                refs.extend(clean_text(v) for v in values if isinstance(v, str) and v.strip())
    return tuple(dict.fromkeys(r for r in refs if r))


def _int(value: object) -> int | None:
    number = to_float(value)
    if number is None or number < 1:
        return None
    return int(number)


def _entry_score(entry: object) -> tuple[float, str] | None:
    """The CVSS v3 score and vector of one source's entry, else its v2 score and vector."""
    if not isinstance(entry, dict):
        return None
    for score_key, vector_key in (("V3Score", "V3Vector"), ("V2Score", "V2Vector")):
        score = to_float(entry.get(score_key))
        if score is not None:
            return score, clean_text(entry.get(vector_key))
    return None


def _cvss(vuln: dict[str, Any]) -> tuple[float | None, str]:
    """The score of the source Trivy took its severity from, else NVD, else the highest score."""
    sources = vuln.get("CVSS")
    if not isinstance(sources, dict):
        return None, ""
    for key in (clean_text(vuln.get("SeveritySource")), "nvd"):
        found = _entry_score(sources.get(key))
        if found is not None:
            return found
    scored = [s for s in (_entry_score(v) for v in sources.values()) if s is not None]
    if not scored:
        return None, ""
    return max(scored, key=lambda pair: pair[0])


def _vulnerability(
    vuln: dict[str, Any],
    target: str,
    file: str,
    rtype: str,
    *,
    image_scope: bool,
    refs: tuple[str, ...],
) -> ExternalFinding:
    identifier = clean_text(vuln.get("VulnerabilityID")) or "unknown"
    purl = ""
    pkg_identifier = vuln.get("PkgIdentifier")
    if isinstance(pkg_identifier, dict):
        purl = clean_text(pkg_identifier.get("PURL"))
    score, vector = _cvss(vuln)
    references: list[str] = []
    primary = clean_text(vuln.get("PrimaryURL"))
    if primary:
        references.append(primary)
    return ExternalFinding(
        tool=TOOL,
        kind="vulnerability",
        id=identifier,
        severity=severity_from_label(vuln.get("Severity")),
        title=clean_text(vuln.get("Title"), 300),
        description=clean_text(vuln.get("Description"), _DESCRIPTION_LIMIT),
        cvss_score=score,
        cvss_vector=vector,
        package=PackageInfo(
            name=clean_text(vuln.get("PkgName")),
            version=clean_text(vuln.get("InstalledVersion")),
            purl=purl,
            ecosystem=rtype,
        ),
        fixed_version=clean_text(vuln.get("FixedVersion")),
        target=target,
        file=file,
        scope="image" if image_scope else "path",
        image_refs=refs,
        references=references,
        status=clean_text(vuln.get("Status")),
    )


def _misconfiguration(
    misconf: dict[str, Any],
    target: str,
    file: str,
    *,
    image_scope: bool,
    refs: tuple[str, ...],
) -> ExternalFinding:
    identifier = clean_text(misconf.get("ID")) or clean_text(misconf.get("AVDID")) or "unknown"
    aliases = [a for a in (clean_text(misconf.get("AVDID")),) if a and a != identifier]
    cause = misconf.get("CauseMetadata")
    start = end = None
    if isinstance(cause, dict):
        start = _int(cause.get("StartLine"))
        end = _int(cause.get("EndLine"))
    primary = clean_text(misconf.get("PrimaryURL"))
    return ExternalFinding(
        tool=TOOL,
        kind="misconfiguration",
        id=identifier,
        severity=severity_from_label(misconf.get("Severity")),
        title=clean_text(misconf.get("Title"), 300),
        description=clean_text(
            misconf.get("Message") or misconf.get("Description"), _DESCRIPTION_LIMIT
        ),
        aliases=aliases,
        target=target,
        file=file,
        line=start,
        end_line=end,
        scope="image" if image_scope else "path",
        image_refs=refs,
        mitigation=clean_text(misconf.get("Resolution"), _DESCRIPTION_LIMIT),
        references=[primary] if primary else [],
        status="FAIL",
    )


def _secret(
    secret: dict[str, Any],
    target: str,
    file: str,
    *,
    image_scope: bool,
    refs: tuple[str, ...],
) -> ExternalFinding:
    return ExternalFinding(
        tool=TOOL,
        kind="secret",
        id=clean_text(secret.get("RuleID")) or "unknown",
        severity=severity_from_label(secret.get("Severity")),
        title=clean_text(secret.get("Title"), 300),
        description=f"Category: {clean_text(secret.get('Category'))}"
        if secret.get("Category")
        else "",
        target=target,
        file=file,
        line=_int(secret.get("StartLine")),
        end_line=_int(secret.get("EndLine")),
        scope="image" if image_scope else "path",
        image_refs=refs,
    )
