"""Grype JSON reports (``grype ... -o json``).

Detected by a ``matches`` list together with ``descriptor`` or ``source``.
An empty ``matches`` list is a Grype report with zero findings.

Every match is a vulnerability: ``vulnerability`` holds the id, severity, CVSS and fix, and
``artifact`` the package.
The ids in ``relatedVulnerabilities`` (the CVE behind a GHSA match, for example) become aliases.
Matches in ``ignoredMatches`` were silenced by the scan's own ignore rules and are counted in
``skipped``.

How a finding is joined
-----------------------
A report whose ``source.type`` is ``image`` is of image scope, and its image references are
``source.target.userInput``, ``tags`` and ``repoDigests``.
Any other source (a directory, a file, an SBOM) is of path scope: the finding sits at the first
``artifact.locations`` path, made relative to the scanned directory.
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

TOOL = "grype"
_DESCRIPTION_LIMIT = 700


def detect(data: object) -> bool:
    if not isinstance(data, dict) or not isinstance(data.get("matches"), list):
        return False
    return "descriptor" in data or "source" in data


def load(data: dict[str, Any]) -> list[ScannerReport]:
    descriptor = data.get("descriptor")
    version = clean_text(descriptor.get("version")) if isinstance(descriptor, dict) else ""
    report = ScannerReport(tool=TOOL, version=version)
    source = data.get("source")
    source = source if isinstance(source, dict) else {}
    target = source.get("target")
    image_scope = clean_text(source.get("type")) == "image" and isinstance(target, dict)
    refs = _image_refs(target) if image_scope and isinstance(target, dict) else ()
    scan_dir = _scan_root(source, target)
    label = refs[0] if refs else scan_dir
    for match in data["matches"]:
        if isinstance(match, dict) and isinstance(match.get("vulnerability"), dict):
            report.findings.append(_finding(match, image_scope, refs, scan_dir, label))
    ignored = data.get("ignoredMatches")
    if isinstance(ignored, list) and ignored:
        report.skip("ignored_matches", len(ignored))
    return [report]


def _image_refs(target: dict[str, Any]) -> tuple[str, ...]:
    refs: list[str] = []
    user_input = clean_text(target.get("userInput"))
    if user_input:
        refs.append(user_input)
    for key in ("tags", "repoDigests"):
        values = target.get(key)
        if isinstance(values, list):
            refs.extend(clean_text(v) for v in values if isinstance(v, str))
    return tuple(dict.fromkeys(r for r in refs if r))


def _scan_root(source: dict[str, Any], target: object) -> str:
    if isinstance(target, str):
        return target
    if isinstance(target, dict):
        for key in ("path", "userInput"):
            value = target.get(key)
            if isinstance(value, str):
                return value
    return ""


def _relative(path: str, scan_dir: str) -> str:
    """A location path relative to the scanned directory; Syft writes it with a leading slash."""
    text = path.replace("\\", "/")
    base = scan_dir.replace("\\", "/").rstrip("/")
    if base and text.startswith(base + "/"):
        text = text[len(base) + 1 :]
    return text.lstrip("/")


def _score(vulnerability: dict[str, Any]) -> tuple[float | None, str]:
    entries = vulnerability.get("cvss")
    if not isinstance(entries, list):
        return None, ""
    best: tuple[float | None, str] = (None, "")
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        metrics = entry.get("metrics")
        score = to_float(metrics.get("baseScore")) if isinstance(metrics, dict) else None
        if score is None:
            continue
        primary = clean_text(entry.get("type")).lower() == "primary"
        if best[0] is None or primary or score > best[0]:
            best = (score, clean_text(entry.get("vector")))
            if primary:
                break
    return best


def _finding(
    match: dict[str, Any], image_scope: bool, refs: tuple[str, ...], scan_dir: str, label: str
) -> ExternalFinding:
    vulnerability: dict[str, Any] = match["vulnerability"]
    identifier = clean_text(vulnerability.get("id")) or "unknown"
    related = [r for r in match.get("relatedVulnerabilities") or [] if isinstance(r, dict)]
    aliases = [clean_text(r.get("id")) for r in related]
    score, vector = _score(vulnerability)
    if score is None:
        for rel in related:
            score, vector = _score(rel)
            if score is not None:
                break
    description = clean_text(vulnerability.get("description"), _DESCRIPTION_LIMIT)
    if not description:
        description = next(
            (clean_text(r.get("description"), _DESCRIPTION_LIMIT) for r in related), ""
        )
    artifact = match.get("artifact")
    artifact = artifact if isinstance(artifact, dict) else {}
    fix = vulnerability.get("fix")
    fix = fix if isinstance(fix, dict) else {}
    versions = [clean_text(v) for v in fix.get("versions") or [] if isinstance(v, str)]
    file = ""
    if not image_scope:
        locations = [loc for loc in artifact.get("locations") or [] if isinstance(loc, dict)]
        if locations:
            file = _relative(clean_text(locations[0].get("path")), scan_dir)
    references = [
        clean_text(v)
        for v in (vulnerability.get("dataSource"), *(vulnerability.get("urls") or []))
        if isinstance(v, str) and v
    ]
    return ExternalFinding(
        tool=TOOL,
        kind="vulnerability",
        id=identifier,
        severity=severity_from_label(vulnerability.get("severity")),
        description=description,
        aliases=[a for a in dict.fromkeys(aliases) if a and a != identifier],
        cvss_score=score,
        cvss_vector=vector,
        package=PackageInfo(
            name=clean_text(artifact.get("name")),
            version=clean_text(artifact.get("version")),
            purl=clean_text(artifact.get("purl")),
            ecosystem=clean_text(artifact.get("type")),
        ),
        fixed_version=", ".join(dict.fromkeys(v for v in versions if v)),
        target=label,
        file=file,
        scope="image" if image_scope else "path",
        image_refs=refs,
        references=references,
        status=clean_text(fix.get("state")),
    )
