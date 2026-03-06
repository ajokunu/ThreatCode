"""ThreatCode — STRIDE threat model generator from Infrastructure-as-Code."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from threatcode.exceptions import ThreatCodeError as ThreatCodeError

if TYPE_CHECKING:
    from threatcode.ir.graph import InfraGraph
    from threatcode.models.analysis import AnalysisResult
    from threatcode.models.finding import ScanReport as ScanReport
    from threatcode.models.report import ThreatReport

__version__ = "0.7.1"


def _run_pipeline(
    input_path: str | Path,
    *,
    no_llm: bool = True,
    min_severity: str = "info",
    config_path: str | Path | None = None,
    extra_rule_paths: list[str | Path] | None = None,
) -> tuple[InfraGraph, ThreatReport]:
    """Shared analysis pipeline for scan() and analyze().

    Returns:
        Tuple of (InfraGraph, ThreatReport).

    Raises:
        ThreatCodeError: On any analysis failure.
    """
    from threatcode.config import load_config
    from threatcode.engine.hybrid import HybridEngine
    from threatcode.ir.graph import InfraGraph
    from threatcode.models.threat import Severity
    from threatcode.parsers import detect_and_parse

    cfg_path = Path(config_path) if config_path else None
    config = load_config(cfg_path)
    config.no_llm = no_llm

    parsed = detect_and_parse(input_path)
    graph = InfraGraph.from_parsed(parsed)

    extra = [Path(p) for p in (extra_rule_paths or [])]
    engine = HybridEngine(config=config, extra_rule_paths=extra)
    report = engine.analyze(graph, input_file=str(input_path))

    if min_severity != "info":
        try:
            threshold = Severity(min_severity)
        except ValueError as e:
            raise ThreatCodeError(
                f"Invalid severity '{min_severity}'. "
                f"Valid values: critical, high, medium, low, info"
            ) from e
        report.threats = report.filter_by_severity(threshold)

    return graph, report


def scan(
    input_path: str | Path,
    *,
    no_llm: bool = True,
    output_format: str = "json",
    min_severity: str = "info",
    config_path: str | Path | None = None,
    extra_rule_paths: list[str | Path] | None = None,
) -> dict[str, Any]:
    """Public API: scan an IaC file and return a threat report dict.

    Args:
        input_path: Path to terraform plan JSON, .tf file, or CFN template.
        no_llm: If True, skip LLM analysis and use rules only.
        output_format: Output format (json, sarif, markdown, bitbucket).
        min_severity: Minimum severity to include (critical, high, medium, low, info).
        config_path: Optional path to .threatcode.yml config file.
        extra_rule_paths: Additional YAML rule files to load.

    Returns:
        Threat report as a dictionary.

    Raises:
        ThreatCodeError: On parsing, config, or analysis failures.
        FileNotFoundError: If input_path does not exist.
    """
    _graph, report = _run_pipeline(
        input_path,
        no_llm=no_llm,
        min_severity=min_severity,
        config_path=config_path,
        extra_rule_paths=extra_rule_paths,
    )
    return report.to_dict()


def analyze(
    input_path: str | Path,
    *,
    no_llm: bool = True,
    min_severity: str = "info",
    config_path: str | Path | None = None,
    extra_rule_paths: list[str | Path] | None = None,
) -> AnalysisResult:
    """Public API: scan an IaC file and return graph + threat report.

    Like scan(), but preserves the infrastructure graph for diagram rendering
    and topology analysis.

    Args:
        input_path: Path to terraform plan JSON, .tf file, or CFN template.
        no_llm: If True, skip LLM analysis and use rules only.
        min_severity: Minimum severity to include (critical, high, medium, low, info).
        config_path: Optional path to .threatcode.yml config file.
        extra_rule_paths: Additional YAML rule files to load.

    Returns:
        AnalysisResult with .graph (InfraGraph) and .report (ThreatReport).

    Raises:
        ThreatCodeError: On parsing, config, or analysis failures.
        FileNotFoundError: If input_path does not exist.
    """
    from threatcode.models.analysis import AnalysisResult

    graph, report = _run_pipeline(
        input_path,
        no_llm=no_llm,
        min_severity=min_severity,
        config_path=config_path,
        extra_rule_paths=extra_rule_paths,
    )
    return AnalysisResult(graph=graph, report=report)


def scan_secrets(
    path: str | Path,
    *,
    config_path: str | Path | None = None,
) -> dict[str, Any]:
    """Public API: scan files for hardcoded secrets.

    Args:
        path: File or directory to scan recursively.
        config_path: Optional path to secret scan config YAML.

    Returns:
        Dict with ``total_secrets`` count and ``findings`` list.
    """
    from threatcode.engine.secrets.scanner import SecretScanner

    scanner = SecretScanner()
    findings = scanner.scan(str(path))
    return {
        "total_secrets": len(findings),
        "findings": [f.to_dict() for f in findings],
    }


def scan_vulnerabilities(
    input_path: str | Path,
    *,
    ignore_unfixed: bool = False,
) -> dict[str, Any]:
    """Public API: scan a lockfile for known vulnerabilities.

    Requires a local vulnerability database — run ``threatcode db update``
    first.

    Args:
        input_path: Path to a supported lockfile.
        ignore_unfixed: If True, skip vulnerabilities without a fix.

    Returns:
        Dict with ``total_vulnerabilities``, ``dependencies_scanned``,
        and ``findings`` list.

    Raises:
        ThreatCodeError: If the vulnerability database has not been created.
        FileNotFoundError: If input_path does not exist.
    """
    from threatcode.engine.vulns.db import VulnDB
    from threatcode.engine.vulns.scanner import VulnerabilityScanner
    from threatcode.parsers import detect_and_parse

    parsed = detect_and_parse(input_path)
    deps = [r.properties for r in parsed.resources if r.resource_type.startswith("dependency_")]

    if not deps:
        return {"total_vulnerabilities": 0, "dependencies_scanned": 0, "findings": []}

    db = VulnDB()
    if not db.exists():
        raise ThreatCodeError("Vulnerability database not found. Run 'threatcode db update' first.")

    scanner = VulnerabilityScanner(db=db)
    findings = scanner.scan_dependencies(deps, ignore_unfixed=ignore_unfixed)
    return {
        "total_vulnerabilities": len(findings),
        "dependencies_scanned": len(deps),
        "findings": [f.to_dict() for f in findings],
    }


def scan_all(
    input_path: str | Path,
    *,
    scanners: tuple[str, ...] = ("misconfig",),
    no_llm: bool = True,
    min_severity: str = "info",
    config_path: str | Path | None = None,
    extra_rule_paths: list[str | Path] | None = None,
    ignore_unfixed: bool = False,
) -> dict[str, Any]:
    """Public API: unified scan combining multiple scanner types.

    Args:
        input_path: Path to file or directory to scan.
        scanners: Scanner types to run. Options: ``misconfig``, ``secret``,
            ``vuln``, ``license``. Default: ``("misconfig",)``.
        no_llm: If True, skip LLM analysis for misconfig scanner.
        min_severity: Minimum severity for misconfig results.
        config_path: Optional path to .threatcode.yml config file.
        extra_rule_paths: Additional YAML rule files for misconfig scanner.
        ignore_unfixed: If True, skip unfixed vulnerabilities.

    Returns:
        Dict with per-scanner results keyed by scanner name.
    """
    result: dict[str, Any] = {"scanners": list(scanners)}

    if "misconfig" in scanners:
        try:
            result["misconfig"] = scan(
                input_path,
                no_llm=no_llm,
                min_severity=min_severity,
                config_path=config_path,
                extra_rule_paths=extra_rule_paths,
            )
        except Exception as e:
            result["misconfig"] = {"error": str(e)}

    if "secret" in scanners:
        try:
            result["secret"] = scan_secrets(input_path, config_path=config_path)
        except Exception as e:
            result["secret"] = {"error": str(e)}

    if "vuln" in scanners:
        try:
            result["vuln"] = scan_vulnerabilities(input_path, ignore_unfixed=ignore_unfixed)
        except Exception as e:
            result["vuln"] = {"error": str(e)}

    if "license" in scanners:
        try:
            from threatcode.engine.licenses.scanner import LicenseScanner
            from threatcode.parsers import detect_and_parse

            parsed = detect_and_parse(input_path)
            deps = [
                r.properties for r in parsed.resources if r.resource_type.startswith("dependency_")
            ]
            scanner = LicenseScanner()
            findings = scanner.scan_dependencies(deps)
            result["license"] = {
                "total_issues": len(findings),
                "dependencies_scanned": len(deps),
                "findings": [f.to_dict() for f in findings],
            }
        except Exception as e:
            result["license"] = {"error": str(e)}

    return result


def scan_image(
    image_ref: str,
    *,
    platform: str = "linux/amd64",
    ignore_unfixed: bool = False,
    scan_secrets: bool = False,
    scan_misconfig: bool = True,
) -> dict[str, Any]:
    """Public API: scan a container image for vulnerabilities.

    Pulls the image from its registry, extracts all layers, detects the OS,
    parses installed packages, and matches them against the vulnerability
    database. Also scans application lockfiles found inside the image.

    Args:
        image_ref: Image reference (e.g. ``"nginx:latest"``, ``"ghcr.io/owner/repo:tag"``).
        platform: Target platform for multi-arch images (e.g. ``"linux/arm64"``).
        ignore_unfixed: If True, skip vulnerabilities without a fixed version.
        scan_secrets: If True, scan the image filesystem for hardcoded secrets.
        scan_misconfig: If True, check image config for security misconfigurations.

    Returns:
        Dict with image metadata, OS info, vulnerability findings, and
        optional secret/misconfig findings.

    Raises:
        ThreatCodeError: On registry errors, extraction failures, or invalid references.
    """
    from threatcode.engine.vulns.db import VulnDB
    from threatcode.image.auth import CredentialStore
    from threatcode.image.layer import LayerExtractor
    from threatcode.image.reference import ImageReference
    from threatcode.image.registry import RegistryClient
    from threatcode.image.scanner import ImageScanner

    platform_parts = platform.split("/")
    platform_os = platform_parts[0] if platform_parts else "linux"
    platform_arch = platform_parts[1] if len(platform_parts) > 1 else "amd64"

    ref = ImageReference.parse(image_ref)
    client = RegistryClient(
        CredentialStore(),
        platform_os=platform_os,
        platform_arch=platform_arch,
    )
    try:
        manifest, _ = client.pull_manifest(ref)
        config = client.pull_config(ref, manifest)
        layer_blobs = [
            client.pull_blob(ref, desc["digest"])
            for desc in manifest.get("layers", [])
            if desc.get("digest")
        ]
    finally:
        client.close()

    extractor = LayerExtractor()
    extracted = extractor.extract_from_blobs(layer_blobs, config)
    try:
        scanner = ImageScanner(
            db=VulnDB(),
            ignore_unfixed=ignore_unfixed,
            scan_secrets=scan_secrets,
            scan_misconfig=scan_misconfig,
        )
        result = scanner.scan_extracted(image_ref, extracted)
    finally:
        extracted.cleanup()

    return result.to_dict()
