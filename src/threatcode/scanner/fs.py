"""Filesystem scanner — walk a directory tree and run all selected scanners."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from threatcode.constants import LOCKFILE_NAMES
from threatcode.exceptions import ThreatCodeError

logger = logging.getLogger(__name__)

# Directories to always skip
_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        "vendor",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "venv",
        ".terraform",
        "dist",
        "build",
        ".eggs",
    }
)

# Max file size for IaC/lockfile parsing (50 MB matches existing parser limit)
_MAX_FILE_SIZE = 50 * 1024 * 1024

# IaC file patterns
_IAC_EXTENSIONS: frozenset[str] = frozenset({".tf", ".json", ".yml", ".yaml"})

# Dockerfile name patterns
_DOCKERFILE_NAMES: frozenset[str] = frozenset({"Dockerfile", "dockerfile"})


def _is_dockerfile(name: str) -> bool:
    """Check if a filename is a Dockerfile variant."""
    lower = name.lower()
    return lower == "dockerfile" or lower.startswith("dockerfile.") or lower.endswith(".dockerfile")


def _is_iac_candidate(path: Path) -> bool:
    """Check if a file might be an IaC file worth scanning."""
    if path.suffix in _IAC_EXTENSIONS:
        return True
    if _is_dockerfile(path.name):
        return True
    return False


def scan_filesystem(
    target: str | Path,
    *,
    scanners: tuple[str, ...] = ("vuln", "secret", "misconfig", "license"),
    ignore_unfixed: bool = False,
    min_severity: str = "info",
    no_llm: bool = True,
    config_path: str | Path | None = None,
    extra_rule_paths: list[str | Path] | None = None,
    skip_dirs: frozenset[str] | None = None,
) -> dict[str, Any]:
    """Scan a filesystem directory for vulnerabilities, secrets, misconfigs, and licenses.

    Walks the directory tree, discovers lockfiles, IaC files, Dockerfiles,
    and K8s manifests, then runs the selected scanners against them.

    Args:
        target: Directory path to scan.
        scanners: Scanner types to run.
        ignore_unfixed: Skip vulnerabilities without a fix.
        min_severity: Minimum severity to include.
        no_llm: Disable LLM analysis for misconfig scanner.
        config_path: Path to .threatcode.yml config file.
        extra_rule_paths: Additional rule files for misconfig scanner.
        skip_dirs: Additional directory names to skip.

    Returns:
        Dict with per-scanner results and file discovery metadata.
    """
    target = Path(target).resolve()
    if not target.is_dir():
        raise ThreatCodeError(f"Target is not a directory: {target}")

    dirs_to_skip = _SKIP_DIRS | (skip_dirs or frozenset())

    # Phase 1: discover files
    lockfiles: list[Path] = []
    iac_files: list[Path] = []
    helm_charts: list[Path] = []
    all_files: list[Path] = []

    for root, dirs, filenames in os.walk(target):
        # Prune skip directories
        dirs[:] = [d for d in dirs if d not in dirs_to_skip and not d.startswith(".")]

        root_path = Path(root)
        for fname in filenames:
            fpath = root_path / fname

            try:
                if fpath.stat().st_size > _MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            all_files.append(fpath)

            if fname in LOCKFILE_NAMES:
                lockfiles.append(fpath)
            elif fname == "Chart.yaml":
                helm_charts.append(fpath)
            elif _is_iac_candidate(fpath):
                iac_files.append(fpath)

    logger.info(
        "Discovered %d files (%d lockfiles, %d IaC candidates, %d Helm charts) in %s",
        len(all_files),
        len(lockfiles),
        len(iac_files),
        len(helm_charts),
        target,
    )

    result: dict[str, Any] = {
        "target": str(target),
        "scanners": list(scanners),
        "files_scanned": len(all_files),
        "lockfiles_found": len(lockfiles),
        "iac_files_found": len(iac_files),
        "helm_charts_found": len(helm_charts),
    }

    has_issues = False

    # Phase 2: run vuln scanner on lockfiles
    if "vuln" in scanners:
        result["vuln"] = _scan_vulns(lockfiles, ignore_unfixed=ignore_unfixed)
        if result["vuln"].get("total_vulnerabilities", 0) > 0:
            has_issues = True

    # Phase 3: run secret scanner on entire directory
    if "secret" in scanners:
        result["secret"] = _scan_secrets(target)
        if result["secret"].get("total_secrets", 0) > 0:
            has_issues = True

    # Phase 4: run misconfig scanner on IaC files (including rendered Helm charts)
    misconfig_files = list(iac_files)
    for chart_yaml in helm_charts:
        misconfig_files.append(chart_yaml)
    if "misconfig" in scanners:
        result["misconfig"] = _scan_misconfigs(
            misconfig_files,
            no_llm=no_llm,
            min_severity=min_severity,
            config_path=config_path,
            extra_rule_paths=extra_rule_paths,
        )
        if result["misconfig"].get("total_threats", 0) > 0:
            has_issues = True

    # Phase 5: run license scanner on lockfiles
    if "license" in scanners:
        result["license"] = _scan_licenses(lockfiles)
        if result["license"].get("total_issues", 0) > 0:
            has_issues = True

    result["has_issues"] = has_issues
    return result


def _scan_vulns(lockfiles: list[Path], *, ignore_unfixed: bool = False) -> dict[str, Any]:
    """Scan lockfiles for known vulnerabilities."""
    from threatcode.engine.vulns.db import VulnDB
    from threatcode.engine.vulns.scanner import VulnerabilityScanner
    from threatcode.parsers import detect_and_parse

    all_findings: list[dict[str, Any]] = []
    total_deps = 0

    db = VulnDB()
    if not db.exists():
        return {
            "total_vulnerabilities": 0,
            "dependencies_scanned": 0,
            "findings": [],
            "warning": "Vulnerability database not found. Run 'threatcode db update' first.",
        }

    scanner = VulnerabilityScanner(db=db)

    for lockfile in lockfiles:
        try:
            parsed = detect_and_parse(lockfile)
            deps = [
                r.properties for r in parsed.resources if r.resource_type.startswith("dependency_")
            ]
            if not deps:
                continue

            total_deps += len(deps)
            findings = scanner.scan_dependencies(deps, ignore_unfixed=ignore_unfixed)
            for f in findings:
                d = f.to_dict()
                d["source_lockfile"] = str(lockfile)
                all_findings.append(d)
        except Exception as e:
            logger.warning("Failed to scan %s for vulns: %s", lockfile, e)

    return {
        "total_vulnerabilities": len(all_findings),
        "dependencies_scanned": total_deps,
        "lockfiles_scanned": len(lockfiles),
        "findings": all_findings,
    }


def _scan_secrets(target: Path) -> dict[str, Any]:
    """Scan directory for hardcoded secrets."""
    from threatcode.engine.secrets.scanner import SecretScanner

    scanner = SecretScanner()
    findings = scanner.scan(target)
    return {
        "total_secrets": len(findings),
        "findings": [f.to_dict() for f in findings],
    }


def _scan_misconfigs(
    iac_files: list[Path],
    *,
    no_llm: bool = True,
    min_severity: str = "info",
    config_path: str | Path | None = None,
    extra_rule_paths: list[str | Path] | None = None,
) -> dict[str, Any]:
    """Scan IaC files for misconfigurations."""
    from threatcode.config import load_config
    from threatcode.engine.hybrid import HybridEngine
    from threatcode.ir.graph import InfraGraph
    from threatcode.models.threat import Severity
    from threatcode.parsers import detect_and_parse

    cfg_path = Path(config_path) if config_path else None
    config = load_config(cfg_path)
    config.no_llm = no_llm

    extra = [Path(p) for p in (extra_rule_paths or [])]
    engine = HybridEngine(config=config, extra_rule_paths=extra)

    all_threats: list[dict[str, Any]] = []
    total_resources = 0

    for iac_file in iac_files:
        try:
            parsed = detect_and_parse(iac_file)
            graph = InfraGraph.from_parsed(parsed)
            report = engine.analyze(graph, input_file=str(iac_file))

            if min_severity != "info":
                try:
                    threshold = Severity(min_severity)
                    report.threats = report.filter_by_severity(threshold)
                except ValueError:
                    pass

            total_resources += report.scanned_resources
            for t in report.threats:
                d = t.to_dict()
                d["source_file"] = str(iac_file)
                all_threats.append(d)
        except Exception as e:
            logger.debug("Skipping %s for misconfig scan: %s", iac_file, e)

    return {
        "total_threats": len(all_threats),
        "resources_scanned": total_resources,
        "iac_files_scanned": len(iac_files),
        "findings": all_threats,
    }


def _scan_licenses(lockfiles: list[Path]) -> dict[str, Any]:
    """Scan lockfiles for license compliance issues."""
    from threatcode.engine.licenses.scanner import LicenseScanner
    from threatcode.parsers import detect_and_parse

    all_findings: list[dict[str, Any]] = []
    total_deps = 0
    scanner = LicenseScanner()

    for lockfile in lockfiles:
        try:
            parsed = detect_and_parse(lockfile)
            deps = [
                r.properties for r in parsed.resources if r.resource_type.startswith("dependency_")
            ]
            if not deps:
                continue

            total_deps += len(deps)
            findings = scanner.scan_dependencies(deps)
            for f in findings:
                d = f.to_dict()
                d["source_lockfile"] = str(lockfile)
                all_findings.append(d)
        except Exception as e:
            logger.warning("Failed to scan %s for licenses: %s", lockfile, e)

    return {
        "total_issues": len(all_findings),
        "dependencies_scanned": total_deps,
        "findings": all_findings,
    }
