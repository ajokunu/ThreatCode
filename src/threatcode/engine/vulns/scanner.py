"""Vulnerability scanning engine."""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from threatcode.engine.vulns.db import VulnDB
from threatcode.engine.vulns.version import is_vulnerable
from threatcode.models.finding import VulnerabilityFinding
from threatcode.models.threat import Severity

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


# CVSS score to severity mapping
def _cvss_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


class VulnerabilityScanner:
    """Scan parsed dependencies against the vulnerability database."""

    def __init__(self, db: VulnDB | None = None) -> None:
        self.db = db or VulnDB()

    def scan_dependencies(
        self,
        dependencies: list[dict[str, Any]],
        *,
        ignore_unfixed: bool = False,
    ) -> list[VulnerabilityFinding]:
        """Scan a list of dependencies for known vulnerabilities.

        Args:
            dependencies: List of dicts with keys: name, version, ecosystem
            ignore_unfixed: Skip vulnerabilities without a fix
        """
        if not self.db.exists():
            logger.warning(
                "Vulnerability database not found at %s. "
                "Run 'threatcode db update' to download it.",
                self.db.db_path,
            )
            return []

        findings: list[VulnerabilityFinding] = []

        for dep in dependencies:
            name = dep.get("name", "")
            version = dep.get("version", "")
            ecosystem = dep.get("ecosystem", "")

            if not name or not version or not ecosystem:
                continue

            vulns = self.db.query(ecosystem, name)
            for vuln in vulns:
                introduced = vuln.get("version_introduced", "")
                fixed = vuln.get("version_fixed", "")

                if ignore_unfixed and not fixed:
                    continue

                if is_vulnerable(version, introduced, fixed, ecosystem):
                    cvss = vuln.get("cvss_score", 0.0)
                    severity_str = vuln.get("severity", "medium")
                    severity = _SEVERITY_MAP.get(severity_str)
                    if severity is None:
                        severity = _cvss_to_severity(cvss)

                    vuln_id = vuln.get("id", "")
                    aliases_raw = vuln.get("aliases", "[]")
                    try:
                        aliases = (
                            json.loads(aliases_raw) if isinstance(aliases_raw, str) else aliases_raw
                        )
                    except json.JSONDecodeError:
                        aliases = []

                    # Use CVE alias if available
                    cve_id = ""
                    if isinstance(aliases, list):
                        for alias in aliases:
                            if isinstance(alias, str) and alias.startswith("CVE-"):
                                cve_id = alias
                                break
                    if not cve_id and vuln_id.startswith("CVE-"):
                        cve_id = vuln_id

                    finding = VulnerabilityFinding(
                        id=f"VULN-{uuid.uuid4().hex[:8]}",
                        title=vuln.get("summary", f"Vulnerability in {name}"),
                        severity=severity,
                        package_name=name,
                        package_version=version,
                        ecosystem=ecosystem,
                        cve_id=cve_id or vuln_id,
                        fixed_version=fixed,
                        advisory_url="",
                        cvss_score=cvss,
                        metadata={"vuln_id": vuln_id, "aliases": aliases},
                    )
                    findings.append(finding)

        return findings
