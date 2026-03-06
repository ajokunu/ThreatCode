"""Extended finding types for multi-scanner results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from threatcode.models.threat import Severity

if TYPE_CHECKING:
    from threatcode.models.report import ThreatReport


class FindingType(str, Enum):
    THREAT = "threat"
    VULNERABILITY = "vulnerability"
    SECRET = "secret"
    LICENSE = "license"


@dataclass
class SecretFinding:
    id: str
    finding_type: FindingType = field(default=FindingType.SECRET, init=False)
    title: str = ""
    severity: Severity = Severity.HIGH
    file_path: str = ""
    line_number: int = 0
    secret_type: str = ""
    match: str = ""  # redacted
    rule_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "finding_type": self.finding_type.value,
            "title": self.title,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "secret_type": self.secret_type,
            "match": self.match,
            "rule_id": self.rule_id,
            "metadata": self.metadata,
        }


@dataclass
class VulnerabilityFinding:
    id: str
    finding_type: FindingType = field(default=FindingType.VULNERABILITY, init=False)
    title: str = ""
    severity: Severity = Severity.MEDIUM
    package_name: str = ""
    package_version: str = ""
    ecosystem: str = ""
    cve_id: str = ""
    fixed_version: str = ""
    advisory_url: str = ""
    cvss_score: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "finding_type": self.finding_type.value,
            "title": self.title,
            "severity": self.severity.value,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "ecosystem": self.ecosystem,
            "cve_id": self.cve_id,
            "fixed_version": self.fixed_version,
            "advisory_url": self.advisory_url,
            "cvss_score": self.cvss_score,
            "metadata": self.metadata,
        }


@dataclass
class LicenseFinding:
    id: str
    finding_type: FindingType = field(default=FindingType.LICENSE, init=False)
    title: str = ""
    severity: Severity = Severity.INFO
    package_name: str = ""
    package_version: str = ""
    ecosystem: str = ""
    license_id: str = ""  # SPDX
    license_name: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "finding_type": self.finding_type.value,
            "title": self.title,
            "severity": self.severity.value,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "ecosystem": self.ecosystem,
            "license_id": self.license_id,
            "license_name": self.license_name,
            "metadata": self.metadata,
        }


@dataclass
class ScanReport:
    """Unified scan report wrapping threat report + extended findings."""

    threat_report: ThreatReport | None = None
    secrets: list[SecretFinding] = field(default_factory=list)
    vulnerabilities: list[VulnerabilityFinding] = field(default_factory=list)
    licenses: list[LicenseFinding] = field(default_factory=list)
    input_path: str = ""
    scanners_used: list[str] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {
            "secrets": len(self.secrets),
            "vulnerabilities": len(self.vulnerabilities),
            "licenses": len(self.licenses),
        }
        if self.threat_report is not None:
            counts["threats"] = len(self.threat_report.threats)
        return counts

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "input_path": self.input_path,
            "scanners_used": self.scanners_used,
            "summary": self.summary,
        }
        if self.threat_report is not None:
            result["threat_report"] = self.threat_report.to_dict()
        if self.secrets:
            result["secrets"] = [s.to_dict() for s in self.secrets]
        if self.vulnerabilities:
            result["vulnerabilities"] = [v.to_dict() for v in self.vulnerabilities]
        if self.licenses:
            result["licenses"] = [lic.to_dict() for lic in self.licenses]
        return result
