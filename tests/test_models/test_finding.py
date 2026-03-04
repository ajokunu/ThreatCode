"""Tests for extended finding types."""

from threatcode.models.finding import (
    FindingType,
    LicenseFinding,
    ScanReport,
    SecretFinding,
    VulnerabilityFinding,
)
from threatcode.models.threat import Severity


class TestFindingType:
    def test_values(self) -> None:
        assert FindingType.THREAT.value == "threat"
        assert FindingType.VULNERABILITY.value == "vulnerability"
        assert FindingType.SECRET.value == "secret"
        assert FindingType.LICENSE.value == "license"


class TestSecretFinding:
    def test_defaults(self) -> None:
        f = SecretFinding(id="SEC-001")
        assert f.finding_type == FindingType.SECRET
        assert f.severity == Severity.HIGH

    def test_to_dict(self) -> None:
        f = SecretFinding(
            id="SEC-001",
            title="AWS Key",
            file_path="main.tf",
            line_number=10,
            secret_type="aws_access_key",
            match="AKIA****",
            rule_id="AWS_ACCESS_KEY",
        )
        d = f.to_dict()
        assert d["id"] == "SEC-001"
        assert d["finding_type"] == "secret"
        assert d["file_path"] == "main.tf"
        assert d["line_number"] == 10


class TestVulnerabilityFinding:
    def test_defaults(self) -> None:
        f = VulnerabilityFinding(id="VULN-001")
        assert f.finding_type == FindingType.VULNERABILITY
        assert f.severity == Severity.MEDIUM

    def test_to_dict(self) -> None:
        f = VulnerabilityFinding(
            id="VULN-001",
            title="lodash prototype pollution",
            package_name="lodash",
            package_version="4.17.15",
            ecosystem="npm",
            cve_id="CVE-2020-28500",
            fixed_version="4.17.21",
            cvss_score=7.5,
            severity=Severity.HIGH,
        )
        d = f.to_dict()
        assert d["cve_id"] == "CVE-2020-28500"
        assert d["ecosystem"] == "npm"
        assert d["cvss_score"] == 7.5


class TestLicenseFinding:
    def test_defaults(self) -> None:
        f = LicenseFinding(id="LIC-001")
        assert f.finding_type == FindingType.LICENSE
        assert f.severity == Severity.INFO

    def test_to_dict(self) -> None:
        f = LicenseFinding(
            id="LIC-001",
            title="Copyleft license detected",
            package_name="gpl-lib",
            license_id="GPL-3.0-only",
            license_name="GNU General Public License v3.0 only",
            severity=Severity.MEDIUM,
        )
        d = f.to_dict()
        assert d["license_id"] == "GPL-3.0-only"


class TestScanReport:
    def test_empty_report(self) -> None:
        r = ScanReport()
        assert r.summary == {"secrets": 0, "vulnerabilities": 0, "licenses": 0}

    def test_summary_with_findings(self) -> None:
        r = ScanReport(
            secrets=[SecretFinding(id="S1"), SecretFinding(id="S2")],
            vulnerabilities=[VulnerabilityFinding(id="V1")],
        )
        assert r.summary["secrets"] == 2
        assert r.summary["vulnerabilities"] == 1

    def test_to_dict(self) -> None:
        r = ScanReport(
            input_path="/app",
            scanners_used=["secret"],
            secrets=[SecretFinding(id="S1", title="Found key")],
        )
        d = r.to_dict()
        assert d["input_path"] == "/app"
        assert d["scanners_used"] == ["secret"]
        assert len(d["secrets"]) == 1
        assert "threat_report" not in d  # None, so excluded

    def test_to_dict_with_threat_report(self) -> None:
        from threatcode.models.report import ThreatReport

        tr = ThreatReport(scanned_resources=5)
        r = ScanReport(threat_report=tr, scanners_used=["misconfig"])
        d = r.to_dict()
        assert "threat_report" in d
        assert r.summary["threats"] == 0
