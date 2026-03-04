"""Tests for license compliance scanner."""

from threatcode.engine.licenses.scanner import LicenseScanner, classify_license
from threatcode.models.threat import Severity


class TestClassifyLicense:
    def test_permissive(self) -> None:
        assert classify_license("MIT") == "permissive"
        assert classify_license("Apache-2.0") == "permissive"
        assert classify_license("BSD-3-Clause") == "permissive"
        assert classify_license("ISC") == "permissive"

    def test_copyleft(self) -> None:
        assert classify_license("GPL-3.0-only") == "copyleft"
        assert classify_license("GPL-2.0-or-later") == "copyleft"

    def test_restrictive(self) -> None:
        assert classify_license("AGPL-3.0-only") == "restrictive"
        assert classify_license("SSPL-1.0") == "restrictive"

    def test_weakly_copyleft(self) -> None:
        assert classify_license("LGPL-2.1-only") == "weakly_copyleft"
        assert classify_license("MPL-2.0") == "weakly_copyleft"

    def test_unknown(self) -> None:
        assert classify_license("") == "unknown"
        assert classify_license("SomeCustomLicense") == "unknown"


class TestLicenseScanner:
    def test_permissive_no_findings(self) -> None:
        scanner = LicenseScanner()
        deps = [
            {
                "name": "lodash",
                "version": "4.17.21",
                "ecosystem": "npm",
                "license": "MIT",
            },
            {
                "name": "express",
                "version": "4.18.0",
                "ecosystem": "npm",
                "license": "MIT",
            },
        ]
        findings = scanner.scan_dependencies(deps)
        assert len(findings) == 0

    def test_copyleft_warning(self) -> None:
        scanner = LicenseScanner()
        deps = [
            {
                "name": "gpl-lib",
                "version": "1.0.0",
                "ecosystem": "npm",
                "license": "GPL-3.0-only",
            },
        ]
        findings = scanner.scan_dependencies(deps)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "Copyleft" in findings[0].title

    def test_restrictive_alert(self) -> None:
        scanner = LicenseScanner()
        deps = [
            {
                "name": "agpl-lib",
                "version": "1.0.0",
                "ecosystem": "npm",
                "license": "AGPL-3.0-only",
            },
        ]
        findings = scanner.scan_dependencies(deps)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_unknown_license_alert(self) -> None:
        scanner = LicenseScanner()
        deps = [
            {
                "name": "mystery",
                "version": "1.0.0",
                "ecosystem": "npm",
                "license": "",
            },
        ]
        findings = scanner.scan_dependencies(deps)
        assert len(findings) == 1
        assert "No license" in findings[0].title

    def test_disable_copyleft_warning(self) -> None:
        scanner = LicenseScanner(warn_copyleft=False)
        deps = [
            {
                "name": "gpl-lib",
                "version": "1.0.0",
                "ecosystem": "npm",
                "license": "GPL-3.0-only",
            },
        ]
        findings = scanner.scan_dependencies(deps)
        assert len(findings) == 0

    def test_to_dict(self) -> None:
        scanner = LicenseScanner()
        deps = [
            {
                "name": "gpl-lib",
                "version": "1.0.0",
                "ecosystem": "npm",
                "license": "GPL-3.0-only",
            },
        ]
        findings = scanner.scan_dependencies(deps)
        d = findings[0].to_dict()
        assert d["license_id"] == "GPL-3.0-only"
        assert d["package_name"] == "gpl-lib"
