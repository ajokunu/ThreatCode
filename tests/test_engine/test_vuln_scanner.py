"""Tests for vulnerability scanner."""

import pytest

from threatcode.engine.vulns.db import VulnDB
from threatcode.engine.vulns.scanner import VulnerabilityScanner


@pytest.fixture
def test_db(tmp_path) -> VulnDB:
    db = VulnDB(db_path=tmp_path / "test.sqlite3")
    db.init_db()
    db.insert_vulnerability(
        vuln_id="CVE-2020-28500",
        ecosystem="npm",
        package="lodash",
        version_introduced="",
        version_fixed="4.17.21",
        severity="high",
        cvss_score=7.5,
        summary="Prototype pollution in lodash",
        aliases=["CVE-2020-28500", "GHSA-xxx"],
    )
    db.insert_vulnerability(
        vuln_id="CVE-2021-23337",
        ecosystem="npm",
        package="lodash",
        version_introduced="",
        version_fixed="4.17.21",
        severity="high",
        cvss_score=7.2,
        summary="Command injection in lodash",
    )
    db.insert_vulnerability(
        vuln_id="CVE-2021-29469",
        ecosystem="npm",
        package="express",
        version_introduced="4.0.0",
        version_fixed="4.17.3",
        severity="medium",
        cvss_score=5.3,
        summary="Open redirect in express",
    )
    return db


class TestVulnerabilityScanner:
    def test_scan_finds_vulns(self, test_db: VulnDB) -> None:
        scanner = VulnerabilityScanner(db=test_db)
        deps = [
            {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
        ]
        findings = scanner.scan_dependencies(deps)
        assert len(findings) >= 1
        assert any(f.cve_id == "CVE-2020-28500" for f in findings)

    def test_fixed_version_not_vulnerable(self, test_db: VulnDB) -> None:
        scanner = VulnerabilityScanner(db=test_db)
        deps = [
            {"name": "lodash", "version": "4.17.21", "ecosystem": "npm"},
        ]
        findings = scanner.scan_dependencies(deps)
        assert len(findings) == 0

    def test_ignore_unfixed(self, test_db: VulnDB) -> None:
        scanner = VulnerabilityScanner(db=test_db)
        # Add an unfixed vuln
        test_db.insert_vulnerability(
            vuln_id="CVE-UNFIXED",
            ecosystem="npm",
            package="unfixed-pkg",
            version_introduced="1.0.0",
            severity="high",
        )
        deps = [{"name": "unfixed-pkg", "version": "1.5.0", "ecosystem": "npm"}]
        findings = scanner.scan_dependencies(deps, ignore_unfixed=True)
        assert len(findings) == 0

    def test_no_db_returns_empty(self, tmp_path) -> None:
        db = VulnDB(db_path=tmp_path / "nonexistent.sqlite3")
        scanner = VulnerabilityScanner(db=db)
        deps = [{"name": "lodash", "version": "4.17.15", "ecosystem": "npm"}]
        findings = scanner.scan_dependencies(deps)
        assert len(findings) == 0


class TestVulnDB:
    def test_init_and_status(self, tmp_path) -> None:
        db = VulnDB(db_path=tmp_path / "test.sqlite3")
        db.init_db()
        status = db.status()
        assert status["exists"] is True
        assert status["entry_count"] == 0

    def test_insert_and_query(self, tmp_path) -> None:
        db = VulnDB(db_path=tmp_path / "test.sqlite3")
        db.init_db()
        db.insert_vulnerability(
            vuln_id="CVE-TEST",
            ecosystem="npm",
            package="test-pkg",
            version_fixed="1.0.1",
            severity="high",
        )
        results = db.query("npm", "test-pkg")
        assert len(results) == 1
        assert results[0]["id"] == "CVE-TEST"

    def test_bulk_insert(self, tmp_path) -> None:
        db = VulnDB(db_path=tmp_path / "test.sqlite3")
        db.init_db()
        records = [
            {"id": f"CVE-{i}", "ecosystem": "npm", "package": f"pkg-{i}"} for i in range(100)
        ]
        count = db.bulk_insert(records)
        assert count == 100
        status = db.status()
        assert status["entry_count"] == 100
