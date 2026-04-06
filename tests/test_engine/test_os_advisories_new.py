"""Tests for new OS advisory parsers (Ubuntu, Amazon Linux, RHEL)."""

from __future__ import annotations

from typing import Any

from threatcode.engine.vulns.os_advisories import (
    _parse_amzn_alas,
    _parse_rhel_cve_api,
    _parse_ubuntu_oval,
)


class TestParseUbuntuOval:
    def test_basic_parsing(self) -> None:
        xml_data = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions
    xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <definitions>
    <definition id="oval:com.ubuntu.jammy:def:1234" class="vulnerability">
      <metadata>
        <title>CVE-2024-1234 in openssl</title>
        <reference ref_id="CVE-2024-1234" source="CVE" />
        <advisory>
          <severity>High</severity>
        </advisory>
      </metadata>
    </definition>
  </definitions>
</oval_definitions>
"""
        records = _parse_ubuntu_oval(xml_data, os_version="22.04")
        assert len(records) == 1
        assert records[0]["id"] == "CVE-2024-1234"
        assert records[0]["os_family"] == "ubuntu"
        assert records[0]["os_version"] == "22.04"
        assert records[0]["severity"] == "high"
        assert records[0]["package"] == "openssl"

    def test_multiple_cves(self) -> None:
        xml_data = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions
    xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <definitions>
    <definition id="oval:def:1" class="vulnerability">
      <metadata>
        <title>CVE-2024-0001 in curl</title>
        <reference ref_id="CVE-2024-0001" source="CVE" />
        <reference ref_id="CVE-2024-0002" source="CVE" />
        <advisory>
          <severity>Medium</severity>
        </advisory>
      </metadata>
    </definition>
  </definitions>
</oval_definitions>
"""
        records = _parse_ubuntu_oval(xml_data, os_version="20.04")
        assert len(records) == 2
        cve_ids = {r["id"] for r in records}
        assert "CVE-2024-0001" in cve_ids
        assert "CVE-2024-0002" in cve_ids

    def test_empty_xml_returns_empty(self) -> None:
        assert _parse_ubuntu_oval(b"<root/>", os_version="22.04") == []

    def test_invalid_xml_returns_empty(self) -> None:
        assert _parse_ubuntu_oval(b"not xml", os_version="22.04") == []

    def test_no_cve_refs_skipped(self) -> None:
        xml_data = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions
    xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <definitions>
    <definition id="oval:def:1" class="vulnerability">
      <metadata>
        <title>No CVE here</title>
        <advisory>
          <severity>Low</severity>
        </advisory>
      </metadata>
    </definition>
  </definitions>
</oval_definitions>
"""
        records = _parse_ubuntu_oval(xml_data, os_version="22.04")
        assert len(records) == 0


class TestParseAmznAlas:
    def test_basic_parsing(self) -> None:
        xml_data = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <item>
      <title>ALAS-2024-1234 (important)</title>
      <description>CVE-2024-5678 CVE-2024-5679</description>
    </item>
  </channel>
</rss>
"""
        records = _parse_amzn_alas(xml_data, os_version="2")
        assert len(records) == 2
        assert all(r["os_family"] == "amzn" for r in records)
        assert all(r["os_version"] == "2" for r in records)
        assert all(r["severity"] == "high" for r in records)
        cves = {r["id"] for r in records}
        assert "CVE-2024-5678" in cves
        assert "CVE-2024-5679" in cves

    def test_severity_mapping(self) -> None:
        template = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <item>
    <title>ALAS-2024-001 (critical)</title>
    <description>CVE-2024-0001</description>
  </item>
  <item>
    <title>ALAS-2024-002 (low)</title>
    <description>CVE-2024-0002</description>
  </item>
</channel></rss>
"""
        records = _parse_amzn_alas(template, os_version="2023")
        sev_map = {r["id"]: r["severity"] for r in records}
        assert sev_map["CVE-2024-0001"] == "critical"
        assert sev_map["CVE-2024-0002"] == "low"

    def test_empty_rss_returns_empty(self) -> None:
        xml_data = b'<rss version="2.0"><channel></channel></rss>'
        assert _parse_amzn_alas(xml_data, os_version="2") == []

    def test_invalid_xml_returns_empty(self) -> None:
        assert _parse_amzn_alas(b"not xml", os_version="2") == []

    def test_no_cves_in_item(self) -> None:
        xml_data = b"""\
<rss version="2.0"><channel>
  <item>
    <title>ALAS-2024-100 (medium)</title>
    <description>No CVE references here</description>
  </item>
</channel></rss>
"""
        records = _parse_amzn_alas(xml_data, os_version="2")
        assert len(records) == 0


class TestParseRhelCveApi:
    def test_basic_parsing(self) -> None:
        entries: list[dict[str, Any]] = [
            {
                "CVE": "CVE-2024-1111",
                "severity": "important",
                "cvss3_score": "8.1",
                "bugzilla_description": "A test vulnerability",
                "affected_packages": ["openssl-3.0.7-1.el8.x86_64"],
            }
        ]
        records = _parse_rhel_cve_api(entries, os_version="8")
        assert len(records) == 1
        assert records[0]["id"] == "CVE-2024-1111"
        assert records[0]["os_family"] == "rhel"
        assert records[0]["os_version"] == "8"
        assert records[0]["severity"] == "high"
        assert records[0]["cvss_score"] == 8.1
        assert records[0]["package"] == "openssl"

    def test_severity_mapping(self) -> None:
        entries: list[dict[str, Any]] = [
            {"CVE": "CVE-2024-0001", "severity": "critical", "affected_packages": []},
            {"CVE": "CVE-2024-0002", "severity": "moderate", "affected_packages": []},
            {"CVE": "CVE-2024-0003", "severity": "low", "affected_packages": []},
        ]
        records = _parse_rhel_cve_api(entries, os_version="9")
        sev_map = {r["id"]: r["severity"] for r in records}
        assert sev_map["CVE-2024-0001"] == "critical"
        assert sev_map["CVE-2024-0002"] == "medium"
        assert sev_map["CVE-2024-0003"] == "low"

    def test_filters_by_rhel_version(self) -> None:
        entries: list[dict[str, Any]] = [
            {
                "CVE": "CVE-2024-9999",
                "severity": "important",
                "affected_packages": [
                    "pkg-1.0.0-1.el9.x86_64",
                    "other-2.0.0-1.el8.x86_64",
                ],
            }
        ]
        records = _parse_rhel_cve_api(entries, os_version="9")
        assert len(records) == 1
        assert records[0]["package"] == "pkg"

    def test_empty_entries(self) -> None:
        assert _parse_rhel_cve_api([], os_version="8") == []

    def test_invalid_input(self) -> None:
        assert _parse_rhel_cve_api("not a list", os_version="8") == []

    def test_missing_cve_skipped(self) -> None:
        entries: list[dict[str, Any]] = [{"severity": "low", "affected_packages": []}]
        assert _parse_rhel_cve_api(entries, os_version="8") == []

    def test_no_matching_packages_still_records(self) -> None:
        entries: list[dict[str, Any]] = [
            {
                "CVE": "CVE-2024-0001",
                "severity": "moderate",
                "affected_packages": ["pkg-1.0.0-1.el7.x86_64"],
            }
        ]
        records = _parse_rhel_cve_api(entries, os_version="8")
        assert len(records) == 1
        assert records[0]["package"] == ""
