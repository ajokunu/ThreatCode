"""Tests for CycloneDX SBOM formatter."""

import json

from threatcode.formatters.cyclonedx import _make_purl, format_cyclonedx


class TestMakePurl:
    def test_npm_package(self) -> None:
        assert _make_purl("npm", "lodash", "4.17.21") == "pkg:npm/lodash@4.17.21"

    def test_npm_scoped(self) -> None:
        assert _make_purl("npm", "@types/node", "18.0.0") == "pkg:npm/@types/node@18.0.0"

    def test_pypi(self) -> None:
        assert _make_purl("pypi", "flask", "2.0.1") == "pkg:pypi/flask@2.0.1"

    def test_go(self) -> None:
        purl = _make_purl("go", "github.com/gin-gonic/gin", "1.7.4")
        assert purl == "pkg:golang/github.com/gin-gonic/gin@1.7.4"

    def test_cargo(self) -> None:
        assert _make_purl("crates.io", "serde", "1.0.130") == "pkg:cargo/serde@1.0.130"

    def test_rubygems(self) -> None:
        assert _make_purl("rubygems", "rails", "7.0.0") == "pkg:gem/rails@7.0.0"


class TestFormatCyclonedx:
    def test_basic_sbom(self) -> None:
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
        output = format_cyclonedx(deps, source_path="package-lock.json")
        sbom = json.loads(output)

        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["specVersion"] == "1.5"
        assert len(sbom["components"]) == 2
        assert sbom["components"][0]["name"] == "lodash"
        assert sbom["components"][0]["purl"] == "pkg:npm/lodash@4.17.21"

    def test_sbom_has_metadata(self) -> None:
        output = format_cyclonedx([{"name": "x", "version": "1.0", "ecosystem": "npm"}])
        sbom = json.loads(output)
        assert "metadata" in sbom
        assert "timestamp" in sbom["metadata"]
        tools = sbom["metadata"]["tools"]["components"]
        assert any(t["name"] == "threatcode" for t in tools)

    def test_sbom_with_license(self) -> None:
        deps = [
            {
                "name": "lodash",
                "version": "4.17.21",
                "ecosystem": "npm",
                "license": "MIT",
            }
        ]
        output = format_cyclonedx(deps)
        sbom = json.loads(output)
        assert sbom["components"][0]["licenses"][0]["license"]["id"] == "MIT"

    def test_sbom_with_vulnerabilities(self) -> None:
        deps = [{"name": "lodash", "version": "4.17.15", "ecosystem": "npm"}]
        vulns = [
            {
                "cve_id": "CVE-2020-28500",
                "title": "Prototype pollution",
                "package_name": "lodash",
                "package_version": "4.17.15",
                "ecosystem": "npm",
                "cvss_score": 7.5,
                "severity": "high",
            }
        ]
        output = format_cyclonedx(deps, vulnerabilities=vulns)
        sbom = json.loads(output)
        assert "vulnerabilities" in sbom
        assert sbom["vulnerabilities"][0]["id"] == "CVE-2020-28500"

    def test_empty_deps(self) -> None:
        output = format_cyclonedx([])
        sbom = json.loads(output)
        assert sbom["components"] == []

    def test_deps_without_version_skipped(self) -> None:
        deps = [{"name": "test", "ecosystem": "npm"}]  # No version
        output = format_cyclonedx(deps)
        sbom = json.loads(output)
        assert len(sbom["components"]) == 0
