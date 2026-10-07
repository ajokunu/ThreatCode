"""Scanner results ingested into an example join its graph and enable its attack paths.

``examples/aws-webapp/scanner/trivy-app-image.json`` is a real-shape Trivy image report with one
critical CVE in the image the app instances run. The join key is the image reference, which the
plan carries in plaintext in each instance's user_data. Today the tests check that the report has
the shape the ingester reads and that the join key is there to find, and that ingesting it puts the
CVE on the workloads that run the image. Two expectations wait on other packages and are marked
pending with the package that delivers them: the attack-path search (the CVE as an enabler of a hop)
and the report writer (the ingested sources in the JSON report).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.helpers.cli import find_key, run_cli, scan_json
from tests.helpers.examples import (
    EXAMPLES_DIR,
    expected_for,
    is_subsequence,
    path_node_ids,
    scan_example,
)
from tests.helpers.pending import pending

WEBAPP = EXAMPLES_DIR / "aws-webapp"
TRIVY = WEBAPP / "scanner" / "trivy-app-image.json"


def trivy_report() -> dict[str, Any]:
    return json.loads(TRIVY.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def scanner_entry() -> dict[str, Any]:
    (entry,) = expected_for("aws-webapp")["scanner"]
    return entry  # type: ignore[no-any-return]


def vulnerabilities(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [v for r in report["Results"] for v in r.get("Vulnerabilities") or []]


class TestTheTrivyReport:
    def test_it_is_a_schema_2_image_report(self) -> None:
        report = trivy_report()
        assert report["SchemaVersion"] == 2
        assert report["ArtifactType"] == "container_image"
        assert report["ArtifactName"] == scanner_entry()["image"]
        assert report["Metadata"]["OS"]["Family"] == "debian"
        assert report["Metadata"]["RepoTags"] == [scanner_entry()["image"]]

    def test_it_holds_exactly_one_critical_vulnerability(self) -> None:
        (vuln,) = vulnerabilities(trivy_report())
        assert vuln["VulnerabilityID"] == scanner_entry()["finding"] == "CVE-2022-37434"
        assert vuln["Severity"] == "CRITICAL"
        assert vuln["FixedVersion"] != vuln["InstalledVersion"]
        assert vuln["CVSS"]["nvd"]["V3Score"] >= 9.0
        assert vuln["PrimaryURL"].endswith("cve-2022-37434")

    def test_each_vulnerability_carries_the_fields_an_ingester_reads(self) -> None:
        required = {
            "VulnerabilityID",
            "PkgName",
            "InstalledVersion",
            "FixedVersion",
            "Severity",
            "Title",
            "PkgIdentifier",
        }
        for vuln in vulnerabilities(trivy_report()):
            assert required <= set(vuln)
            assert vuln["PkgIdentifier"]["PURL"].startswith("pkg:deb/debian/")

    def test_the_results_name_the_image_and_its_os_as_trivy_prints_them(self) -> None:
        (result,) = trivy_report()["Results"]
        assert result["Target"] == f"{scanner_entry()['image']} (debian 11.8)"
        assert (result["Class"], result["Type"]) == ("os-pkgs", "debian")


class TestTheJoinKey:
    def test_the_image_reference_is_in_the_user_data_of_the_instances_the_report_attaches_to(
        self,
    ) -> None:
        graph = scan_example("aws-webapp").graph
        image = trivy_report()["ArtifactName"]
        for address in scanner_entry()["attaches_to"]:
            assert image in graph.nodes[address].properties["user_data"], address

    def test_no_other_node_mentions_the_image_so_the_attachment_is_unambiguous(self) -> None:
        graph = scan_example("aws-webapp").graph
        image = trivy_report()["ArtifactName"]
        holders = sorted(
            node.id for node in graph.nodes.values() if image in json.dumps(node.properties)
        )
        assert holders == sorted(scanner_entry()["attaches_to"])

    def test_the_expected_file_ties_the_cve_to_a_listed_path(self) -> None:
        path_ids = {p["id"] for p in expected_for("aws-webapp")["attack_paths"]}
        assert scanner_entry()["enables_path"] in path_ids
        assert scanner_entry()["file"] == "scanner/trivy-app-image.json"
        assert (WEBAPP / scanner_entry()["file"]).is_file()


class TestIngestion:
    def test_the_cve_becomes_a_finding_on_each_app_instance(self) -> None:
        run = scan_json([WEBAPP], ingest=[TRIVY])
        assert run.exit_code == 0, run.stderr[-300:]
        threats = find_key(run.json(), "threats") or []
        hits = [t for t in threats if t.get("rule_id") == "trivy:CVE-2022-37434"]
        assert sorted(t["resource_address"] for t in hits) == sorted(scanner_entry()["attaches_to"])
        assert all(t["severity"] == "critical" for t in hits)

    @pending(
        "WP-4-1",
        "attack paths exist and list the findings that enable each hop, so the ingested CVE "
        "(a threat on the instance the path crosses) shows up as an enabler",
    )
    def test_the_cve_is_an_enabler_of_the_expected_path(self) -> None:
        run = scan_json([WEBAPP], ingest=[TRIVY])
        paths = find_key(run.json(), "attack_paths") or []
        wanted = next(
            p
            for p in expected_for("aws-webapp")["attack_paths"]
            if p["id"] == scanner_entry()["enables_path"]
        )
        for path in paths:
            ids = path_node_ids(path)
            if ids[-1] == wanted["target"] and is_subsequence(wanted["via"], ids):
                enablers = json.dumps([hop.get("enabled_by") for hop in path.get("hops", [])])
                assert "CVE-2022-37434" in enablers
                return
        pytest.fail("the expected path is not in the report")

    def test_the_report_lists_the_ingested_source(self) -> None:
        run = scan_json([WEBAPP], ingest=[TRIVY])
        sources = find_key(run.json(), "sources") or find_key(run.json(), "ingest") or []
        text = json.dumps(sources)
        assert "trivy" in text and "attached" in text

    def test_an_unrecognized_ingest_file_exits_2_and_names_the_file(self, tmp_path: Path) -> None:
        junk = tmp_path / "not-a-report.json"
        junk.write_text('{"hello": "world"}', encoding="utf-8")
        run = run_cli(
            ["scan", str(WEBAPP), "-f", "json", "--fail-on", "none", "--ingest", str(junk)]
        )
        assert run.exit_code == 2, run.stderr[-300:]
        assert "not-a-report.json" in run.stderr

    def test_a_report_for_an_unrelated_image_is_kept_as_unattached(self, tmp_path: Path) -> None:
        report = trivy_report()
        report["ArtifactName"] = "registry.example.com/other/service:1.0.0"
        report["Metadata"]["RepoTags"] = ["registry.example.com/other/service:1.0.0"]
        other = tmp_path / "other.json"
        other.write_text(json.dumps(report), encoding="utf-8")
        run = scan_json([WEBAPP], ingest=[other])
        assert run.exit_code == 0, run.stderr[-300:]
        threats = find_key(run.json(), "threats") or []
        hits = [t for t in threats if t.get("rule_id") == "trivy:CVE-2022-37434"]
        assert len(hits) == 1
        assert hits[0].get("resource_address", "") == ""
