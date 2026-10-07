"""What each reader makes of its tool's report, before any join to the graph."""

from __future__ import annotations

import json
from typing import Any

import pytest

from tests.test_ingest.conftest import INGEST_FIXTURES
from threatcode.ingest import grype, osv, sarif, trivy
from threatcode.ingest.model import ExternalFinding, ScannerReport


def document(name: str) -> dict[str, Any]:
    return json.loads((INGEST_FIXTURES / name).read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def one(reports: list[ScannerReport]) -> ScannerReport:
    (report,) = reports
    return report


def find(report: ScannerReport, finding_id: str) -> ExternalFinding:
    (match,) = [f for f in report.findings if f.id == finding_id]
    return match


class TestTrivy:
    def test_an_image_report_is_of_image_scope_and_names_every_reference(self) -> None:
        report = one(trivy.load(document("trivy-image.json")))
        assert report.tool == "trivy"
        assert {f.scope for f in report.findings} == {"image"}
        refs = report.findings[0].image_refs
        assert refs[0] == "ghcr.io/acme/api:1.4.2"
        assert any(r.startswith("ghcr.io/acme/api@sha256:") for r in refs)
        assert all(f.file == "" for f in report.findings)

    def test_a_vulnerability_carries_package_versions_cvss_and_purl(self) -> None:
        finding = find(one(trivy.load(document("trivy-image.json"))), "CVE-2023-4911")
        assert finding.kind == "vulnerability"
        assert finding.severity == "high"
        assert finding.package is not None
        assert (finding.package.name, finding.package.version) == ("libc6", "2.36-9+deb12u3")
        assert finding.package.ecosystem == "debian"
        assert finding.package.purl.startswith("pkg:deb/debian/libc6@")
        assert finding.fixed_version == "2.36-9+deb12u4"
        assert (finding.cvss_score, finding.cvss_vector) == (
            7.8,
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        )
        assert finding.title.startswith("glibc:")
        assert finding.references == ["https://avd.aquasec.com/nvd/cve-2023-4911"]

    def test_unknown_severity_is_info_and_an_unfixed_vulnerability_has_no_fixed_version(
        self,
    ) -> None:
        finding = find(one(trivy.load(document("trivy-image.json"))), "CVE-2024-0001")
        assert finding.severity == "info"
        assert finding.fixed_version == ""
        assert finding.cvss_score is None
        assert finding.status == "affected"

    def test_a_secret_in_an_image_keeps_the_rule_and_never_the_matched_text(self) -> None:
        finding = find(one(trivy.load(document("trivy-image.json"))), "aws-access-key-id")
        assert finding.kind == "secret"
        assert finding.severity == "critical"
        assert (finding.line, finding.end_line) == (3, 3)
        assert "AWS_ACCESS_KEY_ID" not in json.dumps(finding.__dict__, default=str)

    def test_a_filesystem_report_is_of_path_scope_with_files_and_lines(self) -> None:
        report = one(trivy.load(document("trivy-fs.json")))
        assert {f.scope for f in report.findings} == {"path"}
        lock = find(report, "CVE-2021-23337")
        assert (lock.file, lock.line) == ("services/api/package-lock.json", None)
        assert lock.package is not None and lock.package.ecosystem == "npm"
        config = find(report, "KSV001")
        assert (config.kind, config.file, config.line, config.end_line) == (
            "misconfiguration",
            "k8s/deployment.yaml",
            19,
            21,
        )
        assert config.aliases == ["AVD-KSV-0001"]
        assert config.mitigation.startswith("Set ")
        secret = find(report, "aws-secret-access-key")
        assert (secret.file, secret.line) == ("infra/main.tf", 20)

    def test_passed_checks_are_counted_not_reported(self) -> None:
        report = one(trivy.load(document("trivy-fs.json")))
        assert "KSV014" not in {f.id for f in report.findings}
        assert report.skipped == {"passed_checks": 1}

    def test_the_target_of_an_os_package_result_is_not_a_file(self) -> None:
        data = document("trivy-fs.json")
        data["Results"][0]["Class"] = "os-pkgs"
        report = one(trivy.load(data))
        assert find(report, "CVE-2021-23337").file == ""

    def test_licenses_are_counted_as_skipped(self) -> None:
        data = document("trivy-fs.json")
        data["Results"][0]["Licenses"] = [{"Name": "MIT"}, {"Name": "GPL-3.0"}]
        assert one(trivy.load(data)).skipped["licenses"] == 2

    def test_the_cvss_of_the_severity_source_wins_over_a_higher_other_source(self) -> None:
        data = document("trivy-image.json")
        vuln = data["Results"][0]["Vulnerabilities"][0]
        vuln["SeveritySource"] = "redhat"
        vuln["CVSS"] = {
            "nvd": {"V3Score": 9.8, "V3Vector": "nvd-vector"},
            "redhat": {"V3Score": 7.0, "V3Vector": "rh-vector"},
        }
        finding = find(one(trivy.load(data)), "CVE-2023-4911")
        assert (finding.cvss_score, finding.cvss_vector) == (7.0, "rh-vector")

    def test_with_no_known_source_the_highest_score_is_used_and_v2_is_the_fallback(self) -> None:
        data = document("trivy-image.json")
        vuln = data["Results"][0]["Vulnerabilities"][0]
        vuln["SeveritySource"] = "unlisted"
        vuln["CVSS"] = {"a": {"V2Score": 5.0, "V2Vector": "v2"}, "b": {"V3Score": 6.5}}
        assert find(one(trivy.load(data)), "CVE-2023-4911").cvss_score == 6.5
        vuln["CVSS"] = {"a": {"V2Score": 5.0, "V2Vector": "v2"}}
        finding = find(one(trivy.load(data)), "CVE-2023-4911")
        assert (finding.cvss_score, finding.cvss_vector) == (5.0, "v2")

    def test_a_report_with_null_results_has_no_findings(self) -> None:
        assert (
            one(trivy.load({"SchemaVersion": 2, "ArtifactName": "x", "Results": None})).findings
            == []
        )


class TestGrype:
    def test_an_image_source_names_the_user_input_tags_and_repo_digests(self) -> None:
        report = one(grype.load(document("grype-image.json")))
        assert (report.tool, report.version) == ("grype", "0.74.7")
        refs = report.findings[0].image_refs
        assert refs == (
            "registry.example.com/shop/worker@sha256:"
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        assert {f.scope for f in report.findings} == {"image"}

    def test_match_fields_are_normalized(self) -> None:
        finding = find(one(grype.load(document("grype-image.json"))), "CVE-2023-4911")
        assert finding.severity == "high"
        assert finding.package is not None
        assert (finding.package.name, finding.package.version, finding.package.ecosystem) == (
            "libc6",
            "2.36-9+deb12u3",
            "deb",
        )
        assert finding.fixed_version == "2.36-9+deb12u4"
        assert finding.status == "fixed"
        assert finding.cvss_score == 7.8
        assert finding.description.startswith("A buffer overflow")

    def test_related_vulnerabilities_become_aliases_and_supply_cvss(self) -> None:
        finding = find(one(grype.load(document("grype-image.json"))), "GHSA-35jh-r3h4-6jhm")
        assert finding.aliases == ["CVE-2021-23337"]
        assert finding.cvss_score == 7.2
        assert finding.description.startswith("Lodash versions")

    def test_negligible_and_unknown_are_info(self) -> None:
        report = one(grype.load(document("grype-image.json")))
        assert find(report, "CVE-2005-2541").severity == "info"
        assert find(report, "CVE-2024-0002").severity == "info"
        assert find(report, "CVE-2005-2541").fixed_version == ""

    def test_ignored_matches_are_counted_not_reported(self) -> None:
        report = one(grype.load(document("grype-image.json")))
        assert "CVE-2022-0000" not in {f.id for f in report.findings}
        assert report.skipped == {"ignored_matches": 1}

    def test_a_directory_source_is_of_path_scope_with_a_scan_relative_file(self) -> None:
        (finding,) = one(grype.load(document("grype-dir.json"))).findings
        assert finding.scope == "path"
        assert finding.file == "services/api/package-lock.json"

    def test_a_location_below_the_scanned_directory_is_made_relative_to_it(self) -> None:
        data = document("grype-dir.json")
        data["matches"][0]["artifact"]["locations"][0]["path"] = (
            "/work/repo/services/api/package-lock.json"
        )
        (finding,) = one(grype.load(data)).findings
        assert finding.file == "services/api/package-lock.json"

    def test_an_empty_report_has_no_findings(self) -> None:
        assert one(grype.load(document("grype-clean.json"))).findings == []


class TestOsv:
    def test_a_group_is_one_finding_with_its_ids_as_aliases(self) -> None:
        report = one(osv.load(document("osv-lockfile.json")))
        finding = find(report, "GHSA-35jh-r3h4-6jhm")
        assert finding.aliases == ["CVE-2021-23337"]
        assert finding.title == "Command Injection in lodash"
        assert finding.fixed_version == "4.17.21"
        assert finding.package is not None
        assert (finding.package.name, finding.package.version, finding.package.ecosystem) == (
            "lodash",
            "4.17.15",
            "npm",
        )
        assert [f.id for f in report.findings if f.package and f.package.name == "lodash"] == [
            "GHSA-35jh-r3h4-6jhm",
            "GHSA-p6mc-m468-83gw",
        ]

    def test_the_group_max_severity_score_is_banded(self) -> None:
        report = one(osv.load(document("osv-lockfile.json")))
        assert find(report, "GHSA-35jh-r3h4-6jhm").severity == "high"
        assert find(report, "GHSA-35jh-r3h4-6jhm").cvss_score == 7.2

    def test_without_groups_the_record_label_is_used(self) -> None:
        finding = find(one(osv.load(document("osv-lockfile.json"))), "GHSA-xvch-5gv4-984h")
        assert finding.severity == "critical"
        assert finding.aliases == ["CVE-2021-44906"]

    def test_a_record_with_only_a_vector_is_scored_here(self) -> None:
        data = document("osv-lockfile.json")
        group = data["results"][0]["packages"][0]
        group["groups"] = []
        finding = find(one(osv.load(data)), "GHSA-p6mc-m468-83gw")
        assert finding.cvss_score == 8.1
        assert finding.severity == "high"
        assert finding.cvss_vector.startswith("CVSS:3.1/")

    def test_an_advisory_with_no_rating_is_info_not_a_guess(self) -> None:
        finding = find(one(osv.load(document("osv-lockfile.json"))), "GO-2024-0001")
        assert finding.severity == "info"
        assert finding.cvss_score is None

    def test_a_lockfile_source_is_of_path_scope_at_its_path(self) -> None:
        finding = find(one(osv.load(document("osv-lockfile.json"))), "GHSA-35jh-r3h4-6jhm")
        assert finding.scope == "path"
        assert finding.file == "/home/runner/work/repo/repo/services/api/package-lock.json"

    def test_an_image_source_is_of_image_scope_and_the_path_is_the_reference(self) -> None:
        data = document("osv-lockfile.json")
        data["results"][0]["source"] = {"path": "ghcr.io/acme/api:1.4.2", "type": "docker"}
        finding = find(one(osv.load(data)), "GHSA-35jh-r3h4-6jhm")
        assert finding.scope == "image"
        assert finding.image_refs == ("ghcr.io/acme/api:1.4.2",)
        assert finding.file == ""

    def test_several_fixed_versions_are_listed_once_each(self) -> None:
        data = document("osv-lockfile.json")
        events = data["results"][0]["packages"][0]["vulnerabilities"][0]["affected"][0]["ranges"]
        events.append({"type": "SEMVER", "events": [{"introduced": "5.0.0"}, {"fixed": "5.1.0"}]})
        events.append({"type": "SEMVER", "events": [{"fixed": "4.17.21"}]})
        finding = find(one(osv.load(data)), "GHSA-35jh-r3h4-6jhm")
        assert finding.fixed_version == "4.17.21, 5.1.0"

    def test_an_empty_report_has_no_findings(self) -> None:
        assert one(osv.load(document("osv-clean.json"))).findings == []


class TestSarif:
    def test_the_run_names_the_tool_and_version(self) -> None:
        checkov = one(sarif.load(document("sarif-checkov.json")))
        assert (checkov.tool, checkov.version) == ("checkov", "3.2.2")
        gitleaks = one(sarif.load(document("sarif-gitleaks.json")))
        assert (gitleaks.tool, gitleaks.version) == ("gitleaks", "v8.18.4")

    def test_tool_names_become_slugs(self) -> None:
        assert sarif.tool_slug("Semgrep OSS") == "semgrep-oss"
        assert sarif.tool_slug("CodeQL") == "codeql"
        assert sarif.tool_slug("!!!") == "sarif"

    def test_each_run_is_its_own_report(self) -> None:
        data = document("sarif-checkov.json")
        data["runs"].append(document("sarif-gitleaks.json")["runs"][0])
        assert [r.tool for r in sarif.load(data)] == ["checkov", "gitleaks"]

    def test_the_level_of_the_result_or_the_rule_default_gives_the_severity(self) -> None:
        report = one(sarif.load(document("sarif-checkov.json")))
        assert find(report, "CKV_AWS_18").severity == "high"
        # No level on the result: the rule's defaultConfiguration says note.
        assert find(report, "CKV_AWS_135").severity == "low"

    def test_a_missing_level_everywhere_is_a_warning(self) -> None:
        data = document("sarif-checkov.json")
        run = data["runs"][0]
        del run["tool"]["driver"]["rules"][1]["defaultConfiguration"]
        assert find(one(sarif.load(data)), "CKV_AWS_135").severity == "medium"

    def test_security_severity_on_the_rule_beats_the_level(self) -> None:
        report = one(sarif.load(document("sarif-trivy.json")))
        assert find(report, "CVE-2021-23337").severity == "high"
        assert find(report, "AVD-AWS-0086").severity == "high"
        assert find(report, "CVE-2021-23337").cvss_score == 7.2

    def test_security_severity_on_the_result_beats_the_rule(self) -> None:
        data = document("sarif-trivy.json")
        data["runs"][0]["results"][0]["properties"] = {"security-severity": "9.1"}
        finding = find(one(sarif.load(data)), "CVE-2021-23337")
        assert (finding.severity, finding.cvss_score) == ("critical", 9.1)

    def test_a_non_numeric_security_severity_falls_back_to_the_level(self) -> None:
        data = document("sarif-trivy.json")
        data["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"] = "n/a"
        assert find(one(sarif.load(data)), "CVE-2021-23337").severity == "high"

    @pytest.mark.parametrize(
        ("tool", "rule", "tags", "kind"),
        [
            ("any", "CVE-2024-12345", [], "vulnerability"),
            ("any", "GHSA-35jh-r3h4-6jhm", [], "vulnerability"),
            ("gitleaks", "aws-access-token", [], "secret"),
            ("trufflehog", "anything", [], "secret"),
            ("any", "rule1", ["secret"], "secret"),
            ("checkov", "CKV_AWS_18", [], "misconfiguration"),
            ("trivy", "AVD-AWS-0086", [], "misconfiguration"),
            ("trivy", "KSV001", [], "misconfiguration"),
            ("any", "rule2", ["misconfiguration"], "misconfiguration"),
            ("any", "rule3", ["vulnerability"], "vulnerability"),
            ("codeql", "py/sql-injection", ["security"], "other"),
        ],
    )
    def test_the_kind_comes_from_the_rule_id_the_tool_and_the_tags(
        self, tool: str, rule: str, tags: list[str], kind: str
    ) -> None:
        data = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": tool,
                            "rules": [{"id": rule, "properties": {"tags": tags}}],
                        }
                    },
                    "results": [{"ruleId": rule, "ruleIndex": 0, "message": {"text": "m"}}],
                }
            ],
        }
        assert one(sarif.load(data)).findings[0].kind == kind

    def test_a_location_gives_file_and_lines(self) -> None:
        finding = find(one(sarif.load(document("sarif-gitleaks.json"))), "aws-access-token")
        assert (finding.file, finding.line, finding.end_line) == ("infra/main.tf", 20, 20)

    @pytest.mark.parametrize(
        ("uri", "path"),
        [
            ("file:///github/workspace/infra/main.tf", "/github/workspace/infra/main.tf"),
            ("file:///C:/repo/infra/main.tf", "C:/repo/infra/main.tf"),
            ("infra%20dir/main.tf", "infra dir/main.tf"),
            ("infra\\main.tf", "infra/main.tf"),
        ],
    )
    def test_uris_are_decoded_to_paths(self, uri: str, path: str) -> None:
        assert sarif._uri_to_path(uri) == path

    def test_trivy_vulnerability_messages_give_the_package_and_fix(self) -> None:
        finding = find(one(sarif.load(document("sarif-trivy.json"))), "CVE-2021-23337")
        assert finding.package is not None
        assert (finding.package.name, finding.package.version) == ("lodash", "4.17.15")
        assert finding.fixed_version == "4.17.21"
        assert "https://avd.aquasec.com/nvd/cve-2021-23337" in finding.references

    def test_passed_and_suppressed_results_are_counted_not_reported(self) -> None:
        data = document("sarif-checkov.json")
        results = data["runs"][0]["results"]
        results[0]["kind"] = "pass"
        results[1]["suppressions"] = [{"kind": "inSource", "status": "accepted"}]
        report = one(sarif.load(data))
        assert report.findings == []
        assert report.skipped == {"passed_checks": 1, "suppressed": 1}

    def test_a_rejected_suppression_does_not_hide_the_result(self) -> None:
        data = document("sarif-checkov.json")
        data["runs"][0]["results"][0]["suppressions"] = [{"kind": "external", "status": "rejected"}]
        assert len(one(sarif.load(data)).findings) == 2

    def test_the_rule_is_found_by_id_when_there_is_no_index(self) -> None:
        data = document("sarif-checkov.json")
        for result in data["runs"][0]["results"]:
            del result["ruleIndex"]
        assert find(one(sarif.load(data)), "CKV_AWS_135").severity == "low"

    def test_a_result_with_no_location_has_no_file(self) -> None:
        data = document("sarif-gitleaks.json")
        data["runs"][0]["results"][0]["locations"] = []
        finding = one(sarif.load(data)).findings[0]
        assert (finding.file, finding.line) == ("", None)

    def test_the_title_comes_from_the_rule_then_the_message(self) -> None:
        finding = find(one(sarif.load(document("sarif-checkov.json"))), "CKV_AWS_18")
        assert finding.title == "Ensure the S3 bucket has access logging enabled"
        data = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "x"}},
                    "results": [{"ruleId": "r", "message": {"text": "first line\nsecond"}}],
                }
            ],
        }
        assert one(sarif.load(data)).findings[0].title == "first line"
