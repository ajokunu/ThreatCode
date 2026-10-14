"""Duplicates between ingested tools and against ThreatCode's own findings."""

from __future__ import annotations

from tests.test_ingest.conftest import Ingest, by_rule
from threatcode.ingest import reconcile_native
from threatcode.ingest.reconcile import merge_across_tools
from threatcode.models.threat import Severity, Threat, ThreatSource


def native(source: ThreatSource, file: str, line: int, rule_id: str = "NATIVE") -> Threat:
    return Threat(
        id=f"native-{rule_id}-{line}",
        title="native",
        description="",
        stride_category="information_disclosure",
        severity=Severity.HIGH,
        source=source,
        resource_type="aws_instance",
        resource_address="aws_instance.web",
        rule_id=rule_id,
        location_file=file,
        location_start_line=line,
    )


class TestAcrossTools:
    def test_the_same_advisory_on_the_same_package_and_node_is_kept_once(
        self, ingest: Ingest
    ) -> None:
        # Trivy, Grype and OSV-Scanner all report lodash CVE-2021-23337 for the same service.
        result = ingest("trivy-fs.json", "grype-dir.json", "osv-lockfile.json")
        lodash = [
            t
            for t in result.threats
            if t.metadata.get("package", {}).get("name") == "lodash"
            and "CVE-2021-23337" in t.aliases
        ]
        assert len(lodash) == 1
        kept = lodash[0]
        assert kept.tool == "trivy"
        assert kept.metadata["corroborated_by"] == ["grype", "osv-scanner"]
        assert {"GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"} <= set(kept.aliases)

    def test_duplicates_are_counted_per_file_and_reported_as_info(self, ingest: Ingest) -> None:
        result = ingest("trivy-fs.json", "grype-dir.json", "osv-lockfile.json")
        counts = {s["tool"]: s["duplicates"] for s in result.sources}
        assert counts == {"trivy": 0, "grype": 1, "osv-scanner": 2}
        duplicates = [d for d in result.diagnostics if d.code == "ingest.duplicate"]
        assert len(duplicates) == 3
        assert {d.level for d in duplicates} == {"info"}

    def test_a_source_still_counts_a_folded_finding_as_attached(self, ingest: Ingest) -> None:
        result = ingest("trivy-fs.json", "grype-dir.json")
        grype = next(s for s in result.sources if s["tool"] == "grype")
        assert (grype["findings"], grype["attached"], grype["duplicates"]) == (1, 1, 1)

    def test_findings_that_only_one_tool_reports_are_kept(self, ingest: Ingest) -> None:
        result = ingest("trivy-fs.json", "osv-lockfile.json")
        rules = by_rule(result)
        assert "trivy:CVE-2020-8203" in rules  # reported by both, kept from the first file
        assert "osv-scanner:GHSA-xvch-5gv4-984h" in rules  # only OSV-Scanner reports minimist
        assert "osv-scanner:GHSA-p6mc-m468-83gw" not in rules

    def test_the_same_tool_reporting_the_same_advisory_twice_is_not_folded(self) -> None:
        a = _vuln("trivy", "aws_instance.web")
        b = _vuln("trivy", "aws_instance.web")
        kept, folded = merge_across_tools([a, b])
        assert (kept, folded) == ([a, b], [])

    def test_another_package_or_node_is_not_a_duplicate(self) -> None:
        a = _vuln("trivy", "aws_instance.web")
        other_package = _vuln("grype", "aws_instance.web")
        other_package.metadata["package"] = {"name": "openssl"}
        other_node = _vuln("grype", "aws_instance.api")
        kept, folded = merge_across_tools([a, other_package, other_node])
        assert (len(kept), folded) == (3, [])

    def test_unattached_findings_are_never_folded(self) -> None:
        a = _vuln("trivy", "")
        b = _vuln("grype", "")
        kept, folded = merge_across_tools([a, b])
        assert (kept, folded) == ([a, b], [])


def _vuln(tool: str, address: str) -> Threat:
    threat = native(ThreatSource.SCANNER, "", 1)
    threat.tool = tool
    threat.resource_address = address
    threat.aliases = ["CVE-1"]
    threat.metadata = {"kind": "vulnerability", "package": {"name": "zlib"}}
    return threat


class TestAgainstNativeFindings:
    def external(self, ingest: Ingest, name: str, rule: str) -> list[Threat]:
        return by_rule(ingest(name))[rule]

    def test_a_scanner_secret_at_the_line_of_a_native_secret_is_dropped(
        self, ingest: Ingest
    ) -> None:
        external = ingest("sarif-gitleaks.json").threats
        secret = native(ThreatSource.SECRET, "infra/main.tf", 20, "SECRET_AWS_ACCESS_KEY")
        remaining, diagnostics = reconcile_native(external, [secret])
        assert remaining == []
        assert secret.metadata["corroborated_by"] == ["gitleaks"]
        (diagnostic,) = diagnostics
        assert (diagnostic.level, diagnostic.code) == ("info", "ingest.duplicate")
        assert diagnostic.file == "infra/main.tf"
        assert diagnostic.line == 20

    def test_a_scanner_misconfiguration_at_the_line_of_a_rule_finding_is_dropped(
        self, ingest: Ingest
    ) -> None:
        external = self.external(ingest, "sarif-checkov.json", "checkov:CKV_AWS_18")
        rule = native(ThreatSource.RULE, "infra/main.tf", 1, "S3_NO_LOGGING")
        remaining, diagnostics = reconcile_native(external, [rule])
        assert (remaining, len(diagnostics)) == ([], 1)
        assert rule.metadata["corroborated_by"] == ["checkov"]

    def test_the_families_do_not_cross(self, ingest: Ingest) -> None:
        external = ingest("sarif-gitleaks.json").threats
        rule = native(ThreatSource.RULE, "infra/main.tf", 20)
        remaining, diagnostics = reconcile_native(external, [rule])
        assert (len(remaining), diagnostics) == (1, [])
        assert "corroborated_by" not in rule.metadata

    def test_another_line_or_file_is_not_a_duplicate(self, ingest: Ingest) -> None:
        external = ingest("sarif-gitleaks.json").threats
        for file, line in (("infra/main.tf", 21), ("infra/other.tf", 20)):
            secret = native(ThreatSource.SECRET, file, line)
            remaining, _ = reconcile_native(external, [secret])
            assert len(remaining) == 1
            assert "corroborated_by" not in secret.metadata

    def test_vulnerabilities_have_no_native_family(self, ingest: Ingest) -> None:
        external = ingest("trivy-fs.json").threats
        everything = [native(ThreatSource.SECRET, "services/api/package-lock.json", 1)]
        remaining, diagnostics = reconcile_native(external, everything)
        assert len(remaining) == len(external)
        assert diagnostics == []

    def test_a_native_finding_without_a_location_never_matches(self, ingest: Ingest) -> None:
        external = ingest("sarif-gitleaks.json").threats
        bare = native(ThreatSource.SECRET, "", 20)
        bare.location_start_line = None
        remaining, _ = reconcile_native(external, [bare])
        assert len(remaining) == 1

    def test_the_tool_is_listed_once(self, ingest: Ingest) -> None:
        external = ingest("sarif-gitleaks.json").threats * 2
        secret = native(ThreatSource.SECRET, "infra/main.tf", 20)
        reconcile_native(external, [secret])
        assert secret.metadata["corroborated_by"] == ["gitleaks"]
