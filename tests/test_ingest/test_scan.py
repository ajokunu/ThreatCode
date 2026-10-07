"""Ingestion through the scan pipeline and the command line: gating, suppression and errors."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from tests.helpers.cli import run_cli
from tests.helpers.examples import EXAMPLES_DIR
from tests.test_ingest.conftest import INGEST_FIXTURES, REPO
from threatcode.pipeline import ScanResult, prepare_request, run_scan

WEBAPP = EXAMPLES_DIR / "aws-webapp"
TRIVY = WEBAPP / "scanner" / "trivy-app-image.json"


def scan(*paths: Path, ingest: list[Path] | None = None, **options: Any) -> ScanResult:
    prepared = prepare_request([str(p) for p in paths], ingest=ingest or [], **options)
    return run_scan(prepared.request)


def scanner_threats(result: ScanResult) -> list[Any]:
    return [t for t in result.report.threats if t.source.value == "scanner"]


@pytest.fixture
def webapp(tmp_path: Path) -> Path:
    """A copy of the example, so a test may add an ignore file beside the plan."""
    target = tmp_path / "webapp"
    target.mkdir()
    shutil.copy(WEBAPP / "tfplan.json", target / "tfplan.json")
    return target


class TestPipeline:
    def test_the_critical_cve_is_a_finding_on_each_instance_that_runs_the_image(self) -> None:
        result = scan(WEBAPP, ingest=[TRIVY], fail_on="none")
        hits = [t for t in scanner_threats(result) if t.rule_id == "trivy:CVE-2022-37434"]
        assert sorted(t.resource_address for t in hits) == [
            "aws_instance.app[0]",
            "aws_instance.app[1]",
        ]
        assert {t.severity.value for t in hits} == {"critical"}
        assert {t.location_file for t in hits} == {"tfplan.json"}
        assert all(t.fingerprint for t in hits)
        assert len({t.fingerprint for t in hits}) == 2

    def test_the_sources_list_each_file_with_its_counts(self) -> None:
        result = scan(WEBAPP, ingest=[TRIVY], fail_on="none")
        (source,) = result.ingest_sources
        assert source["tool"] == "trivy"
        assert source["format"] == "trivy"
        assert source["file"].endswith("trivy-app-image.json")
        assert (source["findings"], source["attached"], source["unattached"]) == (1, 1, 0)
        assert source["duplicates"] == 0

    def test_a_scanner_finding_gates_the_exit_code_like_any_other(self) -> None:
        without = scan(WEBAPP, fail_on="critical")
        with_report = scan(WEBAPP, ingest=[TRIVY], fail_on="critical")
        assert without.exit_code == 0
        assert with_report.exit_code == 1

    def test_a_cve_id_in_the_ignore_file_suppresses_it_and_the_gate_follows(
        self, webapp: Path
    ) -> None:
        (webapp / ".threatcodeignore").write_text("CVE-2022-37434\n", encoding="utf-8")
        result = scan(webapp, ingest=[TRIVY], fail_on="critical")
        assert scanner_threats(result) == []
        assert result.coverage.suppressed == 2
        assert result.exit_code == 0

    def test_a_ghsa_alias_suppresses_a_finding_whichever_tool_reported_it(
        self, tmp_path: Path
    ) -> None:
        shutil.copytree(REPO, tmp_path / "repo")
        root = tmp_path / "repo"
        ingest = [INGEST_FIXTURES / "osv-lockfile.json"]
        before = {t.rule_id for t in scanner_threats(scan(root, ingest=ingest, fail_on="none"))}
        assert "osv-scanner:GHSA-35jh-r3h4-6jhm" in before
        (root / ".threatcodeignore").write_text("CVE-2021-23337\n", encoding="utf-8")
        after = {t.rule_id for t in scanner_threats(scan(root, ingest=ingest, fail_on="none"))}
        assert after == before - {"osv-scanner:GHSA-35jh-r3h4-6jhm"}

    def test_the_rule_id_of_a_scanner_finding_suppresses_it_too(self, webapp: Path) -> None:
        (webapp / ".threatcodeignore").write_text("trivy:CVE-2022-37434\n", encoding="utf-8")
        result = scan(webapp, ingest=[TRIVY], fail_on="critical")
        assert scanner_threats(result) == []

    def test_an_unattached_report_is_a_coverage_gap_that_strict_turns_into_exit_2(
        self, tmp_path: Path
    ) -> None:
        report = json.loads(TRIVY.read_text(encoding="utf-8"))
        report["ArtifactName"] = "registry.example.com/other/service:1.0.0"
        report["Metadata"]["RepoTags"] = [report["ArtifactName"]]
        other = tmp_path / "other.json"
        other.write_text(json.dumps(report), encoding="utf-8")
        loose = scan(WEBAPP, ingest=[other], fail_on="none")
        assert loose.exit_code == 0
        (finding,) = scanner_threats(loose)
        assert finding.resource_address == ""
        assert [g["code"] for g in loose.coverage.gaps] == ["ingest.unattached"]
        strict = scan(WEBAPP, ingest=[other], fail_on="none", strict=True)
        assert strict.exit_code == 2

    def test_a_partly_unattached_report_is_not_a_gap(self) -> None:
        result = scan(REPO, ingest=[INGEST_FIXTURES / "trivy-fs.json"], fail_on="none", strict=True)
        assert result.coverage.gaps == []
        assert result.exit_code == 0
        assert any(d.code == "ingest.unattached" for d in result.graph.diagnostics)

    def test_a_scan_without_ingest_files_has_no_scanner_findings(self) -> None:
        result = scan(WEBAPP, fail_on="none")
        assert scanner_threats(result) == []
        assert result.ingest_sources == []

    def test_several_reports_ingest_together(self) -> None:
        names = ["trivy-image.json", "grype-image.json", "osv-lockfile.json", "sarif-gitleaks.json"]
        result = scan(REPO, ingest=[INGEST_FIXTURES / n for n in names], fail_on="none")
        assert {s["tool"] for s in result.ingest_sources} == {
            "trivy",
            "grype",
            "osv-scanner",
            "gitleaks",
        }
        tools = {t.tool for t in scanner_threats(result)}
        assert tools == {"trivy", "grype", "osv-scanner", "gitleaks"}


class TestCommandLine:
    def test_the_json_report_holds_the_scanner_finding(self, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        run = run_cli(
            [
                "scan",
                str(WEBAPP),
                "--ingest",
                str(TRIVY),
                "-f",
                "json",
                "--fail-on",
                "none",
                "-o",
                str(out),
            ]
        )
        assert run.exit_code == 0, run.stderr[-300:]
        report = json.loads(out.read_text(encoding="utf-8"))
        hits = [t for t in report["threats"] if t.get("rule_id") == "trivy:CVE-2022-37434"]
        assert len(hits) == 2
        assert {t["tool"] for t in hits} == {"trivy"}
        assert {t["evidence"] for t in hits} == {"scanner"}
        assert {t["source"] for t in hits} == {"scanner"}

    def test_a_file_that_is_not_a_scanner_report_exits_2_and_names_the_file(self) -> None:
        run = run_cli(["scan", str(WEBAPP), "--ingest", "pyproject.toml"])
        assert run.exit_code == 2
        assert "pyproject.toml" in run.stderr
        assert "Trivy" in run.stderr
        assert "Traceback" not in run.stderr

    def test_a_missing_ingest_file_exits_2(self) -> None:
        run = run_cli(["scan", str(WEBAPP), "--ingest", "does-not-exist.json"])
        assert run.exit_code == 2
        assert "does-not-exist.json" in run.stderr

    def test_the_gate_uses_the_ingested_severity(self) -> None:
        run = run_cli(
            ["scan", str(WEBAPP), "--ingest", str(TRIVY), "--fail-on", "critical", "-f", "json"]
        )
        assert run.exit_code == 1
        run = run_cli(["scan", str(WEBAPP), "--fail-on", "critical", "-f", "json"])
        assert run.exit_code == 0
