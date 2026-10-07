"""Tests for threatcode.formatters.bitbucket."""

from __future__ import annotations

import json
from typing import Any

from threatcode.formatters.bitbucket import (
    BATCH_SIZE,
    DETAILS_LIMIT,
    MAX_ANNOTATIONS,
    SUMMARY_LIMIT,
    format_bitbucket,
)
from threatcode.ir.graph import InfraGraph
from threatcode.models.attack_path import AttackHop, AttackPath
from threatcode.models.report import ThreatReport
from threatcode.models.threat import Severity, Threat, ThreatSource
from threatcode.parsers.base import ParsedOutput, ParsedResource


def make_threat(index: int = 1, severity: Severity = Severity.HIGH, **fields: Any) -> Threat:
    return Threat(
        id=fields.pop("threat_id", f"t{index}"),
        title=fields.pop("title", "Test Threat"),
        description=fields.pop("description", "Description"),
        stride_category="tampering",
        severity=severity,
        source=ThreatSource.RULE,
        resource_type="aws_s3_bucket",
        resource_address=fields.pop("address", f"aws_s3_bucket.test{index}"),
        location_file=fields.pop("file", "infra/main.tf"),
        location_start_line=fields.pop("line", 10 + index),
        **fields,
    )


def _make_report(severity: Severity) -> ThreatReport:
    report = ThreatReport(scanned_resources=3, input_file="infra/main.tf")
    report.add(make_threat(1, severity))
    return report


def parse(report: ThreatReport, graph: InfraGraph | None = None, **kwargs: Any) -> dict[str, Any]:
    return json.loads(format_bitbucket(report, graph, **kwargs))  # type: ignore[no-any-return]


class TestFormatBitbucket:
    def test_output_is_valid_json(self) -> None:
        data = parse(_make_report(Severity.HIGH))
        assert {"report", "annotations", "annotation_batches"} <= set(data)

    def test_report_fields(self) -> None:
        report = parse(_make_report(Severity.MEDIUM))["report"]
        assert report["title"] == "ThreatCode STRIDE Threat Model"
        assert report["report_type"] == "SECURITY"
        assert report["reporter"] == "ThreatCode"

    def test_failed_on_critical_or_high_after_context(self) -> None:
        assert parse(_make_report(Severity.CRITICAL))["report"]["result"] == "FAILED"
        assert parse(_make_report(Severity.HIGH))["report"]["result"] == "FAILED"
        raised = _make_report(Severity.LOW)
        raised.threats[0].effective_severity = Severity.HIGH
        assert parse(raised)["report"]["result"] == "FAILED"

    def test_passed_on_medium_or_lower(self) -> None:
        for severity in (Severity.MEDIUM, Severity.LOW, Severity.INFO):
            assert parse(_make_report(severity))["report"]["result"] == "PASSED"

    def test_a_downgrade_by_context_passes(self) -> None:
        report = _make_report(Severity.HIGH)
        report.threats[0].effective_severity = Severity.LOW
        assert parse(report)["report"]["result"] == "PASSED"

    def test_a_high_attack_path_fails_the_report(self) -> None:
        report = ThreatReport()
        report.attack_paths.append(path("p1", Severity.HIGH))
        assert parse(report)["report"]["result"] == "FAILED"

    def test_the_data_counts_every_severity_including_low_and_info(self) -> None:
        report = ThreatReport(scanned_resources=9)
        for i, sev in enumerate(
            [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        ):
            report.add(make_threat(i, sev))
        data = {d["title"]: d["value"] for d in parse(report)["report"]["data"]}
        assert data == {
            "Total Threats": 5,
            "Critical": 1,
            "High": 1,
            "Medium": 1,
            "Low": 1,
            "Info": 1,
            "Attack Paths": 0,
            "Resources Scanned": 9,
        }

    def test_the_report_data_fits_bitbucket_limits(self) -> None:
        report = parse(_make_report(Severity.HIGH))["report"]
        assert len(report["data"]) <= 10
        assert all(d["type"] == "NUMBER" for d in report["data"])
        assert len(report["details"]) <= 2000

    def test_annotations_match_threats(self) -> None:
        data = parse(_make_report(Severity.HIGH))
        assert len(data["annotations"]) == 1
        assert data["annotations"][0]["external_id"] == "t1"


class TestAnnotationLocations:
    def test_path_and_line_come_from_the_threat_location(self) -> None:
        annotation = parse(_make_report(Severity.HIGH))["annotations"][0]
        assert annotation["path"] == "infra/main.tf"
        assert annotation["line"] == 11

    def test_no_annotation_path_is_a_resource_address(self) -> None:
        report = ThreatReport(input_file="main.tf")
        report.add(make_threat(1, file="", line=None, address="aws_s3_bucket.logs"))
        report.add(make_threat(2, address="module.x.aws_instance.web[0]"))
        for annotation in parse(report)["annotations"]:
            assert annotation["path"] in ("main.tf", "infra/main.tf")
            assert annotation["line"] >= 1

    def test_the_input_file_and_line_one_stand_in_when_nothing_is_known(self) -> None:
        report = ThreatReport(input_file="a.tf, b.tf")
        report.add(make_threat(1, file="", line=None))
        annotation = parse(report)["annotations"][0]
        assert (annotation["path"], annotation["line"]) == ("a.tf", 1)

    def test_the_graph_supplies_a_missing_location(self) -> None:
        graph = InfraGraph.from_parsed(
            ParsedOutput(
                source_path="net/main.tf",
                format_type="terraform_hcl",
                resources=[
                    ParsedResource(
                        resource_type="aws_s3_bucket",
                        name="x",
                        provider="aws",
                        address="aws_s3_bucket.x",
                        source_location="net/main.tf",
                        start_line=33,
                    )
                ],
            )
        )
        report = ThreatReport(input_file="elsewhere.tf")
        report.add(make_threat(1, file="", line=None, address="aws_s3_bucket.x"))
        annotation = parse(report, graph)["annotations"][0]
        assert (annotation["path"], annotation["line"]) == ("net/main.tf", 33)

    def test_paths_are_repository_relative_and_cannot_escape(self) -> None:
        report = ThreatReport()
        report.add(make_threat(1, file="../../etc/passwd"))
        report.add(make_threat(2, file="a\\b\\c.tf"))
        paths = {a["path"] for a in parse(report)["annotations"]}
        assert paths == {"etc/passwd", "a/b/c.tf"}

    def test_the_scan_root_prefix_is_applied(self, monkeypatch: Any, tmp_path: Any) -> None:
        monkeypatch.chdir(tmp_path)
        report = ThreatReport()
        report.add(make_threat(1, file="main.tf"))
        annotation = parse(report, source_root=tmp_path / "infra")["annotations"][0]
        assert annotation["path"] == "infra/main.tf"


def path(path_id: str, severity: Severity = Severity.CRITICAL, target: str = "db") -> AttackPath:
    return AttackPath(
        id=path_id,
        entry="internet",
        target=target,
        hops=[
            AttackHop(node_id="internet"),
            AttackHop(node_id="lb"),
            AttackHop(node_id=target),
        ],
        severity=severity,
        score=50.0,
        rationale="Reachable.",
    )


class TestCapAndBatches:
    def big_report(self, count: int = 1500) -> ThreatReport:
        report = ThreatReport(scanned_resources=count)
        severities = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        for i in range(count):
            report.add(make_threat(i, severities[i % 4]))
        return report

    def test_annotations_are_capped_at_1000(self) -> None:
        data = parse(self.big_report())
        assert len(data["annotations"]) == MAX_ANNOTATIONS == 1000

    def test_the_most_severe_annotations_are_kept(self) -> None:
        severities = [a["severity"] for a in parse(self.big_report())["annotations"]]
        assert severities.count("CRITICAL") == 375
        assert "LOW" not in severities[:750]
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        assert [order[s] for s in severities] == sorted(order[s] for s in severities)

    def test_the_omitted_count_is_in_the_report_details(self) -> None:
        details = parse(self.big_report())["report"]["details"]
        assert "1000 annotations are shown" in details and "500 more were left out" in details

    def test_batches_are_lists_of_at_most_100_covering_every_annotation_once(self) -> None:
        data = parse(self.big_report())
        batches = data["annotation_batches"]
        assert len(batches) == 10 and BATCH_SIZE == 100
        assert all(isinstance(b, list) and 0 < len(b) <= 100 for b in batches)
        flat = [a for batch in batches for a in batch]
        assert flat == data["annotations"]

    def test_a_small_report_has_one_short_batch_and_no_omission_note(self) -> None:
        data = parse(self.big_report(30))
        assert [len(b) for b in data["annotation_batches"]] == [30]
        assert "left out" not in data["report"]["details"]

    def test_an_empty_report_has_no_batches(self) -> None:
        assert parse(ThreatReport())["annotation_batches"] == []

    def test_external_ids_are_unique_even_when_threat_ids_repeat(self) -> None:
        report = ThreatReport()
        for _ in range(3):
            report.add(make_threat(1, threat_id="same"))
        ids = [a["external_id"] for a in parse(report)["annotations"]]
        assert len(set(ids)) == 3 and ids[0] == "same"

    def test_summary_and_details_obey_the_limits(self) -> None:
        report = ThreatReport()
        report.add(make_threat(1, title="T" * 900, description="D" * 5000, mitigation="M" * 5000))
        annotation = parse(report)["annotations"][0]
        assert len(annotation["summary"]) <= SUMMARY_LIMIT == 450
        assert len(annotation["details"]) <= DETAILS_LIMIT == 2000
        assert len(annotation["external_id"]) <= 64

    def test_details_include_the_mitigation_and_are_one_line(self) -> None:
        report = ThreatReport()
        report.add(make_threat(1, description="Bad.\n\nReally.", mitigation="Fix\nit."))
        assert parse(report)["annotations"][0]["details"] == "Bad. Really. Mitigation: Fix it."

    def test_severities_map_to_bitbucket_values(self) -> None:
        report = ThreatReport()
        for i, sev in enumerate(Severity):
            report.add(make_threat(i, sev))
        seen = {a["severity"] for a in parse(report)["annotations"]}
        assert seen == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


class TestAttackPathAnnotations:
    def graph(self) -> InfraGraph:
        return InfraGraph.from_parsed(
            ParsedOutput(
                source_path="infra/main.tf",
                format_type="terraform_hcl",
                resources=[
                    ParsedResource(
                        resource_type="aws_lb",
                        name="web",
                        provider="aws",
                        address="lb",
                        source_location="infra/main.tf",
                        start_line=7,
                    )
                ],
            )
        )

    def test_a_path_is_an_annotation_on_the_first_resource_with_a_file(self) -> None:
        report = ThreatReport(input_file="infra")
        report.attack_paths.append(path("abc123"))
        annotation = parse(report, self.graph())["annotations"][0]
        assert annotation["external_id"] == "path-abc123"
        assert annotation["summary"] == "Attack path from internet to db"
        assert annotation["path"] == "infra/main.tf" and annotation["line"] == 7
        assert "internet -> lb -> db" in annotation["details"]
        assert annotation["severity"] == "CRITICAL"

    def test_without_a_graph_the_input_file_stands_in(self) -> None:
        report = ThreatReport(input_file="infra/main.tf")
        report.attack_paths.append(path("abc123"))
        annotation = parse(report)["annotations"][0]
        assert (annotation["path"], annotation["line"]) == ("infra/main.tf", 1)

    def test_paths_sort_before_findings_of_the_same_severity(self) -> None:
        report = ThreatReport(input_file="x")
        report.add(make_threat(1, Severity.CRITICAL))
        report.attack_paths.append(path("abc123", Severity.CRITICAL))
        ids = [a["external_id"] for a in parse(report)["annotations"]]
        assert ids == ["path-abc123", "t1"]
