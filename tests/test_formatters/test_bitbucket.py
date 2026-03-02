"""Tests for threatcode.formatters.bitbucket."""

from __future__ import annotations

import json

from threatcode.formatters.bitbucket import format_bitbucket
from threatcode.models.report import ThreatReport
from threatcode.models.threat import Severity, Threat, ThreatSource


def _make_report(severity: Severity) -> ThreatReport:
    report = ThreatReport(scanned_resources=3)
    report.add(
        Threat(
            id="t1",
            title="Test Threat",
            description="Description",
            stride_category="tampering",
            severity=severity,
            source=ThreatSource.RULE,
            resource_type="aws_s3_bucket",
            resource_address="aws_s3_bucket.test",
        )
    )
    return report


class TestFormatBitbucket:
    def test_output_is_valid_json(self) -> None:
        output = format_bitbucket(_make_report(Severity.HIGH))
        data = json.loads(output)
        assert "report" in data
        assert "annotations" in data

    def test_report_fields(self) -> None:
        data = json.loads(format_bitbucket(_make_report(Severity.MEDIUM)))
        assert data["report"]["title"] == "ThreatCode STRIDE Threat Model"
        assert data["report"]["report_type"] == "SECURITY"

    def test_failed_on_critical(self) -> None:
        data = json.loads(format_bitbucket(_make_report(Severity.CRITICAL)))
        assert data["report"]["result"] == "FAILED"

    def test_passed_on_low(self) -> None:
        data = json.loads(format_bitbucket(_make_report(Severity.LOW)))
        assert data["report"]["result"] == "PASSED"

    def test_annotations_match_threats(self) -> None:
        data = json.loads(format_bitbucket(_make_report(Severity.HIGH)))
        assert len(data["annotations"]) == 1
        assert data["annotations"][0]["external_id"] == "t1"
