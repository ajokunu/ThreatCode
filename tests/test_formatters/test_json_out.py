"""Tests for threatcode.formatters.json_out."""

from __future__ import annotations

import json

from threatcode.formatters.json_out import format_json
from threatcode.models.report import ThreatReport
from threatcode.models.threat import Severity, Threat, ThreatSource


class TestFormatJson:
    def test_output_is_valid_json(self) -> None:
        report = ThreatReport(scanned_resources=1)
        output = format_json(report)
        data = json.loads(output)
        assert "threats" in data

    def test_threats_serialized(self) -> None:
        report = ThreatReport(scanned_resources=1)
        report.add(Threat(
            id="t1",
            title="Test",
            description="Desc",
            stride_category="tampering",
            severity=Severity.HIGH,
            source=ThreatSource.RULE,
            resource_type="aws_s3_bucket",
            resource_address="aws_s3_bucket.test",
        ))
        data = json.loads(format_json(report))
        assert len(data["threats"]) == 1
        assert data["threats"][0]["id"] == "t1"

    def test_empty_report(self) -> None:
        data = json.loads(format_json(ThreatReport()))
        assert data["total_threats"] == 0
        assert data["threats"] == []
