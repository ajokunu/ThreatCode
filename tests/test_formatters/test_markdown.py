"""Tests for threatcode.formatters.markdown."""

from __future__ import annotations

from threatcode.formatters.markdown import format_markdown
from threatcode.models.report import ThreatReport
from threatcode.models.threat import Severity, Threat, ThreatSource


def _make_report(*severities: Severity) -> ThreatReport:
    report = ThreatReport(scanned_resources=5)
    for i, sev in enumerate(severities):
        report.add(Threat(
            id=f"t{i}",
            title=f"Threat {i}",
            description=f"Description {i}",
            stride_category="tampering",
            severity=sev,
            source=ThreatSource.RULE,
            resource_type="aws_s3_bucket",
            resource_address=f"aws_s3_bucket.test{i}",
            mitigation=f"Fix {i}",
        ))
    return report


class TestFormatMarkdown:
    def test_header_present(self) -> None:
        md = format_markdown(_make_report(Severity.HIGH))
        assert "# ThreatCode Threat Model Report" in md

    def test_summary_table(self) -> None:
        md = format_markdown(_make_report(Severity.HIGH, Severity.HIGH, Severity.LOW))
        assert "| Severity | Count |" in md

    def test_stride_grouping(self) -> None:
        md = format_markdown(_make_report(Severity.MEDIUM))
        assert "Tampering" in md

    def test_empty_report(self) -> None:
        md = format_markdown(ThreatReport(scanned_resources=0))
        assert "No threats detected." in md

    def test_mitigation_blockquote(self) -> None:
        md = format_markdown(_make_report(Severity.HIGH))
        assert "> **Mitigation:**" in md

    def test_mitre_techniques_shown(self) -> None:
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
            mitre_techniques=["T1530"],
        ))
        md = format_markdown(report)
        assert "T1530" in md
