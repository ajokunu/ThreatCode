"""Tests for threatcode.models.report."""

from __future__ import annotations

from threatcode.models.report import ThreatReport
from threatcode.models.threat import Severity, Threat, ThreatSource


def _make_threat(tid: str, severity: Severity) -> Threat:
    return Threat(
        id=tid,
        title=f"Threat {tid}",
        description="desc",
        stride_category="tampering",
        severity=severity,
        source=ThreatSource.RULE,
        resource_type="aws_s3_bucket",
        resource_address="aws_s3_bucket.test",
    )


class TestThreatReport:
    def test_add(self) -> None:
        r = ThreatReport()
        r.add(_make_threat("t1", Severity.HIGH))
        assert len(r.threats) == 1

    def test_filter_by_severity(self) -> None:
        r = ThreatReport()
        r.add(_make_threat("t1", Severity.HIGH))
        r.add(_make_threat("t2", Severity.LOW))
        r.add(_make_threat("t3", Severity.CRITICAL))
        filtered = r.filter_by_severity(Severity.HIGH)
        assert len(filtered) == 2
        assert all(t.severity >= Severity.HIGH for t in filtered)

    def test_summary_counts(self) -> None:
        r = ThreatReport()
        r.add(_make_threat("t1", Severity.HIGH))
        r.add(_make_threat("t2", Severity.HIGH))
        r.add(_make_threat("t3", Severity.LOW))
        assert r.summary == {"high": 2, "low": 1}

    def test_to_dict_structure(self) -> None:
        r = ThreatReport(scanned_resources=5, input_file="test.json")
        d = r.to_dict()
        assert d["scanned_resources"] == 5
        assert d["input_file"] == "test.json"
        assert "threats" in d
        assert "summary" in d

    def test_empty_report(self) -> None:
        r = ThreatReport()
        assert r.summary == {}
        assert r.to_dict()["total_threats"] == 0
