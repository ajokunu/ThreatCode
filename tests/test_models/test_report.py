"""Tests for threatcode.models.report."""

from __future__ import annotations

from threatcode.models.attack_path import AttackHop, AttackPath
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


class TestReportContract:
    def test_schema_version(self) -> None:
        assert ThreatReport.SCHEMA_VERSION == "2"
        assert ThreatReport().SCHEMA_VERSION == "2"

    def test_defaults_keep_the_old_json_shape(self) -> None:
        d = ThreatReport(version="1", timestamp="t").to_dict()
        assert list(d) == [
            "version",
            "timestamp",
            "input_file",
            "scanned_resources",
            "summary",
            "total_threats",
            "threats",
        ]

    def test_attack_paths_serialize_when_present(self) -> None:
        path = AttackPath(
            id="0123456789ab",
            entry="internet",
            target="aws_db_instance.db",
            hops=[AttackHop(node_id="internet"), AttackHop(node_id="aws_db_instance.db")],
            severity=Severity.HIGH,
        )
        r = ThreatReport(attack_paths=[path])
        d = r.to_dict()
        assert [p["id"] for p in d["attack_paths"]] == ["0123456789ab"]
        assert d["attack_paths"][0]["severity"] == "high"
        # Paths are not threats: the counts do not move.
        assert d["total_threats"] == 0
        assert d["summary"] == {}

    def test_attack_paths_not_shared_between_reports(self) -> None:
        a, b = ThreatReport(), ThreatReport()
        a.attack_paths.append(AttackPath(id="x", entry="e", target="t"))
        a.rule_errors.append({"rule_id": "R", "node_id": "n", "error": "boom"})
        assert b.attack_paths == []
        assert b.rule_errors == []

    def test_llm_status_serializes_when_the_phase_ran_or_failed(self) -> None:
        for status in ("ran", "failed"):
            r = ThreatReport(llm={"provider": "anthropic", "status": status})
            assert r.to_dict()["llm"]["status"] == status

    def test_skipped_llm_status_is_not_serialized(self) -> None:
        r = ThreatReport(llm={"provider": "", "model": "", "status": "skipped"})
        assert "llm" not in r.to_dict()
        assert r.llm is not None

    def test_llm_serialization_copies_the_mapping(self) -> None:
        r = ThreatReport(llm={"status": "ran"})
        r.to_dict()["llm"]["status"] = "failed"
        assert r.llm == {"status": "ran"}

    def test_rule_errors_serialize_when_present(self) -> None:
        err = {"rule_id": "R1", "node_id": "n1", "error": "TypeError: boom"}
        d = ThreatReport(rule_errors=[err]).to_dict()
        assert d["rule_errors"] == [err]
