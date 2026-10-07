"""Tests for threatcode.models.report."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from threatcode.exceptions import ConfigError
from threatcode.models.attack_path import AttackHop, AttackPath
from threatcode.models.report import (
    NOT_IAC_PATH_LIMIT,
    Coverage,
    ThreatReport,
    current_timestamp,
    threat_severity,
)
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

    def test_to_dict_always_carries_schema_version_attack_paths_and_coverage(self) -> None:
        d = ThreatReport(version="1", timestamp="t").to_dict()
        assert list(d) == [
            "schema_version",
            "version",
            "timestamp",
            "input_file",
            "scanned_resources",
            "summary",
            "total_threats",
            "threats",
            "attack_paths",
            "coverage",
        ]
        assert d["schema_version"] == "2"
        assert d["attack_paths"] == []
        assert d["coverage"]["files_discovered"] == 0

    def test_an_empty_timestamp_is_left_out(self) -> None:
        assert "timestamp" not in ThreatReport(timestamp="").to_dict()

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


class TestEffectiveSeverity:
    def test_threat_severity_prefers_the_effective_one(self) -> None:
        t = _make_threat("t1", Severity.MEDIUM)
        assert threat_severity(t) is Severity.MEDIUM
        t.effective_severity = Severity.CRITICAL
        assert threat_severity(t) is Severity.CRITICAL

    def test_summary_and_filter_use_the_effective_severity(self) -> None:
        raised = _make_threat("t1", Severity.LOW)
        raised.effective_severity = Severity.CRITICAL
        lowered = _make_threat("t2", Severity.HIGH)
        lowered.effective_severity = Severity.INFO
        r = ThreatReport(threats=[raised, lowered])
        assert r.summary == {"critical": 1, "info": 1}
        assert r.filter_by_severity(Severity.HIGH) == [raised]


class TestTimestamp:
    def test_source_date_epoch_fixes_the_timestamp(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
        assert current_timestamp() == "2023-11-14T22:13:20+00:00"
        assert ThreatReport().timestamp == "2023-11-14T22:13:20+00:00"

    def test_without_it_the_timestamp_is_the_wall_clock(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
        moment = datetime.fromisoformat(current_timestamp())
        assert moment.utcoffset() == timedelta(0)
        assert abs(datetime.now(timezone.utc) - moment) < timedelta(seconds=30)

    @pytest.mark.parametrize("value", ["soon", "12.5", "99999999999999999999"])
    def test_an_invalid_epoch_is_a_config_error(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("SOURCE_DATE_EPOCH", value)
        with pytest.raises(ConfigError, match="SOURCE_DATE_EPOCH"):
            current_timestamp()


class TestCoverage:
    def test_defaults_serialize_to_a_complete_block(self) -> None:
        assert Coverage().to_dict() == {
            "files_discovered": 0,
            "units_parsed": 0,
            "not_iac": {"count": 0, "paths": []},
            "symlinks_skipped": 0,
            "special_files_skipped": 0,
            "errors": [],
            "gaps": [],
            "rule_errors": 0,
            "suppressed": 0,
            "baselined": 0,
        }

    def test_not_iac_keeps_the_full_count_but_only_the_first_twenty_paths(self) -> None:
        c = Coverage()
        for index in range(NOT_IAC_PATH_LIMIT + 5):
            c.note_not_iac(f"f{index}.json")
        assert c.not_iac_count == NOT_IAC_PATH_LIMIT + 5
        assert c.not_iac_paths == [f"f{i}.json" for i in range(NOT_IAC_PATH_LIMIT)]
        assert c.to_dict()["not_iac"]["count"] == NOT_IAC_PATH_LIMIT + 5

    def test_gaps_and_rule_errors_count_as_gaps_but_errors_do_not(self) -> None:
        assert not Coverage().has_gaps
        assert not Coverage(errors=[{"file": "a", "code": "parse.failed", "message": "m"}]).has_gaps
        assert Coverage(gaps=[{"level": "warning", "code": "k8s.skipped_document"}]).has_gaps
        assert Coverage(rule_errors=1).has_gaps

    def test_to_dict_copies_the_lists(self) -> None:
        c = Coverage(errors=[{"file": "a", "code": "parse.failed", "message": "m"}])
        c.to_dict()["errors"][0]["message"] = "changed"
        assert c.errors[0]["message"] == "m"

    def test_each_report_has_its_own_coverage(self) -> None:
        a, b = ThreatReport(), ThreatReport()
        a.coverage.note_not_iac("x.json")
        assert b.coverage.not_iac_count == 0

    def test_the_report_serializes_its_coverage(self) -> None:
        r = ThreatReport(coverage=Coverage(files_discovered=3, units_parsed=2, suppressed=1))
        cov = r.to_dict()["coverage"]
        assert (cov["files_discovered"], cov["units_parsed"], cov["suppressed"]) == (3, 2, 1)
