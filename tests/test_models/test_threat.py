"""Tests for threatcode.models.threat."""

from __future__ import annotations

from threatcode.models.threat import Severity, Threat, ThreatSource


class TestSeverity:
    def test_ordering(self) -> None:
        assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO

    def test_rank_values(self) -> None:
        assert Severity.CRITICAL.rank == 4
        assert Severity.INFO.rank == 0

    def test_ge_le(self) -> None:
        assert Severity.HIGH >= Severity.HIGH
        assert Severity.HIGH >= Severity.MEDIUM
        assert Severity.LOW <= Severity.LOW
        assert Severity.LOW <= Severity.HIGH

    def test_comparison_with_non_severity_returns_not_implemented(self) -> None:
        assert Severity.HIGH.__gt__("high") is NotImplemented
        assert Severity.HIGH.__lt__("high") is NotImplemented
        assert Severity.HIGH.__ge__("high") is NotImplemented
        assert Severity.HIGH.__le__("high") is NotImplemented


class TestThreat:
    def _make_threat(self, **overrides: object) -> Threat:
        defaults = {
            "id": "test-1",
            "title": "Test Threat",
            "description": "A test threat",
            "stride_category": "tampering",
            "severity": Severity.MEDIUM,
            "source": ThreatSource.RULE,
            "resource_type": "aws_s3_bucket",
            "resource_address": "aws_s3_bucket.test",
        }
        defaults.update(overrides)
        return Threat(**defaults)  # type: ignore[arg-type]

    def test_valid_stride_category_preserved(self) -> None:
        t = self._make_threat(stride_category="spoofing")
        assert t.stride_category == "spoofing"

    def test_invalid_stride_category_defaults(self) -> None:
        t = self._make_threat(stride_category="not_real")
        assert t.stride_category == "information_disclosure"

    def test_to_dict_has_all_keys(self) -> None:
        t = self._make_threat()
        d = t.to_dict()
        assert set(d.keys()) == {
            "id", "title", "description", "stride_category", "severity",
            "source", "resource_type", "resource_address", "mitigation",
            "rule_id", "confidence", "metadata", "mitre_techniques", "mitre_tactics",
        }

    def test_to_dict_serializes_enums(self) -> None:
        t = self._make_threat()
        d = t.to_dict()
        assert d["severity"] == "medium"
        assert d["source"] == "rule"

    def test_mitre_fields_default_empty(self) -> None:
        t = self._make_threat()
        assert t.mitre_techniques == []
        assert t.mitre_tactics == []
