"""Tests for threatcode.models.threat."""

from __future__ import annotations

import itertools

import pytest

from threatcode.models.threat import Severity, Threat, ThreatSource, hash_id


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

    @pytest.mark.parametrize(
        ("left", "right"), list(itertools.product(list(Severity), list(Severity)))
    )
    def test_comparison_matrix_follows_rank(self, left: Severity, right: Severity) -> None:
        assert (left < right) == (left.rank < right.rank)
        assert (left <= right) == (left.rank <= right.rank)
        assert (left > right) == (left.rank > right.rank)
        assert (left >= right) == (left.rank >= right.rank)
        assert (left == right) == (left.rank == right.rank)
        assert (left != right) == (left.rank != right.rank)

    def test_hash_matches_string_value_and_works_in_sets(self) -> None:
        for sev in Severity:
            assert hash(sev) == hash(sev.value)
        assert {Severity.HIGH, Severity.HIGH, Severity.LOW} == {Severity.LOW, Severity.HIGH}

    def test_sorted_and_max_use_rank_not_alphabet(self) -> None:
        # Alphabetical order would put "critical" first and "medium" last.
        assert sorted(Severity) == [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        assert max([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]) is Severity.CRITICAL

    def test_still_a_string(self) -> None:
        assert Severity("high") is Severity.HIGH
        assert Severity.HIGH == "high"
        assert f"{Severity.HIGH.value}" == "high"

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

    def test_invalid_stride_category_raises(self) -> None:
        with pytest.raises(ValueError, match="not_real"):
            self._make_threat(stride_category="not_real")

    def test_empty_stride_category_raises(self) -> None:
        with pytest.raises(ValueError):
            self._make_threat(stride_category="")

    def test_invalid_evidence_raises(self) -> None:
        with pytest.raises(ValueError, match="evidence"):
            self._make_threat(evidence="guess")

    @pytest.mark.parametrize("evidence", ["config", "design", "scanner"])
    def test_valid_evidence_accepted(self, evidence: str) -> None:
        assert self._make_threat(evidence=evidence).evidence == evidence

    def test_confidence_is_clamped(self) -> None:
        assert self._make_threat(confidence=7).confidence == 1.0
        assert self._make_threat(confidence=-1).confidence == 0.0

    def test_new_source_values(self) -> None:
        assert ThreatSource.SECRET.value == "secret"
        assert ThreatSource.SCANNER.value == "scanner"
        assert ThreatSource("secret") is ThreatSource.SECRET
        t = self._make_threat(source=ThreatSource.SCANNER)
        assert t.to_dict()["source"] == "scanner"

    def test_contract_field_defaults(self) -> None:
        t = self._make_threat()
        assert t.location_file == ""
        assert t.location_start_line is None
        assert t.location_end_line is None
        assert t.fingerprint == ""
        assert t.evidence == "config"
        assert t.tool == ""
        assert t.aliases == []
        assert t.target_address == ""
        assert t.effective_severity is None
        assert t.severity_reason == ""
        assert t.path_ids == []
        assert t.root_cause == ""

    def test_list_defaults_are_not_shared_between_threats(self) -> None:
        a = self._make_threat()
        b = self._make_threat()
        a.aliases.append("CVE-2024-0001")
        a.path_ids.append("abc")
        assert b.aliases == []
        assert b.path_ids == []

    def test_to_dict_omits_contract_fields_at_defaults(self) -> None:
        d = self._make_threat().to_dict()
        for key in (
            "location_file",
            "location_start_line",
            "location_end_line",
            "fingerprint",
            "evidence",
            "tool",
            "aliases",
            "target_address",
            "effective_severity",
            "severity_reason",
            "path_ids",
            "root_cause",
        ):
            assert key not in d

    def test_to_dict_emits_contract_fields_when_set(self) -> None:
        t = self._make_threat(
            location_file="main.tf",
            location_start_line=10,
            location_end_line=18,
            fingerprint="fp-1",
            evidence="scanner",
            tool="trivy",
            aliases=["CVE-2024-0001", "GHSA-xxxx-yyyy-zzzz"],
            target_address="aws_db_instance.db",
            effective_severity=Severity.CRITICAL,
            severity_reason="reachable from the internet",
            path_ids=["0123456789ab"],
            root_cause="aws_security_group.open",
        )
        d = t.to_dict()
        assert d["location_file"] == "main.tf"
        assert d["location_start_line"] == 10
        assert d["location_end_line"] == 18
        assert d["fingerprint"] == "fp-1"
        assert d["evidence"] == "scanner"
        assert d["tool"] == "trivy"
        assert d["aliases"] == ["CVE-2024-0001", "GHSA-xxxx-yyyy-zzzz"]
        assert d["target_address"] == "aws_db_instance.db"
        assert d["effective_severity"] == "critical"
        assert d["severity_reason"] == "reachable from the internet"
        assert d["path_ids"] == ["0123456789ab"]
        assert d["root_cause"] == "aws_security_group.open"

    def test_to_dict_emits_each_contract_field_alone(self) -> None:
        # A line number of 0 is a value, not an absent one.
        d = self._make_threat(location_start_line=0).to_dict()
        assert d["location_start_line"] == 0
        assert "location_end_line" not in d

    def test_to_dict_has_all_keys(self) -> None:
        t = self._make_threat()
        d = t.to_dict()
        assert set(d.keys()) == {
            "id",
            "title",
            "description",
            "stride_category",
            "severity",
            "source",
            "resource_type",
            "resource_address",
            "mitigation",
            "rule_id",
            "confidence",
            "metadata",
            "mitre_techniques",
            "mitre_tactics",
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


class TestHashId:
    def test_is_twelve_hex_characters_and_stable(self) -> None:
        value = hash_id("RULE_aws_s3_bucket.x")
        assert len(value) == 12
        int(value, 16)
        assert value == hash_id("RULE_aws_s3_bucket.x")

    def test_differs_for_different_seeds(self) -> None:
        assert hash_id("a") != hash_id("b")
