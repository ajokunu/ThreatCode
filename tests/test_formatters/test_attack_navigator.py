"""Tests for the ATT&CK Navigator formatter."""

from __future__ import annotations

import json

from threatcode.formatters.attack_navigator import format_attack_navigator
from threatcode.models.report import ThreatReport
from threatcode.models.threat import Severity, Threat, ThreatSource


def _make_threat(rule_id: str, techniques: list[str], severity: Severity = Severity.HIGH) -> Threat:
    return Threat(
        id=f"test_{rule_id}",
        title=f"Test {rule_id}",
        description="Test threat",
        stride_category="information_disclosure",
        severity=severity,
        source=ThreatSource.RULE,
        resource_type="aws_s3_bucket",
        resource_address="aws_s3_bucket.test",
        rule_id=rule_id,
        mitre_techniques=techniques,
        mitre_tactics=["TA0009"],
    )


class TestAttackNavigator:
    def test_basic_layer_structure(self) -> None:
        report = ThreatReport(threats=[_make_threat("S3_NO_ENC", ["T1530"])])
        output = format_attack_navigator(report)
        layer = json.loads(output)

        assert layer["name"] == "ThreatCode Threat Model"
        assert layer["domain"] == "enterprise-attack"
        assert "versions" in layer
        assert "techniques" in layer
        assert "gradient" in layer
        assert "legendItems" in layer

    def test_technique_mapped(self) -> None:
        report = ThreatReport(threats=[_make_threat("S3_NO_ENC", ["T1530"])])
        layer = json.loads(format_attack_navigator(report))

        techniques = layer["techniques"]
        assert len(techniques) == 1
        assert techniques[0]["techniqueID"] == "T1530"
        assert techniques[0]["enabled"] is True

    def test_multiple_threats_same_technique(self) -> None:
        report = ThreatReport(
            threats=[
                _make_threat("RULE_A", ["T1530"], Severity.MEDIUM),
                _make_threat("RULE_B", ["T1530"], Severity.CRITICAL),
            ]
        )
        layer = json.loads(format_attack_navigator(report))

        techniques = layer["techniques"]
        assert len(techniques) == 1
        # Highest severity wins
        assert techniques[0]["score"] == 100  # CRITICAL

    def test_multiple_techniques(self) -> None:
        report = ThreatReport(
            threats=[
                _make_threat("RULE_A", ["T1530", "T1190"]),
            ]
        )
        layer = json.loads(format_attack_navigator(report))

        tech_ids = {t["techniqueID"] for t in layer["techniques"]}
        assert tech_ids == {"T1530", "T1190"}

    def test_empty_report(self) -> None:
        report = ThreatReport()
        layer = json.loads(format_attack_navigator(report))
        assert layer["techniques"] == []

    def test_unknown_technique_skipped(self) -> None:
        report = ThreatReport(threats=[_make_threat("RULE_A", ["T9999"])])
        layer = json.loads(format_attack_navigator(report))
        assert layer["techniques"] == []

    def test_valid_json_output(self) -> None:
        report = ThreatReport(
            threats=[
                _make_threat("S3_NO_ENC", ["T1530"]),
                _make_threat("S3_PUB", ["T1530", "T1190"]),
            ]
        )
        output = format_attack_navigator(report)
        layer = json.loads(output)
        assert isinstance(layer, dict)

    def test_iaas_platform_filter(self) -> None:
        report = ThreatReport(threats=[_make_threat("TEST", ["T1530"])])
        layer = json.loads(format_attack_navigator(report))
        assert layer["filters"]["platforms"] == ["IaaS"]
