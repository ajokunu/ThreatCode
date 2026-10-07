"""Tests for the ATT&CK Navigator formatter."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import pytest

from threatcode.engine.mitre import ATTACK_VERSION, TACTIC_SHORTNAME, TECHNIQUE_DB
from threatcode.formatters.attack_navigator import (
    LAYER_VERSION,
    NAVIGATOR_VERSION,
    format_attack_navigator,
)
from threatcode.models.attack_path import AttackHop, AttackPath
from threatcode.models.report import ThreatReport
from threatcode.models.threat import Severity, Threat, ThreatSource

VALID_SHORTNAMES = set(TACTIC_SHORTNAME.values())


def _make_threat(
    rule_id: str,
    techniques: list[str],
    severity: Severity = Severity.HIGH,
    tactics: list[str] | None = None,
    **fields: Any,
) -> Threat:
    return Threat(
        id=f"test_{rule_id}",
        title=fields.pop("title", f"Test {rule_id}"),
        description="Test threat",
        stride_category="information_disclosure",
        severity=severity,
        source=ThreatSource.RULE,
        resource_type="aws_s3_bucket",
        resource_address="aws_s3_bucket.test",
        rule_id=rule_id,
        mitre_techniques=techniques,
        mitre_tactics=["TA0009"] if tactics is None else tactics,
        **fields,
    )


def layer_of(*threats: Threat, paths: list[AttackPath] | None = None) -> dict[str, Any]:
    report = ThreatReport(threats=list(threats), input_file="main.tf")
    report.attack_paths = paths or []
    return json.loads(format_attack_navigator(report))  # type: ignore[no-any-return]


class TestAttackNavigator:
    def test_basic_layer_structure(self) -> None:
        layer = layer_of(_make_threat("S3_NO_ENC", ["T1530"]))
        assert layer["name"] == "ThreatCode Threat Model"
        assert layer["domain"] == "enterprise-attack"
        for key in ("versions", "techniques", "gradient", "legendItems"):
            assert key in layer

    def test_technique_mapped(self) -> None:
        techniques = layer_of(_make_threat("S3_NO_ENC", ["T1530"]))["techniques"]
        assert len(techniques) == 1
        assert techniques[0]["techniqueID"] == "T1530"
        assert techniques[0]["tactic"] == "collection"
        assert techniques[0]["enabled"] is True

    def test_multiple_threats_same_technique_keep_the_highest_severity(self) -> None:
        layer = layer_of(
            _make_threat("RULE_A", ["T1530"], Severity.MEDIUM),
            _make_threat("RULE_B", ["T1530"], Severity.CRITICAL),
        )
        assert len(layer["techniques"]) == 1
        assert layer["techniques"][0]["score"] == 100
        assert layer["techniques"][0]["metadata"][0] == {"name": "findings", "value": "2"}

    def test_the_effective_severity_is_scored(self) -> None:
        threat = _make_threat("A", ["T1530"], Severity.LOW, effective_severity=Severity.CRITICAL)
        assert layer_of(threat)["techniques"][0]["score"] == 100

    def test_multiple_techniques(self) -> None:
        layer = layer_of(_make_threat("RULE_A", ["T1530", "T1190"], tactics=["TA0009", "TA0001"]))
        assert {t["techniqueID"] for t in layer["techniques"]} == {"T1530", "T1190"}

    def test_empty_report(self) -> None:
        assert layer_of()["techniques"] == []

    def test_the_comment_lists_the_finding_titles(self) -> None:
        layer = layer_of(_make_threat("A", ["T1530"], title="Bucket is public"))
        assert layer["techniques"][0]["comment"] == "1 finding(s): Bucket is public"


class TestTactics:
    def test_no_technique_has_an_empty_tactic(self) -> None:
        layer = layer_of(
            _make_threat("A", ["T1530", "T1078", "T1190", "T1552.005"], tactics=[]),
            _make_threat("B", ["T9999"], tactics=[]),
        )
        for technique in layer["techniques"]:
            assert technique.get("tactic", "x") != ""

    def test_every_tactic_is_an_official_shortname(self) -> None:
        threats = [
            _make_threat(f"R{i}", [tid], tactics=[])
            for i, tid in enumerate(sorted(TECHNIQUE_DB)[:300])
            if not TECHNIQUE_DB[tid]["revoked"]
        ]
        for technique in layer_of(*threats)["techniques"]:
            assert technique["tactic"] in VALID_SHORTNAMES

    def test_a_technique_in_two_tactics_gets_two_entries(self) -> None:
        two = next(
            tid
            for tid, entry in sorted(TECHNIQUE_DB.items())
            if len(entry["tactic_ids"]) == 2 and not entry["revoked"]
        )
        expected = sorted(TACTIC_SHORTNAME[t] for t in TECHNIQUE_DB[two]["tactic_ids"])
        layer = layer_of(_make_threat("A", [two], tactics=[]))
        assert sorted(t["tactic"] for t in layer["techniques"]) == expected
        assert {t["techniqueID"] for t in layer["techniques"]} == {two}

    def test_the_finding_tactics_narrow_the_technique_tactics(self) -> None:
        two = next(
            tid
            for tid, entry in sorted(TECHNIQUE_DB.items())
            if len(entry["tactic_ids"]) == 2 and not entry["revoked"]
        )
        first = TECHNIQUE_DB[two]["tactic_ids"][0]
        layer = layer_of(_make_threat("A", [two], tactics=[first, "TA9999"]))
        assert [t["tactic"] for t in layer["techniques"]] == [TACTIC_SHORTNAME[first]]

    def test_a_finding_tactic_the_technique_lacks_falls_back_to_its_own(self) -> None:
        layer = layer_of(_make_threat("A", ["T1530"], tactics=["TA0001"]))
        assert [t["tactic"] for t in layer["techniques"]] == ["collection"]

    def test_scores_and_comments_are_per_tactic(self) -> None:
        two = next(
            tid
            for tid, entry in sorted(TECHNIQUE_DB.items())
            if len(entry["tactic_ids"]) == 2 and not entry["revoked"]
        )
        a, b = TECHNIQUE_DB[two]["tactic_ids"]
        layer = layer_of(
            _make_threat("A", [two], Severity.CRITICAL, tactics=[a], title="first"),
            _make_threat("B", [two], Severity.LOW, tactics=[b], title="second"),
        )
        by_tactic = {t["tactic"]: t for t in layer["techniques"]}
        assert by_tactic[TACTIC_SHORTNAME[a]]["score"] == 100
        assert by_tactic[TACTIC_SHORTNAME[b]]["score"] == 25
        assert "second" not in by_tactic[TACTIC_SHORTNAME[a]]["comment"]

    def test_a_revoked_technique_is_mapped_to_its_replacement(self) -> None:
        layer = layer_of(_make_threat("A", ["T1562.008"], tactics=[]))
        assert [t["techniqueID"] for t in layer["techniques"]] == ["T1685.002"]


class TestUnknownTechniques:
    def test_an_unknown_id_is_kept_with_a_warning_not_dropped(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            layer = layer_of(_make_threat("A", ["T9999"], tactics=["TA0001"]))
        assert [t["techniqueID"] for t in layer["techniques"]] == ["T9999"]
        assert any("T9999" in r.message for r in caplog.records)
        assert layer["metadata"] == [
            {"name": "techniques not in the bundled ATT&CK data", "value": "T9999"}
        ]

    def test_an_unknown_id_uses_the_tactics_the_finding_names(self) -> None:
        layer = layer_of(_make_threat("A", ["T9999"], tactics=["TA0001"]))
        assert layer["techniques"][0]["tactic"] == "initial-access"

    def test_an_unknown_id_with_no_tactic_has_no_tactic_key(self) -> None:
        layer = layer_of(_make_threat("A", ["T9999"], tactics=[]))
        assert "tactic" not in layer["techniques"][0]

    def test_text_that_is_not_a_technique_id_is_left_out(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            layer = layer_of(_make_threat("A", ["not-an-id", "T1530"]))
        assert [t["techniqueID"] for t in layer["techniques"]] == ["T1530"]
        assert any("not-an-id" in r.message for r in caplog.records)

    def test_a_scan_with_only_known_ids_has_no_layer_metadata(self) -> None:
        assert "metadata" not in layer_of(_make_threat("A", ["T1530"]))


class TestLayerSettings:
    def test_no_platform_filter(self) -> None:
        layer = layer_of(_make_threat("TEST", ["T1530"]))
        assert "platforms" not in layer["filters"]
        assert layer["filters"] == {}

    def test_sub_techniques_are_expanded_where_annotated(self) -> None:
        assert layer_of()["layout"]["expandedSubtechniques"] == "annotated"

    def test_versions(self) -> None:
        versions = layer_of()["versions"]
        assert versions["layer"] == LAYER_VERSION == "4.5"
        assert versions["attack"] == ATTACK_VERSION
        assert re.fullmatch(r"\d+\.\d+\.\d+", versions["navigator"])
        assert versions["navigator"] == NAVIGATOR_VERSION
        assert tuple(int(p) for p in NAVIGATOR_VERSION.split(".")) >= (4, 9, 0)

    def test_the_description_counts_threats_and_techniques(self) -> None:
        layer = layer_of(_make_threat("A", ["T1530"]), _make_threat("B", ["T1530"]))
        assert "2 threats mapped to 1 ATT&CK techniques" in layer["description"]

    def test_valid_json_output(self) -> None:
        text = format_attack_navigator(
            ThreatReport(threats=[_make_threat("S3", ["T1530", "T1190"])])
        )
        assert isinstance(json.loads(text), dict)


class TestAttackPathTechniques:
    def path(self, severity: Severity = Severity.CRITICAL) -> AttackPath:
        return AttackPath(
            id="0123456789ab",
            entry="internet",
            target="aws_db_instance.main",
            hops=[
                AttackHop(node_id="internet", techniques=["T1190"]),
                AttackHop(node_id="aws_db_instance.main", techniques=["T1530"]),
            ],
            severity=severity,
            techniques=["T1190", "T1530"],
            tactics=["TA0001", "TA0009"],
        )

    def test_path_techniques_are_in_the_layer_with_their_own_comment(self) -> None:
        layer = layer_of(paths=[self.path()])
        by_id = {t["techniqueID"]: t for t in layer["techniques"]}
        assert set(by_id) == {"T1190", "T1530"}
        assert by_id["T1190"]["tactic"] == "initial-access"
        assert by_id["T1190"]["comment"] == "1 attack path(s): internet to aws_db_instance.main"
        assert by_id["T1190"]["score"] == 100
        assert {m["name"]: m["value"] for m in by_id["T1190"]["metadata"]}["attack_paths"] == "1"

    def test_findings_and_paths_share_an_entry_per_technique_and_tactic(self) -> None:
        layer = layer_of(_make_threat("A", ["T1530"], Severity.LOW), paths=[self.path()])
        entries = [t for t in layer["techniques"] if t["techniqueID"] == "T1530"]
        assert len(entries) == 1
        assert entries[0]["score"] == 100
        assert (
            "1 finding(s):" in entries[0]["comment"]
            and "1 attack path(s):" in entries[0]["comment"]
        )

    def test_a_hop_technique_is_included_even_when_the_path_lists_none(self) -> None:
        path = self.path()
        path.techniques = []
        ids = {t["techniqueID"] for t in layer_of(paths=[path])["techniques"]}
        assert ids == {"T1190", "T1530"}
