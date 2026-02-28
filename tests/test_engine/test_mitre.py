"""Tests for the MITRE ATT&CK reference module."""

from __future__ import annotations

from threatcode.engine.mitre import (
    BOUNDARY_TACTICS,
    BOUNDARY_TECHNIQUES,
    STRIDE_TO_TACTICS,
    TACTIC_DB,
    TECHNIQUE_DB,
    lookup_tactic,
    lookup_technique,
    tactics_for_techniques,
)


class TestTechniqueDB:
    def test_t1530_exists(self) -> None:
        tech = TECHNIQUE_DB["T1530"]
        assert tech["name"] == "Data from Cloud Storage"
        assert "TA0009" in tech["tactic_ids"]

    def test_t1190_exists(self) -> None:
        tech = TECHNIQUE_DB["T1190"]
        assert tech["name"] == "Exploit Public-Facing Application"
        assert "TA0001" in tech["tactic_ids"]

    def test_t1562_008_exists(self) -> None:
        tech = TECHNIQUE_DB["T1562.008"]
        assert "Disable" in tech["name"] or "Cloud Logs" in tech["name"]
        assert "TA0005" in tech["tactic_ids"]

    def test_t1078_004_exists(self) -> None:
        tech = TECHNIQUE_DB["T1078.004"]
        assert "Cloud Accounts" in tech["name"]

    def test_all_techniques_have_urls(self) -> None:
        for tid, tech in TECHNIQUE_DB.items():
            assert "url" in tech, f"Technique {tid} missing url"
            assert tech["url"].startswith("https://attack.mitre.org/"), f"{tid} has bad url"

    def test_all_techniques_have_tactic_ids(self) -> None:
        for tid, tech in TECHNIQUE_DB.items():
            tactic_ids = tech["tactic_ids"]
            assert isinstance(tactic_ids, list), f"{tid} tactic_ids not a list"
            assert len(tactic_ids) > 0, f"{tid} has no tactic_ids"
            for ta in tactic_ids:
                assert ta in TACTIC_DB, f"{tid} references unknown tactic {ta}"


class TestTacticDB:
    def test_all_tactics_have_names_and_urls(self) -> None:
        for ta_id, tactic in TACTIC_DB.items():
            assert "name" in tactic
            assert "url" in tactic
            assert ta_id.startswith("TA")


class TestLookups:
    def test_lookup_existing_technique(self) -> None:
        result = lookup_technique("T1530")
        assert result is not None
        assert result["name"] == "Data from Cloud Storage"

    def test_lookup_missing_technique(self) -> None:
        result = lookup_technique("T9999")
        assert result is None

    def test_lookup_existing_tactic(self) -> None:
        result = lookup_tactic("TA0001")
        assert result is not None
        assert result["name"] == "Initial Access"

    def test_lookup_missing_tactic(self) -> None:
        result = lookup_tactic("TA9999")
        assert result is None


class TestTacticsForTechniques:
    def test_single_technique(self) -> None:
        tactics = tactics_for_techniques(["T1530"])
        assert "TA0009" in tactics

    def test_multiple_techniques(self) -> None:
        tactics = tactics_for_techniques(["T1530", "T1190"])
        assert "TA0009" in tactics
        assert "TA0001" in tactics

    def test_unknown_technique_ignored(self) -> None:
        tactics = tactics_for_techniques(["T9999"])
        assert tactics == []

    def test_empty_list(self) -> None:
        assert tactics_for_techniques([]) == []

    def test_result_sorted(self) -> None:
        tactics = tactics_for_techniques(["T1530", "T1190", "T1078.004"])
        assert tactics == sorted(tactics)


class TestStrideToTactics:
    def test_all_stride_categories_mapped(self) -> None:
        expected = {
            "spoofing",
            "tampering",
            "repudiation",
            "information_disclosure",
            "denial_of_service",
            "elevation_of_privilege",
        }
        assert set(STRIDE_TO_TACTICS.keys()) == expected

    def test_tactics_are_valid(self) -> None:
        for stride, tactics in STRIDE_TO_TACTICS.items():
            for ta in tactics:
                assert ta in TACTIC_DB, f"STRIDE {stride} maps to unknown tactic {ta}"


class TestBoundaryDefaults:
    def test_boundary_techniques_valid(self) -> None:
        for tid in BOUNDARY_TECHNIQUES:
            assert tid in TECHNIQUE_DB

    def test_boundary_tactics_valid(self) -> None:
        for ta in BOUNDARY_TACTICS:
            assert ta in TACTIC_DB
