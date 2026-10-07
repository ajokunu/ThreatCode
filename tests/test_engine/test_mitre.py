"""Tests for the MITRE ATT&CK reference module and its STIX generator."""

from __future__ import annotations

import copy
import importlib.util
import json
import re
import subprocess
import sys
import warnings
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from threatcode.engine import mitre
from threatcode.engine.mitre import (
    ATTACK_VERSION,
    BOUNDARY_TACTICS,
    BOUNDARY_TECHNIQUES,
    REVOKED_ALIASES,
    TACTIC_DB,
    TACTIC_SHORTNAME,
    TECHNIQUE_DB,
    is_deprecated,
    is_revoked,
    lookup_tactic,
    lookup_technique,
    normalize_technique,
    tactic_shortname,
    tactics_for_techniques,
)
from threatcode.engine.rules.loader import load_builtin_rules

REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATOR = REPO_ROOT / "scripts" / "gen_mitre_db.py"
EXCERPT = REPO_ROOT / "tests" / "fixtures" / "stix" / "enterprise-attack-excerpt.json"
MITRE_DATA = REPO_ROOT / "src" / "threatcode" / "engine" / "mitre_data.py"

# The tactic lists of the previous hand-written database, frozen for the parity test.
OLD_TACTICS: dict[str, list[str]] = {
    "T1040": ["TA0006", "TA0007"],
    "T1046": ["TA0007"],
    "T1078": ["TA0001", "TA0003", "TA0004", "TA0005"],
    "T1078.004": ["TA0001", "TA0003", "TA0004", "TA0005"],
    "T1098": ["TA0003", "TA0004"],
    "T1190": ["TA0001"],
    "T1485": ["TA0040"],
    "T1499": ["TA0040"],
    "T1530": ["TA0009"],
    "T1537": ["TA0010"],
    "T1557": ["TA0006", "TA0009"],
    "T1562.008": ["TA0005"],
    "T1580": ["TA0007"],
    "T1059": ["TA0002"],
    "T1005": ["TA0009"],
    "T1611": ["TA0004"],
    "T1610": ["TA0002", "TA0005"],
    "T1552.001": ["TA0006"],
    "T1195.002": ["TA0001"],
    "T1021": ["TA0008"],
    "T1528": ["TA0006"],
    "T1565.001": ["TA0040"],
    "T1613": ["TA0007"],
    "T1609": ["TA0002"],
    "T1552": ["TA0006"],
    "T1195": ["TA0001"],
    "T1565": ["TA0040"],
    "T1548": ["TA0004", "TA0005"],
    "T1053": ["TA0002", "TA0003", "TA0004"],
    "T1068": ["TA0004"],
    "T1048": ["TA0010"],
    "T1189": ["TA0001"],
    "T1587.001": ["TA0042"],
    "T1587": ["TA0042"],
}

# Techniques whose tactic list ATT&CK itself changed since the hand-written database was made.
# Verified against the v19.2 bundle: T1610 is Execution only and T1548 is Privilege Escalation only.
TACTICS_CHANGED_BY_ATTACK = {"T1610": ["TA0002"], "T1548": ["TA0004"]}

NAVIGATOR_SHORTNAMES = {
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "stealth",
    "defense-impairment",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
}


def _load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("gen_mitre_db", GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["gen_mitre_db"] = module
    spec.loader.exec_module(module)
    return module


gen = _load_generator()


def _excerpt() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(EXCERPT.read_text(encoding="utf-8"))
    return data


def _run_module(source: str) -> dict[str, Any]:
    namespace: dict[str, Any] = {"__name__": "generated_mitre_data"}
    exec(compile(source, "<generated>", "exec"), namespace)  # noqa: S102
    return namespace


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(GENERATOR), *args],
        capture_output=True,
        text=True,
        check=False,
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

    def test_t1562_008_is_revoked_and_still_resolvable(self) -> None:
        tech = TECHNIQUE_DB["T1562.008"]
        assert "Cloud Logs" in tech["name"]
        assert "TA0005" in tech["tactic_ids"]
        assert tech["revoked"] is True
        assert tech["revoked_by"] == "T1685.002"

    def test_t1685_002_replaces_it_under_defense_impairment(self) -> None:
        tech = TECHNIQUE_DB["T1685.002"]
        assert tech["revoked"] is False
        assert tech["deprecated"] is False
        assert tech["tactic_ids"] == ["TA0112"]

    def test_t1078_004_exists(self) -> None:
        tech = TECHNIQUE_DB["T1078.004"]
        assert tech["name"] == "Valid Accounts: Cloud Accounts"

    def test_sub_technique_names_carry_the_parent_name(self) -> None:
        for tid, tech in TECHNIQUE_DB.items():
            if "." in tid:
                parent_name = TECHNIQUE_DB[tid.split(".")[0]]["name"]
                assert tech["name"].startswith(parent_name + ": "), tid

    def test_database_is_complete_not_a_hand_picked_subset(self) -> None:
        assert len(TECHNIQUE_DB) > 800
        for tid in ("T1552.005", "T1555.006", "T1133", "T1110", "T1525", "T1496", "T1098.003"):
            assert tid in TECHNIQUE_DB, tid

    def test_cloud_techniques_carry_their_tactics(self) -> None:
        assert TECHNIQUE_DB["T1552.005"]["tactic_ids"] == ["TA0006"]
        assert TECHNIQUE_DB["T1133"]["tactic_ids"] == ["TA0001", "TA0003"]
        assert TECHNIQUE_DB["T1098.003"]["tactic_ids"] == ["TA0003", "TA0004"]

    def test_all_techniques_have_urls(self) -> None:
        for tid, tech in TECHNIQUE_DB.items():
            assert tech["url"].startswith("https://attack.mitre.org/techniques/"), f"{tid} bad url"
            assert tech["url"].endswith("/"), tid
            assert tech["url"] == f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"

    def test_every_technique_has_valid_tactic_ids(self) -> None:
        for tid, tech in TECHNIQUE_DB.items():
            tactic_ids = tech["tactic_ids"]
            assert isinstance(tactic_ids, list), f"{tid} tactic_ids not a list"
            assert len(tactic_ids) > 0, f"{tid} has no tactic_ids"
            assert tactic_ids == sorted(set(tactic_ids)), f"{tid} tactic_ids not sorted/unique"
            for ta in tactic_ids:
                assert ta in TACTIC_DB, f"{tid} references unknown tactic {ta}"

    def test_entries_have_the_full_shape(self) -> None:
        keys = {"name", "tactic_ids", "url", "platforms", "deprecated", "revoked", "revoked_by"}
        for tid, tech in TECHNIQUE_DB.items():
            assert set(tech) == keys, tid
            assert isinstance(tech["platforms"], list), tid
            assert isinstance(tech["deprecated"], bool), tid
            assert isinstance(tech["revoked"], bool), tid
            assert tech["revoked_by"] is None or tech["revoked_by"] in TECHNIQUE_DB, tid

    def test_revoked_by_implies_revoked(self) -> None:
        for tid, tech in TECHNIQUE_DB.items():
            if tech["revoked_by"] is not None:
                assert tech["revoked"] is True, tid


class TestTacticDB:
    def test_all_tactics_have_names_urls_and_shortnames(self) -> None:
        for ta_id, tactic in TACTIC_DB.items():
            assert tactic["name"]
            assert tactic["url"] == f"https://attack.mitre.org/tactics/{ta_id}/"
            assert tactic["shortname"]
            assert ta_id.startswith("TA")

    def test_ta0005_is_stealth(self) -> None:
        assert TACTIC_DB["TA0005"]["name"] == "Stealth"
        assert TACTIC_DB["TA0005"]["shortname"] == "stealth"

    def test_defense_impairment_and_reconnaissance_exist(self) -> None:
        assert TACTIC_DB["TA0112"]["name"] == "Defense Impairment"
        assert TACTIC_DB["TA0112"]["shortname"] == "defense-impairment"
        assert TACTIC_DB["TA0043"]["name"] == "Reconnaissance"

    def test_all_tactics_present(self) -> None:
        assert len(TACTIC_DB) == 15
        assert {t["shortname"] for t in TACTIC_DB.values()} == NAVIGATOR_SHORTNAMES

    def test_every_tactic_has_a_shortname(self) -> None:
        assert set(TACTIC_SHORTNAME) == set(TACTIC_DB)
        for ta_id in TACTIC_DB:
            assert tactic_shortname(ta_id) == TACTIC_DB[ta_id]["shortname"]

    def test_unknown_tactic_has_no_shortname(self) -> None:
        assert tactic_shortname("TA9999") is None


class TestLookups:
    def test_lookup_existing_technique(self) -> None:
        result = lookup_technique("T1530")
        assert result is not None
        assert result["name"] == "Data from Cloud Storage"

    def test_lookup_missing_technique(self) -> None:
        assert lookup_technique("T9999") is None

    def test_lookup_existing_tactic(self) -> None:
        result = lookup_tactic("TA0001")
        assert result is not None
        assert result["name"] == "Initial Access"

    def test_lookup_missing_tactic(self) -> None:
        assert lookup_tactic("TA9999") is None


class TestRevocation:
    def test_normalize_maps_revoked_to_current(self) -> None:
        assert normalize_technique("T1562.008") == "T1685.002"

    def test_normalize_leaves_current_and_unknown_ids_alone(self) -> None:
        assert normalize_technique("T1685.002") == "T1685.002"
        assert normalize_technique("T1530") == "T1530"
        assert normalize_technique("T9999") == "T9999"
        assert normalize_technique("not-an-id") == "not-an-id"

    def test_normalize_is_idempotent_and_lands_on_a_known_id(self) -> None:
        assert REVOKED_ALIASES
        for old in REVOKED_ALIASES:
            new = normalize_technique(old)
            assert new not in REVOKED_ALIASES, old
            assert new in TECHNIQUE_DB, old
            assert normalize_technique(new) == new

    def test_normalize_follows_chains(self) -> None:
        chained = [old for old, new in REVOKED_ALIASES.items() if new in REVOKED_ALIASES]
        assert chained, "ATT&CK v19.2 has revoked-by chains; the data should keep them"
        for old in chained:
            assert normalize_technique(old) == normalize_technique(REVOKED_ALIASES[old])

    def test_normalize_survives_an_alias_cycle(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(mitre, "REVOKED_ALIASES", {"T0001": "T0002", "T0002": "T0001"})
        assert normalize_technique("T0001") in {"T0001", "T0002"}

    def test_aliases_agree_with_revoked_by(self) -> None:
        for tid, tech in TECHNIQUE_DB.items():
            if tech["revoked_by"] is not None:
                assert REVOKED_ALIASES[tid] == tech["revoked_by"], tid
        for old, new in REVOKED_ALIASES.items():
            assert TECHNIQUE_DB[old]["revoked_by"] == new

    def test_is_revoked(self) -> None:
        assert is_revoked("T1562.008") is True
        assert is_revoked("T1685.002") is False
        assert is_revoked("T9999") is False

    def test_is_deprecated(self) -> None:
        deprecated = [tid for tid, tech in TECHNIQUE_DB.items() if tech["deprecated"]]
        assert deprecated
        assert all(is_deprecated(tid) for tid in deprecated)
        assert is_deprecated("T1530") is False
        assert is_deprecated("T9999") is False


class TestTacticsForTechniques:
    def test_single_technique(self) -> None:
        assert "TA0009" in tactics_for_techniques(["T1530"])

    def test_multiple_techniques(self) -> None:
        tactics = tactics_for_techniques(["T1530", "T1190"])
        assert "TA0009" in tactics
        assert "TA0001" in tactics

    def test_unknown_technique_ignored(self) -> None:
        assert tactics_for_techniques(["T9999"]) == []

    def test_empty_list(self) -> None:
        assert tactics_for_techniques([]) == []

    def test_result_sorted_and_unique(self) -> None:
        tactics = tactics_for_techniques(["T1530", "T1190", "T1078.004", "T1078"])
        assert tactics == sorted(set(tactics))

    def test_parity_with_the_previous_database(self) -> None:
        for tid, old_tactics in OLD_TACTICS.items():
            expected = TACTICS_CHANGED_BY_ATTACK.get(tid, old_tactics)
            assert tactics_for_techniques([tid]) == sorted(expected), tid

    def test_attack_changes_are_exactly_the_two_verified_ones(self) -> None:
        differing = {
            tid for tid, old in OLD_TACTICS.items() if TECHNIQUE_DB[tid]["tactic_ids"] != old
        }
        assert differing == set(TACTICS_CHANGED_BY_ATTACK)


class TestBoundaryDefaults:
    def test_boundary_values_are_unchanged_in_this_release(self) -> None:
        assert BOUNDARY_TECHNIQUES == ["T1040", "T1557"]
        assert BOUNDARY_TACTICS == ["TA0006", "TA0009"]

    def test_boundary_techniques_valid(self) -> None:
        for tid in BOUNDARY_TECHNIQUES:
            assert tid in TECHNIQUE_DB
            assert not is_revoked(tid)

    def test_boundary_tactics_valid(self) -> None:
        for ta in BOUNDARY_TACTICS:
            assert ta in TACTIC_DB


class TestBuiltinRuleTechniques:
    @staticmethod
    def _rule_techniques() -> dict[str, list[str]]:
        found: dict[str, list[str]] = {}
        for rule in load_builtin_rules():
            mitre_meta = rule.metadata.get("mitre") or {}
            for tid in mitre_meta.get("techniques", []):
                found.setdefault(tid, []).append(rule.id)
        return found

    def test_every_rule_technique_exists_in_the_database(self) -> None:
        missing = {t: ids for t, ids in self._rule_techniques().items() if t not in TECHNIQUE_DB}
        assert missing == {}

    def test_every_rule_tactic_exists_in_the_database(self) -> None:
        bad: dict[str, list[str]] = {}
        for rule in load_builtin_rules():
            for ta in (rule.metadata.get("mitre") or {}).get("tactics", []):
                if ta not in TACTIC_DB:
                    bad.setdefault(ta, []).append(rule.id)
        assert bad == {}

    def test_revoked_rule_techniques_are_reported_not_failed(self) -> None:
        revoked = {t: ids for t, ids in self._rule_techniques().items() if is_revoked(t)}
        if revoked:
            summary = ", ".join(
                f"{t} -> {normalize_technique(t)} ({len(ids)} rules)" for t, ids in revoked.items()
            )
            warnings.warn(
                f"builtin rules still use revoked ATT&CK techniques: {summary}",
                stacklevel=1,
            )


class TestGeneratedModule:
    def test_header_names_version_and_source(self) -> None:
        text = MITRE_DATA.read_text(encoding="utf-8")
        assert "GENERATED FILE" in text
        assert f"ATT&CK v{ATTACK_VERSION}" in text
        assert f"attack-stix-data/v{ATTACK_VERSION}/enterprise-attack/" in text
        assert re.search(rf'^ATTACK_VERSION: str = "{re.escape(ATTACK_VERSION)}"$', text, re.M)

    def test_attack_version_is_the_pinned_release(self) -> None:
        assert ATTACK_VERSION == "19.2"
        assert mitre.ATTACK_SOURCE_URL.endswith(
            "/v19.2/enterprise-attack/enterprise-attack-19.2.json"
        )


class TestGenerator:
    def test_round_trip_on_the_excerpt(self) -> None:
        version, source = gen.generate(_excerpt())
        assert version == "19.2"
        ns = _run_module(source)
        assert ns["ATTACK_VERSION"] == "19.2"
        assert set(ns["TACTICS"]) == set(TACTIC_DB)
        assert ns["TACTICS"]["TA0005"] == TACTIC_DB["TA0005"]
        assert ns["TACTICS"]["TA0112"] == TACTIC_DB["TA0112"]
        assert set(ns["TECHNIQUES"]) == {
            "T1053",
            "T1053.004",
            "T1078",
            "T1078.004",
            "T1133",
            "T1562",
            "T1562.008",
            "T1685",
            "T1685.002",
        }
        # Every excerpt entry equals the committed entry generated from the full bundle.
        for tid, entry in ns["TECHNIQUES"].items():
            assert entry == TECHNIQUE_DB[tid], tid
        assert ns["REVOKED_ALIASES"] == {"T1562": "T1685", "T1562.008": "T1685.002"}

    def test_revoked_deprecated_subtechnique_and_multi_tactic_cases(self) -> None:
        techniques = _run_module(gen.generate(_excerpt())[1])["TECHNIQUES"]
        revoked = techniques["T1562.008"]
        assert revoked["revoked"] is True
        assert revoked["revoked_by"] == "T1685.002"
        assert revoked["deprecated"] is False
        deprecated = techniques["T1053.004"]
        assert deprecated["deprecated"] is True
        assert deprecated["revoked"] is False
        assert deprecated["revoked_by"] is None
        sub = techniques["T1078.004"]
        assert sub["name"] == "Valid Accounts: Cloud Accounts"
        assert sub["url"] == "https://attack.mitre.org/techniques/T1078/004/"
        assert techniques["T1133"]["tactic_ids"] == ["TA0001", "TA0003"]
        assert techniques["T1133"]["platforms"] == sorted(techniques["T1133"]["platforms"])

    def test_generation_is_deterministic_and_order_independent(self) -> None:
        bundle = _excerpt()
        shuffled = copy.deepcopy(bundle)
        shuffled["objects"].reverse()
        assert gen.generate(bundle)[1] == gen.generate(shuffled)[1]

    def test_generated_source_is_valid_python_with_a_header(self) -> None:
        source = gen.generate(_excerpt())[1]
        compile(source, "<generated>", "exec")
        assert source.startswith('"""MITRE ATT&CK enterprise data. GENERATED FILE')
        assert "enterprise-attack-19.2.json" in source.split('"""')[1]

    def test_noise_objects_are_ignored(self) -> None:
        source = gen.generate(_excerpt())[1]
        assert "Noise" not in source
        assert "malware" not in source

    @pytest.mark.parametrize(
        "mutate, message",
        [
            (lambda b: b["objects"].clear(), "x-mitre-collection"),
            (
                lambda b: [
                    b["objects"].remove(o)
                    for o in list(b["objects"])
                    if o["id"].startswith("x-mitre-tactic")
                ],
                "no tactics",
            ),
            (
                lambda b: [
                    b["objects"].remove(o)
                    for o in list(b["objects"])
                    if o.get("external_references", [{}])[0].get("external_id") == "T1078"
                ],
                "no parent",
            ),
        ],
    )
    def test_malformed_bundles_are_rejected(self, mutate: Any, message: str) -> None:
        bundle = _excerpt()
        mutate(bundle)
        with pytest.raises(gen.GenError, match=message):
            gen.generate(bundle)

    def test_unknown_tactic_shortname_is_rejected(self) -> None:
        bundle = _excerpt()
        for obj in bundle["objects"]:
            if obj.get("name") == "External Remote Services":
                obj["kill_chain_phases"][0]["phase_name"] = "no-such-tactic"
        with pytest.raises(gen.GenError, match="unknown tactic shortname"):
            gen.generate(bundle)

    def test_non_bundle_input_is_rejected(self) -> None:
        with pytest.raises(gen.GenError, match="not a STIX bundle"):
            gen.generate({"type": "bundle"})


class TestGeneratorCli:
    def test_stix_to_out_then_check_passes(self, tmp_path: Path) -> None:
        out = tmp_path / "mitre_excerpt.py"
        result = _run_cli("--stix", str(EXCERPT), "--out", str(out))
        assert result.returncode == 0, result.stderr
        assert out.read_text(encoding="utf-8") == gen.generate(_excerpt())[1]
        check = _run_cli("--stix", str(EXCERPT), "--out", str(out), "--check")
        assert check.returncode == 0, check.stderr

    def test_check_detects_a_modified_module(self, tmp_path: Path) -> None:
        out = tmp_path / "mitre_excerpt.py"
        assert _run_cli("--stix", str(EXCERPT), "--out", str(out)).returncode == 0
        out.write_text(
            out.read_text(encoding="utf-8").replace('"Stealth"', '"Defense Evasion"'),
            encoding="utf-8",
        )
        check = _run_cli("--stix", str(EXCERPT), "--out", str(out), "--check")
        assert check.returncode == 1
        assert "Stealth" in check.stderr
        assert "stale" in check.stderr

    def test_check_does_not_write(self, tmp_path: Path) -> None:
        out = tmp_path / "mitre_excerpt.py"
        out.write_text("# stale\n", encoding="utf-8")
        assert _run_cli("--stix", str(EXCERPT), "--out", str(out), "--check").returncode == 1
        assert out.read_text(encoding="utf-8") == "# stale\n"

    def test_check_with_missing_module_is_an_input_error(self, tmp_path: Path) -> None:
        result = _run_cli("--stix", str(EXCERPT), "--out", str(tmp_path / "absent.py"), "--check")
        assert result.returncode == 2

    def test_missing_stix_file_is_an_input_error(self, tmp_path: Path) -> None:
        result = _run_cli("--stix", str(tmp_path / "absent.json"), "--out", str(tmp_path / "o.py"))
        assert result.returncode == 2
        assert "cannot read" in result.stderr

    def test_invalid_json_is_an_input_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        result = _run_cli("--stix", str(bad), "--out", str(tmp_path / "o.py"))
        assert result.returncode == 2
        assert not (tmp_path / "o.py").exists()

    def test_version_mismatch_is_an_input_error(self, tmp_path: Path) -> None:
        result = _run_cli(
            "--stix", str(EXCERPT), "--version", "18.0", "--out", str(tmp_path / "o.py")
        )
        assert result.returncode == 2
        assert "19.2" in result.stderr

    def test_no_pin_and_no_stix_is_an_input_error(self, tmp_path: Path) -> None:
        result = _run_cli("--out", str(tmp_path / "o.py"), "--check")
        assert result.returncode == 2
        assert "no pinned version" in result.stderr
