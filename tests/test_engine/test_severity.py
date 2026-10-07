"""The contextual severity phase: what changes a finding's severity and how it says so.

A rule fixes the base severity.
This phase adds an effective severity when the finding sits on a resource the internet reaches,
on a data store tagged as sensitive, or on an exposure someone marked intentional, and it always
gives the reason.
"""

from __future__ import annotations

from typing import Any

import pytest

from tests.helpers.cli import scan_json
from tests.helpers.scan import FIXTURES_DIR, scan_text
from tests.test_engine.test_paths import (
    APP,
    BUCKET,
    DB,
    LB,
    ROLE,
    bind,
    finding,
    flow,
    graph_of,
    res,
    web_stack,
)
from tests.test_ir.test_reachability import NETWORK, group, ingress, instance
from threatcode.engine import severity
from threatcode.ir.nodes import INTERNET_ID
from threatcode.models.report import ThreatReport, threat_severity
from threatcode.models.threat import Severity, Threat, ThreatSource


def apply(graph: Any, *threats: Threat) -> list[Threat]:
    report = ThreatReport(threats=list(threats))
    severity.apply(report, graph)
    return report.threats


def only(graph: Any, threat: Threat) -> Threat:
    (result,) = apply(graph, threat)
    return result


# ---------------------------------------------------------------------------------------
# Reachable from the internet
# ---------------------------------------------------------------------------------------


class TestReachableFromTheInternet:
    def test_a_reachable_resource_raises_the_finding_one_level_and_says_why(self) -> None:
        threat = finding(APP, Severity.MEDIUM, stride="elevation_of_privilege")
        result = only(web_stack(), threat)
        assert result.severity is Severity.MEDIUM
        assert result.effective_severity is Severity.HIGH
        assert result.severity_reason == (
            "raised one level: aws_instance.app is reachable from the internet "
            "(internet -> aws_lb.front -> aws_instance.app)"
        )
        assert threat_severity(result) is Severity.HIGH

    def test_the_same_finding_on_an_isolated_resource_keeps_its_severity(self) -> None:
        graph = graph_of(res("aws_instance", "app"))
        result = only(graph, finding(APP, Severity.MEDIUM, stride="elevation_of_privilege"))
        assert result.effective_severity is None and result.severity_reason == ""

    def test_the_route_names_the_shortest_way_in(self) -> None:
        graph = web_stack()
        flow(graph, INTERNET_ID, APP)  # a direct way in as well
        result = only(graph, finding(APP, Severity.LOW, stride="tampering"))
        assert result.severity_reason.endswith("(internet -> aws_instance.app)")

    @pytest.mark.parametrize(
        "stride", ["spoofing", "tampering", "information_disclosure", "elevation_of_privilege"]
    )
    def test_the_four_categories_an_outsider_can_use_are_raised(self, stride: str) -> None:
        result = only(web_stack(), finding(APP, Severity.LOW, stride=stride))
        assert result.effective_severity is Severity.MEDIUM

    @pytest.mark.parametrize("stride", ["repudiation", "denial_of_service"])
    def test_the_other_categories_are_not(self, stride: str) -> None:
        result = only(web_stack(), finding(APP, Severity.LOW, stride=stride))
        assert result.effective_severity is None

    def test_a_finding_that_states_the_exposure_itself_is_not_raised(self) -> None:
        for rule_id in ("S3_PUBLIC_ACCESS", "SG_UNRESTRICTED_INGRESS", "EKS_PUBLIC_ENDPOINT"):
            result = only(web_stack(), finding(APP, Severity.MEDIUM, rule_id=rule_id))
            assert result.effective_severity is None, rule_id
        by_cause = finding(APP, Severity.MEDIUM, rule_id="CUSTOM_RULE")
        by_cause.root_cause = "unauthenticated-public-endpoint"
        assert only(web_stack(), by_cause).effective_severity is None
        # A missing firewall is a weakness of what is exposed, so it is raised
        no_waf = finding(APP, Severity.MEDIUM, rule_id="CLOUDFRONT_NO_WAF", stride="tampering")
        assert only(web_stack(), no_waf).effective_severity is Severity.HIGH

    def test_a_finding_on_something_only_reached_through_a_role_is_not_raised(self) -> None:
        """The bucket is reached by a compromised instance, not by a request from outside."""
        graph = web_stack()
        bind(graph, ROLE, BUCKET, "permission", access="read")
        assert only(graph, finding(BUCKET, Severity.MEDIUM)).effective_severity is None
        assert only(graph, finding(APP, Severity.MEDIUM)).effective_severity is Severity.HIGH

    def test_critical_cannot_be_raised(self) -> None:
        result = only(web_stack(), finding(APP, Severity.CRITICAL))
        assert result.effective_severity is None and result.severity_reason == ""

    def test_without_an_internet_node_nothing_is_raised(self) -> None:
        graph = graph_of(res("aws_instance", "app"), res("aws_db_instance", "db"))
        flow(graph, APP, DB)
        assert only(graph, finding(DB, Severity.MEDIUM)).effective_severity is None

    @pytest.mark.parametrize("source", [ThreatSource.BOUNDARY, ThreatSource.LLM])
    def test_boundary_and_llm_findings_are_left_alone(self, source: ThreatSource) -> None:
        result = only(web_stack(), finding(APP, Severity.LOW, source=source))
        assert result.effective_severity is None

    @pytest.mark.parametrize(
        "source", [ThreatSource.RULE, ThreatSource.SECRET, ThreatSource.SCANNER]
    )
    def test_rule_secret_and_scanner_findings_are_raised(self, source: ThreatSource) -> None:
        result = only(web_stack(), finding(APP, Severity.LOW, source=source))
        assert result.effective_severity is Severity.MEDIUM

    def test_a_finding_on_a_node_the_graph_does_not_have_is_left_alone(self) -> None:
        assert only(web_stack(), finding("aws_vpc.gone", Severity.LOW)).effective_severity is None

    def test_the_base_severity_is_never_touched(self) -> None:
        threats = [finding(APP, Severity.LOW), finding(LB, Severity.HIGH)]
        result = apply(web_stack(), *threats)
        assert [t.severity for t in result] == [Severity.LOW, Severity.HIGH]


class TestReachabilityInARealInput:
    def instances(self, *blocks: str) -> list[Threat]:
        return list(scan_text(NETWORK + "\n".join(blocks), "main.tf").report.threats)

    OPEN = group("web", ingress(22, cidr="0.0.0.0/0"))

    def imds(self, threats: list[Threat], address: str) -> Threat:
        (found,) = [
            t for t in threats if t.rule_id == "EC2_IMDSV1" and t.resource_address == address
        ]
        return found

    def test_the_same_rule_gives_different_severities_on_a_public_and_a_private_instance(
        self,
    ) -> None:
        threats = self.instances(
            self.OPEN,
            instance("pub", "pub", "web", public=True),
            instance("priv", "priv", "web"),
        )
        reachable = self.imds(threats, "aws_instance.pub")
        isolated = self.imds(threats, "aws_instance.priv")
        assert reachable.severity is isolated.severity
        assert reachable.effective_severity is not None
        assert reachable.effective_severity > reachable.severity
        assert "reachable from the internet" in reachable.severity_reason
        assert "aws_instance.pub" in reachable.severity_reason
        assert isolated.effective_severity is None

    def test_the_summary_and_the_gate_count_the_effective_severity(self) -> None:
        result = scan_text(
            NETWORK + self.OPEN + instance("pub", "pub", "web", public=True), "main.tf"
        )
        report = result.report
        raised = [t for t in report.threats if t.effective_severity is not None]
        assert raised
        assert sum(report.summary.values()) == len(report.threats)
        by_effective: dict[str, int] = {}
        for threat in report.threats:
            key = threat_severity(threat).value
            by_effective[key] = by_effective.get(key, 0) + 1
        assert report.summary == by_effective
        assert report.filter_by_severity(Severity.HIGH) == [
            t for t in report.threats if threat_severity(t) >= Severity.HIGH
        ]

    def test_the_cli_report_carries_the_effective_severity_and_its_reason(self) -> None:
        run = scan_json([FIXTURES_DIR / "realistic" / "01_aws_ecommerce_platform.json"])
        assert run.exit_code == 0
        raised = [t for t in run.json()["threats"] if "effective_severity" in t]
        assert raised
        for entry in raised:
            assert entry["effective_severity"] != entry["severity"]
            assert entry["severity_reason"]
        quiet = [t for t in run.json()["threats"] if "effective_severity" not in t]
        assert quiet and all("severity_reason" not in t for t in quiet)


# ---------------------------------------------------------------------------------------
# Sensitive data
# ---------------------------------------------------------------------------------------


def store(tags: Any, key: str = "tags") -> Any:
    return graph_of(res("aws_db_instance", "db", **{key: tags}), res("aws_instance", "app"))


class TestSensitiveData:
    @pytest.mark.parametrize(
        ("tags", "shown"),
        [
            ({"DataClassification": "confidential"}, "dataclassification=confidential"),
            ({"DataClassification": "Restricted"}, "dataclassification=Restricted"),
            ({"Compliance": "PCI"}, "compliance=PCI"),
            ({"compliance": "hipaa"}, "compliance=hipaa"),
            ({"COMPLIANCE": "phi"}, "compliance=phi"),
            ({"data_classification": "PII"}, "data_classification=PII"),
            ({"data-classification": "pii"}, "data-classification=pii"),
            ({"Compliance": "SOC2, PCI-DSS"}, "compliance=SOC2, PCI-DSS"),
            (
                {"DataClassification": "PII-EmployeeDocuments"},
                "dataclassification=PII-EmployeeDocuments",
            ),
        ],
    )
    def test_a_sensitive_tag_raises_every_finding_on_the_data_store(
        self, tags: dict[str, str], shown: str
    ) -> None:
        result = only(store(tags), finding(DB, Severity.MEDIUM, stride="repudiation"))
        assert result.effective_severity is Severity.HIGH
        assert result.severity_reason == f"raised one level: the data store is tagged {shown}"

    @pytest.mark.parametrize(
        "tags",
        [
            {"DataClassification": "public"},
            {"DataClassification": "internal"},
            {"Compliance": "SOC2"},
            {"Compliance": "non-PII"},
            {"DataClassification": "no pii here"},
            {"Owner": "pci-team"},
            {"Classification": "restricted"},
            {},
        ],
    )
    def test_other_tags_do_not(self, tags: dict[str, str]) -> None:
        assert only(store(tags), finding(DB, Severity.MEDIUM)).effective_severity is None

    def test_only_a_data_store_is_raised(self) -> None:
        graph = graph_of(res("aws_instance", "app", tags={"DataClassification": "restricted"}))
        assert only(graph, finding(APP, Severity.MEDIUM)).effective_severity is None

    def test_a_cloudformation_tag_list_is_read(self) -> None:
        tags = [{"Key": "DataClassification", "Value": "Restricted"}, {"Key": "x", "Value": "y"}]
        assert (
            only(store(tags, "Tags"), finding(DB, Severity.LOW)).effective_severity
            is Severity.MEDIUM
        )

    def test_labels_count_as_tags(self) -> None:
        graph = store({"compliance": "hipaa"}, "labels")
        assert only(graph, finding(DB, Severity.LOW)).effective_severity is Severity.MEDIUM

    def test_an_unknown_tag_value_is_not_a_classification(self) -> None:
        from threatcode.values import Unknown

        assert only(store({"Compliance": Unknown()}), finding(DB)).effective_severity is None

    def test_the_two_context_raises_add_up(self) -> None:
        graph = web_stack()
        graph.nodes[LB].properties["tags"] = {"Compliance": "pci"}
        graph.nodes[LB].category = graph.nodes[DB].category  # a store that is also reachable
        result = only(graph, finding(LB, Severity.LOW, stride="tampering"))
        assert result.effective_severity is Severity.HIGH
        assert result.severity_reason.count("raised one level") == 2
        assert "reachable from the internet" in result.severity_reason
        assert "tagged compliance=pci" in result.severity_reason

    def test_the_raise_stops_at_critical(self) -> None:
        result = only(store({"Compliance": "pci"}), finding(DB, Severity.CRITICAL))
        assert result.effective_severity is None

    def test_a_high_finding_on_a_pci_store_becomes_critical(self) -> None:
        assert (
            only(store({"Compliance": "pci"}), finding(DB, Severity.HIGH)).effective_severity
            is Severity.CRITICAL
        )


# ---------------------------------------------------------------------------------------
# Intentional exposure
# ---------------------------------------------------------------------------------------


def bucket(tags: Any) -> Any:
    return graph_of(res("aws_s3_bucket", "data", tags=tags))


class TestIntentionalExposure:
    @pytest.mark.parametrize(
        ("tags", "shown"),
        [
            ({"Public": "true"}, "public=true"),
            ({"public": True}, "public=true"),
            ({"PUBLIC": "TRUE"}, "public=TRUE"),
            ({"Intent": "public"}, "intent=public"),
            ({"intent": "Public"}, "intent=Public"),
            ({"threatcode:intent": "public"}, "threatcode:intent=public"),
            ({"ThreatCode:Intent": "public"}, "threatcode:intent=public"),
        ],
    )
    def test_a_marked_exposure_finding_is_one_level_lower(
        self, tags: dict[str, Any], shown: str
    ) -> None:
        result = only(bucket(tags), finding(BUCKET, Severity.CRITICAL, rule_id="S3_PUBLIC_ACCESS"))
        assert result.severity is Severity.CRITICAL
        assert result.effective_severity is Severity.HIGH
        assert "marked intentional" in result.severity_reason
        assert result.severity_reason == f"lowered one level: marked intentional: {shown}"

    @pytest.mark.parametrize(
        "tags",
        [{"Public": "false"}, {"Intent": "private"}, {"Visibility": "public"}, {}, None],
    )
    def test_without_the_mark_the_finding_keeps_its_base_severity(self, tags: Any) -> None:
        result = only(bucket(tags), finding(BUCKET, Severity.CRITICAL, rule_id="S3_PUBLIC_ACCESS"))
        assert result.effective_severity is None

    def test_a_finding_that_is_not_about_exposure_is_not_lowered(self) -> None:
        result = only(
            bucket({"Public": "true"}), finding(BUCKET, Severity.HIGH, rule_id="S3_NO_VERSIONING")
        )
        assert result.effective_severity is None

    def test_the_finding_is_lowered_but_never_silenced_or_dropped(self) -> None:
        threat = finding(BUCKET, Severity.LOW, rule_id="S3_PUBLIC_ACCESS")
        report = ThreatReport(threats=[threat])
        severity.apply(report, bucket({"Public": "true"}))
        assert report.threats == [threat]
        assert threat.effective_severity is Severity.INFO
        assert threat.effective_severity is not None
        assert threat_severity(threat) is Severity.INFO

    def test_the_floor_is_info(self) -> None:
        result = only(
            bucket({"Public": "true"}), finding(BUCKET, Severity.INFO, rule_id="S3_PUBLIC_ACCESS")
        )
        assert result.effective_severity is None

    def test_a_lowering_and_a_sensitive_tag_cancel_out(self) -> None:
        tags = {"Public": "true", "DataClassification": "confidential"}
        result = only(bucket(tags), finding(BUCKET, Severity.HIGH, rule_id="S3_PUBLIC_ACCESS"))
        assert result.effective_severity is None
        assert result.severity_reason == ""

    def test_the_whole_scan_applies_the_mark_to_the_real_rule(self) -> None:
        text = """
resource "aws_s3_bucket" "site" {
  bucket = "site"
  tags = { Public = "true" }
}
resource "aws_s3_bucket_acl" "site" {
  bucket = aws_s3_bucket.site.id
  acl    = "public-read"
}
"""
        marked = scan_text(text, "main.tf")
        (public,) = [t for t in marked.threats if t.rule_id == "S3_PUBLIC_ACCESS"]
        assert public.effective_severity is not None
        assert public.effective_severity < public.severity
        assert "marked intentional: public=true" in public.severity_reason
        plain = scan_text(text.replace('tags = { Public = "true" }', ""), "main.tf")
        (unmarked,) = [t for t in plain.threats if t.rule_id == "S3_PUBLIC_ACCESS"]
        assert unmarked.effective_severity is None


class TestClassifier:
    @pytest.mark.parametrize(
        "rule_id",
        [
            "S3_PUBLIC_ACCESS",
            "RDS_PUBLIC_ACCESS",
            "SG_UNRESTRICTED_INGRESS",
            "AZURE_NSG_ALLOW_ALL_INBOUND",
            "AZURE_NSG_SSH_OPEN",
            "EKS_PUBLIC_ENDPOINT",
            "APIGW_METHOD_NO_AUTH",
            "LAMBDA_URL_NO_AUTH",
            "GKE_MASTER_WORLD_ACCESS",
        ],
    )
    def test_builtin_rules_that_state_an_exposure(self, rule_id: str) -> None:
        assert severity.is_exposure_finding(finding(APP, rule_id=rule_id))

    @pytest.mark.parametrize(
        "rule_id",
        [
            "S3_NO_VERSIONING",
            "EC2_IMDSV1",
            "IAM_WILDCARD_ACTION",
            "K8S_RUN_AS_ROOT",
            "CLOUDFRONT_NO_WAF",
            "WAFV2_NO_XSS_RULE",
            "EKS_OUTDATED_VERSION",
            "SAGEMAKER_NOTEBOOK_DIRECT_INTERNET",
            "ELASTICACHE_NO_AUTH",
        ],
    )
    def test_builtin_rules_that_do_not(self, rule_id: str) -> None:
        assert not severity.is_exposure_finding(finding(APP, rule_id=rule_id))

    @pytest.mark.parametrize(
        ("rule_id", "expected"),
        [
            ("MY_PUBLIC_BUCKET", True),
            ("CUSTOM_WORLD_READABLE", True),
            ("CUSTOM_ALLOW_ALL_TRAFFIC", True),
            ("CUSTOM_OPEN_PORT", True),
            ("CUSTOM_ALLOW_SOME", False),
            ("CUSTOM_OPENSEARCH_LOGS", False),
            ("CUSTOM_NO_WAF", False),
            ("", False),
        ],
    )
    def test_a_rule_without_a_root_cause_is_judged_by_the_words_of_its_id(
        self, rule_id: str, expected: bool
    ) -> None:
        assert severity.is_exposure_finding(finding(APP, rule_id=rule_id)) is expected

    def test_the_root_cause_on_the_finding_wins_over_the_words(self) -> None:
        threat = finding(APP, rule_id="CUSTOM_PUBLIC_THING")
        threat.root_cause = "waf-protection-missing"
        assert not severity.is_exposure_finding(threat)
        threat.root_cause = "s3-public-access"
        assert severity.is_exposure_finding(threat)

    def test_every_exposure_root_cause_belongs_to_a_builtin_rule(self) -> None:
        from threatcode.engine.rules.loader import load_builtin_rules

        known = {rule.root_cause for rule in load_builtin_rules()}
        assert severity.EXPOSURE_ROOT_CAUSES <= known
