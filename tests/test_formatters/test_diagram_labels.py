"""Tests for the words the diagram, Mermaid and Markdown formats share."""

from __future__ import annotations

from typing import Any

import pytest

from threatcode.formatters.diagram_labels import (
    edge_label,
    edge_phrase,
    first_sentence,
    friendly_noun,
    hop_enablers,
    humanize_tokens,
    node_labels,
    ordered_attack_paths,
    port_phrase,
    shared_prefix_length,
    short_type,
    shorten_address,
    shorten_middle,
)
from threatcode.models.attack_path import AttackHop, AttackPath
from threatcode.models.threat import Severity, Threat, ThreatSource


def threat(threat_id: str, severity: Severity, title: str, rule_id: str = "") -> Threat:
    return Threat(
        id=threat_id,
        title=title,
        description="d",
        stride_category="tampering",
        severity=severity,
        source=ThreatSource.RULE,
        resource_type="aws_s3_bucket",
        resource_address="a.b",
        rule_id=rule_id,
    )


class TestPorts:
    @pytest.mark.parametrize(
        ("via", "phrase"),
        [
            ({"ports": ["443"], "protocol": "tcp"}, "HTTPS 443"),
            ({"ports": ["443"]}, "HTTPS 443"),
            ({"ports": [443]}, "HTTPS 443"),
            ({"port": "5432"}, "PostgreSQL 5432"),
            ({"ports": ["8080"]}, "tcp/8080"),
            ({"ports": ["53"], "protocol": "udp"}, "udp/53"),
            ({"ports": ["443"], "protocol": "https"}, "HTTPS 443"),
            ({"ports": ["8000-8100"]}, "tcp/8000-8100"),
            ({"ports": ["80", "443"]}, "tcp/80,443"),
            ({"ports": ["1", "2", "3", "4"]}, "tcp/1,2,3,..."),
            ({}, ""),
            ({"ports": []}, ""),
            ({"ports": True}, ""),
        ],
    )
    def test_ports_in_words(self, via: dict[str, Any], phrase: str) -> None:
        assert port_phrase(via) == phrase


class TestEdgeWords:
    @pytest.mark.parametrize(
        ("edge_type", "relation", "via", "short"),
        [
            ("network_flow", "", {"ports": ["443"]}, "HTTPS 443"),
            ("network_flow", "", {}, "traffic"),
            ("network_flow", "backend", {"ports": ["80"]}, "HTTP 80"),
            ("network_flow", "selects", {}, "selects"),
            ("iam_binding", "assumes", {}, "assumes"),
            ("iam_binding", "instance_profile", {}, "uses profile"),
            ("iam_binding", "invokes", {"protocol": "stdio"}, "invokes"),
            ("iam_binding", "permission", {"access": "read"}, "can read"),
            ("iam_binding", "permission", {"access": "write"}, "can write"),
            ("iam_binding", "permission", {"access": "admin"}, "full access"),
            ("iam_binding", "permission", {}, "permission"),
            ("iam_binding", "", {}, "permissions"),
            ("data_flow", "returns_content", {}, "returns content"),
            ("data_flow", "reads_secret", {}, "reads"),
            ("data_flow", "", {}, "data flow"),
            ("dependency", "security_group", {}, "security group"),
            ("dependency", "", {}, "depends on"),
            ("dependency", "grants_extra_access", {}, "grants extra access"),
        ],
    )
    def test_the_short_label(
        self, edge_type: str, relation: str, via: dict[str, Any], short: str
    ) -> None:
        assert edge_label(edge_type, relation, via) == short

    def test_the_relation_can_come_from_the_hops_via(self) -> None:
        assert edge_label("iam_binding", via={"relation": "assumes"}) == "assumes"
        assert edge_phrase(
            "iam_binding", via={"relation": "assumes"}, target_type="aws_iam_role"
        ) == ("assumes the role")

    def test_no_edge_type_means_no_words(self) -> None:
        assert edge_label(None) == "" and edge_label("") == ""
        assert edge_phrase(None) == ""

    @pytest.mark.parametrize(
        ("edge_type", "relation", "via", "target", "phrase"),
        [
            ("network_flow", "", {"ports": ["443"]}, "aws_lb", "sends traffic on HTTPS 443"),
            ("network_flow", "", {}, "aws_instance", "sends traffic to the instance"),
            (
                "network_flow",
                "backend",
                {"ports": ["80"]},
                "kubernetes_service",
                "routes requests to the service on HTTP 80",
            ),
            (
                "iam_binding",
                "instance_profile",
                {},
                "aws_iam_instance_profile",
                "runs with the instance profile",
            ),
            ("iam_binding", "assumes", {}, "aws_iam_role", "assumes the role"),
            ("iam_binding", "can_assume", {}, "aws_iam_role", "can assume the role"),
            (
                "iam_binding",
                "runs_as",
                {},
                "kubernetes_service_account",
                "runs as the service account",
            ),
            (
                "iam_binding",
                "bound_role",
                {},
                "kubernetes_cluster_role",
                "is bound to the cluster role",
            ),
            (
                "iam_binding",
                "invokes",
                {"protocol": "stdio"},
                "mcp_server",
                "invokes the MCP server over stdio",
            ),
            (
                "iam_binding",
                "permission",
                {"access": "admin", "actions": ["*"]},
                "aws_s3_bucket",
                "has full access to the bucket (*)",
            ),
            (
                "iam_binding",
                "permission",
                {"access": "read", "actions": ["a", "b", "c"]},
                "aws_s3_bucket",
                "can read the bucket (a, b, ...)",
            ),
            ("data_flow", "reads_secret", {}, "kubernetes_secret", "reads the secret"),
            (
                "data_flow",
                "remote_server",
                {"protocol": "http"},
                "mcp_server",
                "reaches the MCP server over http",
            ),
            (
                "iam_binding",
                "made_up_relation",
                {},
                "aws_foo_bar",
                "is linked to the foo bar (made up relation)",
            ),
        ],
    )
    def test_the_phrase(
        self, edge_type: str, relation: str, via: dict[str, Any], target: str, phrase: str
    ) -> None:
        assert edge_phrase(edge_type, relation, via, target) == phrase

    def test_no_phrase_leaves_a_placeholder_or_a_raw_token(self) -> None:
        for edge_type in ("network_flow", "data_flow", "iam_binding", "dependency", "containment"):
            for relation in ("", "assumes", "weird_one"):
                text = edge_phrase(edge_type, relation, {}, "")
                assert "{" not in text and "_" not in text.replace("next hop", "")
                assert edge_type not in text

    def test_internal_tokens_read_as_words(self) -> None:
        text = "crosses (network_flow) and (data_flow) via iam_binding; network_flows stay"
        assert humanize_tokens(text) == (
            "crosses (network traffic) and (data flow) via IAM binding; network_flows stay"
        )


class TestTypeNames:
    @pytest.mark.parametrize(
        ("resource_type", "short"),
        [
            ("aws_iam_role", "role"),
            ("aws_iam_instance_profile", "profile"),
            ("aws_security_group", "sg"),
            ("kubernetes_ingress", "ingress"),
            ("kubernetes_cluster_role_binding", "role_binding"),
            ("kubernetes_service", "service"),
            ("azurerm_storage_account", "storage_account"),
            ("google_compute_instance", "compute_instance"),
            ("aws_s3_bucket_public_access_block", "access_block"),
            ("mcp_server", "server"),
            ("thing", "thing"),
            ("", ""),
        ],
    )
    def test_short_type(self, resource_type: str, short: str) -> None:
        assert short_type(resource_type) == short

    def test_nouns(self) -> None:
        assert friendly_noun("aws_iam_instance_profile") == "instance profile"
        assert friendly_noun("aws_lambda_function") == "lambda"
        assert friendly_noun("") == "next hop"


class TestNodeLabels:
    def test_a_unique_name_stays_as_it_is(self) -> None:
        labels = node_labels([("aws_instance.app[0]", "aws_instance"), ("aws_db.main", "aws_db")])
        assert labels == {"aws_instance.app[0]": "app[0]", "aws_db.main": "main"}

    def test_names_that_collide_get_their_type(self) -> None:
        labels = node_labels(
            [
                ("aws_iam_role.app", "aws_iam_role"),
                ("aws_iam_instance_profile.app", "aws_iam_instance_profile"),
                ("aws_lb_target_group.app", "aws_lb_target_group"),
                ("aws_instance.app[0]", "aws_instance"),
            ]
        )
        assert labels == {
            "aws_iam_role.app": "role.app",
            "aws_iam_instance_profile.app": "profile.app",
            "aws_lb_target_group.app": "target_group.app",
            "aws_instance.app[0]": "app[0]",
        }

    def test_kubernetes_kinds_are_written_with_a_slash(self) -> None:
        labels = node_labels(
            [
                ("kubernetes_ingress.platform.storefront", "kubernetes_ingress"),
                ("kubernetes_service.platform.storefront", "kubernetes_service"),
                ("kubernetes_deployment.platform.storefront", "kubernetes_deployment"),
            ]
        )
        assert labels == {
            "kubernetes_ingress.platform.storefront": "ingress/storefront",
            "kubernetes_service.platform.storefront": "service/storefront",
            "kubernetes_deployment.platform.storefront": "deployment/storefront",
        }

    def test_the_same_type_and_name_in_two_namespaces_stay_apart(self) -> None:
        labels = node_labels(
            [
                ("kubernetes_service.a.web", "kubernetes_service"),
                ("kubernetes_service.b.web", "kubernetes_service"),
            ]
        )
        assert labels["kubernetes_service.a.web"] != labels["kubernetes_service.b.web"]
        assert labels["kubernetes_service.a.web"].endswith("a.web")

    def test_a_dot_inside_an_index_is_not_a_separator(self) -> None:
        labels = node_labels([('aws_s3_bucket.b["x.y"]', "aws_s3_bucket")])
        assert labels == {'aws_s3_bucket.b["x.y"]': 'b["x.y"]'}

    def test_a_logical_name_after_a_file_is_the_name(self) -> None:
        labels = node_labels([("a/b/template.yaml::HelloFunction", "aws_serverless_function")])
        assert labels == {"a/b/template.yaml::HelloFunction": "HelloFunction"}

    def test_a_dockerfile_instruction_keeps_its_kind(self) -> None:
        labels = node_labels([("dockerfile.run.3", "dockerfile_run")])
        assert labels == {"dockerfile.run.3": "run.3"}

    def test_a_long_name_keeps_both_ends(self) -> None:
        name = "x" * 30 + "-the-end"
        label = node_labels([(f"aws_s3_bucket.{name}", "aws_s3_bucket")], limit=24)[
            f"aws_s3_bucket.{name}"
        ]
        assert len(label) <= 24 and label.endswith("-the-end") and "..." in label


class TestShortening:
    def test_a_short_text_is_untouched(self) -> None:
        assert shorten_middle("abc", 10) == "abc" and shorten_address("a/b/c", 10) == "a/b/c"

    def test_the_end_gets_the_larger_share(self) -> None:
        out = shorten_middle("a" * 50 + "TAIL", 20)
        assert len(out) <= 20 and out.endswith("TAIL")
        assert out.index("...") < len(out) - out.index("...") - 3

    def test_a_tiny_limit_still_returns_something_that_fits(self) -> None:
        assert len(shorten_middle("abcdefghij", 3)) <= 3

    def test_whole_middle_segments_go_first(self) -> None:
        text = "python3.10/step-func/{{x}}/template.yaml::Fn"
        assert shorten_address(text, 42) == "python3.10/step-func/.../template.yaml::Fn"
        assert shorten_address(text, 32) == "python3.10/.../template.yaml::Fn"
        assert len(shorten_address(text, 30)) <= 30

    def test_an_address_without_slashes_is_cut_in_the_middle(self) -> None:
        out = shorten_address(
            "aws_s3_bucket_server_side_encryption_configuration.customer_data", 30
        )
        assert len(out) <= 30 and out.endswith("customer_data") and "..." in out

    def test_first_sentence(self) -> None:
        assert first_sentence("One thing. Another thing.") == "One thing."
        assert first_sentence("Only one") == "Only one"
        assert first_sentence("Use e.g. a role. Then more.") == "Use e.g. a role."
        assert first_sentence("Version 1.2.3 is old. Update.") == "Version 1.2.3 is old."
        assert first_sentence("Line one\nstill one. Two.") == "Line one still one."
        assert first_sentence("") == ""


class TestHopEnablers:
    def path(self) -> AttackPath:
        return AttackPath(
            id="p",
            entry="a",
            target="d",
            hops=[
                AttackHop("a", enabled_by=["sg"]),
                AttackHop("b", enabled_by=["sg"]),
                AttackHop("c", enabled_by=["low", "cve", "gone"]),
                AttackHop("d", enabled_by=["sg"]),
            ],
        )

    def by_id(self) -> dict[str, Threat]:
        return {
            "sg": threat("sg", Severity.LOW, "Open group", "SG_OPEN"),
            "low": threat("low", Severity.MEDIUM, "Medium one", "MED"),
            "cve": threat("cve", Severity.CRITICAL, "Bad image", ""),
        }

    def test_a_finding_on_the_hop_before_is_not_repeated(self) -> None:
        found = hop_enablers(self.path(), self.by_id())
        assert [[e.threat_id for e in hop] for hop in found] == [
            ["sg"],
            [],
            ["cve", "low", "gone"],
            ["sg"],
        ]

    def test_worst_first_with_a_label_and_unknown_ids_kept(self) -> None:
        third = hop_enablers(self.path(), self.by_id())[2]
        assert [e.label for e in third] == ["rule", "MED", "gone"]
        assert [e.known for e in third] == [True, True, False]
        assert third[2].severity is None and third[2].title == ""

    def test_a_repeated_id_on_one_hop_is_listed_once(self) -> None:
        path = AttackPath(
            id="p",
            entry="a",
            target="b",
            hops=[AttackHop("a", enabled_by=["x", "x"]), AttackHop("b")],
        )
        found = hop_enablers(path, {"x": threat("x", Severity.LOW, "X", "X")})
        assert len(found[0]) == 1


class TestSharedPrefix:
    def hop(self, node_id: str, edge: str | None, **via: Any) -> AttackHop:
        return AttackHop(node_id=node_id, edge_type_to_next=edge, via=via)

    def path(self, *hops: AttackHop) -> AttackPath:
        return AttackPath(id="p", entry=hops[0].node_id, target=hops[-1].node_id, hops=list(hops))

    def test_the_longest_shared_run_and_its_path(self) -> None:
        first = self.path(
            self.hop("a", "network_flow", ports=["443"]),
            self.hop("b", "network_flow", ports=["80"]),
            self.hop("c", "iam_binding", relation="assumes"),
            self.hop("d", None),
        )
        second = self.path(
            self.hop("a", "network_flow", ports=["443"]),
            self.hop("b", "network_flow", ports=["80"]),
            self.hop("c", "network_flow", ports=["5432"]),
            self.hop("e", None),
        )
        other = self.path(self.hop("a", "network_flow", ports=["443"]), self.hop("z", None))
        assert shared_prefix_length(second, [other, first]) == (2, 1)

    def test_the_same_node_with_other_ports_is_not_shared(self) -> None:
        first = self.path(self.hop("a", "network_flow", ports=["443"]), self.hop("b", None))
        second = self.path(self.hop("a", "network_flow", ports=["80"]), self.hop("b", None))
        assert shared_prefix_length(second, [first]) == (0, -1)

    def test_no_earlier_path_means_nothing_shared(self) -> None:
        assert shared_prefix_length(self.path(self.hop("a", None)), []) == (0, -1)


class TestOrderedAttackPaths:
    def path(self, path_id: str, severity: Severity, score: float) -> AttackPath:
        return AttackPath(
            id=path_id,
            entry="entry",
            target=f"target-{path_id}",
            hops=[AttackHop("entry"), AttackHop(f"target-{path_id}")],
            severity=severity,
            score=score,
        )

    def ids(self, paths: list[AttackPath]) -> list[str]:
        return [p.id for p in ordered_attack_paths(paths)]

    def test_severity_comes_before_score(self) -> None:
        paths = [
            self.path("a", Severity.HIGH, 9.9),
            self.path("b", Severity.CRITICAL, 5.0),
            self.path("c", Severity.MEDIUM, 9.9),
        ]
        assert self.ids(paths) == ["b", "a", "c"]

    def test_score_comes_before_id_within_a_severity(self) -> None:
        paths = [self.path("a", Severity.HIGH, 5.0), self.path("z", Severity.HIGH, 8.0)]
        assert self.ids(paths) == ["z", "a"]

    def test_a_tie_on_severity_and_score_is_broken_by_id_whatever_the_input_order(self) -> None:
        tied = [self.path(i, Severity.CRITICAL, 9.0) for i in ("e716", "1e87", "5453")]
        assert self.ids(tied) == ["1e87", "5453", "e716"]
        assert self.ids(tied[::-1]) == ["1e87", "5453", "e716"]

    def test_the_input_is_left_as_it_was(self) -> None:
        paths = [self.path("b", Severity.LOW, 1.0), self.path("a", Severity.LOW, 1.0)]
        ordered_attack_paths(paths)
        assert [p.id for p in paths] == ["b", "a"]

    def test_no_paths_is_an_empty_list(self) -> None:
        assert ordered_attack_paths([]) == []
