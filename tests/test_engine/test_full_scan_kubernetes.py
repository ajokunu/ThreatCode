"""End-to-end scan tests for Kubernetes manifests."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.rules.loader import load_all_rules
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import Severity, ThreatSource
from threatcode.parsers import detect_and_parse

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "kubernetes"


def _scan(name: str) -> dict[str, set[str]]:
    path = FIXTURES_DIR / name
    graph = InfraGraph.from_parsed(detect_and_parse(path))
    report = HybridEngine().analyze(graph, input_file=str(path))
    found: dict[str, set[str]] = defaultdict(set)
    for threat in report.threats:
        if threat.source == ThreatSource.RULE:
            found[threat.resource_address].add(threat.rule_id)
    return found


class TestInsecureDeployment:
    def test_the_headline_findings_fire(self) -> None:
        (rule_ids,) = _scan("insecure_deployment.yml").values()
        assert {
            "K8S_PRIVILEGED_CONTAINER",
            "K8S_HOST_NETWORK",
            "K8S_HOST_PID",
            "K8S_LATEST_TAG",
            "K8S_HOST_PATH_VOLUME",
            "K8S_RUN_AS_ROOT",
            "K8S_DANGEROUS_CAPABILITIES",
        } <= rule_ids


class TestSecureDeployment:
    def test_nothing_serious_fires(self) -> None:
        path = FIXTURES_DIR / "secure_deployment.yml"
        graph = InfraGraph.from_parsed(detect_and_parse(path))
        report = HybridEngine().analyze(graph, input_file=str(path))
        serious = [t.rule_id for t in report.threats if t.severity >= Severity.HIGH]
        assert serious == []


class TestMultiResourceManifest:
    def test_each_kind_gets_only_the_rules_written_for_it(self) -> None:
        found = _scan("multi_resource.yml")
        rules = {r.id: r for r in load_all_rules()}
        graph = InfraGraph.from_parsed(detect_and_parse(FIXTURES_DIR / "multi_resource.yml"))
        for address, rule_ids in found.items():
            for rule_id in rule_ids:
                assert rules[rule_id].matches_type(graph.nodes[address].resource_type), (
                    address,
                    rule_id,
                )

    def test_the_cluster_admin_binding_is_reported_on_the_binding_only(self) -> None:
        found = _scan("multi_resource.yml")
        by_rule = defaultdict(set)
        for address, rule_ids in found.items():
            for rule_id in rule_ids:
                by_rule[rule_id].add(address)
        assert {a.split(".")[0] for a in by_rule["K8S_CLUSTER_ADMIN_BINDING"]} == {
            "kubernetes_cluster_role_binding"
        }
        assert {a.split(".")[0] for a in by_rule["K8S_WILDCARD_RBAC_VERBS"]} == {
            "kubernetes_cluster_role"
        }

    def test_service_account_gets_its_own_rule_and_nothing_else(self) -> None:
        found = _scan("multi_resource.yml")
        account = next(a for a in found if a.startswith("kubernetes_service_account."))
        assert found[account] == {"K8S_AUTOMOUNT_DEFAULT"}


# ---------------------------------------------------------------------------------------
# Inputs the parser now understands: List kinds, JSON, mixed files, every workload kind,
# effective security context and connected manifests
# ---------------------------------------------------------------------------------------

REAL_SHAPES = Path(__file__).parent.parent / "fixtures" / "real_shapes" / "kubernetes"


def _scan_all(path: Path) -> tuple[InfraGraph, dict[str, set[str]]]:
    graph = InfraGraph.from_parsed(detect_and_parse(path))
    report = HybridEngine().analyze(graph, input_file=str(path))
    found: dict[str, set[str]] = defaultdict(set)
    for threat in report.threats:
        if threat.source == ThreatSource.RULE:
            found[threat.resource_address].add(threat.rule_id)
    return graph, found


class TestKubectlOutput:
    def test_a_kubectl_yaml_list_is_one_resource_per_item_with_the_privileged_finding(self) -> None:
        graph, found = _scan_all(FIXTURES_DIR / "list_pod_deployment.yaml")
        assert sorted(graph.nodes) == [
            "kubernetes_deployment.ops.metrics",
            "kubernetes_pod.ops.debug-shell",
        ]
        assert "K8S_PRIVILEGED_CONTAINER" in found["kubernetes_pod.ops.debug-shell"]
        assert "K8S_PRIVILEGED_CONTAINER" not in found["kubernetes_deployment.ops.metrics"]

    def test_a_kubectl_json_deployment_list_scans_like_its_yaml_form(self) -> None:
        graph, found = _scan_all(FIXTURES_DIR / "deployment_list.json")
        assert sorted(graph.nodes) == [
            "kubernetes_deployment.finance.billing",
            "kubernetes_deployment.finance.ledger",
        ]
        assert "K8S_PRIVILEGED_CONTAINER" in found["kubernetes_deployment.finance.billing"]
        assert "K8S_PRIVILEGED_CONTAINER" not in found["kubernetes_deployment.finance.ledger"]

    def test_the_real_kubectl_output_in_both_encodings_gives_the_same_scan(self) -> None:
        yaml_graph, yaml_found = _scan_all(REAL_SHAPES / "kubectl_get_all.yaml")
        json_graph, json_found = _scan_all(REAL_SHAPES / "kubectl_get_all.json")
        assert sorted(yaml_graph.nodes) == sorted(json_graph.nodes)
        assert dict(yaml_found) == dict(json_found)
        edges = {(e.source, e.target) for e in yaml_graph.edges}
        assert (
            "kubernetes_service.stock.inventory",
            "kubernetes_deployment.stock.inventory",
        ) in edges

    def test_a_mixed_file_scans_its_kubernetes_documents_and_names_what_it_skipped(self) -> None:
        path = FIXTURES_DIR / "mixed_documents.yml"
        parsed = detect_and_parse(path)
        graph = InfraGraph.from_parsed(parsed)
        assert sorted(graph.nodes) == [
            "kubernetes_config_map.mixed.settings",
            "kubernetes_pod.mixed.probe",
        ]
        codes = [d.code for d in graph.diagnostics]
        assert codes.count("k8s.skipped_document") == 2

    def test_the_command_line_lists_one_resource_per_item(self) -> None:
        from tests.helpers.cli import run_cli

        run = run_cli(
            ["scan", str(FIXTURES_DIR / "deployment_list.json"), "-f", "json", "--no-llm"]
        )
        threats = run.json()["threats"]
        privileged = {
            t["resource_address"] for t in threats if t["rule_id"] == "K8S_PRIVILEGED_CONTAINER"
        }
        assert privileged == {"kubernetes_deployment.finance.billing"}
        addresses = {t["resource_address"] for t in threats}
        assert "kubernetes_deployment.finance.ledger" in addresses


class TestEveryWorkloadKind:
    def test_the_same_pod_spec_gets_the_same_findings_in_all_seven_kinds(self) -> None:
        graph, found = _scan_all(FIXTURES_DIR / "workload_kinds.yml")
        assert len(graph.nodes) == 7
        baseline = found["kubernetes_deployment.kinds.deployment"]
        assert {
            "K8S_PRIVILEGED_CONTAINER",
            "K8S_HOST_NETWORK",
            "K8S_DANGEROUS_CAPABILITIES",
        } <= baseline
        for address, rule_ids in found.items():
            assert rule_ids == baseline, address

    def test_the_real_workload_file_reads_each_kind_through_its_own_pod_template(self) -> None:
        _, found = _scan_all(REAL_SHAPES / "workloads.yaml")
        # the privileged sidecar of the Deployment, the privileged DaemonSet, nothing else
        privileged = {a for a, ids in found.items() if "K8S_PRIVILEGED_CONTAINER" in ids}
        assert privileged == {
            "kubernetes_deployment.platform.api",
            "kubernetes_daemon_set.platform.node-agent",
        }
        # the CronJob nests its pod spec three levels down; its pod-level context is read there
        graph = InfraGraph.from_parsed(detect_and_parse(REAL_SHAPES / "workloads.yaml"))
        cron = graph.nodes["kubernetes_cron_job.platform.nightly-report"].properties
        assert cron["seccomp_profile_type"] == "RuntimeDefault"
        assert cron["run_as_root"] is False


class TestEffectiveSecurityContext:
    def test_pod_level_settings_apply_and_a_container_overrides_one_field(self) -> None:
        graph = InfraGraph.from_parsed(detect_and_parse(FIXTURES_DIR / "pod_level_context.yml"))
        props = graph.nodes["kubernetes_deployment.apps.pod-level"].properties
        assert props["seccomp_profile_type"] == "RuntimeDefault"
        assert props["container_findings"]["run_as_root"] == ["root-helper"]
        assert props["pod_run_as_user"] == 10001

    def test_the_weak_container_makes_the_workload_weak_whatever_its_position(self) -> None:
        graph = InfraGraph.from_parsed(detect_and_parse(FIXTURES_DIR / "multi_container.yml"))
        props = graph.nodes["kubernetes_deployment.apps.sidecar-mix"].properties
        assert props["allow_privilege_escalation"] is True
        assert props["writable_root_fs"] is True
        assert props["run_as_root"] is True
        assert props["container_findings"]["allow_privilege_escalation"] == ["bad"]
        _, found = _scan_all(FIXTURES_DIR / "multi_container.yml")
        assert {
            "K8S_ALLOW_PRIVILEGE_ESCALATION",
            "K8S_WRITABLE_ROOT_FS",
            "K8S_RUN_AS_ROOT",
        } <= found["kubernetes_deployment.apps.sidecar-mix"]

    def test_a_pod_level_non_root_user_silences_the_run_as_root_rule(self) -> None:
        _, found = _scan_all(REAL_SHAPES / "shop_stack.yaml")
        assert "K8S_RUN_AS_ROOT" not in found["kubernetes_deployment.shop.web"]

    def test_a_service_account_that_disables_the_mount_is_reflected_on_the_workload(self) -> None:
        graph = InfraGraph.from_parsed(detect_and_parse(REAL_SHAPES / "shop_stack.yaml"))
        props = graph.nodes["kubernetes_deployment.shop.web"].properties
        assert props["effective_automount_sa_token"] is False
        assert props["sa_resolved"] is True

    def test_an_ingress_without_tls_fires_the_tls_rule_and_one_with_tls_does_not(self) -> None:
        _, found = _scan_all(FIXTURES_DIR / "graph_stack.yml")
        assert "K8S_INGRESS_NO_TLS" not in found["kubernetes_ingress.default.web"]
        stripped = (
            (FIXTURES_DIR / "graph_stack.yml")
            .read_text()
            .replace("  tls:\n    - hosts: [shop.example.com]\n      secretName: shop-tls\n", "")
        )
        from tests.helpers.scan import scan_text

        result = scan_text(stripped, "graph_stack.yml")
        assert result.fired("K8S_INGRESS_NO_TLS", "kubernetes_ingress.default.web")


class TestConnectedManifests:
    def test_the_graph_stack_is_connected(self) -> None:
        graph = InfraGraph.from_parsed(detect_and_parse(FIXTURES_DIR / "graph_stack.yml"))
        assert len(graph.edges) >= 8
        zones = {n.id: n.trust_zone.value for n in graph.nodes.values()}
        assert zones["kubernetes_service.default.web-lb"] == "dmz"
        assert zones["kubernetes_service.default.web-np"] == "dmz"
        assert zones["kubernetes_service.default.api-internal"] == "private"
        assert zones["kubernetes_config_map.default.web-config"] == "private"
        assert zones["kubernetes_secret.default.db-creds"] == "data"

    def test_the_ingress_to_cluster_role_chain_has_five_linked_edges_and_two_reach_edges(
        self,
    ) -> None:
        graph = InfraGraph.from_parsed(
            detect_and_parse(FIXTURES_DIR / "ingress_to_cluster_admin.yml")
        )
        chain = {(e.source, e.target, e.edge_type.value, e.relation) for e in graph.edges}
        assert chain == {
            (
                "kubernetes_ingress.edge.portal",
                "kubernetes_service.edge.portal",
                "network_flow",
                "backend",
            ),
            (
                "kubernetes_service.edge.portal",
                "kubernetes_deployment.edge.portal",
                "network_flow",
                "selects",
            ),
            (
                "kubernetes_deployment.edge.portal",
                "kubernetes_service_account.edge.portal-admin",
                "iam_binding",
                "runs_as",
            ),
            (
                "kubernetes_cluster_role_binding.portal-admin",
                "kubernetes_service_account.edge.portal-admin",
                "iam_binding",
                "bound_subject",
            ),
            (
                "kubernetes_cluster_role_binding.portal-admin",
                "kubernetes_cluster_role.everything",
                "iam_binding",
                "grants",
            ),
            # Added by the reachability pass: the public ingress is reached from the internet,
            # and the service account that is bound to a cluster role reaches that role
            ("internet", "kubernetes_ingress.edge.portal", "network_flow", ""),
            (
                "kubernetes_service_account.edge.portal-admin",
                "kubernetes_cluster_role.everything",
                "iam_binding",
                "bound_role",
            ),
        }

    def test_the_cluster_scoped_nodes_have_no_namespace_in_their_address(self) -> None:
        graph = InfraGraph.from_parsed(
            detect_and_parse(FIXTURES_DIR / "ingress_to_cluster_admin.yml")
        )
        assert "kubernetes_cluster_role.everything" in graph.nodes
        assert not any(
            ".default." in node_id for node_id in graph.nodes if "cluster_role" in node_id
        )

    def test_a_service_that_is_not_exposed_adds_no_boundary_crossing_to_its_workload(self) -> None:
        graph = InfraGraph.from_parsed(detect_and_parse(FIXTURES_DIR / "graph_stack.yml"))
        crossing = {(e.source, e.target) for e in graph.edges if e.crosses_trust_boundary}
        # a ClusterIP Service and its Deployment are both private, so that edge is no crossing
        assert (
            "kubernetes_service.default.api-internal",
            "kubernetes_deployment.default.api",
        ) not in crossing
        assert (
            "kubernetes_service.default.web-lb",
            "kubernetes_deployment.default.web",
        ) in crossing

    def test_the_network_policy_fixture_has_the_four_coverage_cases(self) -> None:
        graph = InfraGraph.from_parsed(detect_and_parse(FIXTURES_DIR / "network_policies.yml"))

        def covered(name: str) -> tuple[bool, bool]:
            props = graph.nodes[name].properties
            return props["ingress_policy_covered"], props["egress_policy_covered"]

        assert covered("kubernetes_deployment.policy.guarded") == (True, True)
        assert covered("kubernetes_deployment.policy.exposed") == (True, False)
        assert covered("kubernetes_deployment.other.elsewhere") == (False, False)
