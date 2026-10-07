"""Graph-level assertions on real-shape Kubernetes manifests.

``shop_stack.yaml`` is a multi-document file with the stack a service usually ships as:
Namespace, ServiceAccount, ConfigMap, Secret, Role, RoleBinding, a hardened Deployment, a Service
selecting it, an Ingress routing to the Service and two NetworkPolicies.
``workloads.yaml`` has every pod workload kind, ``kubectl_get_all.*`` the ``List`` that
``kubectl get -o yaml`` and ``-o json`` print.

Today manifests make nodes and nothing connects them: no Ingress to Service to workload edge,
no ServiceAccount binding, and a ``List`` is one node. Assertions that hold now run now; each one a
later package delivers is its own pending test.
"""

from __future__ import annotations

import pytest

from tests.helpers.graph_assert import (
    assert_edge,
    assert_exposure,
    assert_nodes,
    assert_path,
    assert_zone,
)
from tests.helpers.pending import pending
from tests.helpers.scan import scan_real_shape

SHOP = "kubernetes/shop_stack.yaml"
WORKLOADS = "kubernetes/workloads.yaml"
LIST_YAML = "kubernetes/kubectl_get_all.yaml"
LIST_JSON = "kubernetes/kubectl_get_all.json"
SCAFFOLD = "helm/scaffold/Chart.yaml"
PLATFORM = "helm/platform/Chart.yaml"
REDIS_SUBCHART = "helm/platform/charts/redis/Chart.yaml"

DEPLOYMENT = "kubernetes_deployment.shop.web"
SERVICE = "kubernetes_service.shop.web"
INGRESS = "kubernetes_ingress.shop.web"
ACCOUNT = "kubernetes_service_account.shop.web"
SECRET = "kubernetes_secret.shop.web-db"
CONFIG = "kubernetes_config_map.shop.web-config"
ROLE = "kubernetes_role.shop.web-config-reader"
BINDING = "kubernetes_role_binding.shop.web-config-reader"
ALLOW_POLICY = "kubernetes_network_policy.shop.allow-ingress-to-web"
DENY_POLICY = "kubernetes_network_policy.shop.default-deny"

# The namespace address changes when cluster-scoped kinds lose their namespace segment, so
# the namespace is found by type, not by id.
SHOP_NODES = {
    DEPLOYMENT,
    SERVICE,
    INGRESS,
    ACCOUNT,
    SECRET,
    CONFIG,
    ROLE,
    BINDING,
    ALLOW_POLICY,
    DENY_POLICY,
}


class TestShopStackNodes:
    def test_every_document_is_a_node(self) -> None:
        graph = scan_real_shape(SHOP).graph
        assert_nodes(graph, SHOP_NODES)
        assert [n for n in graph.nodes.values() if n.resource_type == "kubernetes_namespace"]
        assert graph.node_count == len(SHOP_NODES) + 1

    def test_the_two_network_policies_are_separate_nodes(self) -> None:
        graph = scan_real_shape(SHOP).graph
        assert graph.nodes[DENY_POLICY].properties["has_ingress_rules"] is False
        assert graph.nodes[ALLOW_POLICY].properties["has_ingress_rules"] is True

    def test_the_deployment_names_its_service_account(self) -> None:
        props = scan_real_shape(SHOP).graph.nodes[DEPLOYMENT].properties
        assert props["service_account_name"] == "web"

    def test_the_rolebinding_carries_the_subject_and_role_reference(self) -> None:
        props = scan_real_shape(SHOP).graph.nodes[BINDING].properties
        assert props["role_ref_name"] == "web-config-reader"
        assert props["subjects"][0]["name"] == "web"

    @pytest.mark.parametrize(
        ("node", "zone"),
        [
            (SECRET, "data"),
            (ACCOUNT, "management"),
            (ROLE, "management"),
            (INGRESS, "dmz"),
            (DEPLOYMENT, "private"),
        ],
    )
    def test_zone(self, node: str, zone: str) -> None:
        assert_zone(scan_real_shape(SHOP).graph, node, zone)

    @pending("WP-2-4", "a ClusterIP Service is private; only LoadBalancer and NodePort are DMZ")
    def test_the_cluster_ip_service_is_private(self) -> None:
        assert_zone(scan_real_shape(SHOP).graph, SERVICE, "private")

    @pending("WP-2-4", "a ConfigMap is PRIVATE, only a Secret is DATA")
    def test_the_config_map_is_private(self) -> None:
        assert_zone(scan_real_shape(SHOP).graph, CONFIG, "private")

    @pending("WP-2-4", "cluster-scoped kinds use <type>.<name> addresses without a namespace")
    def test_the_namespace_address_has_no_namespace_segment(self) -> None:
        assert_nodes(scan_real_shape(SHOP).graph, ["kubernetes_namespace.shop"])


class TestShopStackEffectiveProperties:
    @pending("WP-2-4", "the effective security context applies pod-level runAsNonRoot")
    def test_pod_level_run_as_non_root_makes_the_workload_non_root(self) -> None:
        props = scan_real_shape(SHOP).graph.nodes[DEPLOYMENT].properties
        assert props["run_as_root"] is False

    @pending("WP-2-4", "a NetworkPolicy podSelector marks the workloads it covers")
    def test_the_deployment_is_covered_by_an_ingress_policy(self) -> None:
        props = scan_real_shape(SHOP).graph.nodes[DEPLOYMENT].properties
        assert props["ingress_policy_covered"] is True

    @pending("WP-2-4", "an Ingress records whether it has TLS")
    def test_the_ingress_has_tls(self) -> None:
        props = scan_real_shape(SHOP).graph.nodes[INGRESS].properties
        assert props["has_tls"] is True

    @pending("WP-2-4", "the effective ServiceAccount token mount comes from the ServiceAccount")
    def test_the_account_setting_wins_over_the_default_mount(self) -> None:
        props = scan_real_shape(SHOP).graph.nodes[DEPLOYMENT].properties
        assert props["effective_automount_sa_token"] is False


class TestShopStackEdges:
    @pending("WP-2-4", "an Ingress backend becomes a network_flow edge to the Service")
    def test_the_ingress_routes_to_the_service(self) -> None:
        graph = scan_real_shape(SHOP).graph
        assert_edge(graph, INGRESS, SERVICE, type="network_flow", relation="backend")

    @pending("WP-2-4", "a Service selector becomes a network_flow edge to the matching workload")
    def test_the_service_selects_the_deployment(self) -> None:
        graph = scan_real_shape(SHOP).graph
        assert_edge(graph, SERVICE, DEPLOYMENT, type="network_flow", relation="selects")

    @pending("WP-2-4", "serviceAccountName becomes an iam_binding edge with relation runs_as")
    def test_the_deployment_runs_as_its_service_account(self) -> None:
        graph = scan_real_shape(SHOP).graph
        assert_edge(graph, DEPLOYMENT, ACCOUNT, type="iam_binding", relation="runs_as")

    @pending("WP-2-4", "secretKeyRef becomes a dependency edge from the workload to the Secret")
    def test_the_deployment_reads_the_secret(self) -> None:
        graph = scan_real_shape(SHOP).graph
        assert_edge(graph, DEPLOYMENT, SECRET, type="dependency")

    @pending("WP-2-4", "envFrom configMapRef becomes a dependency edge to the ConfigMap")
    def test_the_deployment_reads_the_config_map(self) -> None:
        graph = scan_real_shape(SHOP).graph
        assert_edge(graph, DEPLOYMENT, CONFIG, type="dependency")

    @pending("WP-2-4", "a RoleBinding roleRef becomes an iam_binding edge with relation grants")
    def test_the_binding_grants_the_role(self) -> None:
        graph = scan_real_shape(SHOP).graph
        assert_edge(graph, BINDING, ROLE, type="iam_binding", relation="grants")

    @pending("WP-2-4", "a RoleBinding subject becomes an iam_binding edge to the ServiceAccount")
    def test_the_binding_names_the_service_account(self) -> None:
        graph = scan_real_shape(SHOP).graph
        assert_edge(graph, BINDING, ACCOUNT, type="iam_binding", relation="bound_subject")

    @pending("WP-2-4", "a NetworkPolicy podSelector becomes an edge to the workloads it selects")
    def test_both_policies_select_the_deployment(self) -> None:
        graph = scan_real_shape(SHOP).graph
        assert_edge(graph, ALLOW_POLICY, DEPLOYMENT, type="dependency", relation="policy")
        assert_edge(graph, DENY_POLICY, DEPLOYMENT, type="dependency", relation="policy")


class TestShopStackExposureAndPaths:
    @pending("WP-3-1", "an Ingress with rules has exposure internet")
    def test_the_ingress_is_exposed(self) -> None:
        assert_exposure(scan_real_shape(SHOP).graph, INGRESS, "internet")

    @pending("WP-4-1", "reachability: internet to the Ingress, Service, workload and Secret")
    def test_the_internet_reaches_the_secret_through_the_workload(self) -> None:
        graph = scan_real_shape(SHOP).graph
        path = assert_path(graph, "internet", SECRET)
        assert path[:4] == ["internet", INGRESS, SERVICE, DEPLOYMENT]


class TestWorkloadKinds:
    EXPECTED = {
        "kubernetes_deployment.platform.api": "kubernetes_deployment",
        "kubernetes_stateful_set.platform.queue": "kubernetes_stateful_set",
        "kubernetes_daemon_set.platform.node-agent": "kubernetes_daemon_set",
        "kubernetes_replica_set.platform.legacy-worker": "kubernetes_replica_set",
        "kubernetes_job.platform.reindex": "kubernetes_job",
        "kubernetes_cron_job.platform.nightly-report": "kubernetes_cron_job",
        "kubernetes_pod.platform.debug-shell": "kubernetes_pod",
    }

    def test_every_workload_kind_is_a_node_of_its_own_type(self) -> None:
        graph = scan_real_shape(WORKLOADS).graph
        assert_nodes(graph, self.EXPECTED, exact=True)
        for node_id, rtype in self.EXPECTED.items():
            assert graph.nodes[node_id].resource_type == rtype

    def test_workloads_are_in_the_private_zone(self) -> None:
        graph = scan_real_shape(WORKLOADS).graph
        for node_id in self.EXPECTED:
            assert_zone(graph, node_id, "private")

    def test_host_namespaces_and_host_paths_are_visible_on_the_daemon_set(self) -> None:
        props = scan_real_shape(WORKLOADS).graph.nodes["kubernetes_daemon_set.platform.node-agent"]
        assert props.properties["host_network"] is True
        assert props.properties["host_pid"] is True
        assert props.properties["has_host_path_volume"] is True

    @pending("WP-2-4", "pod-level runAsNonRoot and runAsUser make the effective context non-root")
    def test_a_stateful_set_with_pod_level_non_root_is_not_run_as_root(self) -> None:
        props = scan_real_shape(WORKLOADS).graph.nodes["kubernetes_stateful_set.platform.queue"]
        assert props.properties["run_as_root"] is False

    @pending("WP-2-4", "one privileged sidecar makes the whole workload privileged")
    def test_the_privileged_sidecar_marks_the_deployment(self) -> None:
        props = scan_real_shape(WORKLOADS).graph.nodes["kubernetes_deployment.platform.api"]
        assert props.properties["privileged"] is True
        assert props.properties["container_findings"]["privileged"] == ["log-shipper"]

    @pending("WP-2-4", "the CronJob pod spec is read from jobTemplate.spec.template.spec")
    def test_the_cron_job_security_context_comes_from_its_job_template(self) -> None:
        props = scan_real_shape(WORKLOADS).graph.nodes[
            "kubernetes_cron_job.platform.nightly-report"
        ]
        assert props.properties["seccomp_profile_type"] == "RuntimeDefault"


class TestKubectlLists:
    @pending("WP-2-4", "a List expands to one node per item")
    def test_the_yaml_list_expands_to_its_items(self) -> None:
        graph = scan_real_shape(LIST_YAML).graph
        assert_nodes(
            graph,
            [
                "kubernetes_deployment.stock.inventory",
                "kubernetes_service.stock.inventory",
                "kubernetes_config_map.stock.inventory-config",
            ],
            exact=True,
        )

    @pending("WP-1-4", "a .json Kubernetes manifest is claimed by the Kubernetes parser")
    def test_a_json_manifest_is_claimed(self) -> None:
        assert scan_real_shape(LIST_JSON).graph.node_count >= 1

    @pending("WP-2-4", "a JSON List expands exactly like the YAML List")
    def test_the_json_list_matches_the_yaml_list(self) -> None:
        yaml_nodes = set(scan_real_shape(LIST_YAML).graph.nodes)
        json_nodes = set(scan_real_shape(LIST_JSON).graph.nodes)
        assert json_nodes == yaml_nodes
        assert len(json_nodes) == 3

    @pending("WP-2-4", "a Service selector links the Service to the Deployment inside a List")
    def test_the_service_selects_the_deployment_inside_the_list(self) -> None:
        graph = scan_real_shape(LIST_YAML).graph
        assert_edge(
            graph,
            "kubernetes_service.stock.inventory",
            "kubernetes_deployment.stock.inventory",
            type="network_flow",
        )

    @pending("WP-3-1", "a LoadBalancer Service has exposure internet")
    def test_the_load_balancer_service_is_exposed(self) -> None:
        assert_exposure(
            scan_real_shape(LIST_YAML).graph, "kubernetes_service.stock.inventory", "internet"
        )


def _types(path: str) -> set[str]:
    return {n.resource_type for n in scan_real_shape(path).graph.nodes.values()}


class TestHelmCharts:
    """Charts as ``helm create`` and real platform charts lay them out."""

    def test_a_chart_without_include_helpers_renders_into_nodes(self) -> None:
        assert _types(REDIS_SUBCHART) >= {"kubernetes_stateful_set", "kubernetes_service"}

    @pending("WP-2-4", "the safe renderer handles include, toYaml, nindent, with and range")
    def test_the_helm_create_scaffold_renders_its_default_resources(self) -> None:
        assert _types(SCAFFOLD) >= {
            "kubernetes_deployment",
            "kubernetes_service",
            "kubernetes_service_account",
        }

    @pending("WP-2-4", "if blocks on literal values drop the disabled Ingress and HPA")
    def test_the_scaffold_renders_no_ingress_or_autoscaler_by_default(self) -> None:
        types = _types(SCAFFOLD)
        assert "kubernetes_ingress" not in types
        assert "kubernetes_horizontal_pod_autoscaler" not in types

    @pending("WP-2-4", "templates/tests/ and NOTES.txt are not rendered as workloads")
    def test_the_helm_test_hook_pod_is_not_a_workload(self) -> None:
        assert "kubernetes_pod" not in _types(SCAFFOLD)

    @pending("WP-2-4", "the renderer walks templates/** including subdirectories")
    def test_templates_in_subdirectories_are_rendered(self) -> None:
        assert _types(PLATFORM) >= {
            "kubernetes_role",
            "kubernetes_role_binding",
            "kubernetes_network_policy",
            "kubernetes_deployment",
        }

    @pending("WP-2-4", "subcharts under charts/ render with their scoped values")
    def test_the_redis_subchart_is_rendered_with_the_parent_chart(self) -> None:
        assert "kubernetes_stateful_set" in _types(PLATFORM)

    @pending("WP-2-4", "range over values lists renders one rule entry per item")
    def test_range_over_a_values_list_fills_the_role(self) -> None:
        graph = scan_real_shape(PLATFORM).graph
        roles = [n for n in graph.nodes.values() if n.resource_type == "kubernetes_role"]
        assert roles
        assert "platform-api-credentials" in str(roles[0].properties["rbac_rules"])

    @pending("WP-2-4", "every fallback render emits a helm.fallback_render warning")
    def test_a_fallback_render_is_reported(self) -> None:
        result = scan_real_shape(PLATFORM)
        codes = {d.code for output in result.parsed for d in output.diagnostics}
        assert "helm.fallback_render" in codes
