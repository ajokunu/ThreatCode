"""The demo examples: their inputs, the structure their paths rest on, and the paths.

Each directory under ``examples/`` holds a small, realistic input set and an ``expected.yml`` that
lists what a scan must show: the nodes it models, the attack paths from the internet to the data
(entry, target and nodes in between) and the key findings. The claims in the demo, the docs and the
pitch are those lines, so they are tested here and nowhere else.

The tests assert that every example parses, models the nodes it names, has the structure its
paths depend on (a world-open load balancer, an app group reachable from it only, a privileged
DaemonSet, a literal token over plain http), reports the findings that the rules produce and, run
through the command line, reports every attack path the expectation file lists.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import yaml

from tests.helpers.cli import find_key, scan_json
from tests.helpers.examples import (
    EXAMPLES,
    EXAMPLES_DIR,
    expected_for,
    finding_present,
    input_paths,
    is_subsequence,
    scan_example,
)
from tests.helpers.graph_assert import assert_nodes
from tests.helpers.plan_shape import plan_shape_problems
from threatcode.parsers import detect_and_parse


def _finding_params() -> list[Any]:
    params = []
    for name in EXAMPLES:
        for entry in expected_for(name)["key_findings"]:
            ident = f"{name}-{entry['resource']}-{entry.get('kind') or entry['rule_ids'][0]}"
            params.append(pytest.param(name, entry, id=ident))
    return params


# ---------------------------------------------------------------------------------------
# The expectation files
# ---------------------------------------------------------------------------------------


class TestExpectationFiles:
    def test_the_three_demo_examples_exist(self) -> None:
        assert EXAMPLES == ["agent-workstation", "aws-webapp", "k8s-platform"]

    @pytest.mark.parametrize("name", EXAMPLES)
    def test_each_expected_file_is_well_formed_and_names_its_directory(self, name: str) -> None:
        assert expected_for(name)["example"] == name
        assert expected_for(name)["attack_paths"], f"{name} lists no attack path"

    @pytest.mark.parametrize("name", EXAMPLES)
    def test_every_input_exists(self, name: str) -> None:
        for path in input_paths(name):
            assert path.is_file(), path

    @pytest.mark.parametrize("name", EXAMPLES)
    def test_every_path_starts_at_the_internet_and_names_nodes_in_between(self, name: str) -> None:
        for entry in expected_for(name)["attack_paths"]:
            assert entry["entry"] == "internet"
            assert entry.get("via"), f"{name}/{entry['id']} names no node in between"


# ---------------------------------------------------------------------------------------
# The inputs, today
# ---------------------------------------------------------------------------------------


class TestExampleInputsParseToTheNamedNodes:
    @pytest.mark.parametrize("name", EXAMPLES)
    def test_every_input_is_detected_and_parsed(self, name: str) -> None:
        for path in input_paths(name):
            assert detect_and_parse(path).resources, path

    @pytest.mark.parametrize("name", EXAMPLES)
    def test_the_graph_has_every_named_node(self, name: str) -> None:
        graph = scan_example(name).graph
        assert_nodes(graph, expected_for(name).get("nodes", []))
        present = {n.resource_type for n in graph.nodes.values()}
        assert set(expected_for(name).get("node_types", [])) <= present

    def test_the_webapp_plan_has_the_shape_terraform_emits(self) -> None:
        plan = json.loads((EXAMPLES_DIR / "aws-webapp" / "tfplan.json").read_text(encoding="utf-8"))
        assert plan_shape_problems(plan) == []


def _plan_resources(plan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["address"]: r["values"] for r in plan["planned_values"]["root_module"]["resources"]}


class TestAwsWebappStructure:
    """The structure the expected paths rest on, read from the plan itself."""

    @pytest.fixture
    def values(self) -> dict[str, dict[str, Any]]:
        text = (EXAMPLES_DIR / "aws-webapp" / "tfplan.json").read_text(encoding="utf-8")
        return _plan_resources(json.loads(text))

    def test_the_load_balancer_is_internet_facing_and_its_group_is_open_on_443(
        self, values: dict[str, dict[str, Any]]
    ) -> None:
        assert values["aws_lb.front"]["internal"] is False
        (rule,) = values["aws_security_group.alb"]["ingress"]
        assert rule["cidr_blocks"] == ["0.0.0.0/0"]
        assert (rule["from_port"], rule["to_port"]) == (443, 443)

    def test_the_app_and_database_groups_admit_only_the_group_in_front_of_them(
        self, values: dict[str, dict[str, Any]]
    ) -> None:
        for name, port in (("app", 8080), ("db", 5432)):
            (rule,) = values[f"aws_security_group.{name}"]["ingress"]
            assert (rule["from_port"], rule["to_port"]) == (port, port)
            assert rule["cidr_blocks"] == []
            assert rule["ipv6_cidr_blocks"] == []

    def test_the_references_that_chain_the_groups_are_in_the_configuration(self) -> None:
        plan = json.loads((EXAMPLES_DIR / "aws-webapp" / "tfplan.json").read_text(encoding="utf-8"))
        config = {r["address"]: r for r in plan["configuration"]["root_module"]["resources"]}
        app = config["aws_security_group.app"]["expressions"]["ingress"][0]["security_groups"]
        db = config["aws_security_group.db"]["expressions"]["ingress"][0]["security_groups"]
        assert "aws_security_group.alb" in app["references"]
        assert "aws_security_group.app" in db["references"]

    def test_both_instances_allow_imdsv1_and_carry_the_instance_profile(
        self, values: dict[str, dict[str, Any]]
    ) -> None:
        for index in (0, 1):
            instance = values[f"aws_instance.app[{index}]"]
            assert instance["metadata_options"][0]["http_tokens"] == "optional"
            assert instance["iam_instance_profile"] == "orders-app"

    def test_the_role_policy_reads_the_customer_data_bucket_and_the_database_secret(
        self, values: dict[str, dict[str, Any]]
    ) -> None:
        policy = json.loads(values["aws_iam_role_policy.app_data"]["policy"])
        actions = {a for s in policy["Statement"] for a in s["Action"]}
        assert actions == {"s3:GetObject", "secretsmanager:GetSecretValue"}
        resources = [s["Resource"] for s in policy["Statement"]]
        assert f"arn:aws:s3:::{values['aws_s3_bucket.customer_data']['bucket']}/*" in resources

    def test_the_database_is_private_and_encrypted(self, values: dict[str, dict[str, Any]]) -> None:
        db = values["aws_db_instance.orders"]
        assert db["publicly_accessible"] is False
        assert db["storage_encrypted"] is True

    def test_the_image_reference_sits_in_plaintext_user_data(
        self, values: dict[str, dict[str, Any]]
    ) -> None:
        image = expected_for("aws-webapp")["scanner"][0]["image"]
        for index in (0, 1):
            assert image in values[f"aws_instance.app[{index}]"]["user_data"]


class TestK8sPlatformStructure:
    def docs(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for path in sorted((EXAMPLES_DIR / "k8s-platform").glob("*.yaml")):
            for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
                out[f"{doc['kind']}/{doc['metadata']['name']}"] = doc
        return out

    def test_ingress_service_deployment_secret_form_a_chain(self) -> None:
        docs = self.docs()
        backend = docs["Ingress/storefront"]["spec"]["rules"][0]["http"]["paths"][0]["backend"]
        assert backend["service"]["name"] == "storefront"
        selector = docs["Service/storefront"]["spec"]["selector"]
        labels = docs["Deployment/storefront"]["spec"]["template"]["metadata"]["labels"]
        assert selector.items() <= labels.items()
        container = docs["Deployment/storefront"]["spec"]["template"]["spec"]["containers"][0]
        assert container["env"][0]["valueFrom"]["secretKeyRef"]["name"] == "payment-api-key"

    def test_the_service_account_is_bound_to_a_cluster_role_that_reads_secrets(self) -> None:
        docs = self.docs()
        assert docs["Deployment/storefront"]["spec"]["template"]["spec"]["serviceAccountName"] == (
            "storefront-sa"
        )
        binding = docs["ClusterRoleBinding/storefront-secret-reader"]
        assert binding["subjects"][0]["name"] == "storefront-sa"
        assert binding["roleRef"]["name"] == "secret-reader"
        (rule,) = docs["ClusterRole/secret-reader"]["rules"]
        assert rule["resources"] == ["secrets"]
        assert {"get", "list"} <= set(rule["verbs"])

    def test_the_daemon_set_is_privileged_on_the_host(self) -> None:
        pod = self.docs()["DaemonSet/node-exporter"]["spec"]["template"]["spec"]
        assert pod["containers"][0]["securityContext"]["privileged"] is True
        assert pod["hostNetwork"] is True and pod["hostPID"] is True


class TestAgentWorkstationStructure:
    def servers(self) -> dict[str, Any]:
        path = EXAMPLES_DIR / "agent-workstation" / ".mcp.json"
        return json.loads(path.read_text(encoding="utf-8"))["mcpServers"]

    def test_the_agent_has_the_three_legs_of_the_trifecta(self) -> None:
        servers = self.servers()
        assert "mcp-server-fetch" in servers["fetch"]["args"]
        assert servers["filesystem"]["args"][-1] == "/Users/dev"
        assert servers["team-tools"]["url"].startswith("http://")
        assert servers["team-tools"]["headers"]["Authorization"].startswith("Bearer ")


# ---------------------------------------------------------------------------------------
# Findings and paths
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(("name", "entry"), _finding_params())
def test_the_key_finding_is_reported(name: str, entry: dict[str, Any]) -> None:
    assert finding_present(scan_example(name), entry), f"{name}: no finding for {entry['resource']}"


def test_no_expected_finding_waits_for_a_package() -> None:
    # An entry that is not reported yet would be a permanent skip, which hides a missing finding
    waiting = [
        f"{name}/{entry['resource']}"
        for name in EXAMPLES
        for entry in expected_for(name)["key_findings"]
        if "pending" in entry
    ]
    assert not waiting, f"expected.yml entries marked pending: {waiting}"


def path_node_ids(path: dict[str, Any]) -> list[str]:
    """The node ids an attack path of the JSON report visits, in order."""
    return [hop["node_id"] for hop in path["hops"]]


def _path_params() -> list[Any]:
    return [
        pytest.param(name, entry, id=f"{name}-{entry['id']}")
        for name in EXAMPLES
        for entry in expected_for(name)["attack_paths"]
    ]


@pytest.mark.parametrize(("name", "entry"), _path_params())
def test_the_attack_path_is_found(name: str, entry: dict[str, Any]) -> None:
    run = scan_json([EXAMPLES_DIR / name])
    assert not run.timed_out, "the scan did not finish"
    assert run.exit_code == 0, run.stderr[-300:]
    paths = find_key(run.json(), "attack_paths")
    assert paths, f"{name}: the scan reports no attack path"
    seen = []
    for path in paths:
        ids = path_node_ids(path)
        seen.append(ids)
        if (
            ids[0] == entry["entry"]
            and ids[-1] == entry["target"]
            and is_subsequence(entry.get("via", []), ids)
        ):
            return
    pytest.fail(f"{name}/{entry['id']}: no path matches; paths found: {seen}")


@pytest.mark.parametrize("name", EXAMPLES)
def test_every_path_has_an_enabling_finding_on_at_least_one_hop(name: str) -> None:
    run = scan_json([EXAMPLES_DIR / name])
    paths = find_key(run.json(), "attack_paths") or []
    assert paths, f"{name}: the scan reports no attack path"
    for path in paths:
        hops = path.get("hops") or []
        assert any(hop.get("enabled_by") for hop in hops), f"{name}: a path has no enabler"
