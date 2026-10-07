"""The demo examples: their inputs, the structure their paths rest on, and the paths.

Each directory under ``examples/`` holds a small, realistic input set and an ``expected.yml`` that
lists what a scan must show: the nodes it models, the attack paths from the internet to the data
(entry, target and nodes in between) and the key findings. The claims in the demo, the docs and the
pitch are those lines, so they are tested here and nowhere else.

Today the tests assert that every example parses, models the nodes it names, has the structure its
paths depend on (a world-open load balancer, an app group reachable from it only, a privileged
DaemonSet, a literal token over plain http) and reports the findings that current rules produce.
Attack paths and findings that later packages add are pending on those packages.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.helpers.cli import find_key, scan_json
from tests.helpers.graph_assert import assert_nodes
from tests.helpers.pending import pending, validate_pending
from tests.helpers.plan_shape import plan_shape_problems
from tests.helpers.scan import ScanResult, scan_files
from tests.test_quality.harness import KIND_PATTERNS
from threatcode.parsers import detect_and_parse

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES_DIR = REPO_ROOT / "examples"
EXAMPLES = sorted(p.name for p in EXAMPLES_DIR.iterdir() if (p / "expected.yml").is_file())

_TOP_KEYS = {
    "example",
    "inputs",
    "scanner_inputs",
    "nodes",
    "node_types",
    "attack_paths",
    "key_findings",
    "scanner",
}
_PATH_KEYS = {"id", "entry", "target", "via", "why"}
_FINDING_KEYS = {"resource", "rule_ids", "kind", "why", "pending"}


class ExampleError(Exception):
    """A malformed expected.yml."""


def validate_expected(data: Any, source: str) -> dict[str, Any]:
    """Check the shape of one expected.yml and return it."""
    if not isinstance(data, dict):
        raise ExampleError(f"{source}: must be a mapping")
    extra = set(data) - _TOP_KEYS
    if extra:
        raise ExampleError(f"{source}: unknown keys {sorted(extra)}")
    for key in ("example", "inputs", "attack_paths", "key_findings"):
        if key not in data:
            raise ExampleError(f"{source}: missing '{key}'")
    if not isinstance(data["inputs"], list) or not data["inputs"]:
        raise ExampleError(f"{source}: 'inputs' must list at least one file")
    seen: set[str] = set()
    for index, entry in enumerate(data["attack_paths"]):
        where = f"{source} attack_paths[{index}]"
        if not isinstance(entry, dict) or set(entry) - _PATH_KEYS:
            raise ExampleError(f"{where}: keys must be among {sorted(_PATH_KEYS)}")
        for key in ("id", "entry", "target", "why"):
            if not isinstance(entry.get(key), str) or not entry[key].strip():
                raise ExampleError(f"{where}: needs a non-empty '{key}'")
        if entry["id"] in seen:
            raise ExampleError(f"{where}: duplicate path id {entry['id']!r}")
        seen.add(entry["id"])
        via = entry.get("via", [])
        if not isinstance(via, list) or not all(isinstance(v, str) for v in via):
            raise ExampleError(f"{where}: 'via' must be a list of node ids")
    for index, entry in enumerate(data["key_findings"]):
        where = f"{source} key_findings[{index}]"
        if not isinstance(entry, dict) or set(entry) - _FINDING_KEYS:
            raise ExampleError(f"{where}: keys must be among {sorted(_FINDING_KEYS)}")
        if not isinstance(entry.get("resource"), str) or not entry.get("why"):
            raise ExampleError(f"{where}: needs 'resource' and 'why'")
        if not entry.get("rule_ids") and entry.get("kind") not in KIND_PATTERNS:
            raise ExampleError(f"{where}: needs rule_ids or a known kind")
        if "pending" in entry:
            package = (
                entry["pending"].get("package") if isinstance(entry["pending"], dict) else None
            )
            try:
                validate_pending(package, entry["pending"].get("reason"))
            except (ValueError, AttributeError) as exc:
                raise ExampleError(f"{where}: invalid pending: {exc}") from exc
    return data


@cache
def expected_for(name: str) -> dict[str, Any]:
    path = EXAMPLES_DIR / name / "expected.yml"
    return validate_expected(yaml.safe_load(path.read_text(encoding="utf-8")), str(path))


def input_paths(name: str) -> list[Path]:
    return [EXAMPLES_DIR / name / rel for rel in expected_for(name)["inputs"]]


@cache
def scan_example(name: str) -> ScanResult:
    return scan_files(input_paths(name))


def path_node_ids(path: dict[str, Any]) -> list[str]:
    """The node ids an attack path visits, in order.

    The JSON shape of an attack path is the attack-path package's to define. This reads either a
    ``nodes`` list or ``hops`` (each hop naming its far end, the first also its near end), and
    names the shapes it understood when it finds neither. Adjust it together with the shape.
    """
    nodes = path.get("nodes")
    if isinstance(nodes, list) and nodes:
        return [n if isinstance(n, str) else str(n.get("id") or n.get("address")) for n in nodes]
    hops = path.get("hops")
    if isinstance(hops, list) and hops:
        ids: list[str] = []
        first = hops[0]
        for key in ("from", "source", "src"):
            if isinstance(first.get(key), str):
                ids.append(first[key])
                break
        for hop in hops:
            for key in ("node", "to", "target", "address", "resource", "id"):
                if isinstance(hop.get(key), str):
                    ids.append(hop[key])
                    break
        return ids
    raise AssertionError(f"cannot read node ids from an attack path with keys {sorted(path)}")


def is_subsequence(needles: list[str], haystack: list[str]) -> bool:
    it = iter(haystack)
    return all(any(n == h for h in it) for n in needles)


def resolve_address(result: ScanResult, resource: str) -> str:
    """The node id a resource name stands for.

    An exact id wins. Otherwise ``<type>.<name>`` names the one node of that type with that name,
    which keeps a cluster-scoped Kubernetes kind findable whether or not its id carries a
    namespace segment.
    """
    nodes = result.graph.nodes
    if resource in nodes:
        return resource
    resource_type, _, name = resource.partition(".")
    matches = [n.id for n in nodes.values() if n.resource_type == resource_type and n.name == name]
    return matches[0] if len(matches) == 1 else resource


def finding_present(result: ScanResult, entry: dict[str, Any]) -> bool:
    """True when a finding on the resource is one of the rules or the kind."""
    rule_ids = set(entry.get("rule_ids") or [])
    kind = entry.get("kind")
    address = resolve_address(result, entry["resource"])
    for threat in result.threats:
        if threat.resource_address != address:
            continue
        if threat.rule_id in rule_ids:
            return True
        text = f"{threat.rule_id} {threat.title} {threat.description}"
        if kind and KIND_PATTERNS[kind].search(text):
            return True
    return False


def _finding_params(*, pending_only: bool) -> list[Any]:
    params = []
    for name in EXAMPLES:
        for entry in expected_for(name)["key_findings"]:
            if ("pending" in entry) != pending_only:
                continue
            marks = []
            if pending_only:
                marks.append(pending(entry["pending"]["package"], entry["pending"]["reason"]))
            ident = f"{name}-{entry['resource']}-{entry.get('kind') or entry['rule_ids'][0]}"
            params.append(pytest.param(name, entry, id=ident, marks=marks))
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

    def test_a_malformed_file_is_rejected_with_its_location(self) -> None:
        good: dict[str, Any] = {
            "example": "x",
            "inputs": ["a"],
            "attack_paths": [
                {"id": "p", "entry": "internet", "target": "t", "via": ["v"], "why": "w"}
            ],
            "key_findings": [{"resource": "r", "rule_ids": ["R"], "why": "w"}],
        }
        assert validate_expected(good, "x.yml") == good
        for mutate, message in (
            (lambda d: d.pop("inputs"), "missing 'inputs'"),
            (lambda d: d.update(extra=1), "unknown keys"),
            (lambda d: d["attack_paths"][0].pop("target"), "needs a non-empty 'target'"),
            (lambda d: d["attack_paths"].append(dict(d["attack_paths"][0])), "duplicate path id"),
            (lambda d: d["attack_paths"][0].update(via="v"), "'via' must be a list"),
            (lambda d: d["key_findings"][0].pop("rule_ids"), "needs rule_ids or a known kind"),
            (
                lambda d: d["key_findings"][0].update(pending={"package": "WP-9-9", "reason": "r"}),
                "invalid pending",
            ),
        ):
            doc = json.loads(json.dumps(good))
            mutate(doc)
            with pytest.raises(ExampleError, match=message):
                validate_expected(doc, "x.yml")


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


@pytest.mark.parametrize(("name", "entry"), _finding_params(pending_only=False))
def test_the_key_finding_is_reported_today(name: str, entry: dict[str, Any]) -> None:
    assert finding_present(scan_example(name), entry), f"{name}: no finding for {entry['resource']}"


@pytest.mark.parametrize(("name", "entry"), _finding_params(pending_only=True))
def test_the_key_finding_a_later_package_adds(name: str, entry: dict[str, Any]) -> None:
    assert finding_present(scan_example(name), entry), f"{name}: no finding for {entry['resource']}"


def _path_params() -> list[Any]:
    return [
        pytest.param(
            name,
            entry,
            id=f"{name}-{entry['id']}",
            marks=pending(
                "WP-4-1", f"attack path {entry['id']} from the internet to {entry['target']}"
            ),
        )
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


@pending("WP-4-1", "every hop of a path lists the findings that enable it")
@pytest.mark.parametrize("name", EXAMPLES)
def test_every_path_has_an_enabling_finding_on_at_least_one_hop(name: str) -> None:
    run = scan_json([EXAMPLES_DIR / name])
    paths = find_key(run.json(), "attack_paths") or []
    assert paths, f"{name}: the scan reports no attack path"
    for path in paths:
        hops = path.get("hops") or []
        assert any(hop.get("enabled_by") for hop in hops), f"{name}: a path has no enabler"
