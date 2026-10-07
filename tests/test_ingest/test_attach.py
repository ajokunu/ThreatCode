"""Joining findings to nodes: image reference, file and line, manifest directory, unattached."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from tests.test_ingest.conftest import REPO, build_graph, write_tree
from threatcode.ingest import load_and_attach
from threatcode.ingest.attach import NodeIndex, node_image_refs
from threatcode.ingest.model import ExternalFinding, PackageInfo
from threatcode.ir.graph import InfraGraph

DIGEST = "sha256:" + "ab12" * 16
OTHER_DIGEST = "sha256:" + "cd34" * 16


def deployment(image: str, name: str = "web") -> str:
    return (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n"
        f"  name: {name}\n  namespace: shop\nspec:\n  selector:\n    matchLabels:\n"
        f"      app: {name}\n  template:\n    metadata:\n      labels:\n        app: {name}\n"
        f"    spec:\n      containers:\n        - name: {name}\n          image: {image}\n"
    )


def finding(**overrides: Any) -> ExternalFinding:
    fields: dict[str, Any] = {
        "tool": "trivy",
        "kind": "vulnerability",
        "id": "CVE-2024-1",
        "severity": "high",
        "package": PackageInfo(name="zlib", version="1.0"),
        "scope": "image",
    }
    fields.update(overrides)
    return ExternalFinding(**fields)


def index_of(tmp_path: Path, files: dict[str, str]) -> NodeIndex:
    write_tree(tmp_path, files)
    return NodeIndex(build_graph(tmp_path), tmp_path)


def attached(index: NodeIndex, **overrides: Any) -> list[str]:
    return [n.id for n in index.place(finding(**overrides)).nodes]


class TestImageReference:
    def test_the_same_tag_attaches(self, tmp_path: Path) -> None:
        index = index_of(tmp_path, {"d.yaml": deployment("ghcr.io/acme/web:1.2.3")})
        assert attached(index, image_refs=("ghcr.io/acme/web:1.2.3",)) == [
            "kubernetes_deployment.shop.web"
        ]

    def test_another_tag_does_not(self, tmp_path: Path) -> None:
        index = index_of(tmp_path, {"d.yaml": deployment("ghcr.io/acme/web:1.2.3")})
        assert attached(index, image_refs=("ghcr.io/acme/web:1.2.4",)) == []

    def test_another_repository_does_not(self, tmp_path: Path) -> None:
        index = index_of(tmp_path, {"d.yaml": deployment("ghcr.io/acme/web:1.2.3")})
        assert attached(index, image_refs=("ghcr.io/acme/web-admin:1.2.3",)) == []
        assert attached(index, image_refs=("quay.io/acme/web:1.2.3",)) == []

    def test_docker_hub_names_are_normalized(self, tmp_path: Path) -> None:
        index = index_of(tmp_path, {"d.yaml": deployment("nginx:1.25")})
        for ref in ("nginx:1.25", "docker.io/library/nginx:1.25", "index.docker.io/nginx:1.25"):
            assert attached(index, image_refs=(ref,)) == ["kubernetes_deployment.shop.web"], ref

    def test_an_untagged_reference_is_latest(self, tmp_path: Path) -> None:
        index = index_of(tmp_path, {"d.yaml": deployment("nginx")})
        assert attached(index, image_refs=("nginx:latest",)) == ["kubernetes_deployment.shop.web"]
        assert attached(index, image_refs=("nginx:1.25",)) == []

    def test_a_digest_attaches_to_a_workload_pinned_by_the_same_digest(
        self, tmp_path: Path
    ) -> None:
        index = index_of(tmp_path, {"d.yaml": deployment(f"ghcr.io/acme/web@{DIGEST}")})
        assert attached(index, image_refs=(f"ghcr.io/acme/web@{DIGEST}",)) == [
            "kubernetes_deployment.shop.web"
        ]

    def test_a_digest_wins_over_the_name(self, tmp_path: Path) -> None:
        index = index_of(tmp_path, {"d.yaml": deployment(f"mirror.example.com/web@{DIGEST}")})
        assert attached(index, image_refs=(f"ghcr.io/acme/web@{DIGEST}",)) == [
            "kubernetes_deployment.shop.web"
        ]

    def test_a_different_digest_never_attaches_even_with_the_same_name(
        self, tmp_path: Path
    ) -> None:
        index = index_of(tmp_path, {"d.yaml": deployment(f"ghcr.io/acme/web@{DIGEST}")})
        assert attached(index, image_refs=(f"ghcr.io/acme/web@{OTHER_DIGEST}",)) == []

    def test_a_tag_cannot_be_proven_equal_to_a_digest(self, tmp_path: Path) -> None:
        index = index_of(tmp_path, {"d.yaml": deployment(f"ghcr.io/acme/web@{DIGEST}")})
        assert attached(index, image_refs=("ghcr.io/acme/web:1.2.3",)) == []

    def test_any_of_several_references_of_one_image_attaches(self, tmp_path: Path) -> None:
        index = index_of(tmp_path, {"d.yaml": deployment("ghcr.io/acme/web:1.2.3")})
        refs = ("local-name:build", f"ghcr.io/acme/web@{DIGEST}", "ghcr.io/acme/web:1.2.3")
        assert attached(index, image_refs=refs) == ["kubernetes_deployment.shop.web"]

    def test_every_node_that_runs_the_image_gets_it_in_id_order(self, tmp_path: Path) -> None:
        text = (
            deployment("ghcr.io/acme/web:1", "b") + "---\n" + deployment("ghcr.io/acme/web:1", "a")
        )
        index = index_of(tmp_path, {"d.yaml": text})
        assert attached(index, image_refs=("ghcr.io/acme/web:1",)) == [
            "kubernetes_deployment.shop.a",
            "kubernetes_deployment.shop.b",
        ]

    def test_a_reference_with_a_variable_matches_nothing(self, tmp_path: Path) -> None:
        index = index_of(tmp_path, {"d.yaml": deployment("ghcr.io/acme/web:1")})
        assert attached(index, image_refs=("ghcr.io/acme/web:${TAG}",)) == []
        assert attached(index, image_refs=("",)) == []

    def test_an_ecs_task_definition_is_read_from_its_container_definitions(
        self, tmp_path: Path
    ) -> None:
        index = index_of(tmp_path, {"main.tf": ECS_TF})
        assert attached(
            index, image_refs=("123456789012.dkr.ecr.us-east-1.amazonaws.com/svc:7",)
        ) == ["aws_ecs_task_definition.svc"]

    def test_a_lambda_image_uri_attaches(self, tmp_path: Path) -> None:
        index = index_of(tmp_path, {"main.tf": LAMBDA_TF})
        ref = f"123456789012.dkr.ecr.us-east-1.amazonaws.com/fn@{DIGEST}"
        assert attached(index, image_refs=(ref,)) == ["aws_lambda_function.fn"]

    def test_instance_user_data_text_attaches_a_reference_written_in_a_command(
        self, tmp_path: Path
    ) -> None:
        index = index_of(tmp_path, {"main.tf": USER_DATA_TF})
        assert attached(index, image_refs=("ghcr.io/acme/web:2.0.1",)) == ["aws_instance.web"]
        # A word of the script, a path and a port mapping are not image references.
        for text in ("bash", "bin/bash", "8080:8080", "docker", "/bin/bash"):
            assert attached(index, image_refs=(text,)) == [], text

    def test_base64_user_data_is_decoded(self, tmp_path: Path) -> None:
        encoded = base64.b64encode(b"#!/bin/bash\ndocker run -d ghcr.io/acme/batch:9\n").decode()
        tf = (
            'resource "aws_launch_template" "lt" {\n  name = "lt"\n'
            f'  user_data = "{encoded}"\n}}\n'
        )
        index = index_of(tmp_path, {"main.tf": tf})
        assert attached(index, image_refs=("ghcr.io/acme/batch:9",)) == ["aws_launch_template.lt"]

    def test_text_outside_script_properties_is_not_searched(self, tmp_path: Path) -> None:
        tf = (
            'resource "aws_instance" "web" {\n  ami = "ami-1"\n  instance_type = "t3.micro"\n'
            '  tags = { Note = "see ghcr.io/acme/web:2.0.1 for details" }\n}\n'
        )
        index = index_of(tmp_path, {"main.tf": tf})
        assert attached(index, image_refs=("ghcr.io/acme/web:2.0.1",)) == []

    def test_a_dockerfile_stage_holds_its_base_image_but_the_from_instruction_does_not(
        self, tmp_path: Path
    ) -> None:
        index = index_of(tmp_path, {"Dockerfile": "FROM node:20-alpine AS build\nRUN true\n"})
        assert attached(index, image_refs=("node:20-alpine",)) == ["dockerfile.stage.build"]

    def test_a_stage_that_builds_from_an_earlier_stage_is_not_an_image_reference(
        self, tmp_path: Path
    ) -> None:
        text = "FROM node:20-alpine AS build\nRUN true\nFROM build AS final\nRUN true\n"
        index = index_of(tmp_path, {"Dockerfile": text})
        assert attached(index, image_refs=("build",)) == []

    def test_the_example_repo_images_are_read_from_every_format(self) -> None:
        graph = build_graph(REPO)
        found = {n.id: [r.normalized for r in node_image_refs(n)] for n in graph.nodes.values()}
        assert found["kubernetes_deployment.shop.api"] == [
            "ghcr.io/acme/api:1.4.2",
            "docker.io/library/nginx:1.25",
        ]
        assert found["aws_instance.web"] == ["ghcr.io/acme/web:2.0.1"]
        assert found["dockerfile.stage.1"] == ["gcr.io/distroless/nodejs20-debian12:nonroot"]
        assert "dockerfile.image.summary" not in {k for k, v in found.items() if v}


class TestFileAndLine:
    def test_the_node_whose_span_holds_the_line_is_the_target(self, tmp_path: Path) -> None:
        index = index_of(tmp_path, {"main.tf": TWO_BUCKETS_TF})
        placed = index.place(finding(scope="path", kind="misconfiguration", file="main.tf", line=6))
        assert [n.id for n in placed.nodes] == ["aws_s3_bucket.second"]
        assert (placed.join, placed.location_file, placed.line) == ("file_line", "main.tf", 6)

    def test_a_line_between_resources_matches_nothing(self, tmp_path: Path) -> None:
        index = index_of(tmp_path, {"main.tf": TWO_BUCKETS_TF})
        placed = index.place(finding(scope="path", kind="secret", file="main.tf", line=4))
        assert (placed.join, placed.nodes) == ("unattached", [])

    def test_the_narrowest_span_wins(self, tmp_path: Path) -> None:
        text = "FROM alpine:3.19\nRUN echo hi\nUSER app\n"
        index = index_of(tmp_path, {"Dockerfile": text})
        placed = index.place(finding(scope="path", kind="secret", file="Dockerfile", line=2))
        assert placed.nodes[0].resource_type == "dockerfile_run"

    def test_a_kubernetes_node_without_an_end_line_spans_to_the_next_node(
        self, tmp_path: Path
    ) -> None:
        text = deployment("a:1", "first") + "---\n" + deployment("b:1", "second")
        index = index_of(tmp_path, {"d.yaml": text})
        first = index.place(finding(scope="path", kind="misconfiguration", file="d.yaml", line=16))
        second = index.place(finding(scope="path", kind="misconfiguration", file="d.yaml", line=34))
        assert first.nodes[0].id == "kubernetes_deployment.shop.first"
        assert second.nodes[0].id == "kubernetes_deployment.shop.second"

    def test_a_leading_dot_slash_and_backslashes_are_normalized(self, tmp_path: Path) -> None:
        index = index_of(tmp_path, {"infra/main.tf": TWO_BUCKETS_TF})
        for path in ("./infra/main.tf", "infra\\main.tf", "infra/main.tf"):
            placed = index.place(finding(scope="path", kind="misconfiguration", file=path, line=1))
            assert placed.nodes[0].id == "aws_s3_bucket.first", path

    def test_an_absolute_path_inside_the_scan_root_is_made_relative(self, tmp_path: Path) -> None:
        index = index_of(tmp_path, {"infra/main.tf": TWO_BUCKETS_TF})
        path = str(tmp_path / "infra" / "main.tf")
        placed = index.place(finding(scope="path", kind="secret", file=path, line=1))
        assert (placed.nodes[0].id, placed.location_file) == (
            "aws_s3_bucket.first",
            "infra/main.tf",
        )

    def test_a_path_from_a_ci_checkout_matches_by_its_longest_suffix(self, tmp_path: Path) -> None:
        index = index_of(
            tmp_path, {"infra/main.tf": TWO_BUCKETS_TF, "other/infra/main.tf": TWO_BUCKETS_TF}
        )
        placed = index.place(
            finding(
                scope="path", kind="secret", file="/github/workspace/other/infra/main.tf", line=1
            )
        )
        assert placed.location_file == "other/infra/main.tf"

    def test_a_path_relative_to_a_subdirectory_matches_only_when_unique(
        self, tmp_path: Path
    ) -> None:
        one = index_of(tmp_path / "one", {"infra/main.tf": TWO_BUCKETS_TF})
        assert one.resolve_file("main.tf") == "infra/main.tf"
        two = index_of(tmp_path / "two", {"a/main.tf": TWO_BUCKETS_TF, "b/main.tf": TWO_BUCKETS_TF})
        assert two.resolve_file("main.tf") == ""

    def test_a_file_the_scan_did_not_model_has_no_node(self, tmp_path: Path) -> None:
        index = index_of(tmp_path, {"main.tf": TWO_BUCKETS_TF})
        placed = index.place(finding(scope="path", kind="secret", file="README.md", line=1))
        assert placed.nodes == []

    def test_an_absolute_path_from_another_machine_is_reported_by_file_name_only(
        self, tmp_path: Path
    ) -> None:
        index = index_of(tmp_path, {"main.tf": TWO_BUCKETS_TF})
        assert index.display_path("/home/ci/secret-place/notes.txt") == "notes.txt"
        assert index.display_path(str(tmp_path / "x" / "y.tf")) == "x/y.tf"
        assert index.display_path("rel/z.tf") == "rel/z.tf"


class TestManifestDirectory:
    def test_a_lockfile_joins_the_final_stage_of_the_dockerfile_beside_it(self) -> None:
        index = NodeIndex(build_graph(REPO), REPO)
        placed = index.place(
            finding(scope="path", file="services/api/package-lock.json", target="lock")
        )
        assert [n.id for n in placed.nodes] == ["dockerfile.stage.1"]
        assert (placed.join, placed.location_file) == (
            "directory",
            "services/api/package-lock.json",
        )

    def test_a_lockfile_joins_kubernetes_workloads_in_the_same_directory(
        self, tmp_path: Path
    ) -> None:
        index = index_of(
            tmp_path,
            {
                "svc/d.yaml": deployment("a:1"),
                "svc/go.sum": "x\n",
                "other/d.yaml": deployment("b:1", "o"),
            },
        )
        placed = index.place(finding(scope="path", file="svc/go.sum"))
        assert [n.id for n in placed.nodes] == ["kubernetes_deployment.shop.web"]

    def test_a_lockfile_at_the_scan_root_joins_the_root_workloads(self, tmp_path: Path) -> None:
        index = index_of(tmp_path, {"Dockerfile": "FROM alpine:3\nRUN true\n"})
        assert attached(index, scope="path", file="package-lock.json") == ["dockerfile.stage.0"]
        assert attached(index, scope="path", file="/package-lock.json") == ["dockerfile.stage.0"]

    def test_a_lockfile_path_from_another_machine_matches_the_longest_directory_suffix(
        self,
    ) -> None:
        index = NodeIndex(build_graph(REPO), REPO)
        placed = index.place(
            finding(scope="path", file="/home/runner/work/repo/repo/services/api/package-lock.json")
        )
        assert [n.id for n in placed.nodes] == ["dockerfile.stage.1"]
        assert placed.location_file == "services/api/package-lock.json"

    def test_a_lockfile_in_a_directory_with_no_workload_is_unattached(self, tmp_path: Path) -> None:
        index = index_of(tmp_path, {"main.tf": TWO_BUCKETS_TF})
        placed = index.place(finding(scope="path", file="go.mod"))
        assert (placed.join, placed.nodes) == ("unattached", [])

    def test_other_kinds_never_use_the_directory_join(self) -> None:
        index = NodeIndex(build_graph(REPO), REPO)
        for kind in ("secret", "misconfiguration", "other"):
            placed = index.place(
                finding(scope="path", kind=kind, file="services/api/package-lock.json")
            )
            assert placed.nodes == [], kind

    def test_terraform_resources_are_not_workloads_of_a_directory(self, tmp_path: Path) -> None:
        index = index_of(tmp_path, {"main.tf": USER_DATA_TF, "package-lock.json": "{}"})
        assert attached(index, scope="path", file="package-lock.json") == []


class TestLoadAndAttach:
    def test_unattached_findings_are_kept_with_no_address_and_counted(self, tmp_path: Path) -> None:
        graph_root = write_tree(tmp_path / "scan", {"main.tf": TWO_BUCKETS_TF})
        report = json.loads((REPO.parent / "trivy-image.json").read_text())
        path = tmp_path / "report.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        result = load_and_attach([path], build_graph(graph_root), graph_root)
        assert len(result.threats) == 4
        assert {t.resource_address for t in result.threats} == {""}
        assert {t.metadata["join"] for t in result.threats} == {"unattached"}
        (source,) = result.sources
        assert (source["findings"], source["attached"], source["unattached"]) == (4, 0, 4)
        (diagnostic,) = result.diagnostics
        assert diagnostic.code == "ingest.unattached"
        assert diagnostic.level == "warning"
        assert "4 of 4" in diagnostic.message

    def test_partly_unattached_is_only_info(self, repo_graph: InfraGraph) -> None:
        result = load_and_attach([REPO.parent / "trivy-fs.json"], repo_graph, REPO)
        (diagnostic,) = result.diagnostics
        assert (diagnostic.level, diagnostic.code) == ("info", "ingest.unattached")
        assert "1 of 7" in diagnostic.message
        unattached = [t for t in result.threats if not t.resource_address]
        assert [t.rule_id for t in unattached] == ["trivy:CVE-2023-44487"]
        assert unattached[0].location_file == "go.mod"

    def test_a_file_outside_the_scan_root_is_labelled_by_name_only(
        self, tmp_path: Path, repo_graph: InfraGraph
    ) -> None:
        result = load_and_attach([REPO.parent / "trivy-clean.json"], repo_graph, tmp_path)
        assert result.sources[0]["file"] == "trivy-clean.json"

    def test_a_file_inside_the_scan_root_is_labelled_relative_to_it(
        self, repo_graph: InfraGraph
    ) -> None:
        result = load_and_attach([REPO.parent / "trivy-clean.json"], repo_graph, REPO.parent)
        assert result.sources[0]["file"] == "trivy-clean.json"
        result = load_and_attach([REPO.parent / "trivy-clean.json"], repo_graph, REPO.parent.parent)
        assert result.sources[0]["file"] == "ingest/trivy-clean.json"


ECS_TF = """\
resource "aws_ecs_task_definition" "svc" {
  family = "svc"
  container_definitions = jsonencode([
    {
      name  = "svc"
      image = "123456789012.dkr.ecr.us-east-1.amazonaws.com/svc:7"
    }
  ])
}
"""

LAMBDA_TF = f"""\
resource "aws_lambda_function" "fn" {{
  function_name = "fn"
  package_type  = "Image"
  image_uri     = "123456789012.dkr.ecr.us-east-1.amazonaws.com/fn@{DIGEST}"
  role          = "arn:aws:iam::123456789012:role/fn"
}}
"""

USER_DATA_TF = """\
resource "aws_instance" "web" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  user_data     = <<-EOT
    #!/bin/bash
    docker run -d -p 8080:8080 ghcr.io/acme/web:2.0.1
  EOT
}
"""

TWO_BUCKETS_TF = """\
resource "aws_s3_bucket" "first" {
  bucket = "first"
}

resource "aws_s3_bucket" "second" {
  bucket = "second"
}
"""
