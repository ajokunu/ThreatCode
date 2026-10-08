"""Tests for the Helm chart parser: renderer choice, fallback visibility and resources."""

from __future__ import annotations

import logging
import os
import shutil
import stat
import sys
import time
from pathlib import Path
from typing import Any

import pytest
import yaml

from threatcode.engine.hybrid import HybridEngine
from threatcode.exceptions import ConfigError, ParseError
from threatcode.ir.graph import InfraGraph
from threatcode.parsers import _detect_helm_chart, detect_and_parse
from threatcode.parsers.base import ParsedOutput
from threatcode.parsers.helm import HelmParser
from threatcode.parsers.kubernetes import readable_placeholders

FIXTURES = Path(__file__).parent.parent / "fixtures"
TEST_CHART = FIXTURES / "helm" / "test-chart"
TWO_DEPLOYMENTS = FIXTURES / "helm" / "two-deployments"
SCAFFOLD = FIXTURES / "real_shapes" / "helm" / "scaffold"
PLATFORM = FIXTURES / "real_shapes" / "helm" / "platform"

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="the fake helm is a shell script")


def parse_chart(chart: Path, **options: Any) -> ParsedOutput:
    chart_yaml = chart / "Chart.yaml"
    data = yaml.safe_load(chart_yaml.read_text(encoding="utf-8"))
    return HelmParser(**options).parse(data, source_path=str(chart_yaml))


def fallback(chart: Path) -> ParsedOutput:
    return parse_chart(chart, helm="off")


def addresses(output: ParsedOutput) -> list[str]:
    return [r.address for r in output.resources]


def types(output: ParsedOutput) -> set[str]:
    return {r.resource_type for r in output.resources}


def copy_chart(source: Path, target: Path) -> Path:
    shutil.copytree(source, target)
    return target


@pytest.fixture
def no_helm(monkeypatch: pytest.MonkeyPatch) -> None:
    """A machine without the helm binary, whatever the machine running the tests has."""
    monkeypatch.setattr("threatcode.parsers.helm.shutil.which", lambda name: None)


def fake_helm(directory: Path, script: str) -> Path:
    """Install a ``helm`` shell script that records its arguments; returns its directory."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "helm"
    path.write_text(f'#!/bin/sh\necho "$@" > "{directory}/args.txt"\n{script}', encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return directory


def put_on_path(monkeypatch: pytest.MonkeyPatch, directory: Path) -> None:
    monkeypatch.setenv("PATH", f"{directory}{os.pathsep}{os.environ['PATH']}")


# ---------------------------------------------------------------------------------------
# The fallback renderer's resources
# ---------------------------------------------------------------------------------------


class TestFallbackRender:
    def test_the_chart_resolves_its_image_from_values_yaml(self) -> None:
        output = fallback(TEST_CHART)
        (deployment,) = output.resources
        assert deployment.address == "kubernetes_deployment.default.release-app"
        assert deployment.properties["images"] == ["nginx:latest"]
        assert deployment.properties["uses_latest_tag"] is True
        assert deployment.properties["privileged"] is True
        assert deployment.properties["host_network"] is True

    def test_the_helm_create_scaffold_renders_a_deployment_service_and_service_account(
        self,
    ) -> None:
        output = fallback(SCAFFOLD)
        assert addresses(output) == [
            "kubernetes_deployment.default.release-scaffold",
            "kubernetes_service.default.release-scaffold",
            "kubernetes_service_account.default.release-scaffold",
        ]

    def test_the_scaffold_deployment_is_fully_resolved(self) -> None:
        deployment = fallback(SCAFFOLD).resources[0].properties
        assert deployment["images"] == ["nginx:1.16.0"]
        assert deployment["uses_latest_tag"] is False
        assert deployment["service_account_name"] == "release-scaffold"
        assert deployment["replicas"] == 1
        assert deployment["pod_labels"]["app.kubernetes.io/name"] == "scaffold"
        assert deployment["has_liveness_probe"] is True
        assert deployment["has_readiness_probe"] is True

    def test_no_placeholder_leaks_into_a_stock_chart(self) -> None:
        for chart in (SCAFFOLD, PLATFORM, TEST_CHART):
            output = fallback(chart)
            assert "placeholder" not in str([r.properties for r in output.resources]), chart.name
            assert not any("placeholder" in r.address for r in output.resources), chart.name

    def test_a_disabled_ingress_and_autoscaler_are_not_rendered(self) -> None:
        output = fallback(SCAFFOLD)
        assert "kubernetes_ingress" not in types(output)
        assert "kubernetes_horizontal_pod_autoscaler" not in types(output)

    def test_enabling_the_ingress_renders_it_with_its_rules_and_backend(
        self, tmp_path: Path
    ) -> None:
        chart = copy_chart(SCAFFOLD, tmp_path / "scaffold")
        values = yaml.safe_load((chart / "values.yaml").read_text())
        values["ingress"]["enabled"] = True
        values["ingress"]["tls"] = [{"secretName": "tls", "hosts": ["chart-example.local"]}]
        (chart / "values.yaml").write_text(yaml.safe_dump(values))
        output = fallback(chart)
        (ingress,) = [r for r in output.resources if r.resource_type == "kubernetes_ingress"]
        assert ingress.properties["has_tls"] is True
        assert ingress.properties["has_rules"] is True
        assert ingress.properties["ingress_backends"] == [
            {"service_name": "release-scaffold", "port": 80}
        ]
        graph = InfraGraph.from_parsed(output)
        targets = {(e.source, e.target) for e in graph.edges}
        assert (ingress.address, "kubernetes_service.default.release-scaffold") in targets

    def test_enabling_autoscaling_renders_the_autoscaler_and_drops_replicas(
        self, tmp_path: Path
    ) -> None:
        chart = copy_chart(SCAFFOLD, tmp_path / "scaffold")
        values = yaml.safe_load((chart / "values.yaml").read_text())
        values["autoscaling"]["enabled"] = True
        (chart / "values.yaml").write_text(yaml.safe_dump(values))
        output = fallback(chart)
        assert "kubernetes_horizontal_pod_autoscaler" in types(output)
        deployment = next(r for r in output.resources if r.resource_type == "kubernetes_deployment")
        assert deployment.properties["replicas"] is None

    def test_the_helm_test_hook_pod_is_not_a_resource(self) -> None:
        assert "kubernetes_pod" not in types(fallback(SCAFFOLD))

    def test_a_test_hook_outside_templates_tests_is_dropped_too(self, tmp_path: Path) -> None:
        chart = copy_chart(TEST_CHART, tmp_path / "c")
        (chart / "templates" / "hook.yaml").write_text(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: probe\n  annotations:\n"
            '    "helm.sh/hook": test-success, post-install\n'
            "spec:\n  containers:\n    - name: c\n      image: busybox\n"
        )
        assert "kubernetes_pod" not in types(fallback(chart))

    def test_other_hooks_are_kept(self, tmp_path: Path) -> None:
        chart = copy_chart(TEST_CHART, tmp_path / "c")
        (chart / "templates" / "job.yaml").write_text(
            "apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: migrate\n  annotations:\n"
            '    "helm.sh/hook": pre-install\nspec:\n  template:\n    spec:\n      containers:\n'
            "        - name: c\n          image: busybox:1.36\n"
        )
        assert "kubernetes_job" in types(fallback(chart))

    def test_templates_in_subdirectories_are_rendered(self) -> None:
        output = fallback(PLATFORM)
        assert {
            "kubernetes_role",
            "kubernetes_role_binding",
            "kubernetes_network_policy",
            "kubernetes_deployment",
        } <= types(output)

    def test_subcharts_render_with_their_scoped_values(self) -> None:
        output = fallback(PLATFORM)
        stateful_set = next(
            r for r in output.resources if r.resource_type == "kubernetes_stateful_set"
        )
        assert stateful_set.address == "kubernetes_stateful_set.default.release-redis"
        # the subchart's own image tag, and the parent's override of its secret name
        assert stateful_set.properties["images"] == ["redis:7.2.5-alpine"]
        assert stateful_set.properties["secret_refs"] == ["platform-redis"]
        assert stateful_set.source_location.endswith("charts/redis/templates/statefulset.yaml")

    def test_a_subchart_the_parent_disables_is_not_rendered(self, tmp_path: Path) -> None:
        chart = copy_chart(PLATFORM, tmp_path / "platform")
        values = yaml.safe_load((chart / "values.yaml").read_text())
        values["redis"]["enabled"] = False
        (chart / "values.yaml").write_text(yaml.safe_dump(values))
        assert "kubernetes_stateful_set" not in types(fallback(chart))

    def test_range_over_a_values_list_fills_the_role(self) -> None:
        output = fallback(PLATFORM)
        role = next(r for r in output.resources if r.resource_type == "kubernetes_role")
        assert "platform-api-credentials" in str(role.properties["rbac_rules"])

    def test_the_manifests_are_connected_as_one_set(self) -> None:
        graph = InfraGraph.from_parsed(fallback(PLATFORM))
        relations = {
            (e.source.split(".")[0], e.target.split(".")[0], e.relation) for e in graph.edges
        }
        assert ("kubernetes_service", "kubernetes_deployment", "selects") in relations
        assert ("kubernetes_deployment", "kubernetes_service_account", "runs_as") in relations
        assert ("kubernetes_role_binding", "kubernetes_role", "grants") in relations
        assert ("kubernetes_network_policy", "kubernetes_deployment", "policy") in relations

    def test_the_service_account_setting_reaches_the_deployment(self) -> None:
        deployment = next(
            r
            for r in fallback(PLATFORM).resources
            if r.address == "kubernetes_deployment.default.release-platform"
        )
        assert deployment.properties["effective_automount_sa_token"] is False
        assert deployment.properties["ingress_policy_covered"] is True

    def test_resources_carry_their_template_file_and_line(self) -> None:
        by_type = {r.resource_type: r for r in fallback(PLATFORM).resources}
        role = by_type["kubernetes_role"]
        assert role.source_location.endswith("templates/rbac/role.yaml")
        assert role.start_line == 2  # the apiVersion line, after the leading {{- if }}
        deployment = by_type["kubernetes_deployment"]
        assert deployment.source_location.endswith("templates/deployment.yaml")
        assert deployment.start_line == 1

    def test_the_output_names_the_chart_as_its_source(self) -> None:
        output = fallback(SCAFFOLD)
        assert output.source_path == str(SCAFFOLD / "Chart.yaml")
        assert output.format_type == "helm"


class TestUnresolvedValues:
    def test_two_templated_deployments_stay_two_resources(self) -> None:
        output = fallback(TWO_DEPLOYMENTS)
        assert addresses(output) == [
            "kubernetes_deployment.shop.web-frontend",
            "kubernetes_deployment.shop.worker-backend",
        ]

    def test_two_templated_deployments_whose_names_the_chart_does_not_give_stay_distinct(
        self, tmp_path: Path
    ) -> None:
        chart = copy_chart(TWO_DEPLOYMENTS, tmp_path / "c")
        values = yaml.safe_load((chart / "values.yaml").read_text())
        del values["web"]["name"]
        del values["worker"]["name"]
        (chart / "values.yaml").write_text(yaml.safe_dump(values))
        output = fallback(chart)
        names = [r.name for r in output.resources]
        assert names == ["unresolved-deployments", "unresolved-deployments-1"]
        assert all("placeholder" not in a for a in addresses(output))

    def test_a_privileged_deployment_among_them_produces_the_privileged_finding(self) -> None:
        graph = InfraGraph.from_parsed(fallback(TWO_DEPLOYMENTS))
        threats = HybridEngine().analyze(graph).threats
        privileged = {
            t.resource_address for t in threats if t.rule_id == "K8S_PRIVILEGED_CONTAINER"
        }
        assert privileged == {"kubernetes_deployment.shop.web-frontend"}

    def test_a_disabled_service_is_not_rendered(self) -> None:
        assert "kubernetes_service" not in types(fallback(TWO_DEPLOYMENTS))

    def test_every_template_value_unresolved_still_gives_distinct_resources(
        self, tmp_path: Path
    ) -> None:
        chart = tmp_path / "chart"
        (chart / "templates").mkdir(parents=True)
        (chart / "Chart.yaml").write_text("apiVersion: v2\nname: c\nversion: 1.0.0\n")
        documents = [
            f"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{{{ .Values.n{i} }}}}\n"
            "spec:\n  template:\n    spec:\n      containers:\n        - name: c\n"
            "          image: {{ .Values.image }}\n          securityContext:\n"
            "            privileged: true\n"
            for i in range(4)
        ]
        (chart / "templates" / "d.yaml").write_text("---\n".join(documents))
        output = fallback(chart)
        assert len(set(addresses(output))) == 4
        threats = HybridEngine().analyze(InfraGraph.from_parsed(output)).threats
        assert sum(t.rule_id == "K8S_PRIVILEGED_CONTAINER" for t in threats) == 4

    def test_an_unresolved_image_is_not_reported_as_untagged(self, tmp_path: Path) -> None:
        chart = tmp_path / "chart"
        (chart / "templates").mkdir(parents=True)
        (chart / "Chart.yaml").write_text("apiVersion: v2\nname: c\nversion: 1.0.0\n")
        (chart / "templates" / "d.yaml").write_text(
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\n"
            "spec:\n  template:\n    spec:\n      containers:\n        - name: c\n"
            "          image: {{ .Values.image }}\n"
        )
        (deployment,) = fallback(chart).resources
        assert deployment.properties["uses_latest_tag"] is False

    def test_a_malformed_template_is_still_rendered_and_reported(self, tmp_path: Path) -> None:
        chart = copy_chart(TEST_CHART, tmp_path / "c")
        (chart / "templates" / "broken.yaml").write_text(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: broken\n"
            "{{ if .Values.x }}\ndata: {}\n"
        )
        output = fallback(chart)
        assert "kubernetes_config_map.default.broken" in addresses(output)
        messages = [d.message for d in output.diagnostics if d.code == "helm.render_warning"]
        assert any("broken.yaml" in m and "approximated" in m for m in messages)

    def test_a_template_that_renders_to_invalid_yaml_is_skipped_and_reported(
        self, tmp_path: Path
    ) -> None:
        chart = copy_chart(TEST_CHART, tmp_path / "c")
        (chart / "templates" / "bad.yaml").write_text("a: [1, 2\nb: : :\n")
        output = fallback(chart)
        assert addresses(output) == ["kubernetes_deployment.default.release-app"]
        messages = [d.message for d in output.diagnostics if d.code == "helm.render_warning"]
        assert any("invalid YAML" in m and "bad.yaml" in m for m in messages)


LIBRARY_USER = (
    "apiVersion: v1\nkind: Service\nmetadata:\n"
    '  name: {{ include "common.names.fullname" . }}\n'
    '  namespace: {{ include "common.names.namespace" . | quote }}\n'
    '  labels: {{- include "common.labels.standard" . | nindent 4 }}\n'
    "    app.kubernetes.io/component: primary\nspec:\n  ports:\n    - port: 80\n"
)


def library_chart(root: Path, dependencies: str = "") -> Path:
    chart = root / "app"
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text(
        "apiVersion: v2\nname: app\nversion: 1.0.0\n"
        f"dependencies:\n  - name: common\n    version: 2.x.x\n    repository: oci://x\n{dependencies}",
        encoding="utf-8",
    )
    (chart / "templates" / "svc.yaml").write_text(LIBRARY_USER, encoding="utf-8")
    return chart


class TestAMissingLibraryChart:
    """A chart whose library dependency is not vendored must say so (RW-09)."""

    @pytest.fixture
    def output(self, tmp_path: Path) -> ParsedOutput:
        return fallback(library_chart(tmp_path))

    @staticmethod
    def warnings(output: ParsedOutput) -> list[str]:
        return [d.message for d in output.diagnostics if d.code == "helm.render_warning"]

    def test_the_skipped_template_names_the_includes_nothing_defines(
        self, output: ParsedOutput
    ) -> None:
        (skipped,) = [m for m in self.warnings(output) if "svc.yaml" in m]
        assert "rendered to invalid YAML and was skipped" in skipped
        assert (
            "it includes common.names.fullname, common.names.namespace, common.labels.standard"
            in skipped
        )
        assert "which no chart defines" in skipped
        assert "dependency common is not vendored" in skipped

    def test_the_dependency_is_one_gap_that_says_what_to_run(self, output: ParsedOutput) -> None:
        (gap,) = [m for m in self.warnings(output) if m.startswith("dependency common")]
        assert "not vendored in charts/" in gap
        assert "helm dependency build" in gap

    def test_the_parse_is_marked_incomplete_with_what_is_missing(
        self, output: ParsedOutput
    ) -> None:
        assert output.metadata["incomplete"] is True
        assert output.metadata["skipped_templates"] == ["templates/svc.yaml"]
        assert output.metadata["missing_dependencies"] == ["common"]

    def test_a_vendored_dependency_is_not_missing(self, tmp_path: Path) -> None:
        chart = library_chart(tmp_path)
        helpers = chart / "charts" / "common" / "templates"
        helpers.mkdir(parents=True)
        (chart / "charts" / "common" / "Chart.yaml").write_text(
            "apiVersion: v2\nname: common\nversion: 2.0.0\ntype: library\n", encoding="utf-8"
        )
        (helpers / "_names.tpl").write_text(
            '{{- define "common.names.fullname" -}}x{{- end -}}\n'
            '{{- define "common.names.namespace" -}}ns{{- end -}}\n'
            '{{- define "common.labels.standard" -}}a: b{{- end -}}\n',
            encoding="utf-8",
        )
        output = fallback(chart)
        assert not [m for m in self.warnings(output) if "not vendored" in m]
        assert "incomplete" not in output.metadata
        assert addresses(output) == ["kubernetes_service.ns.x"]

    def test_a_packed_dependency_is_not_missing_either(self, tmp_path: Path) -> None:
        chart = library_chart(tmp_path)
        (chart / "charts").mkdir()
        (chart / "charts" / "common-2.0.0.tgz").write_bytes(b"x")
        output = fallback(chart)
        assert not [m for m in self.warnings(output) if m.startswith("dependency")]
        assert output.metadata["missing_dependencies"] == []

    def test_a_dependency_its_condition_turns_off_is_not_missing(self, tmp_path: Path) -> None:
        chart = library_chart(tmp_path, "    condition: common.enabled\n")
        (chart / "values.yaml").write_text("common:\n  enabled: false\n", encoding="utf-8")
        output = fallback(chart)
        assert not [m for m in self.warnings(output) if m.startswith("dependency")]

    def test_two_missing_dependencies_are_one_plural_gap(self, tmp_path: Path) -> None:
        chart = library_chart(
            tmp_path, "  - name: redis\n    version: 1.x.x\n    repository: oci://x\n"
        )
        (gap,) = [m for m in self.warnings(fallback(chart)) if m.startswith("dependencies")]
        assert gap.startswith("dependencies common, redis are not vendored")

    def test_a_chart_without_dependencies_has_nothing_to_report(self) -> None:
        output = fallback(TEST_CHART)
        assert "missing_dependencies" not in output.metadata
        assert not [d for d in output.diagnostics if "not vendored" in d.message]

    def test_a_template_with_an_unrelated_yaml_error_does_not_blame_a_dependency(
        self, tmp_path: Path
    ) -> None:
        chart = copy_chart(TEST_CHART, tmp_path / "c")
        (chart / "templates" / "bad.yaml").write_text("a: [1, 2\nb: : :\n")
        (skipped,) = [
            d.message
            for d in fallback(chart).diagnostics
            if d.code == "helm.render_warning" and "bad.yaml" in d.message
        ]
        assert "which no chart defines" not in skipped
        assert "not vendored" not in skipped


class TestUnresolvedNamesAreReadable:
    def test_an_unresolved_service_name_and_namespace_are_words(self, tmp_path: Path) -> None:
        chart = tmp_path / "c"
        (chart / "templates").mkdir(parents=True)
        (chart / "Chart.yaml").write_text("apiVersion: v2\nname: c\nversion: 1.0.0\n")
        (chart / "templates" / "svc.yaml").write_text(
            "apiVersion: v1\nkind: Service\nmetadata:\n  name: {{ .Values.name }}\n"
            "  namespace: {{ .Values.ns }}\nspec:\n  ports:\n    - port: 80\n"
        )
        (service,) = fallback(chart).resources
        assert service.address == "kubernetes_service.unresolved-namespace.unresolved-svc"
        assert service.name == "unresolved-svc"

    def test_a_name_with_text_around_the_placeholder_keeps_the_text(self, tmp_path: Path) -> None:
        chart = tmp_path / "c"
        (chart / "templates").mkdir(parents=True)
        (chart / "Chart.yaml").write_text("apiVersion: v2\nname: c\nversion: 1.0.0\n")
        (chart / "templates" / "svc.yaml").write_text(
            "apiVersion: v1\nkind: Service\nmetadata:\n  name: {{ .Values.name }}-web\n"
            "spec:\n  ports:\n    - port: 80\n"
        )
        (service,) = fallback(chart).resources
        assert service.name == "unresolved-svc-web"

    def test_a_resolved_name_is_untouched(self) -> None:
        assert readable_placeholders("web-frontend", "name") == "web-frontend"
        assert readable_placeholders("shop", "namespace") == "shop"

    @pytest.mark.parametrize(
        ("token", "field", "expected"),
        [
            ("placeholder-templates-svc-yaml-0-1", "name", "unresolved-svc"),
            ("placeholder-templates-svc-yaml-2-1", "name", "unresolved-svc-2"),
            ("placeholder-templates-primary-svc-yaml-0-3", "name", "unresolved-primary-svc"),
            (
                "placeholder-charts-redis-templates-svc-yaml-0-1",
                "name",
                "unresolved-redis-svc",
            ),
            ("placeholder-templates-svc-yaml-0-2", "namespace", "unresolved-namespace"),
            (
                "placeholder-templates-a-yaml-0-1-placeholder-templates-a-yaml-0-2",
                "name",
                "unresolved-a-unresolved-a",
            ),
        ],
    )
    def test_the_placeholder_forms(self, token: str, field: str, expected: str) -> None:
        assert readable_placeholders(token, field) == expected
        assert "placeholder" not in expected

    def test_two_documents_of_one_template_stay_distinct(self) -> None:
        first = readable_placeholders("placeholder-templates-d-yaml-0-1", "name")
        second = readable_placeholders("placeholder-templates-d-yaml-1-1", "name")
        assert first != second


# ---------------------------------------------------------------------------------------
# The renderer is never chosen silently
# ---------------------------------------------------------------------------------------


class TestRendererIsVisible:
    def test_a_missing_binary_is_a_visible_fallback(
        self, no_helm: None, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="threatcode.parsers.helm"):
            output = parse_chart(TEST_CHART)
        assert output.metadata["render"] == "fallback"
        assert output.metadata["render_reason"] == "the helm binary was not found on PATH"
        (diagnostic,) = [d for d in output.diagnostics if d.code == "helm.fallback_render"]
        assert diagnostic.level == "warning"
        assert "not found on PATH" in diagnostic.message
        assert diagnostic.file.endswith("Chart.yaml")
        assert any("not found on PATH" in r.message for r in caplog.records)

    def test_the_diagnostic_is_one_per_chart_not_one_per_template(self, no_helm: None) -> None:
        output = parse_chart(PLATFORM)
        assert [d.code for d in output.diagnostics].count("helm.fallback_render") == 1

    def test_off_is_a_fallback_with_its_reason(self) -> None:
        output = parse_chart(TEST_CHART, helm="off")
        assert output.metadata["render"] == "fallback"
        assert "off" in output.metadata["render_reason"]
        assert any(d.code == "helm.fallback_render" for d in output.diagnostics)

    @posix_only
    def test_off_never_starts_helm(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        marker = tmp_path / "ran"
        put_on_path(monkeypatch, fake_helm(tmp_path / "bin", f'touch "{marker}"\nexit 0\n'))
        parse_chart(TEST_CHART, helm="off")
        assert not marker.exists()

    @posix_only
    def test_a_failing_helm_falls_back_visibly_with_its_stderr(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        script = 'echo "Error: chart requires kubeVersion >= 1.99" >&2\nexit 1\n'
        put_on_path(monkeypatch, fake_helm(tmp_path / "bin", script))
        with caplog.at_level(logging.WARNING, logger="threatcode.parsers.helm"):
            output = parse_chart(TEST_CHART)
        assert output.metadata["render"] == "fallback"
        reason = output.metadata["render_reason"]
        assert "exited with status 1" in reason
        assert "chart requires kubeVersion >= 1.99" in reason
        (diagnostic,) = [d for d in output.diagnostics if d.code == "helm.fallback_render"]
        assert "chart requires kubeVersion" in diagnostic.message
        assert any("chart requires kubeVersion" in r.message for r in caplog.records)
        # the fallback still produced the resource
        assert addresses(output) == ["kubernetes_deployment.default.release-app"]

    @posix_only
    def test_a_helm_that_does_not_finish_is_killed_and_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # the sleep is a child of the shell: the kill has to reach the whole process group
        put_on_path(monkeypatch, fake_helm(tmp_path / "bin", "sleep 30 &\nwait\n"))
        started = time.monotonic()
        output = parse_chart(TEST_CHART, timeout=0.5)
        assert time.monotonic() - started < 10
        assert output.metadata["render"] == "fallback"
        assert "did not finish within 0.5 seconds" in output.metadata["render_reason"]

    @posix_only
    def test_output_over_the_cap_kills_helm_and_falls_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        script = (
            "i=0\nwhile [ $i -lt 100000 ]; do echo '# padding padding padding padding'; "
            "i=$((i+1)); done\n"
        )
        put_on_path(monkeypatch, fake_helm(tmp_path / "bin", script))
        started = time.monotonic()
        output = parse_chart(TEST_CHART, max_output_bytes=10_000)
        assert time.monotonic() - started < 20
        assert output.metadata["render"] == "fallback"
        assert "more than 10000 bytes" in output.metadata["render_reason"]

    @posix_only
    def test_a_helm_that_cannot_start_is_a_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        directory = tmp_path / "bin"
        directory.mkdir()
        broken = directory / "helm"
        broken.write_text("#!/nonexistent/interpreter\n", encoding="utf-8")
        broken.chmod(0o755)
        put_on_path(monkeypatch, directory)
        output = parse_chart(TEST_CHART)
        assert output.metadata["render"] == "fallback"
        assert "could not be started" in output.metadata["render_reason"]


# ---------------------------------------------------------------------------------------
# helm=required and the environment variable
# ---------------------------------------------------------------------------------------


class TestModes:
    def test_required_with_no_helm_is_an_error(self, no_helm: None) -> None:
        with pytest.raises(ConfigError, match="not found on PATH"):
            parse_chart(TEST_CHART, helm="required")

    @posix_only
    def test_required_with_a_failing_helm_is_an_error_naming_the_reason(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        put_on_path(monkeypatch, fake_helm(tmp_path / "bin", 'echo "boom" >&2\nexit 3\n'))
        with pytest.raises(ConfigError, match=r"status 3: boom"):
            parse_chart(TEST_CHART, helm="required")

    @posix_only
    def test_required_with_a_working_helm_uses_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        put_on_path(monkeypatch, fake_helm(tmp_path / "bin", HELM_OUTPUT))
        output = parse_chart(SCAFFOLD, helm="required")
        assert output.metadata["render"] == "helm"

    def test_an_unknown_mode_is_a_configuration_error(self) -> None:
        with pytest.raises(ConfigError, match="auto, off, required"):
            HelmParser(helm="sometimes")

    def test_the_mode_comes_from_the_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("THREATCODE_HELM", "off")
        assert HelmParser().mode == "off"
        monkeypatch.setenv("THREATCODE_HELM", "Required")
        assert HelmParser().mode == "required"
        monkeypatch.setenv("THREATCODE_HELM", "bogus")
        with pytest.raises(ConfigError):
            HelmParser()

    def test_an_explicit_argument_beats_the_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("THREATCODE_HELM", "required")
        assert HelmParser(helm="off").mode == "off"

    def test_the_default_is_auto(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("THREATCODE_HELM", raising=False)
        assert HelmParser().mode == "auto"

    def test_through_the_registry_the_environment_selects_the_mode(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("THREATCODE_HELM", "off")
        output = detect_and_parse(TEST_CHART / "Chart.yaml")
        assert output.metadata["render"] == "fallback"
        monkeypatch.setenv("THREATCODE_HELM", "required")
        monkeypatch.setattr("threatcode.parsers.helm.shutil.which", lambda name: None)
        with pytest.raises(ParseError, match="helm is required"):
            detect_and_parse(TEST_CHART / "Chart.yaml")


# ---------------------------------------------------------------------------------------
# A working helm
# ---------------------------------------------------------------------------------------

HELM_OUTPUT = """\
cat <<'EOF'
---
# Source: scaffold/templates/serviceaccount.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: release-scaffold
automountServiceAccountToken: true
---
# Source: scaffold/templates/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: release-scaffold
spec:
  type: ClusterIP
  selector:
    app.kubernetes.io/name: scaffold
---
# Source: scaffold/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: release-scaffold
spec:
  template:
    metadata:
      labels:
        app.kubernetes.io/name: scaffold
    spec:
      serviceAccountName: release-scaffold
      containers:
        - name: scaffold
          image: "nginx:1.16.0"
EOF
"""


@posix_only
class TestWithHelm:
    @pytest.fixture
    def helm_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        directory = fake_helm(tmp_path / "bin", HELM_OUTPUT)
        put_on_path(monkeypatch, directory)
        return directory

    def test_the_binary_output_is_used_and_marked(self, helm_dir: Path) -> None:
        output = parse_chart(SCAFFOLD)
        assert output.metadata["render"] == "helm"
        assert "render_reason" not in output.metadata
        assert not any(d.code == "helm.fallback_render" for d in output.diagnostics)
        assert sorted(addresses(output)) == sorted(
            [
                "kubernetes_service_account.default.release-scaffold",
                "kubernetes_service.default.release-scaffold",
                "kubernetes_deployment.default.release-scaffold",
            ]
        )

    def test_helm_gets_the_release_name_the_fallback_uses_and_skips_tests(
        self, helm_dir: Path
    ) -> None:
        parse_chart(SCAFFOLD)
        arguments = (helm_dir / "args.txt").read_text().split()
        assert arguments[:3] == ["template", "release", str(SCAFFOLD)]
        assert "--skip-tests" in arguments

    def test_a_chart_path_that_starts_with_a_dash_is_not_taken_for_a_flag(
        self, helm_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        output = HelmParser().parse({"apiVersion": "v2", "name": "x"}, "-odd/Chart.yaml")
        arguments = (helm_dir / "args.txt").read_text().split()
        assert arguments[2] == "./-odd"
        assert output.metadata["render"] == "helm"

    def test_each_document_is_attributed_to_its_template_with_a_line(self, helm_dir: Path) -> None:
        by_type = {r.resource_type: r for r in parse_chart(SCAFFOLD).resources}
        deployment = by_type["kubernetes_deployment"]
        assert deployment.source_location == str(SCAFFOLD / "templates" / "deployment.yaml")
        assert deployment.start_line == 1  # where the document starts in the template
        assert by_type["kubernetes_service"].source_location == str(
            SCAFFOLD / "templates" / "service.yaml"
        )
        assert by_type["kubernetes_service_account"].start_line == 2

    def test_the_documents_are_one_connected_set(self, helm_dir: Path) -> None:
        graph = InfraGraph.from_parsed(parse_chart(SCAFFOLD))
        assert {e.relation for e in graph.edges} == {"selects", "runs_as"}

    def test_a_document_without_a_source_comment_belongs_to_the_chart_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        script = "printf 'apiVersion: v1\\nkind: ConfigMap\\nmetadata:\\n  name: bare\\n'\n"
        put_on_path(monkeypatch, fake_helm(tmp_path / "bin", script))
        (resource,) = parse_chart(TEST_CHART).resources
        assert resource.source_location == str(TEST_CHART / "Chart.yaml")
        assert resource.start_line is None

    def test_helm_test_hooks_in_the_output_are_dropped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        script = (
            "cat <<'EOF'\n---\n# Source: x/templates/t.yaml\napiVersion: v1\nkind: Pod\n"
            'metadata:\n  name: probe\n  annotations:\n    "helm.sh/hook": test\n'
            "spec:\n  containers:\n    - name: c\n      image: busybox\nEOF\n"
        )
        put_on_path(monkeypatch, fake_helm(tmp_path / "bin", script))
        assert parse_chart(TEST_CHART).resources == []

    def test_invalid_yaml_in_the_output_is_reported_and_the_rest_is_kept(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        script = (
            "cat <<'EOF'\n---\n# Source: x/templates/bad.yaml\na: [1, 2\nb: : :\n"
            "---\n# Source: x/templates/good.yaml\napiVersion: v1\nkind: ConfigMap\n"
            "metadata:\n  name: good\nEOF\n"
        )
        put_on_path(monkeypatch, fake_helm(tmp_path / "bin", script))
        output = parse_chart(TEST_CHART)
        assert addresses(output) == ["kubernetes_config_map.default.good"]
        assert any(
            d.code == "helm.render_warning" and "bad.yaml" in d.message for d in output.diagnostics
        )

    def test_comment_only_chunks_are_not_documents(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        script = "cat <<'EOF'\n---\n# Source: x/templates/empty.yaml\n# nothing rendered\nEOF\n"
        put_on_path(monkeypatch, fake_helm(tmp_path / "bin", script))
        output = parse_chart(TEST_CHART)
        assert output.resources == []
        assert output.metadata["render"] == "helm"


# ---------------------------------------------------------------------------------------
# Both renderers
# ---------------------------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("helm") is None, reason="needs the helm binary to compare with")
@pytest.mark.parametrize("chart", [SCAFFOLD, PLATFORM, TEST_CHART])
def test_the_fallback_agrees_with_helm(chart: Path) -> None:
    """Both renderers give a chart the same resources, so a scan does not depend on the machine."""
    with_helm = parse_chart(chart, helm="required")
    without = parse_chart(chart, helm="off")
    assert with_helm.metadata["render"] == "helm"
    assert sorted(addresses(with_helm)) == sorted(addresses(without))
    helm_by_address = {r.address: r.properties for r in with_helm.resources}
    for resource in without.resources:
        helm_props = helm_by_address[resource.address]
        for key in ("images", "privileged", "run_as_root", "service_account_name", "has_tls"):
            assert resource.properties.get(key) == helm_props.get(key), (resource.address, key)


# ---------------------------------------------------------------------------------------
# Edges of the parser
# ---------------------------------------------------------------------------------------


class TestParserEdges:
    def test_parse_chart_yaml_text(self) -> None:
        chart_yaml = TEST_CHART / "Chart.yaml"
        result = HelmParser(helm="off").parse(chart_yaml.read_text(), source_path=str(chart_yaml))
        assert result.format_type == "helm"
        assert len(result.resources) == 1

    def test_a_chart_without_a_templates_directory_has_no_resources(self, tmp_path: Path) -> None:
        (tmp_path / "Chart.yaml").write_text("apiVersion: v2\nname: lib\nversion: 1.0.0\n")
        output = HelmParser(helm="off").parse(
            {"apiVersion": "v2", "name": "lib"}, source_path=str(tmp_path / "Chart.yaml")
        )
        assert output.resources == []
        assert output.metadata["render"] == "fallback"

    def test_a_source_path_of_nothing_means_the_current_directory(self) -> None:
        output = HelmParser(helm="off").parse({"apiVersion": "v2", "name": "x"})
        assert output.format_type == "helm"

    def test_the_budget_is_reported_as_a_warning_with_what_was_rendered(self) -> None:
        output = parse_chart(PLATFORM, helm="off", time_budget=-1.0)
        assert output.resources == []
        assert any("time budget" in d.message for d in output.diagnostics)

    def test_the_same_chart_scans_identically_twice(self) -> None:
        first = [(r.address, r.start_line) for r in fallback(PLATFORM).resources]
        second = [(r.address, r.start_line) for r in fallback(PLATFORM).resources]
        assert first == second


class TestHelmDetection:
    def test_chart_yaml_detected(self) -> None:
        path = Path("Chart.yaml")
        data = {"apiVersion": "v2", "name": "test", "version": "0.1.0"}
        assert _detect_helm_chart(path, "", data)

    def test_non_chart_yaml_not_detected(self) -> None:
        path = Path("values.yaml")
        data = {"replicaCount": 1}
        assert not _detect_helm_chart(path, "", data)

    def test_chart_yaml_without_api_version(self) -> None:
        path = Path("Chart.yaml")
        data = {"name": "test"}
        assert not _detect_helm_chart(path, "", data)

    def test_a_chart_yaml_goes_through_the_registry_to_the_helm_parser(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("THREATCODE_HELM", "off")
        output = detect_and_parse(SCAFFOLD / "Chart.yaml")
        assert output.format_type == "helm"
        assert len(output.resources) == 3
