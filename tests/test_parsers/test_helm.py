"""Tests for Helm chart parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from threatcode.parsers.helm import HelmParser


@pytest.fixture
def parser() -> HelmParser:
    return HelmParser()


@pytest.fixture
def chart_dir() -> Path:
    return Path(__file__).parent.parent / "fixtures" / "helm" / "test-chart"


class TestHelmParser:
    def test_raw_template_scan(self, parser: HelmParser, chart_dir: Path) -> None:
        rendered = parser._raw_template_scan(chart_dir)
        assert "Deployment" in rendered
        assert "apiVersion" in rendered
        # Go template directives should be stripped
        assert "{{" not in rendered

    def test_parse_chart_yaml(self, parser: HelmParser, chart_dir: Path) -> None:
        chart_yaml = chart_dir / "Chart.yaml"
        content = chart_yaml.read_text()
        result = parser.parse(content, source_path=str(chart_yaml))
        assert result.format_type == "helm"

    def test_raw_template_preserves_k8s_structure(
        self, parser: HelmParser, chart_dir: Path
    ) -> None:
        rendered = parser._raw_template_scan(chart_dir)
        # Should preserve YAML structure
        assert "kind:" in rendered
        assert "spec:" in rendered

    def test_raw_template_handles_missing_dir(self, parser: HelmParser) -> None:
        result = parser._raw_template_scan(Path("/nonexistent/chart"))
        assert result == ""

    def test_helm_template_fallback(self, parser: HelmParser, chart_dir: Path) -> None:
        # When helm is not on PATH, _helm_template returns None
        # _render_chart should fall back to raw scan
        rendered = parser._render_chart(chart_dir)
        assert rendered  # Should produce some output via fallback


class TestHelmDetection:
    def test_chart_yaml_detected(self) -> None:
        from threatcode.parsers import _detect_helm_chart

        path = Path("Chart.yaml")
        data = {"apiVersion": "v2", "name": "test", "version": "0.1.0"}
        assert _detect_helm_chart(path, "", data)

    def test_non_chart_yaml_not_detected(self) -> None:
        from threatcode.parsers import _detect_helm_chart

        path = Path("values.yaml")
        data = {"replicaCount": 1}
        assert not _detect_helm_chart(path, "", data)

    def test_chart_yaml_without_api_version(self) -> None:
        from threatcode.parsers import _detect_helm_chart

        path = Path("Chart.yaml")
        data = {"name": "test"}
        assert not _detect_helm_chart(path, "", data)
