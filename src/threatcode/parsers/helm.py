"""Helm chart parser for ThreatCode.

Renders Helm chart templates to Kubernetes YAML and delegates
to the Kubernetes parser for security analysis.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from threatcode.parsers.base import BaseParser, ParsedOutput

logger = logging.getLogger(__name__)


class HelmParser(BaseParser):
    """Parse Helm charts by rendering templates to Kubernetes YAML."""

    def parse(self, data: Any, source_path: str = "") -> ParsedOutput:
        chart_dir = Path(source_path).parent if source_path else Path(".")
        rendered = self._render_chart(chart_dir)
        if not rendered.strip():
            return ParsedOutput(resources=[], source_path=source_path, format_type="helm")

        from threatcode.parsers.kubernetes import KubernetesParser

        result = KubernetesParser().parse(rendered, source_path=source_path)
        result.format_type = "helm"
        return result

    def _render_chart(self, chart_dir: Path) -> str:
        """Render a Helm chart to Kubernetes YAML.

        Tries `helm template` first for accurate rendering.
        Falls back to raw template scanning if helm CLI is not available.
        """
        rendered = self._helm_template(chart_dir)
        if rendered is not None:
            return rendered
        return self._raw_template_scan(chart_dir)

    def _helm_template(self, chart_dir: Path) -> str | None:
        """Try to render using the helm CLI."""
        if not shutil.which("helm"):
            logger.debug("helm CLI not found on PATH, falling back to raw template scan")
            return None

        try:
            result = subprocess.run(
                ["helm", "template", "scan", str(chart_dir)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                return result.stdout
            logger.debug("helm template failed: %s", result.stderr[:500])
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.debug("helm template error: %s", e)
        return None

    def _raw_template_scan(self, chart_dir: Path) -> str:
        """Fallback: read template files and strip Go template directives."""
        templates_dir = chart_dir / "templates"
        if not templates_dir.is_dir():
            return ""

        parts: list[str] = []
        for tmpl_file in sorted(templates_dir.iterdir()):
            if tmpl_file.suffix not in (".yaml", ".yml"):
                continue
            if tmpl_file.name.startswith("_"):
                continue

            try:
                content = tmpl_file.read_text(encoding="utf-8")
            except OSError:
                continue

            # Strip Go template directives, replace with safe defaults
            # Replace {{ .Values.xxx }} with placeholder strings
            cleaned = re.sub(r"\{\{-?\s*\.Values\.\S+\s*-?\}\}", "placeholder", content)
            # Replace {{ .Release.Name }} etc. with placeholder
            cleaned = re.sub(r"\{\{-?\s*\.Release\.\S+\s*-?\}\}", "release", cleaned)
            # Replace {{ .Chart.Name }} etc. with placeholder
            cleaned = re.sub(r"\{\{-?\s*\.Chart\.\S+\s*-?\}\}", "chart", cleaned)
            # Remove template control structures (if, range, end, define, etc.)
            cleaned = re.sub(
                r"\{\{-?\s*(if|else|end|range|define|template|block|with).*?-?\}\}", "", cleaned
            )
            # Remove include/toYaml helpers
            cleaned = re.sub(
                r"\{\{-?\s*(include|toYaml|toJson|indent|nindent|trim).*?-?\}\}",
                "placeholder",
                cleaned,
            )
            # Remove any remaining template directives
            cleaned = re.sub(r"\{\{.*?\}\}", "placeholder", cleaned)

            parts.append(cleaned)

        return "\n---\n".join(parts)
