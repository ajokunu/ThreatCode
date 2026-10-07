"""Helm chart parser for ThreatCode.

Renders a chart to Kubernetes manifests and hands them to the Kubernetes parser, which
reads them as one connected set (Services find their Deployments, a Deployment finds its
ServiceAccount) however many template files the chart spread them over.

The renderer is ``helm template`` when the binary is on ``PATH``, and the safe renderer in
``_helm_render`` otherwise or when helm fails. The choice is never silent:
``metadata['render']`` is ``'helm'`` or ``'fallback'``, and every fallback adds a
``helm.fallback_render`` warning that says why. ``THREATCODE_HELM`` (or the ``helm`` argument)
selects ``auto`` (the default), ``off`` (always the fallback) or ``required`` (a missing or
failing helm is an error).

Both renderers use the release name ``release`` and skip chart tests, so a chart's resources
get the same addresses either way.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any

from threatcode.diagnostics import Diagnostic, register_code
from threatcode.exceptions import ConfigError, ParseError
from threatcode.parsers._helm_render import (
    DEFAULT_TIME_BUDGET_SECONDS,
    RELEASE_NAME,
    ChartRender,
    find_document_line,
    read_template,
    render_chart,
)
from threatcode.parsers._k8s_security import as_dict
from threatcode.parsers._yaml import load_yaml_documents
from threatcode.parsers.base import BaseParser, ParsedOutput
from threatcode.parsers.kubernetes import KubernetesParser, ManifestDocument

logger = logging.getLogger(__name__)

register_code(
    "helm.render_warning",
    "A Helm template was skipped or only approximated, so its resources may be missing or inexact",
)

HELM_MODE_ENV = "THREATCODE_HELM"
HELM_MODES = ("auto", "off", "required")
DEFAULT_HELM_TIMEOUT_SECONDS = 30.0
MAX_HELM_OUTPUT_BYTES = 20 * 1024 * 1024
_STDERR_TAIL_BYTES = 500
_SOURCE_COMMENT = re.compile(r"#\s*Source:\s*(\S.*?)\s*\Z")
_SEPARATOR = re.compile(r"---[ \t]*\Z")


class HelmParser(BaseParser):
    """Parse Helm charts by rendering their templates to Kubernetes manifests."""

    def __init__(
        self,
        helm: str | None = None,
        *,
        timeout: float = DEFAULT_HELM_TIMEOUT_SECONDS,
        max_output_bytes: int = MAX_HELM_OUTPUT_BYTES,
        time_budget: float = DEFAULT_TIME_BUDGET_SECONDS,
    ) -> None:
        mode = (helm if helm is not None else os.environ.get(HELM_MODE_ENV, "auto")).strip().lower()
        if mode not in HELM_MODES:
            raise ConfigError(
                f"Invalid helm mode '{mode}': use one of {', '.join(HELM_MODES)} "
                f"(set with {HELM_MODE_ENV})"
            )
        self.mode = mode
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes
        self.time_budget = time_budget

    def parse(self, data: Any, source_path: str = "") -> ParsedOutput:
        chart_dir = Path(source_path).parent if source_path else Path(".")
        meta = data if isinstance(data, dict) else None
        diagnostics: list[Diagnostic] = []

        documents: list[ManifestDocument] | None = None
        reason = f"disabled by {HELM_MODE_ENV}=off"
        if self.mode != "off":
            text, reason = self._run_helm(chart_dir)
            if text is not None:
                documents = _documents_from_helm(text, chart_dir, source_path, diagnostics)
            elif self.mode == "required":
                raise ConfigError(f"helm is required but {reason}")

        renderer = "helm"
        if documents is None:
            renderer = "fallback"
            documents = self._fallback(chart_dir, meta, source_path, reason, diagnostics)

        result = KubernetesParser().parse_documents(documents, source_path)
        result.format_type = "helm"
        result.diagnostics = [*diagnostics, *result.diagnostics]
        result.metadata["render"] = renderer
        if renderer == "fallback":
            result.metadata["render_reason"] = reason
        return result

    # -- the fallback renderer -----------------------------------------------------------

    def _fallback(
        self,
        chart_dir: Path,
        meta: dict[str, Any] | None,
        source_path: str,
        reason: str,
        diagnostics: list[Diagnostic],
    ) -> list[ManifestDocument]:
        name = Path(source_path).name or "Chart.yaml"
        message = (
            f"{name} was rendered without helm ({reason}); values the chart takes from "
            "elsewhere are approximated"
        )
        logger.warning("%s", message)
        diagnostics.append(Diagnostic("warning", "helm.fallback_render", message, source_path))
        render = render_chart(chart_dir, chart_meta=meta, time_budget=self.time_budget)
        return _documents_from_render(render, chart_dir, source_path, diagnostics)

    # -- the helm binary -----------------------------------------------------------------

    def _run_helm(self, chart_dir: Path) -> tuple[str | None, str]:
        """Run ``helm template``; returns its output, or None and the reason it was not used.

        Output is read through a bounded reader: past ``max_output_bytes`` the process is killed
        and the result is a failure, so a chart cannot make helm's output fill memory.
        """
        binary = shutil.which("helm")
        if binary is None:
            return None, "the helm binary was not found on PATH"
        chart_argument = str(chart_dir)
        if chart_argument.startswith("-"):
            chart_argument = f"./{chart_argument}"
        command = [binary, "template", RELEASE_NAME, chart_argument, "--skip-tests"]
        chunks: list[bytes] = []
        state = {"size": 0, "overflow": False}
        with tempfile.TemporaryFile() as stderr:
            try:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=stderr,
                    # Its own process group, so a kill reaches anything helm started too
                    start_new_session=os.name == "posix",
                )
            except OSError as exc:
                return None, f"helm could not be started: {exc}"

            def pump() -> None:
                assert process.stdout is not None
                while True:
                    block = process.stdout.read(65536)
                    if not block:
                        return
                    state["size"] += len(block)
                    if state["size"] > self.max_output_bytes:
                        state["overflow"] = True
                        _kill(process)
                        return
                    chunks.append(block)

            reader = threading.Thread(target=pump, daemon=True)
            reader.start()
            reader.join(self.timeout)
            timed_out = reader.is_alive()
            if timed_out:
                _kill(process)
            reader.join(5)
            try:
                code = process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _kill(process)
                code = process.wait()
            if process.stdout is not None:
                process.stdout.close()
            stderr.seek(0, os.SEEK_END)
            stderr.seek(max(0, stderr.tell() - _STDERR_TAIL_BYTES))
            tail = stderr.read().decode("utf-8", errors="replace").strip()

        if state["overflow"]:
            return None, f"helm printed more than {self.max_output_bytes} bytes"
        if timed_out:
            return None, f"helm did not finish within {self.timeout:g} seconds"
        if code != 0:
            detail = f": {tail}" if tail else ""
            return None, f"helm exited with status {code}{detail}"
        return b"".join(chunks).decode("utf-8", errors="replace"), ""


def _kill(process: subprocess.Popen[bytes]) -> None:
    """Kill helm and, where there are process groups, everything it started."""
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:  # pragma: no cover - Windows has no process groups to signal
            process.kill()
    except OSError:
        process.kill()


# ---------------------------------------------------------------------------------------
# Rendered output to documents
# ---------------------------------------------------------------------------------------


def _is_test_hook(document: Any) -> bool:
    """True for a manifest that is a Helm test hook, which is not part of the release."""
    annotations = as_dict(as_dict(as_dict(document).get("metadata")).get("annotations"))
    hooks = annotations.get("helm.sh/hook")
    if not isinstance(hooks, str):
        return False
    return any(hook.strip().startswith("test") for hook in hooks.split(","))


def _warn(diagnostics: list[Diagnostic], message: str, file: str) -> None:
    logger.warning("%s", message)
    diagnostics.append(Diagnostic("warning", "helm.render_warning", message, file))


def _documents_from_render(
    render: ChartRender, chart_dir: Path, source_path: str, diagnostics: list[Diagnostic]
) -> list[ManifestDocument]:
    for message in render.warnings:
        _warn(diagnostics, message, source_path)
    documents: list[ManifestDocument] = []
    for rendered in render.files:
        file = str(chart_dir / rendered.path)
        try:
            loaded, indexes = load_yaml_documents(
                rendered.text, with_lines=True, source=rendered.path
            )
        except ParseError as exc:
            _warn(
                diagnostics,
                f"{rendered.path} rendered to invalid YAML and was skipped: {exc}",
                file,
            )
            continue
        for data, index in zip(loaded, indexes):
            if _is_test_hook(data):
                continue
            line = rendered.template_line(index.get("", 0)) if index else None
            documents.append(ManifestDocument(data, file, start_line=line))
    return documents


def _split_documents(text: str) -> list[tuple[str, str]]:
    """Split ``helm template`` output into ``(source template, document text)`` pairs."""
    pieces: list[tuple[str, str]] = []
    lines: list[str] = []

    def flush() -> None:
        source = ""
        body: list[str] = []
        for line in lines:
            found = _SOURCE_COMMENT.match(line.strip())
            if found and not source and not body:
                source = found.group(1)
            else:
                body.append(line)
        if any(part.strip() and not part.lstrip().startswith("#") for part in body):
            pieces.append((source, "\n".join(body)))

    for line in text.split("\n"):
        if _SEPARATOR.match(line):
            flush()
            lines = []
        else:
            lines.append(line)
    flush()
    return pieces


def _documents_from_helm(
    text: str, chart_dir: Path, source_path: str, diagnostics: list[Diagnostic]
) -> list[ManifestDocument]:
    """Documents of ``helm template`` output, each attributed to its template through ``# Source:``.

    The comment names ``<chart>/templates/<file>``; the first segment is the chart's own name,
    so the rest is a path inside ``chart_dir``. The start line is where the matching document
    starts in that template.
    """
    documents: list[ManifestDocument] = []
    template_text: dict[str, str | None] = {}
    seen_kinds: dict[tuple[str, str], int] = {}
    for source, body in _split_documents(text):
        relative = source.partition("/")[2] if source else ""
        file = str(chart_dir / relative) if relative else source_path
        try:
            loaded = load_yaml_documents(body, source=relative or "helm output")
        except ParseError as exc:
            _warn(
                diagnostics,
                f"A document of {relative or 'the helm output'} was invalid YAML: {exc}",
                file,
            )
            continue
        for data in loaded:
            if _is_test_hook(data):
                continue
            line = None
            kind = data.get("kind") if isinstance(data, dict) else None
            if relative and isinstance(kind, str):
                if relative not in template_text:
                    template_text[relative] = read_template(chart_dir / relative)
                key = (relative, kind)
                occurrence = seen_kinds.get(key, 0)
                seen_kinds[key] = occurrence + 1
                text_of_template = template_text[relative]
                if text_of_template is not None:
                    line = find_document_line(text_of_template, kind, occurrence)
            documents.append(ManifestDocument(data, file, start_line=line))
    return documents
