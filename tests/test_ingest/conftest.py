"""Shared helpers for the ingestion tests: the sample repository, its graph and report files."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from functools import cache
from pathlib import Path
from typing import Any

import pytest

from threatcode.ingest import IngestResult, load_and_attach
from threatcode.ir.graph import InfraGraph
from threatcode.pipeline import prepare_request, run_scan

INGEST_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "ingest"
REPO = INGEST_FIXTURES / "repo"

Ingest = Callable[..., IngestResult]


def build_graph(root: Path) -> InfraGraph:
    """The graph the scan pipeline builds for ``root``."""
    return run_scan(prepare_request([str(root)], fail_on="none").request).graph


@cache
def _repo_graph() -> InfraGraph:
    return build_graph(REPO)


@pytest.fixture(scope="session")
def repo_graph() -> InfraGraph:
    """The graph of ``tests/fixtures/ingest/repo``; tests only read it."""
    return _repo_graph()


@pytest.fixture
def ingest(repo_graph: InfraGraph) -> Ingest:
    """``ingest('trivy-image.json', ...)`` loads fixture files into the sample repository."""

    def run(*names: str) -> IngestResult:
        return load_and_attach([INGEST_FIXTURES / n for n in names], repo_graph, REPO)

    return run


def write_tree(root: Path, files: Mapping[str, str]) -> Path:
    for name, text in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return root


def write_json(path: Path, data: Any) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def by_rule(result: IngestResult) -> dict[str, list[Any]]:
    """The threats of a result grouped by rule id."""
    grouped: dict[str, list[Any]] = {}
    for threat in result.threats:
        grouped.setdefault(threat.rule_id, []).append(threat)
    return grouped
