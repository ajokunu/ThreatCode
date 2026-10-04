"""Golden test: IaC threat models must not change when the IR grows new features.

Each IaC fixture is parsed, built into an InfraGraph and analyzed without an LLM.
The report (minus timestamp and version), every node's category and trust zone,
and every edge with its trust-boundary metadata are compared with a recording in
``tests/fixtures/golden/``.

To re-record after an intended change in IaC output, run::

    THREATCODE_UPDATE_GOLDEN=1 pytest tests/test_ir/test_golden.py

and review the diff of ``tests/fixtures/golden/`` before committing it.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from threatcode.engine.hybrid import HybridEngine
from threatcode.ir.graph import InfraGraph
from threatcode.parsers import detect_and_parse

REPO_ROOT = Path(__file__).parent.parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures"
GOLDEN_DIR = FIXTURES / "golden"
UPDATE = os.environ.get("THREATCODE_UPDATE_GOLDEN") == "1"

GOLDEN_INPUTS: list[str] = sorted(
    [str(p.relative_to(REPO_ROOT)) for p in (FIXTURES / "realistic").iterdir() if p.is_file()]
    + [
        "tests/fixtures/terraform/multi_service_insecure.plan.json",
        "tests/fixtures/terraform/multi_service_secure.plan.json",
        "tests/fixtures/terraform/simple_s3.plan.json",
        "tests/fixtures/terraform/simple.tf",
        "tests/fixtures/cloudformation/insecure_stack.yml",
        "tests/fixtures/kubernetes/insecure_deployment.yml",
        "tests/fixtures/kubernetes/multi_resource.yml",
        "tests/fixtures/kubernetes/secure_deployment.yml",
        "tests/fixtures/docker/insecure.Dockerfile",
        "tests/fixtures/docker/multistage.Dockerfile",
        "tests/fixtures/docker/secure.Dockerfile",
        "tests/fixtures/helm/test-chart/Chart.yaml",
        "tests/fixtures/mcp/vulnerable/.mcp.json",
        "tests/fixtures/mcp/fixed/.mcp.json",
    ]
)


def _snapshot(relpath: str) -> dict[str, Any]:
    parsed = detect_and_parse(REPO_ROOT / relpath)
    graph = InfraGraph.from_parsed(parsed)
    report = HybridEngine().analyze(graph, input_file=relpath).to_dict()
    report.pop("timestamp", None)
    report.pop("version", None)
    return {
        "report": report,
        "nodes": {
            nid: {"category": n.category.value, "trust_zone": n.trust_zone.value}
            for nid, n in sorted(graph.nodes.items())
        },
        "edges": [
            {
                "source": e.source,
                "target": e.target,
                "type": e.edge_type.value,
                "crosses_trust_boundary": e.crosses_trust_boundary,
                "source_zone": e.metadata.get("source_zone"),
                "target_zone": e.metadata.get("target_zone"),
            }
            for e in graph.edges
        ],
    }


def _golden_path(relpath: str) -> Path:
    name = relpath.removeprefix("tests/fixtures/").replace("/", "__")
    return GOLDEN_DIR / f"{name}.json"


@pytest.mark.parametrize("relpath", GOLDEN_INPUTS)
def test_iac_output_matches_golden(relpath: str) -> None:
    actual = json.loads(json.dumps(_snapshot(relpath), sort_keys=True))
    path = _golden_path(relpath)
    if UPDATE:
        GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return
    assert path.exists(), f"No golden recording for {relpath}; see the module docstring."
    expected = json.loads(path.read_text(encoding="utf-8"))
    assert actual == expected
