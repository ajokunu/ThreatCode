"""Shared test fixtures."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import InfraNode, NodeCategory, TrustZone
from threatcode.parsers.base import ParsedOutput

# The pending marker and its hooks live in tests/helpers/pending.py; "pytester" backs the
# harness self-tests that run a throwaway pytest session. Later packages add per-directory
# conftest files and never edit this one.
pytest_plugins = ["pytester", "tests.helpers.pending"]

FIXTURES_DIR = Path(__file__).parent / "fixtures"
TERRAFORM_FIXTURES = FIXTURES_DIR / "terraform"


@pytest.fixture
def simple_s3_plan_path() -> Path:
    return TERRAFORM_FIXTURES / "simple_s3.plan.json"


@pytest.fixture
def simple_s3_plan_data(simple_s3_plan_path: Path) -> dict:
    return json.loads(simple_s3_plan_path.read_text(encoding="utf-8"))


@pytest.fixture
def simple_s3_parsed(simple_s3_plan_data: dict) -> ParsedOutput:
    from threatcode.parsers.terraform_plan import TerraformPlanParser

    parser = TerraformPlanParser()
    return parser.parse(simple_s3_plan_data, source_path="test.plan.json")


@pytest.fixture
def simple_s3_graph(simple_s3_parsed: ParsedOutput) -> InfraGraph:
    return InfraGraph.from_parsed(simple_s3_parsed)


@pytest.fixture
def s3_node_no_encryption() -> InfraNode:
    return InfraNode(
        id="aws_s3_bucket.test",
        resource_type="aws_s3_bucket",
        name="test",
        category=NodeCategory.STORAGE,
        trust_zone=TrustZone.DATA,
        properties={
            "bucket": "test-bucket",
            "acl": "private",
        },
    )


@pytest.fixture
def s3_node_public() -> InfraNode:
    return InfraNode(
        id="aws_s3_bucket.public",
        resource_type="aws_s3_bucket",
        name="public",
        category=NodeCategory.STORAGE,
        trust_zone=TrustZone.DATA,
        properties={
            "bucket": "public-bucket",
            "acl": "public-read",
        },
    )


@pytest.fixture
def s3_node_secure() -> InfraNode:
    return InfraNode(
        id="aws_s3_bucket.secure",
        resource_type="aws_s3_bucket",
        name="secure",
        category=NodeCategory.STORAGE,
        trust_zone=TrustZone.DATA,
        properties={
            "bucket": "secure-bucket",
            "acl": "private",
            "versioning": [{"enabled": True}],
            "logging": {"target_bucket": "logs"},
            "server_side_encryption_configuration": {
                "rule": {"apply_server_side_encryption_by_default": {"sse_algorithm": "aws:kms"}}
            },
        },
    )


@dataclass
class FakeLLMServer:
    """A local OpenAI-compatible chat completions server (stands in for Ollama)."""

    base_url: str
    reply: str = '{"threats": []}'
    requests: list[dict[str, Any]] = field(default_factory=list)


@pytest.fixture
def fake_llm_server() -> Iterator[FakeLLMServer]:
    """Serve /v1/chat/completions on 127.0.0.1 and record each request body."""
    state = FakeLLMServer(base_url="")

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - http.server naming
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            state.requests.append({"path": self.path, "body": body})
            payload = json.dumps({"choices": [{"message": {"content": state.reply}}]})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload.encode())

        def log_message(self, format: str, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    state.base_url = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
