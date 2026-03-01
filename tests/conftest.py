"""Shared test fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import InfraNode, NodeCategory, TrustZone
from threatcode.parsers.base import ParsedOutput

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
