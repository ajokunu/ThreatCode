"""Test doubles and builders for the LLM tests: a fake client and graphs that carry canaries.

``FakeLLMClient`` returns queued replies (or raises queued errors) and records every prompt it
receives, so a test can assert on what would have left the machine.
``canary_graph`` builds a graph whose names, tags and properties hold values that must never
appear in a prompt, next to values that must.
"""

from __future__ import annotations

import json
from typing import Any

from threatcode.engine.llm.client import BaseLLMClient
from threatcode.ir.graph import InfraGraph
from threatcode.parsers.base import ParsedEdge, ParsedOutput, ParsedResource

EMPTY_REPLY = '{"threats": []}'

# Values that must never reach a prompt.
CANARY_NAME = "acme_payments_prod"
CANARY_PASSWORD = "Sup3rS3cretDbPassw0rd!"
CANARY_MASTER_PASSWORD = "m4st3r-p4ssw0rd-canary"
CANARY_AWS_KEY = "AKIAQWERTYUIOP123456"
CANARY_AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYcanarySECRET"
CANARY_TOKEN = "ghp_canaryTOKEN0123456789abcdefghijklmnopqr"
CANARY_ACCOUNT = "123456789012"
CANARY_PRIVATE_IP = "10.20.30.40"
CANARY_TEAM = "payments-platform-team"
CANARY_USER_DATA = "#!/bin/bash\\necho canary-user-data-line"
CANARIES = (
    CANARY_NAME,
    CANARY_PASSWORD,
    CANARY_MASTER_PASSWORD,
    CANARY_AWS_KEY,
    CANARY_AWS_SECRET,
    CANARY_TOKEN,
    CANARY_ACCOUNT,
    CANARY_PRIVATE_IP,
    CANARY_TEAM,
    "canary-user-data-line",
)


class FakeLLMClient(BaseLLMClient):
    """Replays queued replies in order and records every prompt.

    A queued ``Exception`` is raised instead of returned.
    When the queue is empty the ``default`` reply is used.
    """

    provider = "fake"
    model = "fake-model"

    def __init__(self, *replies: str | Exception, default: str = EMPTY_REPLY) -> None:
        self._queue: list[str | Exception] = list(replies)
        self._default = default
        self.prompts: list[str] = []

    @property
    def calls(self) -> int:
        return len(self.prompts)

    def analyze(self, prompt: str) -> str:
        self.prompts.append(prompt)
        reply: str | Exception = self._queue.pop(0) if self._queue else self._default
        if isinstance(reply, Exception):
            raise reply
        return reply


def threats_reply(*items: dict[str, Any]) -> str:
    """A model reply holding the given threat objects."""
    return json.dumps({"threats": list(items)})


def raw_threat(**overrides: Any) -> dict[str, Any]:
    """A well-formed model threat; override any field."""
    item: dict[str, Any] = {
        "title": "Lateral movement from the public bucket role",
        "description": "An attacker who reads the bucket can reach the role.",
        "stride_category": "elevation_of_privilege",
        "severity": "high",
        "resource_type": "aws_s3_bucket",
        "resource_address": "aws_s3_bucket.n1",
        "mitigation": "Split the role",
        "confidence": 0.9,
    }
    item.update(overrides)
    return item


def canary_graph(extra_resources: int = 0) -> InfraGraph:
    """A small AWS graph whose names and properties carry the canary values."""
    resources = [
        ParsedResource(
            resource_type="aws_db_instance",
            address=f"aws_db_instance.{CANARY_NAME}",
            name=CANARY_NAME,
            provider="aws",
            properties={
                "identifier": CANARY_NAME,
                "engine": "postgres",
                "publicly_accessible": True,
                "storage_encrypted": False,
                "password": CANARY_PASSWORD,
                "master_password": CANARY_MASTER_PASSWORD,
                "access_key": CANARY_AWS_KEY,
                "secret_key": CANARY_AWS_SECRET,
                "kms_key_id": f"arn:aws:kms:us-east-1:{CANARY_ACCOUNT}:key/abc",
                "tags": {"team": CANARY_TEAM, "owner": f"{CANARY_NAME}@example.com"},
                "private_ip": CANARY_PRIVATE_IP,
                "user_data": CANARY_USER_DATA,
                "connection_string": f"postgres://admin:{CANARY_PASSWORD}@db.internal/{CANARY_NAME}",
            },
        ),
        ParsedResource(
            resource_type="aws_security_group",
            address=f"aws_security_group.{CANARY_NAME}_sg",
            name=f"{CANARY_NAME}_sg",
            provider="aws",
            properties={
                "name": f"{CANARY_NAME}-sg",
                "description": f"Allow {CANARY_NAME} traffic from {CANARY_PRIVATE_IP}",
                "ingress": [
                    {
                        "from_port": 5432,
                        "to_port": 5432,
                        "protocol": "tcp",
                        "cidr_blocks": ["0.0.0.0/0", f"{CANARY_PRIVATE_IP}/32"],
                        "description": f"{CANARY_NAME} access",
                    }
                ],
            },
        ),
        ParsedResource(
            resource_type="aws_s3_bucket",
            address=f"aws_s3_bucket.{CANARY_NAME}_logs",
            name=f"{CANARY_NAME}_logs",
            provider="aws",
            properties={
                "bucket": f"{CANARY_NAME}-logs",
                "acl": "public-read",
                "tags": {"team": CANARY_TEAM},
            },
        ),
    ]
    for index in range(extra_resources):
        resources.append(
            ParsedResource(
                resource_type="aws_subnet",
                address=f"aws_subnet.{CANARY_NAME}_{index}",
                name=f"{CANARY_NAME}_{index}",
                provider="aws",
                properties={"cidr_block": f"10.{index % 250}.0.0/24"},
            )
        )
    edges = [
        ParsedEdge(
            source=f"aws_db_instance.{CANARY_NAME}",
            target=f"aws_security_group.{CANARY_NAME}_sg",
            edge_type="network_flow",
            metadata={"protocol": "tcp", "port": 5432, "authenticated": False, "note": CANARY_NAME},
        )
    ]
    output = ParsedOutput(resources=resources, edges=edges, source_path="main.tf", format_type="x")
    return InfraGraph.from_parsed(output)
