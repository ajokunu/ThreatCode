"""Classes of finding that do not depend on which rule reports them.

A ``kind`` names what a finding is about (``imdsv1``, ``open_ingress``, ``wildcard_iam``) so an
expectation survives a rule being renamed, split or replaced. Each kind is a regular expression
applied, case-insensitively, to ``"<rule id> <title> <description>"`` of a finding.

The planted-issue benchmark (``tests/test_quality``) and the demo example expectations
(``examples/*/expected.yml``) both use these kinds.
"""

from __future__ import annotations

import re

KIND_PATTERNS: dict[str, re.Pattern[str]] = {
    name: re.compile(pattern, re.IGNORECASE)
    for name, pattern in {
        "open_ingress": (
            r"ingress|inbound|any source|0\.0\.0\.0/0|open to the (internet|world)|allow[- ]?all"
        ),
        "wildcard_iam": (
            r"wildcard|admin|full access|overpermissive|over-permissive|excessive|\*:\*"
        ),
        "public_access": r"public",
        "public_ip": r"public ip|public address|publicly addressable",
        "unencrypted_storage": r"encrypt",
        "imdsv1": r"imds|instance metadata|http_tokens|metadata (service|options)",
        "hardcoded_secret": r"secret|password|credential|hard-?coded",
        "rbac_disabled": r"rbac",
        "registry_admin_enabled": r"admin (user|account|enabled)|admin_enabled",
        "https_not_enforced": r"https|tls|plaintext|unencrypted transport",
        "no_vpc": r"\bvpc\b",
        "secrets_read": r"secrets?.*(read|get|list|access)|(read|get|list|access).*secrets?",
    }.items()
}
