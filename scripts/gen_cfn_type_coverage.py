#!/usr/bin/env python3
"""Check that every AWS resource type a built-in rule names is reachable from CloudFormation.

The rules are written for Terraform resource types, and the CloudFormation parser names each
resource after the Terraform type in ``threatcode.parsers._cfn_types``.
A rule type that no CloudFormation type maps to never fires on a template, so the gap would
read as a clean scan.

Usage:
    python scripts/gen_cfn_type_coverage.py                 # print the support matrix (Markdown)
    python scripts/gen_cfn_type_coverage.py --format json   # the same as JSON
    python scripts/gen_cfn_type_coverage.py --check         # exit 1 when a rule type is a gap

``--check`` fails when

- a built-in rule resource type starting with ``aws`` has no CloudFormation mapping and is
  not listed in ``UNSUPPORTED_IN_CFN`` with a reason,
- a type listed in ``UNSUPPORTED_IN_CFN`` is in fact mapped, or no built-in rule names it, so
  the list stays honest, or
- the table itself is malformed (a key that is not ``Namespace::Service::Type``, a value that
  is not an ``aws_`` type).

Exit codes: 0 success, 1 ``--check`` found a problem, 2 usage or import error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

try:
    from threatcode.engine.rules.loader import load_builtin_rules
    from threatcode.parsers._cfn_types import (
        CFN_TO_TERRAFORM,
        UNSUPPORTED_IN_CFN,
        cfn_types_for,
        terraform_types,
    )
except ImportError as exc:  # pragma: no cover - only when ThreatCode is not importable
    print(f"error: cannot import threatcode ({exc}); run pip install -e .", file=sys.stderr)
    raise SystemExit(2) from exc

_CFN_KEY = re.compile(r"^[A-Z][A-Za-z0-9]*::[A-Z][A-Za-z0-9]*::[A-Z][A-Za-z0-9]*$")
_TF_VALUE = re.compile(r"^aws_[a-z0-9_]+$")


def rule_types_by_rule() -> dict[str, list[str]]:
    """AWS resource type (or glob) a built-in rule names -> ids of the rules that name it."""
    found: dict[str, list[str]] = defaultdict(list)
    for rule in load_builtin_rules():
        for resource_type in rule.resource_types:
            if resource_type.startswith("aws"):
                found[resource_type].append(rule.id)
    return {key: sorted(set(ids)) for key, ids in sorted(found.items())}


def is_mapped(resource_type: str) -> bool:
    """Whether some CloudFormation type reaches a rule type; a trailing ``*`` is a prefix."""
    targets = terraform_types()
    if resource_type.endswith("*"):
        prefix = resource_type[:-1]
        return any(target.startswith(prefix) for target in targets)
    return resource_type in targets


def table_problems() -> list[str]:
    problems: list[str] = []
    for cfn_type, terraform_type in CFN_TO_TERRAFORM.items():
        if not _CFN_KEY.match(cfn_type):
            problems.append(f"table key {cfn_type!r} is not Namespace::Service::Type")
        if not _TF_VALUE.match(terraform_type):
            problems.append(f"table value {terraform_type!r} for {cfn_type} is not an aws_ type")
    return problems


def check() -> list[str]:
    """Every problem found; an empty list means the table covers the rules."""
    problems = table_problems()
    by_type = rule_types_by_rule()
    for resource_type, rule_ids in by_type.items():
        if is_mapped(resource_type) or resource_type in UNSUPPORTED_IN_CFN:
            continue
        shown = ", ".join(rule_ids[:4]) + (", ..." if len(rule_ids) > 4 else "")
        problems.append(
            f"{resource_type} ({shown}) has no CloudFormation mapping and is not in "
            "UNSUPPORTED_IN_CFN; add a type to CFN_TO_TERRAFORM or list it with a reason"
        )
    for resource_type, reason in UNSUPPORTED_IN_CFN.items():
        if not reason.strip():
            problems.append(f"UNSUPPORTED_IN_CFN lists {resource_type} without a reason")
        if is_mapped(resource_type):
            problems.append(f"{resource_type} is in UNSUPPORTED_IN_CFN but a type maps to it")
        if resource_type not in by_type:
            problems.append(
                f"{resource_type} is in UNSUPPORTED_IN_CFN but no built-in rule names it"
            )
    return problems


@dataclass(frozen=True)
class Row:
    """One Terraform type: the CloudFormation types that reach it and the rules that read it."""

    terraform_type: str
    cloudformation_types: tuple[str, ...]
    rules: tuple[str, ...]
    supported: bool
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "terraform_type": self.terraform_type,
            "cloudformation_types": list(self.cloudformation_types),
            "rules": list(self.rules),
            "supported": self.supported,
            "reason": self.reason,
        }


def matrix() -> list[Row]:
    by_type = rule_types_by_rule()
    rows: list[Row] = []
    for terraform_type in sorted(terraform_types() | set(UNSUPPORTED_IN_CFN)):
        supported = terraform_type not in UNSUPPORTED_IN_CFN
        rows.append(
            Row(
                terraform_type=terraform_type,
                cloudformation_types=tuple(cfn_types_for(terraform_type)) if supported else (),
                rules=tuple(by_type.get(terraform_type, [])),
                supported=supported,
                reason=UNSUPPORTED_IN_CFN.get(terraform_type, ""),
            )
        )
    return rows


def render_markdown(rows: list[Row]) -> str:
    read = sum(1 for row in rows if row.supported and row.rules)
    lines = [
        "| CloudFormation type | Terraform type | Built-in rules |",
        "| --- | --- | --- |",
    ]
    for row in rows:
        rules = ", ".join(f"`{rule}`" for rule in row.rules)
        if not row.supported:
            lines.append(f"| not expressible | `{row.terraform_type}` | {rules} ({row.reason}) |")
            continue
        for cfn_type in row.cloudformation_types:
            lines.append(f"| `{cfn_type}` | `{row.terraform_type}` | {rules or 'none yet'} |")
    lines.append("")
    lines.append(
        f"{len(CFN_TO_TERRAFORM)} CloudFormation types map to {len(terraform_types())} "
        f"Terraform types; {read} of those Terraform types are read by a built-in rule."
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument("--check", action="store_true", help="exit 1 when a rule type is a gap")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    args = parser.parse_args(argv)

    if args.check:
        problems = check()
        if problems:
            print("CloudFormation type coverage problems:", file=sys.stderr)
            for problem in problems:
                print(f"  - {problem}", file=sys.stderr)
            return 1
        by_type = rule_types_by_rule()
        print(
            f"ok: all {len(by_type)} AWS rule resource types are mapped or listed as "
            f"unsupported ({len(UNSUPPORTED_IN_CFN)} unsupported)"
        )
        return 0

    rows = matrix()
    if args.format == "json":
        print(json.dumps([row.to_dict() for row in rows], indent=2))
    else:
        print(render_markdown(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
