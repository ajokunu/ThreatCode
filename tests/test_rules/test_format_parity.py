"""One configuration in three formats must trip the same rules.

Each file set under ``parity/`` expresses one small configuration as Terraform HCL, as the
plan JSON ``terraform show -json`` prints for it, and as a CloudFormation template.
A rule that fires for the HCL but not the plan, or for the plan but not the template,
is a format-specific blind spot: users of the quiet format get a clean report for a
configuration that is just as exposed.

The comparison is restricted to the rules named in ``FOCUS``: the rules whose conditions read
attributes the configuration sets explicitly. Other rules read attributes that a plan reports
as unknown after apply while HCL leaves them absent, and those differences are intended
(``values.Unknown`` in the rework), not blind spots.

Plan JSON is the reference. Differences that are known and owned by a later package are
listed in ``EXPECTED_DIFFERENCES``, with the package that removes them, and run as pending.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from tests.helpers.pending import pending
from tests.helpers.scan import scan_files
from tests.test_rules.harness import compare_formats

PARITY_DIR = Path(__file__).parent / "parity"
REFERENCE = "plan"
FILE_SUFFIX = {"hcl": ".tf", "plan": ".plan.json", "cfn": ".cfn.yaml"}

# configuration name -> the rules whose firing must agree across formats
FOCUS: dict[str, frozenset[str]] = {
    "public_bucket": frozenset({"S3_PUBLIC_ACCESS"}),
    "public_database": frozenset({"RDS_PUBLIC_ACCESS", "RDS_NO_ENCRYPTION"}),
    "open_instance": frozenset({"EC2_PUBLIC_IP"}),
    "wildcard_policy": frozenset({"IAM_WILDCARD_ACTION"}),
}

# (configuration, format) -> (package that removes the difference, what differs today)
EXPECTED_DIFFERENCES: dict[tuple[str, str], tuple[str, str]] = {
    ("public_bucket", "cfn"): ("WP-2-3", "AccessControl is not translated to acl"),
    ("public_database", "cfn"): ("WP-2-3", "PubliclyAccessible is not translated"),
    ("open_instance", "cfn"): ("WP-2-3", "NetworkInterfaces association is not hoisted"),
    ("wildcard_policy", "cfn"): ("WP-2-3", "ManagedPolicy documents are not a known type"),
    ("wildcard_policy", "hcl"): ("WP-2-2", "jsonencode text is not normalized to JSON"),
}


def fired(config: str, fmt: str) -> Counter[str]:
    path = PARITY_DIR / f"{config}{FILE_SUFFIX[fmt]}"
    result = scan_files([path])
    return Counter(t.rule_id for t in result.threats if t.rule_id and t.rule_id in FOCUS[config])


def _legs() -> list[object]:
    legs = []
    for config in FOCUS:
        for fmt in ("hcl", "cfn"):
            marks = []
            if (config, fmt) in EXPECTED_DIFFERENCES:
                package, why = EXPECTED_DIFFERENCES[(config, fmt)]
                marks.append(pending(package, f"{config} {fmt} parity: {why}"))
            legs.append(pytest.param(config, fmt, id=f"{config}-{fmt}", marks=marks))
    return legs


@pytest.mark.parametrize("config", FOCUS)
def test_the_reference_format_fires_the_focused_rules(config: str) -> None:
    """Parity of two empty sets proves nothing: the plan must trip every focused rule."""
    counts = fired(config, REFERENCE)
    missing = FOCUS[config] - set(counts)
    assert not missing, f"{config}: the plan fixture does not trip {sorted(missing)}"


@pytest.mark.parametrize(("config", "fmt"), _legs())
def test_format_trips_the_same_rules_as_the_plan(config: str, fmt: str) -> None:
    results = {REFERENCE: fired(config, REFERENCE), fmt: fired(config, fmt)}
    problems = compare_formats(results, REFERENCE)
    assert not problems, f"{config} ({fmt} vs {REFERENCE}):\n  " + "\n  ".join(problems)


def test_every_configuration_has_all_three_formats() -> None:
    for config in FOCUS:
        for suffix in FILE_SUFFIX.values():
            assert (PARITY_DIR / f"{config}{suffix}").is_file(), f"{config}{suffix} is missing"
    on_disk = {p.name.split(".")[0] for p in PARITY_DIR.iterdir() if p.is_file()}
    assert on_disk == set(FOCUS), "a parity file set is not registered in FOCUS"
