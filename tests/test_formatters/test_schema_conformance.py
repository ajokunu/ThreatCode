"""Schema conformance of the SARIF and ATT&CK Navigator output for every input a golden test scans.

SARIF is validated against the vendored OASIS SARIF 2.1.0 schema, and the Navigator layer against
a schema derived from the layer 4.5 format document (see ``tests/fixtures/schemas/README.md``).
Valid-looking JSON is not enough for the consumers: GitHub code scanning rejects or drops results
that lack a physical location with a region, a fingerprint or a security severity, and the
Navigator drops techniques with an empty tactic. Those checks are written here as lints. The ones
that current output fails are pending on the package that fixes the formatters.

The input list is enumerated here, not imported from the golden test: every file under
``tests/fixtures/realistic`` plus an explicit list of the other fixtures, plus two inputs
generated on the fly whose names carry markup, quotes and mentions.
"""

from __future__ import annotations

import json
import re
from functools import cache
from pathlib import Path
from typing import Any

import pytest

from tests.helpers.pending import pending
from tests.helpers.scan import scan_files, scan_text

jsonschema = pytest.importorskip("jsonschema")

from threatcode.formatters.attack_navigator import format_attack_navigator  # noqa: E402
from threatcode.formatters.sarif import format_sarif  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "fixtures"
SCHEMAS = FIXTURES / "schemas"

OTHER_INPUTS = (
    "terraform/multi_service_insecure.plan.json",
    "terraform/multi_service_secure.plan.json",
    "terraform/simple_s3.plan.json",
    "terraform/simple.tf",
    "cloudformation/insecure_stack.yml",
    "kubernetes/insecure_deployment.yml",
    "kubernetes/multi_resource.yml",
    "kubernetes/secure_deployment.yml",
    "docker/insecure.Dockerfile",
    "docker/multistage.Dockerfile",
    "docker/secure.Dockerfile",
    "helm/test-chart/Chart.yaml",
    "mcp/vulnerable/.mcp.json",
    "mcp/fixed/.mcp.json",
)
FILE_INPUTS = sorted(
    [f"realistic/{p.name}" for p in (FIXTURES / "realistic").iterdir() if p.is_file()]
    + list(OTHER_INPUTS)
)

# Inputs generated on the fly. Their resource names carry markup, quotes, mentions and path
# segments, so output built from them is checked for validity, not only for tidy inputs.
HOSTILE_MCP = json.dumps(
    {
        "mcpServers": {
            "<script>alert(1)</script> @octocat #1234": {
                "command": "npx",
                "args": ["-y", "left-pad"],
                "env": {"API_TOKEN": "ghp_16C7e42F292c6912E7710c838347Ae178B4a"},
            }
        }
    }
)
HOSTILE_PLAN = json.dumps(
    {
        "format_version": "1.2",
        "terraform_version": "1.9.5",
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": address,
                        "mode": "managed",
                        "type": "aws_s3_bucket",
                        "name": "logs",
                        "index": key,
                        "provider_name": "registry.terraform.io/hashicorp/aws",
                        "values": {"acl": "public-read", "bucket": "logs"},
                    }
                    for key, address in (
                        ('a b"c', 'aws_s3_bucket.logs["a b\\"c"]'),
                        ("../../etc/passwd", 'aws_s3_bucket.logs["../../etc/passwd"]'),
                        ("x|`$(id)`", 'aws_s3_bucket.logs["x|`$(id)`"]'),
                    )
                ]
            }
        },
        "resource_changes": [],
        "configuration": {"root_module": {}},
    }
)
GENERATED_INPUTS = {
    "generated/hostile-mcp-server-name": (HOSTILE_MCP, ".mcp.json"),
    "generated/hostile-for-each-keys": (HOSTILE_PLAN, "tfplan.json"),
}

ALL_INPUTS = FILE_INPUTS + sorted(GENERATED_INPUTS)
# The fixed MCP config yields no finding, so a per-result lint over it checks nothing
# multi_service_secure only ever produced the false internet-gateway-to-VPC boundary threat (WP-3-1)
EMPTY_INPUTS = {"mcp/fixed/.mcp.json", "terraform/multi_service_secure.plan.json"}
LINT_INPUTS = [i for i in ALL_INPUTS if i not in EMPTY_INPUTS]


@cache
def report_for(name: str) -> Any:
    """The analysis report of an input, computed once because both formats read it."""
    if name in GENERATED_INPUTS:
        text, filename = GENERATED_INPUTS[name]
        return scan_text(text, filename).report
    return scan_files([FIXTURES / name]).report


@cache
def sarif_for(name: str) -> dict[str, Any]:
    return json.loads(format_sarif(report_for(name)))  # type: ignore[no-any-return]


@cache
def navigator_for(name: str) -> dict[str, Any]:
    return json.loads(format_attack_navigator(report_for(name)))  # type: ignore[no-any-return]


def _load(name: str) -> dict[str, Any]:
    return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))  # type: ignore[no-any-return]


@cache
def sarif_validator() -> Any:
    return jsonschema.Draft4Validator(_load("sarif-schema-2.1.0.json"))


@cache
def navigator_validator() -> Any:
    return jsonschema.Draft7Validator(_load("attack-navigator-layer-4.5.schema.json"))


def schema_errors(validator: Any, document: Any, limit: int = 5) -> list[str]:
    """The first few validation errors, each with the JSON path it applies to."""
    errors = sorted(validator.iter_errors(document), key=lambda e: list(map(str, e.path)))
    return [f"{'/'.join(map(str, e.path)) or '<root>'}: {e.message[:160]}" for e in errors[:limit]]


# ---------------------------------------------------------------------------------------
# GitHub ingestion lints for SARIF
# ---------------------------------------------------------------------------------------

GITHUB_MAX_TAGS = 10


def lint_locations(sarif: dict[str, Any]) -> list[str]:
    """Every result needs a physical location with a region, or GitHub cannot annotate a line."""
    problems = []
    for run in sarif.get("runs") or []:
        for index, result in enumerate(run.get("results") or []):
            locations = result.get("locations") or []
            physical = [loc.get("physicalLocation") or {} for loc in locations]
            if not any((p.get("region") or {}).get("startLine") for p in physical):
                problems.append(
                    f"results[{index}] ({result.get('ruleId')}) has no region.startLine"
                )
    return problems


def lint_fingerprints(sarif: dict[str, Any]) -> list[str]:
    """Every result needs a partial fingerprint so alerts survive code moving between commits."""
    return [
        f"results[{i}] ({r.get('ruleId')}) has no partialFingerprints"
        for run in sarif.get("runs") or []
        for i, r in enumerate(run.get("results") or [])
        if not r.get("partialFingerprints")
    ]


def lint_security_severity(sarif: dict[str, Any]) -> list[str]:
    """Every rule needs a numeric security-severity or GitHub shows no severity for the alert."""
    problems = []
    for run in sarif.get("runs") or []:
        for rule in (run.get("tool") or {}).get("driver", {}).get("rules") or []:
            value = (rule.get("properties") or {}).get("security-severity")
            try:
                ok = value is not None and 0.0 <= float(value) <= 10.0
            except (TypeError, ValueError):
                ok = False
            if not ok:
                problems.append(f"rule {rule.get('id')} has no valid security-severity ({value!r})")
    return problems


def lint_tag_count(sarif: dict[str, Any]) -> list[str]:
    """GitHub shows at most ten tags per rule and drops the rest."""
    return [
        f"rule {rule.get('id')} has {len(tags)} tags (maximum {GITHUB_MAX_TAGS})"
        for run in sarif.get("runs") or []
        for rule in (run.get("tool") or {}).get("driver", {}).get("rules") or []
        if len(tags := (rule.get("properties") or {}).get("tags") or []) > GITHUB_MAX_TAGS
    ]


def lint_unique_rule_ids(sarif: dict[str, Any]) -> list[str]:
    """Rule ids are the dedup key for suppressions; a duplicate makes them ambiguous."""
    problems = []
    for run in sarif.get("runs") or []:
        seen: set[str] = set()
        for rule in (run.get("tool") or {}).get("driver", {}).get("rules") or []:
            if rule.get("id") in seen:
                problems.append(f"rule id {rule.get('id')} appears more than once")
            seen.add(rule.get("id"))
    return problems


# ---------------------------------------------------------------------------------------
# Navigator semantic checks
# ---------------------------------------------------------------------------------------

_SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
# Platform names the layer 4.5 document lists for the enterprise domain
ENTERPRISE_PLATFORMS = frozenset(
    {
        "PRE",
        "Windows",
        "Linux",
        "macOS",
        "Network",
        "AWS",
        "GCP",
        "Azure",
        "Azure AD",
        "Office 365",
        "SaaS",
    }
)


def navigator_tactic_problems(layer: dict[str, Any], valid_tactics: set[str]) -> list[str]:
    """An empty or unknown tactic makes the Navigator place the technique nowhere or everywhere."""
    problems = []
    for technique in layer.get("techniques") or []:
        tactic = technique.get("tactic")
        if not tactic:
            problems.append(f"{technique.get('techniqueID')} has an empty tactic")
        elif tactic not in valid_tactics:
            problems.append(f"{technique.get('techniqueID')} has unknown tactic {tactic!r}")
    return problems


def navigator_version_problems(layer: dict[str, Any]) -> list[str]:
    """The layer document requires a full Navigator version of at least 4.9.0."""
    version = (layer.get("versions") or {}).get("navigator", "")
    match = _SEMVER.match(str(version))
    if not match:
        return [f"versions.navigator {version!r} is not a full semantic version"]
    if tuple(int(g) for g in match.groups()) < (4, 9, 0):
        return [f"versions.navigator {version} is older than 4.9.0"]
    return []


def navigator_platform_problems(layer: dict[str, Any]) -> list[str]:
    """Platforms must be among the names the format document lists for the domain."""
    platforms = (layer.get("filters") or {}).get("platforms") or []
    return [f"unknown platform {p!r}" for p in platforms if p not in ENTERPRISE_PLATFORMS]


# ---------------------------------------------------------------------------------------
# The vendored schemas are what the README says they are
# ---------------------------------------------------------------------------------------


class TestVendoredSchemas:
    def test_the_sarif_schema_is_the_oasis_2_1_0_draft_4_schema(self) -> None:
        schema = _load("sarif-schema-2.1.0.json")
        assert schema["$schema"] == "http://json-schema.org/draft-04/schema#"
        assert schema["id"].endswith("/sarif-schema-2.1.0.json")
        assert schema["properties"]["version"]["enum"] == ["2.1.0"]
        jsonschema.Draft4Validator.check_schema(schema)

    def test_the_navigator_schema_is_valid_draft_7(self) -> None:
        jsonschema.Draft7Validator.check_schema(_load("attack-navigator-layer-4.5.schema.json"))

    def test_the_readme_records_source_commit_and_retrieval_date(self) -> None:
        readme = (SCHEMAS / "README.md").read_text(encoding="utf-8")
        for needle in (
            "a560296ca8c921f3bdb8d4a8db57ab83dae968a7",
            "db05f442e84038f967b082a82d7ccfa77b7593c7",
            "2026-10-07",
            "github.com/oasis-tcs/sarif-spec",
            "github.com/mitre-attack/attack-navigator",
        ):
            assert needle in readme

    def test_every_golden_input_exists(self) -> None:
        missing = [n for n in FILE_INPUTS if not (FIXTURES / n).is_file()]
        assert not missing
        assert len(FILE_INPUTS) == len(set(FILE_INPUTS)) >= 24


class TestValidatorsCatchDefects:
    """The schemas must reject broken documents, or passing them proves nothing."""

    def test_sarif_without_a_version_is_rejected(self) -> None:
        assert schema_errors(sarif_validator(), {"runs": []})

    def test_sarif_with_a_wrong_level_is_rejected(self) -> None:
        document = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "x"}},
                    "results": [{"ruleId": "R", "level": "critical", "message": {"text": "m"}}],
                }
            ],
        }
        errors = schema_errors(sarif_validator(), document)
        assert errors and "level" in errors[0]

    def test_a_minimal_sarif_document_passes(self) -> None:
        document = {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "x"}}, "results": []}],
        }
        assert schema_errors(sarif_validator(), document) == []

    def test_a_layer_with_an_unknown_domain_is_rejected(self) -> None:
        layer = {"name": "n", "domain": "cloud-attack"}
        assert schema_errors(navigator_validator(), layer)

    def test_a_layer_with_a_misspelled_property_is_rejected(self) -> None:
        layer = {"name": "n", "domain": "enterprise-attack", "technique": []}
        errors = schema_errors(navigator_validator(), layer)
        assert errors and "technique" in errors[0]

    def test_a_technique_id_of_the_wrong_shape_is_rejected(self) -> None:
        layer = {
            "name": "n",
            "domain": "enterprise-attack",
            "techniques": [{"techniqueID": "1190", "tactic": "initial-access"}],
        }
        assert schema_errors(navigator_validator(), layer)

    def test_a_layer_with_the_wrong_layer_version_is_rejected(self) -> None:
        layer = {
            "name": "n",
            "domain": "enterprise-attack",
            "versions": {"navigator": "5.1.0", "layer": "4.4"},
        }
        assert schema_errors(navigator_validator(), layer)

    def test_a_minimal_layer_passes(self) -> None:
        layer = {
            "name": "n",
            "domain": "enterprise-attack",
            "versions": {"navigator": "5.1.0", "layer": "4.5"},
            "techniques": [{"techniqueID": "T1190", "tactic": "initial-access", "score": 80}],
        }
        assert schema_errors(navigator_validator(), layer) == []


# ---------------------------------------------------------------------------------------
# Current output validates for every input
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("name", ALL_INPUTS)
def test_sarif_output_validates_against_2_1_0(name: str) -> None:
    errors = schema_errors(sarif_validator(), sarif_for(name))
    assert not errors, f"{name}: " + "; ".join(errors)


@pytest.mark.parametrize("name", ALL_INPUTS)
def test_navigator_output_validates_against_layer_4_5(name: str) -> None:
    errors = schema_errors(navigator_validator(), navigator_for(name))
    assert not errors, f"{name}: " + "; ".join(errors)


def test_the_hostile_names_reach_the_output_unchanged() -> None:
    """The generated inputs must exercise the formatters with the awkward strings in them."""
    sarif = json.dumps(sarif_for("generated/hostile-mcp-server-name"))
    assert "<script>" in sarif and "@octocat" in sarif
    assert "../../etc/passwd" in json.dumps(sarif_for("generated/hostile-for-each-keys"))


def test_every_result_input_produces_findings_so_the_lints_are_not_vacuous() -> None:
    for name in LINT_INPUTS:
        runs = sarif_for(name)["runs"]
        assert runs and runs[0]["results"], f"{name} yields no result; add it to EMPTY_INPUTS"


# ---------------------------------------------------------------------------------------
# GitHub ingestion lints
# ---------------------------------------------------------------------------------------


class TestGithubLintsPassCurrentOutput:
    """Lints current output already satisfies stay regression guards, not pending."""

    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_a_rule_carries_at_most_ten_tags(self, name: str) -> None:
        assert lint_tag_count(sarif_for(name)) == []

    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_rule_ids_are_unique(self, name: str) -> None:
        assert lint_unique_rule_ids(sarif_for(name)) == []


class TestGithubLintsPendingFormatterFixes:
    @pending("WP-4-3", "results carry the source file and region.startLine, not a resource address")
    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_every_result_has_a_physical_location_with_a_region(self, name: str) -> None:
        problems = lint_locations(sarif_for(name))
        assert not problems, f"{name}: {problems[:3]}"

    @pending("WP-4-3", "results carry partialFingerprints {'threatcode/v1': fingerprint}")
    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_every_result_has_a_partial_fingerprint(self, name: str) -> None:
        problems = lint_fingerprints(sarif_for(name))
        assert not problems, f"{name}: {problems[:3]}"

    @pending("WP-4-3", "rules carry properties security-severity from the effective severity")
    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_every_rule_has_a_security_severity(self, name: str) -> None:
        problems = lint_security_severity(sarif_for(name))
        assert not problems, f"{name}: {problems[:3]}"


class TestGithubLintsSelfTest:
    GOOD = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "t",
                        "rules": [
                            {"id": "A", "properties": {"security-severity": "8.0", "tags": ["x"]}}
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "A",
                        "message": {"text": "m"},
                        "partialFingerprints": {"threatcode/v1": "abc"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "main.tf"},
                                    "region": {"startLine": 3},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }

    def lints(self, document: dict[str, Any]) -> dict[str, list[str]]:
        return {
            "locations": lint_locations(document),
            "fingerprints": lint_fingerprints(document),
            "severity": lint_security_severity(document),
            "tags": lint_tag_count(document),
            "ids": lint_unique_rule_ids(document),
        }

    def mutated(self) -> dict[str, Any]:
        return json.loads(json.dumps(self.GOOD))

    def test_a_good_document_passes_every_lint(self) -> None:
        assert all(not problems for problems in self.lints(self.GOOD).values())

    def test_a_result_without_a_region_is_flagged(self) -> None:
        document = self.mutated()
        del document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert self.lints(document)["locations"] == ["results[0] (A) has no region.startLine"]

    def test_a_result_with_an_address_instead_of_a_location_is_flagged(self) -> None:
        document = self.mutated()
        document["runs"][0]["results"][0]["locations"] = [{"logicalLocations": [{"name": "a.b"}]}]
        assert self.lints(document)["locations"]

    def test_a_result_without_a_fingerprint_is_flagged(self) -> None:
        document = self.mutated()
        del document["runs"][0]["results"][0]["partialFingerprints"]
        assert self.lints(document)["fingerprints"] == ["results[0] (A) has no partialFingerprints"]

    def test_a_rule_without_a_valid_security_severity_is_flagged(self) -> None:
        for bad in (None, "high", "11.0", "-1"):
            document = self.mutated()
            props = document["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
            if bad is None:
                del props["security-severity"]
            else:
                props["security-severity"] = bad
            assert self.lints(document)["severity"], bad

    def test_more_than_ten_tags_are_flagged(self) -> None:
        document = self.mutated()
        document["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"] = [
            f"t{i}" for i in range(11)
        ]
        assert self.lints(document)["tags"] == ["rule A has 11 tags (maximum 10)"]

    def test_a_duplicate_rule_id_is_flagged(self) -> None:
        document = self.mutated()
        rules = document["runs"][0]["tool"]["driver"]["rules"]
        rules.append(dict(rules[0]))
        assert self.lints(document)["ids"] == ["rule id A appears more than once"]

    def test_current_output_fails_the_pending_lints_so_the_markers_are_honest(self) -> None:
        """If this fails, a pending lint already passes and its marker should be removed."""
        sarif = sarif_for("realistic/01_aws_ecommerce_platform.json")
        assert lint_locations(sarif)
        assert lint_fingerprints(sarif)
        assert lint_security_severity(sarif)


# ---------------------------------------------------------------------------------------
# Navigator semantics
# ---------------------------------------------------------------------------------------


class TestNavigatorSemantics:
    @pending("WP-4-3", "one entry per (technique, tactic) using official tactic shortnames")
    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_no_technique_has_an_empty_or_unknown_tactic(self, name: str) -> None:
        from threatcode.engine.mitre import TACTIC_DB, tactic_shortname

        valid = {tactic_shortname(tactic_id) for tactic_id in TACTIC_DB}
        problems = navigator_tactic_problems(navigator_for(name), valid)
        assert not problems, f"{name}: {problems[:3]}"

    @pending("WP-4-3", "versions carry the pinned ATT&CK release and a full Navigator semver")
    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_the_navigator_version_is_a_full_semver_of_at_least_4_9_0(self, name: str) -> None:
        assert navigator_version_problems(navigator_for(name)) == []

    @pending("WP-4-3", "the IaaS platform filter is removed")
    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_platforms_are_names_the_format_lists(self, name: str) -> None:
        assert navigator_platform_problems(navigator_for(name)) == []

    @pytest.mark.parametrize("name", ALL_INPUTS)
    def test_the_layer_version_is_4_5_and_the_domain_is_enterprise(self, name: str) -> None:
        layer = navigator_for(name)
        assert layer["versions"]["layer"] == "4.5"
        assert layer["domain"] == "enterprise-attack"

    def test_self_test_tactics(self) -> None:
        valid = {"initial-access", "execution"}
        layer = {
            "techniques": [
                {"techniqueID": "T1190", "tactic": "initial-access"},
                {"techniqueID": "T1078", "tactic": ""},
                {"techniqueID": "T1059", "tactic": "Execution"},
                {"techniqueID": "T1133"},
            ]
        }
        assert navigator_tactic_problems(layer, valid) == [
            "T1078 has an empty tactic",
            "T1059 has unknown tactic 'Execution'",
            "T1133 has an empty tactic",
        ]

    def test_self_test_version(self) -> None:
        assert navigator_version_problems({"versions": {"navigator": "5.1.0"}}) == []
        assert navigator_version_problems({"versions": {"navigator": "5.1"}})
        assert navigator_version_problems({"versions": {"navigator": "4.8.9"}})
        assert navigator_version_problems({})

    def test_self_test_platforms(self) -> None:
        assert navigator_platform_problems({"filters": {"platforms": ["AWS", "Azure"]}}) == []
        assert navigator_platform_problems({"filters": {"platforms": ["IaaS"]}}) == [
            "unknown platform 'IaaS'"
        ]

    def test_current_output_fails_the_pending_semantics_so_the_markers_are_honest(self) -> None:
        layer = navigator_for("realistic/01_aws_ecommerce_platform.json")
        assert navigator_tactic_problems(layer, {"initial-access"})
        assert navigator_version_problems(layer)
        assert navigator_platform_problems(layer)
