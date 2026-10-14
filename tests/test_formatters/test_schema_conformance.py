"""Schema conformance of the SARIF, Navigator and Bitbucket output for every golden input.

SARIF is validated against the vendored OASIS SARIF 2.1.0 schema, the Navigator layer against
a schema derived from the layer 4.5 format document (see ``tests/fixtures/schemas/README.md``)
and the Bitbucket payload against a small schema written here from the Code Insights limits.
Valid-looking JSON is not enough for the consumers: GitHub code scanning rejects or drops results
that lack a physical location with a region, a fingerprint or a security severity, and the
Navigator drops techniques with an empty tactic. Those checks are written here as lints, and the
current output passes every one of them for every input.

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

from tests.helpers.scan import scan_files, scan_text

jsonschema = pytest.importorskip("jsonschema")

from threatcode.formatters.attack_navigator import format_attack_navigator  # noqa: E402
from threatcode.formatters.bitbucket import format_bitbucket  # noqa: E402
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
def scan_for(name: str) -> Any:
    """The scan of an input (graph and report), computed once because every format reads it."""
    if name in GENERATED_INPUTS:
        text, filename = GENERATED_INPUTS[name]
        return scan_text(text, filename)
    return scan_files([FIXTURES / name])


def report_for(name: str) -> Any:
    return scan_for(name).report


@cache
def sarif_for(name: str) -> dict[str, Any]:
    scan = scan_for(name)
    return json.loads(format_sarif(scan.report, scan.graph))  # type: ignore[no-any-return]


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


class TestGithubLints:
    """Every lint GitHub's ingestion applies, over every input the golden tests scan."""

    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_a_rule_carries_at_most_ten_tags(self, name: str) -> None:
        assert lint_tag_count(sarif_for(name)) == []

    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_rule_ids_are_unique(self, name: str) -> None:
        assert lint_unique_rule_ids(sarif_for(name)) == []


class TestGithubLintsOnLocationsFingerprintsAndSeverity:
    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_every_result_has_a_physical_location_with_a_region(self, name: str) -> None:
        problems = lint_locations(sarif_for(name))
        assert not problems, f"{name}: {problems[:3]}"

    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_every_result_has_a_partial_fingerprint(self, name: str) -> None:
        problems = lint_fingerprints(sarif_for(name))
        assert not problems, f"{name}: {problems[:3]}"

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


# ---------------------------------------------------------------------------------------
# Navigator semantics
# ---------------------------------------------------------------------------------------


class TestNavigatorSemantics:
    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_no_technique_has_an_empty_or_unknown_tactic(self, name: str) -> None:
        from threatcode.engine.mitre import TACTIC_DB, tactic_shortname

        valid = {tactic_shortname(tactic_id) for tactic_id in TACTIC_DB}
        problems = navigator_tactic_problems(navigator_for(name), valid)
        assert not problems, f"{name}: {problems[:3]}"

    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_the_navigator_version_is_a_full_semver_of_at_least_4_9_0(self, name: str) -> None:
        assert navigator_version_problems(navigator_for(name)) == []

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


# ---------------------------------------------------------------------------------------
# More SARIF lints, each with a self-test
# ---------------------------------------------------------------------------------------


def lint_uris(sarif: dict[str, Any]) -> list[str]:
    """A location URI is a relative file path: no address, no scheme, no '..', no absolute path."""
    problems = []
    for run in sarif.get("runs") or []:
        for index, result in enumerate(run.get("results") or []):
            for location in result.get("locations") or []:
                uri = ((location.get("physicalLocation") or {}).get("artifactLocation") or {}).get(
                    "uri", ""
                )
                bad = (
                    not uri
                    or uri.startswith("/")
                    or ".." in uri.split("/")
                    or "%SRCROOT%" in uri
                    or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", uri)
                    or "\\" in uri
                )
                if bad:
                    problems.append(f"results[{index}] has the uri {uri!r}")
    return problems


def lint_rule_references(sarif: dict[str, Any]) -> list[str]:
    """ruleIndex must point at the rule named by ruleId, or GitHub shows the wrong rule text."""
    problems = []
    for run in sarif.get("runs") or []:
        rules = (run.get("tool") or {}).get("driver", {}).get("rules") or []
        for index, result in enumerate(run.get("results") or []):
            at = result.get("ruleIndex")
            if (
                at is None
                or not 0 <= at < len(rules)
                or rules[at].get("id") != result.get("ruleId")
            ):
                problems.append(f"results[{index}] ({result.get('ruleId')}) has a wrong ruleIndex")
    return problems


def lint_unique_fingerprints(sarif: dict[str, Any]) -> list[str]:
    """Results that share a fingerprint are one alert to GitHub, so a finding would disappear."""
    seen: dict[str, int] = {}
    for run in sarif.get("runs") or []:
        for result in run.get("results") or []:
            for value in (result.get("partialFingerprints") or {}).values():
                seen[value] = seen.get(value, 0) + 1
    return [f"fingerprint {value} is shared by {n} results" for value, n in seen.items() if n > 1]


class TestMoreGithubLints:
    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_locations_are_relative_file_paths(self, name: str) -> None:
        assert lint_uris(sarif_for(name)) == [], name

    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_rule_indexes_point_at_their_rules(self, name: str) -> None:
        assert lint_rule_references(sarif_for(name)) == [], name

    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_no_two_results_share_a_fingerprint(self, name: str) -> None:
        assert lint_unique_fingerprints(sarif_for(name)) == [], name

    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_no_location_uri_contains_a_resource_address(self, name: str) -> None:
        report = report_for(name)
        addresses = {t.resource_address for t in report.threats if "." in t.resource_address}
        for run in sarif_for(name)["runs"]:
            for result in run["results"]:
                uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                assert not any(address in uri for address in addresses), uri

    def test_the_uri_lint_rejects_an_address_an_absolute_path_and_an_escape(self) -> None:
        def doc(uri: str) -> dict[str, Any]:
            location = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
            return {"runs": [{"results": [{"locations": [location]}]}]}

        for bad in (
            "",
            "/etc/passwd",
            "../x.tf",
            "a/../b",
            "file:///x",
            "C:/x",
            "%SRCROOT%/x",
            "a\\b",
        ):
            assert lint_uris(doc(bad)), bad
        assert lint_uris(doc("infra/main%20file.tf")) == []

    def test_the_rule_reference_lint_catches_a_wrong_index(self) -> None:
        document = {
            "runs": [
                {
                    "tool": {"driver": {"rules": [{"id": "A"}, {"id": "B"}]}},
                    "results": [{"ruleId": "A", "ruleIndex": 1}, {"ruleId": "B"}],
                }
            ]
        }
        assert len(lint_rule_references(document)) == 2

    def test_the_fingerprint_lint_catches_a_shared_value(self) -> None:
        result = {"partialFingerprints": {"k": "same"}}
        assert lint_unique_fingerprints({"runs": [{"results": [result, dict(result)]}]})


# ---------------------------------------------------------------------------------------
# Lints for what GitHub shows: severity, names, messages and code flows
# ---------------------------------------------------------------------------------------

# critical 9.5, high 8.0, medium 5.5, low 3.0 by the level they map to; info has no score
_LEVEL_OF_SCORE = {"9.5": "error", "8.0": "error", "5.5": "warning", "3.0": "note"}
MAX_RULE_NAME = 64
MAX_MESSAGE = 600


def _rules(run: dict[str, Any]) -> list[dict[str, Any]]:
    return (run.get("tool") or {}).get("driver", {}).get("rules") or []  # type: ignore[no-any-return]


def lint_result_matches_rule(sarif: dict[str, Any]) -> list[str]:
    """GitHub ranks an alert by its rule, so a result must carry its rule's level and score."""
    problems = []
    for run in sarif.get("runs") or []:
        rules = {rule["id"]: rule for rule in _rules(run)}
        for index, result in enumerate(run.get("results") or []):
            rule = rules.get(result.get("ruleId"))
            if rule is None:
                continue
            level = (rule.get("defaultConfiguration") or {}).get("level")
            if result.get("level") != level:
                problems.append(
                    f"results[{index}] is {result.get('level')} but rule {rule['id']} is {level}"
                )
            rule_score = (rule.get("properties") or {}).get("security-severity")
            score = (result.get("properties") or {}).get("security-severity")
            if score != rule_score:
                problems.append(
                    f"results[{index}] has security-severity {score} but rule {rule['id']} "
                    f"has {rule_score}"
                )
    return problems


def lint_score_matches_level(sarif: dict[str, Any]) -> list[str]:
    """A security-severity and the level of the same rule or result tell one story."""
    problems = []
    for run in sarif.get("runs") or []:
        for rule in _rules(run):
            score = (rule.get("properties") or {}).get("security-severity")
            level = (rule.get("defaultConfiguration") or {}).get("level")
            if score in _LEVEL_OF_SCORE and _LEVEL_OF_SCORE[score] != level:
                problems.append(f"rule {rule['id']} has score {score} and level {level}")
    return problems


def lint_rule_names_and_ids(sarif: dict[str, Any]) -> list[str]:
    """A rule name is short and a rule id carries its tool prefix once."""
    problems = []
    for run in sarif.get("runs") or []:
        for rule in _rules(run):
            if len(rule.get("name", "")) > MAX_RULE_NAME:
                problems.append(f"rule {rule['id']} has a {len(rule['name'])} character name")
            if rule["id"].count(":") > 1:
                problems.append(f"rule id {rule['id']} has a doubled prefix")
    return problems


def lint_messages(sarif: dict[str, Any]) -> list[str]:
    """A message is the headline of an alert: one line, not a page."""
    problems = []
    for run in sarif.get("runs") or []:
        for index, result in enumerate(run.get("results") or []):
            text = (result.get("message") or {}).get("text", "")
            if "\n" in text or len(text) > MAX_MESSAGE:
                problems.append(f"results[{index}] message is {len(text)} characters or multiline")
    return problems


def lint_code_flows(sarif: dict[str, Any]) -> list[str]:
    """When any step of a code flow has a file, every step has, or GitHub drops the others."""
    problems = []
    for run in sarif.get("runs") or []:
        for index, result in enumerate(run.get("results") or []):
            for flow in result.get("codeFlows") or []:
                for thread in flow.get("threadFlows") or []:
                    steps = thread.get("locations") or []
                    located = ["physicalLocation" in (s.get("location") or {}) for s in steps]
                    if any(located) and not all(located):
                        problems.append(f"results[{index}] has a code flow step without a file")
    return problems


class TestLintsOnWhatGithubShows:
    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_a_result_has_the_level_and_score_of_its_rule(self, name: str) -> None:
        assert lint_result_matches_rule(sarif_for(name)) == [], name

    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_a_score_and_a_level_agree(self, name: str) -> None:
        assert lint_score_matches_level(sarif_for(name)) == [], name

    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_rule_names_are_short_and_ids_are_not_doubly_prefixed(self, name: str) -> None:
        assert lint_rule_names_and_ids(sarif_for(name)) == [], name

    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_messages_are_one_short_line(self, name: str) -> None:
        assert lint_messages(sarif_for(name)) == [], name

    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_code_flows_have_a_file_on_every_step(self, name: str) -> None:
        assert lint_code_flows(sarif_for(name)) == [], name

    def run_with(self, rules: list[dict[str, Any]], results: list[dict[str, Any]]) -> Any:
        return {"runs": [{"tool": {"driver": {"rules": rules}}, "results": results}]}

    def test_the_level_lint_catches_a_result_that_outranks_its_rule(self) -> None:
        rule = {
            "id": "A",
            "defaultConfiguration": {"level": "warning"},
            "properties": {"security-severity": "5.5"},
        }
        result = {"ruleId": "A", "level": "note", "properties": {"security-severity": "3.0"}}
        assert len(lint_result_matches_rule(self.run_with([rule], [result]))) == 2
        good = {"ruleId": "A", "level": "warning", "properties": {"security-severity": "5.5"}}
        assert lint_result_matches_rule(self.run_with([rule], [good])) == []

    def test_the_score_lint_catches_a_level_that_disagrees(self) -> None:
        rule = {
            "id": "A",
            "defaultConfiguration": {"level": "note"},
            "properties": {"security-severity": "8.0"},
        }
        assert lint_score_matches_level(self.run_with([rule], []))

    def test_the_name_lint_catches_a_long_name_and_a_doubled_prefix(self) -> None:
        rules = [
            {"id": "trivy:trivy:CVE-1", "name": "ok"},
            {"id": "X", "name": "N" * 65},
            {"id": "trivy:CVE-1", "name": "CVE-1"},
        ]
        assert len(lint_rule_names_and_ids(self.run_with(rules, []))) == 2

    def test_the_message_lint_catches_a_wall_and_a_line_break(self) -> None:
        results = [{"message": {"text": "a" * 601}}, {"message": {"text": "a\nb"}}]
        assert len(lint_messages(self.run_with([], results))) == 2

    def test_the_code_flow_lint_catches_a_step_without_a_file(self) -> None:
        located = {"location": {"physicalLocation": {}}}
        flow = {"threadFlows": [{"locations": [located, {"location": {}}]}]}
        assert lint_code_flows(self.run_with([], [{"codeFlows": [flow]}]))
        assert (
            lint_code_flows(
                self.run_with([], [{"codeFlows": [{"threadFlows": [{"locations": [located]}]}]}])
            )
            == []
        )


# ---------------------------------------------------------------------------------------
# The real pipeline: what `threatcode scan` hands the formatters
# ---------------------------------------------------------------------------------------


PIPELINE_INPUTS = [
    "terraform/simple.tf",
    "terraform/simple_s3.plan.json",
    "kubernetes/insecure_deployment.yml",
    "docker/insecure.Dockerfile",
    "cloudformation/insecure_stack.yml",
    "mcp/vulnerable/.mcp.json",
]


@cache
def pipeline_sarif(name: str) -> dict[str, Any]:
    from threatcode.pipeline import prepare_request, run_scan

    prepared = prepare_request([str(FIXTURES / name)], fail_on="none")
    result = run_scan(prepared.request)
    # Everything the CLI hands the SARIF formatter comes from the analysis
    text = format_sarif(result.report, result.graph, source_root=result.root)
    return json.loads(text)  # type: ignore[no-any-return]


class TestPipelineSarif:
    @pytest.mark.parametrize("name", PIPELINE_INPUTS)
    def test_it_validates_and_passes_every_github_lint(
        self, name: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(REPO_ROOT)
        sarif = pipeline_sarif(name)
        assert schema_errors(sarif_validator(), sarif) == []
        for lint in (
            lint_locations,
            lint_fingerprints,
            lint_security_severity,
            lint_tag_count,
            lint_unique_rule_ids,
            lint_uris,
            lint_rule_references,
            lint_unique_fingerprints,
        ):
            assert lint(sarif) == [], (name, lint.__name__)

    @pytest.mark.parametrize("name", PIPELINE_INPUTS)
    def test_the_uri_is_the_scanned_file_from_the_checkout_root(
        self, name: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(REPO_ROOT)
        sarif = pipeline_sarif(name)
        uris = {
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in sarif["runs"][0]["results"]
        }
        assert uris == {f"tests/fixtures/{name}"}

    def test_a_directory_scan_names_each_file_with_its_directory(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from threatcode.pipeline import prepare_request, run_scan

        monkeypatch.chdir(REPO_ROOT)
        prepared = prepare_request([str(FIXTURES / "kubernetes")], fail_on="none")
        result = run_scan(prepared.request)
        sarif = json.loads(format_sarif(result.report, result.graph, source_root=result.root))
        uris = {
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in sarif["runs"][0]["results"]
        }
        assert uris
        assert all(u.startswith("tests/fixtures/kubernetes/") for u in uris)
        assert lint_unique_fingerprints(sarif) == []


# ---------------------------------------------------------------------------------------
# The three example stacks, scanned the way a user scans them
# ---------------------------------------------------------------------------------------

EXAMPLE_SCANS = {
    "aws-webapp": ("examples/aws-webapp", "examples/aws-webapp/scanner/trivy-app-image.json"),
    "k8s-platform": ("examples/k8s-platform", ""),
    "agent-workstation": ("examples/agent-workstation", ""),
}


@cache
def example_analysis(name: str) -> Any:
    from threatcode.pipeline import prepare_request, run_scan

    target, ingest = EXAMPLE_SCANS[name]
    prepared = prepare_request(
        [str(REPO_ROOT / target)],
        ingest=[REPO_ROOT / ingest] if ingest else [],
        fail_on="none",
    )
    return run_scan(prepared.request).analysis


def example_sarif(name: str) -> dict[str, Any]:
    from threatcode.formatters import render

    return json.loads(render("sarif", example_analysis(name)))  # type: ignore[no-any-return]


class TestExampleStacks:
    """Findings that reach the Security tab: ranked right, named right, placed right."""

    LINTS = (
        lint_locations,
        lint_fingerprints,
        lint_security_severity,
        lint_tag_count,
        lint_unique_rule_ids,
        lint_uris,
        lint_rule_references,
        lint_unique_fingerprints,
        lint_result_matches_rule,
        lint_score_matches_level,
        lint_rule_names_and_ids,
        lint_messages,
        lint_code_flows,
    )

    @pytest.mark.parametrize("name", sorted(EXAMPLE_SCANS))
    def test_it_validates_and_passes_every_lint(self, name: str) -> None:
        sarif = example_sarif(name)
        assert schema_errors(sarif_validator(), sarif) == []
        for lint in self.LINTS:
            assert lint(sarif) == [], (name, lint.__name__)

    @pytest.mark.parametrize("name", sorted(EXAMPLE_SCANS))
    def test_every_uri_is_relative_to_the_repository_root(
        self, name: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = EXAMPLE_SCANS[name][0]
        for cwd in (REPO_ROOT, REPO_ROOT / "examples", REPO_ROOT / target):
            monkeypatch.chdir(cwd)
            from threatcode.formatters import render

            sarif = json.loads(render("sarif", example_analysis(name)))
            for run in sarif["runs"]:
                for result in run["results"]:
                    for location in result["locations"]:
                        uri = location["physicalLocation"]["artifactLocation"]["uri"]
                        assert uri.startswith(f"{target}/"), (cwd, uri)

    def test_the_trivy_rule_has_one_prefix_and_a_short_name(self) -> None:
        rules = {
            r["id"]: r for r in example_sarif("aws-webapp")["runs"][0]["tool"]["driver"]["rules"]
        }
        assert "trivy:CVE-2022-37434" in rules
        assert "trivy:trivy:CVE-2022-37434" not in rules
        assert rules["trivy:CVE-2022-37434"]["name"] == "CVE-2022-37434"

    def test_a_low_severity_instance_does_not_show_as_medium(self) -> None:
        run = example_sarif("k8s-platform")["runs"][0]
        rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
        by_rule: dict[str, set[str]] = {}
        for result in run["results"]:
            by_rule.setdefault(result["ruleId"], set()).add(result["level"])
        assert all(len(levels) == 1 for levels in by_rule.values())
        base = [rid for rid in rules if rid.startswith("K8S_AUTOMOUNT_SA_TOKEN")]
        assert len(base) == 2
        levels = {rid: rules[rid]["defaultConfiguration"]["level"] for rid in base}
        assert set(levels.values()) == {"note", "warning"}

    def test_a_path_is_anchored_at_its_entry_resource_and_walks_located_hops(self) -> None:
        run = example_sarif("aws-webapp")["runs"][0]
        paths = [r for r in run["results"] if r["ruleId"].startswith("THREATCODE_ATTACK_PATH")]
        assert paths
        for result in paths:
            assert result["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] == (
                "aws_lb.front"
            )
            steps = result["codeFlows"][0]["threadFlows"][0]["locations"]
            assert all("physicalLocation" in s["location"] for s in steps)
            assert "enabled by" in " ".join(s["location"]["message"]["text"] for s in steps)

    def test_messages_do_not_repeat_the_rule_description(self) -> None:
        for name in EXAMPLE_SCANS:
            run = example_sarif(name)["runs"][0]
            descriptions = {r["fullDescription"]["text"] for r in run["tool"]["driver"]["rules"]}
            for result in run["results"]:
                text = result["message"]["text"]
                assert len(text) <= 600
                assert not any(d[:80] in text for d in descriptions if len(d) > 80), text

    def test_the_unpinned_package_message_names_no_hidden_property(self) -> None:
        results = example_sarif("agent-workstation")["runs"][0]["results"]
        unpinned = [r for r in results if r["ruleId"].startswith("MCP_UNPINNED_PACKAGE")]
        assert unpinned
        assert not any("unpinned_reasons" in r["message"]["text"] for r in unpinned)


# ---------------------------------------------------------------------------------------
# Attack paths in every format
# ---------------------------------------------------------------------------------------


def path_report() -> Any:
    """A real scan with a hand-built attack path over its first two resources."""
    from threatcode.models.attack_path import AttackHop, AttackPath
    from threatcode.models.threat import Severity

    scan = scan_files([FIXTURES / "terraform" / "simple.tf"])
    ids = sorted(scan.graph.nodes)
    hops = [
        AttackHop(node_id="internet", zone="internet", edge_type_to_next="network_flow"),
        AttackHop(
            node_id=ids[0],
            zone="dmz",
            edge_type_to_next="network_flow",
            enabled_by=[scan.report.threats[0].id],
            techniques=["T1190"],
        ),
        AttackHop(node_id=ids[-1], zone="data", techniques=["T1530"]),
    ]
    scan.report.attack_paths.append(
        AttackPath(
            id="0123456789ab",
            entry="internet",
            target=ids[-1],
            hops=hops,
            severity=Severity.CRITICAL,
            score=90.0,
            rationale="Reachable from the internet.",
            techniques=["T1190", "T1530"],
            tactics=["TA0001", "TA0009"],
        )
    )
    return scan


class TestAttackPathsValidate:
    def test_sarif_with_a_path_validates_and_passes_the_lints(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(REPO_ROOT)
        scan = path_report()
        sarif = json.loads(format_sarif(scan.report, scan.graph))
        assert schema_errors(sarif_validator(), sarif) == []
        for lint in (
            lint_locations,
            lint_fingerprints,
            lint_security_severity,
            lint_tag_count,
            lint_unique_rule_ids,
            lint_uris,
            lint_rule_references,
            lint_unique_fingerprints,
        ):
            assert lint(sarif) == [], lint.__name__
        paths = [r for r in sarif["runs"][0]["results"] if r["ruleId"] == "THREATCODE_ATTACK_PATH"]
        assert len(paths) == 1 and paths[0]["codeFlows"]

    def test_sarif_with_a_path_but_no_graph_still_validates(self) -> None:
        scan = path_report()
        sarif = json.loads(format_sarif(scan.report))
        assert schema_errors(sarif_validator(), sarif) == []
        assert lint_locations(sarif) == [] and lint_fingerprints(sarif) == []

    def test_navigator_with_a_path_validates_and_has_no_empty_tactic(self) -> None:
        from threatcode.engine.mitre import TACTIC_SHORTNAME

        layer = json.loads(format_attack_navigator(path_report().report))
        assert schema_errors(navigator_validator(), layer) == []
        assert navigator_tactic_problems(layer, set(TACTIC_SHORTNAME.values())) == []

    def test_bitbucket_with_a_path_validates(self) -> None:
        scan = path_report()
        payload = json.loads(format_bitbucket(scan.report, scan.graph))
        assert bitbucket_errors(payload) == []
        assert any(a["external_id"] == "path-0123456789ab" for a in payload["annotations"])


# ---------------------------------------------------------------------------------------
# Bitbucket Code Insights payload
# ---------------------------------------------------------------------------------------

BITBUCKET_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["report", "annotations", "annotation_batches"],
    "additionalProperties": False,
    "definitions": {
        "annotation": {
            "type": "object",
            "required": ["external_id", "annotation_type", "summary", "severity", "path", "line"],
            "additionalProperties": False,
            "properties": {
                "external_id": {"type": "string", "minLength": 1, "maxLength": 64},
                "annotation_type": {"enum": ["VULNERABILITY", "CODE_SMELL", "BUG"]},
                "summary": {"type": "string", "minLength": 1, "maxLength": 450},
                "details": {"type": "string", "maxLength": 2000},
                "severity": {"enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                "path": {"type": "string", "minLength": 1, "pattern": "^[^/\\\\].*$"},
                "line": {"type": "integer", "minimum": 1},
            },
        }
    },
    "properties": {
        "report": {
            "type": "object",
            "required": ["title", "details", "report_type", "reporter", "result", "data"],
            "additionalProperties": False,
            "properties": {
                "title": {"type": "string", "minLength": 1},
                "details": {"type": "string", "maxLength": 2000},
                "report_type": {"enum": ["SECURITY", "COVERAGE", "TEST", "BUG"]},
                "reporter": {"type": "string"},
                "result": {"enum": ["PASSED", "FAILED", "PENDING"]},
                "data": {
                    "type": "array",
                    "maxItems": 10,
                    "items": {
                        "type": "object",
                        "required": ["title", "type", "value"],
                        "properties": {
                            "title": {"type": "string"},
                            "type": {"enum": ["NUMBER", "TEXT", "BOOLEAN", "PERCENTAGE"]},
                            "value": {"type": ["integer", "string", "boolean"]},
                        },
                    },
                },
            },
        },
        "annotations": {
            "type": "array",
            "maxItems": 1000,
            "items": {"$ref": "#/definitions/annotation"},
        },
        "annotation_batches": {
            "type": "array",
            "items": {
                "type": "array",
                "minItems": 1,
                "maxItems": 100,
                "items": {"$ref": "#/definitions/annotation"},
            },
        },
    },
}


def bitbucket_errors(payload: Any) -> list[str]:
    validator = jsonschema.Draft7Validator(BITBUCKET_SCHEMA)
    errors = schema_errors(validator, payload)
    ids = [a["external_id"] for a in payload.get("annotations", [])]
    if len(ids) != len(set(ids)):
        errors.append("external_id values are not unique")
    batches = [a for batch in payload.get("annotation_batches", []) for a in batch]
    if batches != payload.get("annotations"):
        errors.append("the batches do not hold the annotations in order")
    return errors


@cache
def bitbucket_for(name: str) -> dict[str, Any]:
    scan = scan_for(name)
    return json.loads(format_bitbucket(scan.report, scan.graph))  # type: ignore[no-any-return]


class TestBitbucketPayload:
    @pytest.mark.parametrize("name", ALL_INPUTS)
    def test_the_payload_validates(self, name: str) -> None:
        assert bitbucket_errors(bitbucket_for(name)) == [], name

    @pytest.mark.parametrize("name", LINT_INPUTS)
    def test_annotations_sit_on_files_not_addresses(self, name: str) -> None:
        for annotation in bitbucket_for(name)["annotations"]:
            assert "." in annotation["path"].rsplit("/", 1)[-1] or annotation["path"].endswith(
                "Dockerfile"
            )
            assert annotation["line"] >= 1

    def test_the_schema_rejects_what_bitbucket_rejects(self) -> None:
        good = bitbucket_for("terraform/simple.tf")
        assert bitbucket_errors(good) == []
        for mutate in (
            lambda d: d["annotations"][0].update(summary="x" * 451),
            lambda d: d["annotations"][0].update(severity="INFO"),
            lambda d: d["annotations"][0].update(line=0),
            lambda d: d["annotations"][0].update(path="/abs/path.tf"),
            lambda d: d["report"].update(result="OK"),
            lambda d: d["annotation_batches"].append([d["annotations"][0]] * 101),
            lambda d: d["report"].update(data=d["report"]["data"] * 2),
        ):
            broken = json.loads(json.dumps(good))
            mutate(broken)
            assert bitbucket_errors(broken), mutate


# ---------------------------------------------------------------------------------------
# Hostile input stays inert in every text format
# ---------------------------------------------------------------------------------------


class TestHostileInputsStayInert:
    @pytest.mark.parametrize("name", sorted(GENERATED_INPUTS))
    def test_markdown_keeps_the_structure_it_wrote(self, name: str) -> None:
        from threatcode.formatters.markdown import format_markdown

        scan = scan_for(name)
        text = format_markdown(scan.report, scan.graph)
        # Inside a code span nothing is interpreted; outside, the specials must be escaped
        prose = re.sub(r"(`+).+?\1", "", text)
        assert "<script>" not in prose.replace("\\<script>", "")
        assert "@octocat" not in prose
        allowed = re.compile(
            r"^(# ThreatCode Threat Model Report"
            r"|## (Summary|Top risks \(\d+\)|Coverage|Attack paths"
            r"|Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service"
            r"|Elevation of Privilege)|### .*)$"
        )
        assert [h for h in text.splitlines() if h.startswith("#") and not allowed.match(h)] == []

    @pytest.mark.parametrize("name", sorted(GENERATED_INPUTS))
    def test_mermaid_parses_as_the_grammar_the_formatter_writes(self, name: str) -> None:
        from tests.test_formatters.test_mermaid import assert_mermaid_grammar
        from threatcode.formatters.mermaid import format_mermaid
        from threatcode.models.analysis import AnalysisResult

        scan = scan_for(name)
        assert_mermaid_grammar(format_mermaid(AnalysisResult(graph=scan.graph, report=scan.report)))

    @pytest.mark.parametrize("name", sorted(GENERATED_INPUTS))
    def test_json_and_text_render_without_error(self, name: str) -> None:
        from threatcode.formatters import render
        from threatcode.models.analysis import AnalysisResult

        scan = scan_for(name)
        analysis = AnalysisResult(graph=scan.graph, report=scan.report)
        assert json.loads(render("json", analysis))["threats"]
        assert render("text", analysis).startswith("ThreatCode scan")
