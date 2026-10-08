"""Tests for the YAML rule loader: typing forms, groups, validation and immutability."""

from __future__ import annotations

import copy
import json
import logging
import pickle
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.rules import loader
from threatcode.engine.rules.loader import (
    RESOURCE_TYPE_GROUPS,
    FrozenDict,
    FrozenList,
    Rule,
    clear_builtin_cache,
    deprecated_rule_ids,
    load_all_rules,
    load_builtin_rules,
    load_rule_file,
    load_rules_from_file,
    validate_condition,
)
from threatcode.engine.rules.matcher import MAX_CONDITION_DEPTH, VALID_OPERATORS
from threatcode.exceptions import RuleLoadError
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import ThreatSource
from threatcode.parsers import detect_and_parse
from threatcode.parsers.kubernetes import _KIND_TO_RESOURCE_TYPE, _WORKLOAD_KINDS

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _scannable_fixtures() -> list[Path]:
    paths: list[Path] = []
    for family in ("realistic", "terraform", "cloudformation", "kubernetes", "docker"):
        paths += sorted(p for p in (FIXTURES / family).iterdir() if p.is_file())
    paths += sorted(p for p in (FIXTURES / "mcp").rglob("*") if p.is_file())
    return paths


def _rule(**overrides: Any) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": "MY_RULE",
        "title": "My rule",
        "description": "Something is wrong",
        "stride_category": "tampering",
        "severity": "medium",
        "resource_type": "aws_s3_bucket",
        "condition": {"logging": {"not_exists": True}},
    }
    rule.update(overrides)
    for key in [k for k, v in rule.items() if v is _OMIT]:
        del rule[key]
    return rule


_OMIT = object()


def _write(tmp_path: Path, *rules: dict[str, Any], name: str = "custom.yml", **top: Any) -> Path:
    path = tmp_path / name
    path.write_text(yaml.safe_dump({"rules": list(rules), **top}), encoding="utf-8")
    return path


def _load(tmp_path: Path, *rules: dict[str, Any], **top: Any) -> list[Rule]:
    return load_rules_from_file(_write(tmp_path, *rules, **top))


def _error(tmp_path: Path, *rules: dict[str, Any], **top: Any) -> str:
    with pytest.raises(RuleLoadError) as excinfo:
        load_rules_from_file(_write(tmp_path, *rules, **top))
    return str(excinfo.value)


class TestBuiltinRules:
    def test_every_builtin_rule_loads_and_validates(self) -> None:
        rules = load_builtin_rules()
        assert len(rules) >= 220
        for rule in rules:
            validate_condition(rule.condition, rule_id=rule.id, source=rule.source_group)

    def test_builtin_rules_are_cached_and_returned_as_a_tuple(self) -> None:
        first = load_builtin_rules()
        assert isinstance(first, tuple)
        assert load_builtin_rules() is first

    def test_load_all_rules_returns_a_fresh_list_each_time(self) -> None:
        first = load_all_rules()
        first.pop()
        assert len(load_all_rules()) == len(first) + 1

    def test_two_engines_do_not_share_mutable_state(self) -> None:
        from threatcode.engine.hybrid import HybridEngine

        one, two = HybridEngine(), HybridEngine()
        assert one._rules[0] is two._rules[0]
        with pytest.raises(TypeError):
            one._rules[0].metadata["mitre"] = {}

    def test_clearing_the_cache_reloads_equal_rules(self) -> None:
        before = load_builtin_rules()
        clear_builtin_cache()
        after = load_builtin_rules()
        assert after is not before
        assert after == before

    def test_rule_ids_are_unique_and_every_rule_has_a_source_group(self) -> None:
        rules = load_builtin_rules()
        assert len({r.id for r in rules}) == len(rules)
        assert all(r.source_group and "/" not in r.source_group for r in rules)

    def test_source_group_names_the_rule_file(self) -> None:
        by_id = {r.id: r for r in load_builtin_rules()}
        assert by_id["S3_NO_ENCRYPTION"].source_group == "aws__s3"
        assert by_id["K8S_PRIVILEGED_CONTAINER"].source_group == "kubernetes__workloads"
        assert by_id["DOCKER_NO_USER"].source_group == "docker__image"
        assert by_id["CLOUDSQL_NO_SSL"].source_group == "gcp__cloud_sql"
        assert by_id["MCP_SECRET_IN_CONFIG"].source_group == "mcp__servers"

    def test_every_builtin_resource_type_belongs_to_a_known_family(self) -> None:
        families = ("aws_", "azurerm_", "google_", "kubernetes_", "dockerfile_", "mcp_")
        for rule in load_builtin_rules():
            for rtype in rule.resource_types:
                assert rtype.startswith(families), (rule.id, rtype)
                assert "*" not in rtype, (rule.id, rtype)  # builtin rules are typed exactly

    def test_no_builtin_rule_matches_by_prefix(self) -> None:
        for rule in load_builtin_rules():
            assert all(not t.endswith("*") for t in rule.resource_types), rule.id

    def test_builtin_rules_declare_a_known_confidence(self) -> None:
        rules = load_builtin_rules()
        assert {r.confidence for r in rules} <= {"definitive", "heuristic", "absence"}

    def test_docker_rules_declare_calibrated_confidence(self) -> None:
        by_id = {r.id: r for r in load_builtin_rules()}
        expected = {
            "definitive": {
                "DOCKER_ROOT_USER",
                "DOCKER_LATEST_TAG",
                "DOCKER_ADD_INSTEAD_OF_COPY",
                "DOCKER_RUN_SUDO",
                "DOCKER_RUN_CURL_PIPE",
                "DOCKER_APT_NO_RECOMMENDS",
                "DOCKER_ADD_FROM_URL",
            },
            "heuristic": {
                "DOCKER_NON_MINIMAL_BASE",
                "DOCKER_EXPOSED_SSH",
                "DOCKER_ENV_SECRET",
                "DOCKER_ARG_SECRET",
                "DOCKER_SENSITIVE_FILE_COPY",
                "DOCKER_SENSITIVE_FILE_ADD",
                "DOCKER_COPY_NO_CHOWN",
            },
            "absence": {
                "DOCKER_NO_USER",
                "DOCKER_NO_DIGEST_PIN",
                "DOCKER_NO_HEALTHCHECK",
                "DOCKER_MISSING_WORKDIR",
                "DOCKER_APT_NO_CLEAN",
            },
        }
        for confidence, ids in expected.items():
            for rule_id in ids:
                assert by_id[rule_id].confidence == confidence, rule_id
        docker_ids = {r.id for r in by_id.values() if r.id.startswith("DOCKER_")}
        assert docker_ids == set().union(*expected.values())
        # the docker rules are no longer uniformly definitive
        assert {by_id[i].confidence for i in docker_ids} == {"definitive", "heuristic", "absence"}

    def test_the_loader_uses_libyaml_when_it_is_available(self) -> None:
        if not getattr(yaml, "__with_libyaml__", False):
            pytest.skip("PyYAML was built without libyaml")
        assert issubclass(loader._RuleYamlLoader, yaml.CSafeLoader)

    def test_s3_public_access_is_judged_on_the_bucket_not_its_acl_resource(self) -> None:
        by_id = {r.id: r for r in load_builtin_rules()}
        assert by_id["S3_PUBLIC_ACCESS"].resource_types == ("aws_s3_bucket",)
        assert by_id["S3_NO_ENCRYPTION"].resource_types == ("aws_s3_bucket",)

    def test_gcp_default_service_account_covers_instance_templates(self) -> None:
        by_id = {r.id: r for r in load_builtin_rules()}
        assert by_id["GCP_VM_DEFAULT_SA"].resource_types == (
            "google_compute_instance",
            "google_compute_instance_template",
        )

    def test_cluster_role_rules_do_not_match_bindings(self) -> None:
        by_id = {r.id: r for r in load_builtin_rules()}
        role_rule = by_id["K8S_WILDCARD_RBAC_VERBS"]
        assert role_rule.matches_type("kubernetes_cluster_role")
        assert not role_rule.matches_type("kubernetes_cluster_role_binding")
        binding_rule = by_id["K8S_CLUSTER_ADMIN_BINDING"]
        assert binding_rule.matches_type("kubernetes_cluster_role_binding")
        assert not binding_rule.matches_type("kubernetes_cluster_role")

    def test_service_account_rule_is_not_a_service_rule(self) -> None:
        by_id = {r.id: r for r in load_builtin_rules()}
        assert by_id["K8S_AUTOMOUNT_DEFAULT"].resource_types == ("kubernetes_service_account",)

    def test_key_vault_and_aks_rules_bind_only_to_the_parent(self) -> None:
        by_id = {r.id: r for r in load_builtin_rules()}
        assert by_id["KEYVAULT_NO_DIAGNOSTICS"].resource_types == ("azurerm_key_vault",)
        assert by_id["AKS_NO_NETWORK_POLICY"].resource_types == ("azurerm_kubernetes_cluster",)


class TestResourceTypeForms:
    def test_single_exact_type(self, tmp_path: Path) -> None:
        (rule,) = _load(tmp_path, _rule(resource_type="aws_s3_bucket"))
        assert rule.resource_types == ("aws_s3_bucket",)
        assert rule.resource_type == "aws_s3_bucket"
        assert rule.matches_type("aws_s3_bucket")
        assert not rule.matches_type("aws_s3_bucket_versioning")

    def test_a_trailing_star_makes_a_prefix_glob(self, tmp_path: Path) -> None:
        (rule,) = _load(tmp_path, _rule(resource_type="aws_s3_bucket*"))
        assert rule.resource_types == ("aws_s3_bucket*",)
        assert rule.matches_type("aws_s3_bucket")
        assert rule.matches_type("aws_s3_bucket_versioning")
        assert not rule.matches_type("aws_s3_object")

    def test_resource_types_list(self, tmp_path: Path) -> None:
        rule_dict = _rule(resource_types=["aws_lb", "aws_alb"], resource_type=_OMIT)
        (rule,) = _load(tmp_path, rule_dict)
        assert rule.resource_types == ("aws_lb", "aws_alb")
        assert rule.resource_type == "aws_lb"
        assert rule.matches_type("aws_alb")

    def test_list_may_mix_exact_types_and_globs(self, tmp_path: Path) -> None:
        rule_dict = _rule(resource_types=["aws_lb", "aws_alb*"], resource_type=_OMIT)
        (rule,) = _load(tmp_path, rule_dict)
        assert rule.matches_type("aws_lb")
        assert rule.matches_type("aws_alb_listener")
        assert not rule.matches_type("aws_lb_listener")

    def test_duplicates_are_dropped_in_order(self, tmp_path: Path) -> None:
        rule_dict = _rule(resource_types=["b", "a", "b"], resource_type=_OMIT)
        assert _load(tmp_path, rule_dict)[0].resource_types == ("b", "a")

    @pytest.mark.parametrize("group", sorted(RESOURCE_TYPE_GROUPS))
    def test_group_expands_in_resource_type(self, tmp_path: Path, group: str) -> None:
        (rule,) = _load(tmp_path, _rule(resource_type=f"@{group}"))
        assert rule.resource_types == RESOURCE_TYPE_GROUPS[group]

    def test_group_expands_inside_a_list(self, tmp_path: Path) -> None:
        rule_dict = _rule(
            resource_types=["@kubernetes_long_running", "kubernetes_job"], resource_type=_OMIT
        )
        (rule,) = _load(tmp_path, rule_dict)
        assert rule.resource_types == (
            *RESOURCE_TYPE_GROUPS["kubernetes_long_running"],
            "kubernetes_job",
        )

    def test_group_contents(self) -> None:
        pods = set(RESOURCE_TYPE_GROUPS["kubernetes_pod_workloads"])
        assert pods == {
            "kubernetes_pod",
            "kubernetes_deployment",
            "kubernetes_daemon_set",
            "kubernetes_stateful_set",
            "kubernetes_replica_set",
            "kubernetes_job",
            "kubernetes_cron_job",
        }
        assert set(RESOURCE_TYPE_GROUPS["kubernetes_long_running"]) == pods - {
            "kubernetes_job",
            "kubernetes_cron_job",
        }
        assert set(RESOURCE_TYPE_GROUPS["kubernetes_controllers"]) == pods - {"kubernetes_pod"}

    def test_the_pod_group_matches_the_kinds_the_kubernetes_parser_emits(self) -> None:
        emitted = {
            rtype
            for kind, rtype in _KIND_TO_RESOURCE_TYPE.items()
            if kind in _WORKLOAD_KINDS or kind == "Pod"
        }
        assert set(RESOURCE_TYPE_GROUPS["kubernetes_pod_workloads"]) == emitted

    def test_unknown_group_fails_and_lists_the_known_ones(self, tmp_path: Path) -> None:
        message = _error(tmp_path, _rule(resource_type="@kubernetes_everything"))
        assert "MY_RULE" in message
        assert "@kubernetes_everything" in message
        assert "@kubernetes_pod_workloads" in message

    def test_unknown_group_inside_a_list_fails(self, tmp_path: Path) -> None:
        rule_dict = _rule(resource_types=["aws_lb", "@nope"], resource_type=_OMIT)
        assert "@nope" in _error(tmp_path, rule_dict)

    def test_both_forms_are_rejected(self, tmp_path: Path) -> None:
        message = _error(tmp_path, _rule(resource_types=["aws_lb"]))
        assert "exactly one of resource_type or resource_types" in message

    def test_neither_form_is_rejected(self, tmp_path: Path) -> None:
        message = _error(tmp_path, _rule(resource_type=_OMIT))
        assert "exactly one of resource_type or resource_types" in message

    @pytest.mark.parametrize("bad", ["aws_*_bucket", "aws_s3_bucket**", "*", "aws?s3", "aws_s3[a]"])
    def test_wildcards_other_than_one_trailing_star_are_rejected(
        self, tmp_path: Path, bad: str
    ) -> None:
        message = _error(tmp_path, _rule(resource_type=bad))
        assert "invalid resource type" in message
        assert bad in message

    @pytest.mark.parametrize("bad", [[], "aws_lb", [""], [1], [None], ["a b"], [["aws_lb"]]])
    def test_malformed_resource_types_lists_are_rejected(self, tmp_path: Path, bad: Any) -> None:
        with pytest.raises(RuleLoadError):
            _load(tmp_path, _rule(resource_types=bad, resource_type=_OMIT))

    @pytest.mark.parametrize("bad", ["", "  ", 5, None, ["aws_lb"]])
    def test_malformed_resource_type_is_rejected(self, tmp_path: Path, bad: Any) -> None:
        with pytest.raises(RuleLoadError):
            _load(tmp_path, _rule(resource_type=bad))

    def test_rule_dataclass_requires_a_type(self) -> None:
        with pytest.raises(ValueError, match="at least one resource type"):
            Rule("X", "t", "d", "tampering", "low", (), {"a": 1})

    def test_rule_accepts_a_single_string_for_resource_types(self) -> None:
        rule = Rule("X", "t", "d", "tampering", "low", "aws_s3_bucket", {"a": 1})  # type: ignore[arg-type]
        assert rule.resource_types == ("aws_s3_bucket",)


class TestRuleFields:
    def test_defaults(self, tmp_path: Path) -> None:
        (rule,) = _load(tmp_path, _rule())
        assert rule.confidence == "definitive"
        assert rule.root_cause == ""
        assert rule.mitigation == ""
        assert dict(rule.metadata) == {}
        assert rule.source_group == "custom__custom"

    @pytest.mark.parametrize("confidence", ["definitive", "heuristic", "absence"])
    def test_confidence_levels(self, tmp_path: Path, confidence: str) -> None:
        assert _load(tmp_path, _rule(confidence=confidence))[0].confidence == confidence

    def test_invalid_confidence_is_rejected(self, tmp_path: Path) -> None:
        message = _error(tmp_path, _rule(confidence="certain"))
        assert "confidence" in message
        assert "definitive, heuristic, absence" in message

    def test_root_cause(self, tmp_path: Path) -> None:
        (rule,) = _load(tmp_path, _rule(root_cause="public_access_block missing"))
        assert rule.root_cause == "public_access_block missing"

    def test_root_cause_must_be_a_string(self, tmp_path: Path) -> None:
        assert "root_cause" in _error(tmp_path, _rule(root_cause=["x"]))

    def test_required_fields(self, tmp_path: Path) -> None:
        for name in ("id", "title", "description", "stride_category", "severity", "condition"):
            message = _error(tmp_path, _rule(**{name: _OMIT}))
            assert f"'{name}'" in message

    def test_invalid_severity_and_stride(self, tmp_path: Path) -> None:
        assert "invalid severity 'urgent'" in _error(tmp_path, _rule(severity="urgent"))
        assert "invalid stride_category" in _error(tmp_path, _rule(stride_category="fun"))

    def test_source_group_of_a_custom_file_uses_its_stem(self, tmp_path: Path) -> None:
        path = _write(tmp_path, _rule(), name="my_org.yml")
        assert load_rules_from_file(path)[0].source_group == "custom__my_org"

    def test_load_all_rules_adds_custom_rules(self, tmp_path: Path) -> None:
        path = _write(tmp_path, _rule(id="MYORG_RULE"))
        rules = load_all_rules([path])
        assert rules[-1].id == "MYORG_RULE"
        assert len(rules) == len(load_builtin_rules()) + 1

    def test_duplicate_ids_are_rejected(self, tmp_path: Path) -> None:
        path = _write(tmp_path, _rule(id="S3_NO_ENCRYPTION"))
        with pytest.raises(RuleLoadError, match="Duplicate rule ID"):
            load_all_rules([path])

    def test_empty_rule_id_is_rejected(self, tmp_path: Path) -> None:
        assert "empty id" in _error(tmp_path, _rule(id="  "))

    def test_rule_must_be_a_mapping(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.yml"
        path.write_text("rules:\n  - just a string\n", encoding="utf-8")
        with pytest.raises(RuleLoadError, match="must be a mapping"):
            load_rules_from_file(path)

    def test_file_shape_errors(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.yml"
        for text, match in (
            ("- a\n", "must contain a 'rules' key"),
            ("other: 1\n", "must contain a 'rules' key"),
            ("rules: x\n", "'rules' must be a list"),
        ):
            path.write_text(text, encoding="utf-8")
            with pytest.raises(RuleLoadError, match=match):
                load_rules_from_file(path)

    def test_yaml_syntax_error_is_a_rule_load_error(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.yml"
        path.write_text("rules: [\n", encoding="utf-8")
        with pytest.raises(RuleLoadError, match="Failed to load rule file"):
            load_rules_from_file(path)

    def test_duplicate_yaml_keys_are_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "dup.yml"
        path.write_text(
            "rules:\n"
            "  - id: DUP\n    title: t\n    description: d\n    stride_category: tampering\n"
            "    severity: low\n    resource_type: aws_s3_bucket\n"
            "    condition:\n      a:\n        equals: 1\n      a:\n        equals: 2\n",
            encoding="utf-8",
        )
        with pytest.raises(RuleLoadError, match="duplicate key 'a'"):
            load_rules_from_file(path)

    def test_too_many_rules_in_a_file(self, tmp_path: Path) -> None:
        rules = [_rule(id=f"R{i}") for i in range(loader.MAX_RULES_PER_FILE + 1)]
        assert "exceeding limit" in _error(tmp_path, *rules)

    def test_unknown_top_level_key_is_warned_about_not_fatal(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            assert len(_load(tmp_path, _rule(), deprecated_id=["X"])) == 1
        assert any("deprecated_id" in r.message for r in caplog.records)


class TestDeprecatedIds:
    def test_exposed_for_builtin_and_extra_files(self, tmp_path: Path) -> None:
        path = _write(tmp_path, _rule(), deprecated_ids=["OLD_ONE", "OLD_TWO"])
        assert load_rule_file(path).deprecated_ids == {"OLD_ONE", "OLD_TWO"}
        assert deprecated_rule_ids([path]) >= {"OLD_ONE", "OLD_TWO"}
        assert isinstance(deprecated_rule_ids(), frozenset)

    def test_a_deprecated_id_that_is_still_defined_is_an_error(self, tmp_path: Path) -> None:
        message = _error(tmp_path, _rule(id="STILL_HERE"), deprecated_ids=["STILL_HERE"])
        assert "STILL_HERE" in message
        assert "deprecated_ids" in message

    @pytest.mark.parametrize("bad", ["OLD", [1], [""], {"a": 1}])
    def test_deprecated_ids_must_be_a_list_of_ids(self, tmp_path: Path, bad: Any) -> None:
        assert "deprecated_ids" in _error(tmp_path, _rule(), deprecated_ids=bad)

    def test_extra_paths_get_the_same_symlink_guard_as_load_all_rules(self, tmp_path: Path) -> None:
        real = _write(tmp_path, _rule(), deprecated_ids=["OLD"])
        link = tmp_path / "link.yml"
        try:
            link.symlink_to(real)
        except OSError:
            pytest.skip("Symlinks not supported on this platform")
        with pytest.raises(RuleLoadError, match="symlink"):
            deprecated_rule_ids([link])
        with pytest.raises(RuleLoadError, match="does not exist"):
            deprecated_rule_ids([tmp_path / "missing.yml"])

    def test_no_builtin_rule_is_also_deprecated(self) -> None:
        assert not deprecated_rule_ids() & {r.id for r in load_builtin_rules()}


class TestConditionValidation:
    def _fail(self, condition: Any, **kwargs: Any) -> str:
        with pytest.raises(RuleLoadError) as excinfo:
            validate_condition(condition, rule_id="MY_RULE", source="rules.yml", **kwargs)
        return str(excinfo.value)

    def _ok(self, condition: Any) -> None:
        validate_condition(condition, rule_id="MY_RULE", source="rules.yml")

    def test_errors_name_the_file_the_rule_and_the_key_path(self, tmp_path: Path) -> None:
        message = _error(
            tmp_path,
            _rule(condition={"all_of": [{"a": {"equals": 1}}, {"bucket": {"equal": "x"}}]}),
        )
        assert "MY_RULE" in message
        assert "custom.yml" in message
        assert "condition.all_of[1].bucket.equal" in message

    def test_operator_typo_suggests_the_right_one(self) -> None:
        message = self._fail({"bucket": {"equal": "x"}})
        assert "Unknown operator 'equal'" in message
        assert "did you mean 'equals'?" in message
        assert "Valid operators:" in message
        assert "equals_ci" in message

    def test_a_far_off_operator_has_no_suggestion(self) -> None:
        message = self._fail({"bucket": {"zzzzzz": "x"}})
        assert "did you mean" not in message
        assert "Unknown operator 'zzzzzz'" in message

    def test_the_typo_message_names_the_operator_from_the_rule_in_the_issue(self) -> None:
        assert "did you mean 'equals'?" in self._fail({"bucket": {"eqauls": "x"}})

    def test_property_path_is_not_an_operator_any_more(self) -> None:
        assert "Unknown operator 'property_path'" in self._fail({"a": {"property_path": "b.c"}})

    def test_nested_bad_operators_are_found(self) -> None:
        for condition in (
            {"any_of": [{"a": {"exists": True}}, {"b": {"nope": 1}}]},
            {"not": {"a": {"nope": 1}}},
            {"none_of": [{"all_of": [{"a": {"nope": 1}}]}]},
            {"p": {"any_item": {"x": {"nope": 1}}}},
        ):
            assert "Unknown operator 'nope'" in self._fail(condition)

    def test_mixed_logical_and_property_keys(self) -> None:
        message = self._fail({"all_of": [{"a": 1}], "b": {"equals": 99}})
        assert "mixes the logical operator 'all_of'" in message
        assert "'b'" in message

    def test_two_logical_keys(self) -> None:
        message = self._fail({"all_of": [{"a": 1}], "any_of": [{"a": 1}]})
        assert "more than one logical operator" in message

    def test_empty_operator_mapping(self) -> None:
        assert "has no operator" in self._fail({"a": {}})

    def test_empty_condition(self) -> None:
        assert "must not be empty" in self._fail({})

    @pytest.mark.parametrize("bad", ["x", [], 5, None])
    def test_condition_must_be_a_mapping(self, bad: Any) -> None:
        assert "must be a mapping" in self._fail(bad)

    @pytest.mark.parametrize("op", ["all_of", "any_of", "none_of"])
    def test_logical_lists_must_be_non_empty_lists_of_mappings(self, op: str) -> None:
        assert "non-empty list" in self._fail({op: []})
        assert "non-empty list" in self._fail({op: {"a": 1}})
        assert "must be a mapping" in self._fail({op: ["a"]})

    def test_not_takes_a_mapping(self) -> None:
        assert "takes a condition mapping" in self._fail({"not": [{"a": 1}]})
        assert "must not be empty" in self._fail({"not": {}})

    def test_depth_limit(self) -> None:
        def nested(levels: int) -> dict[str, Any]:
            cond: dict[str, Any] = {"a": {"equals": 1}}
            for _ in range(levels):
                cond = {"not": cond}
            return cond

        self._ok(nested(MAX_CONDITION_DEPTH))
        message = self._fail(nested(MAX_CONDITION_DEPTH + 1))
        assert f"at most {MAX_CONDITION_DEPTH} levels" in message

    def test_depth_limit_counts_quantifiers(self) -> None:
        cond: dict[str, Any] = {"x": 1}
        for _ in range(MAX_CONDITION_DEPTH + 1):
            cond = {"p": {"any_item": cond}}
        assert "levels deep" in self._fail(cond)

    def test_a_deep_rule_fails_at_load_not_at_match(self, tmp_path: Path) -> None:
        cond: dict[str, Any] = {"a": {"equals": 1}}
        for _ in range(MAX_CONDITION_DEPTH + 1):
            cond = {"not": cond}
        assert "levels deep" in _error(tmp_path, _rule(condition=cond))

    @pytest.mark.parametrize(
        ("op", "argument"),
        [
            ("exists", "yes"),
            ("not_exists", 1),
            ("is_true", "true"),
            ("is_empty", None),
            ("is_world_cidr", "x"),
            ("matches_any", "a"),
            ("matches_any", []),
            ("matches_any", [["a"]]),
            ("matches_any", [None]),
            ("greater_than", "5"),
            ("less_than", True),
            ("less_than", [1]),
            ("equals_ci", 1),
            ("contains", ["a"]),
            ("contains", {"a": 1}),
            ("contains", None),
            ("not_contains", ["a"]),
            ("equals", None),
            ("not_equals", None),
            ("any_item", "x"),
            ("all_items", ["x"]),
            ("none_items", 5),
        ],
    )
    def test_argument_types_are_checked(self, op: str, argument: Any) -> None:
        message = self._fail({"a": {op: argument}})
        assert f"'{op}'" in message
        assert "condition.a." + op in message

    @pytest.mark.parametrize(
        ("op", "argument"),
        [
            ("exists", True),
            ("not_exists", False),
            ("is_true", False),
            ("is_empty", True),
            ("is_world_cidr", True),
            ("matches_any", ["a", 1, True]),
            ("greater_than", 5),
            ("less_than", 1.5),
            ("equals_ci", "x"),
            ("contains", "x"),
            ("contains", 22),
            ("not_contains", True),
            ("equals", "x"),
            ("equals", ["a", "b"]),
            ("equals", False),
            ("not_equals", 0),
            ("any_item", {"x": 1}),
            ("all_items", {"x": {"equals": 1}}),
            ("none_items", {"any_of": [{"x": 1}]}),
        ],
    )
    def test_valid_arguments_pass(self, op: str, argument: Any) -> None:
        self._ok({"a": {op: argument}})

    def test_every_operator_has_a_passing_example(self) -> None:
        # Keeps the table above honest when an operator is added
        property_operators = VALID_OPERATORS - {
            "all_of",
            "any_of",
            "none_of",
            "not",
            "port_overlaps",
        }
        covered = {"exists", "not_exists", "is_true", "is_empty", "is_world_cidr", "matches_any"}
        covered |= {"greater_than", "less_than", "equals_ci", "contains", "not_contains"}
        covered |= {"equals", "not_equals", "any_item", "all_items", "none_items"}
        assert property_operators == covered

    def test_direct_equality_values(self) -> None:
        for value in ("x", 1, True, 1.5, ["a"]):
            self._ok({"a": value})
        assert "null is not a comparison value" in self._fail({"a": None})

    def test_an_operator_used_as_a_property_key(self) -> None:
        message = self._fail({"equals": "x"})
        assert "is an operator, not a property" in message

    def test_a_logical_operator_under_a_property(self) -> None:
        assert "goes around properties" in self._fail({"a": {"all_of": [{"b": 1}]}})

    def test_a_misspelled_logical_operator_is_caught(self) -> None:
        message = self._fail({"all_off": [{"a": 1}, {"b": 2}]})
        assert "unknown logical operator 'all_off'" in message
        assert "did you mean 'all_of'?" in message

    def test_a_property_named_like_a_logical_operator_with_a_normal_check_is_fine(self) -> None:
        self._ok({"note": {"exists": True}})
        self._ok({"notes": "x"})

    @pytest.mark.parametrize(
        "path", ["a..b", ".a", "a.", "a[", "a['']", "x" * 17 + "." + ".".join("yyyyyyyyyyyyyyyy")]
    )
    def test_property_paths_are_validated(self, path: str) -> None:
        assert "invalid property path" in self._fail({path: {"exists": True}})

    @pytest.mark.parametrize(
        "path",
        [
            "a.b.c",
            "labels.pod-security.kubernetes.io/enforce",
            "labels['a.b']",
            r"labels.a\.b",
            "a.0.b",
            "a[0].b",
            "a.*.b",
            "ingress.*.cidr_blocks",
        ],
    )
    def test_valid_property_paths(self, path: str) -> None:
        self._ok({path: {"exists": True}})

    def test_non_string_keys(self) -> None:
        assert "keys must be strings" in self._fail({5: {"exists": True}})

    def test_port_overlaps_is_a_key_that_takes_a_port_list(self) -> None:
        self._ok({"port_overlaps": [22, 3389, "1024-1100", "*"]})
        self._ok({"all_of": [{"port_overlaps": [22]}, {"protocol": "tcp"}]})
        self._ok({"cidr_blocks": {"is_world_cidr": True}, "port_overlaps": [22]})

    @pytest.mark.parametrize("bad", [22, "22", [], ["abc"], [True], [70000], [[22]], None])
    def test_port_overlaps_arguments_are_checked(self, bad: Any) -> None:
        assert "port_overlaps" in self._fail({"port_overlaps": bad})

    def test_port_overlaps_is_not_an_operator_under_a_property(self) -> None:
        assert "whole mapping" in self._fail({"a": {"port_overlaps": [22]}})

    def test_quantifier_conditions_are_validated_recursively(self) -> None:
        self._ok(
            {
                "ingress": {
                    "any_item": {"cidr_blocks": {"is_world_cidr": True}, "port_overlaps": [22]}
                }
            }
        )
        message = self._fail({"ingress": {"any_item": {"cidr_blocks": {"is_world": True}}}})
        assert "condition.ingress.any_item.cidr_blocks.is_world" in message


class TestMetadataValidation:
    def test_techniques_must_be_a_list_of_strings(self, tmp_path: Path) -> None:
        for bad in ("T1530", {"a": 1}, [1530], ["T1530", None]):
            message = _error(tmp_path, _rule(metadata={"mitre": {"techniques": bad}}))
            assert "metadata.mitre.techniques must be a list of strings" in message

    def test_tactics_must_be_a_list_of_strings(self, tmp_path: Path) -> None:
        message = _error(tmp_path, _rule(metadata={"mitre": {"tactics": "TA0009"}}))
        assert "metadata.mitre.tactics must be a list of strings" in message

    def test_mitre_must_be_a_mapping(self, tmp_path: Path) -> None:
        assert "metadata.mitre must be a mapping" in _error(
            tmp_path, _rule(metadata={"mitre": ["T1530"]})
        )

    def test_metadata_must_be_a_mapping(self, tmp_path: Path) -> None:
        assert "metadata must be a mapping" in _error(tmp_path, _rule(metadata=["x"]))

    def test_valid_metadata_loads(self, tmp_path: Path) -> None:
        meta = {"mitre": {"techniques": ["T1530"], "tactics": ["TA0009"]}, "owasp": {"a": ["x"]}}
        (rule,) = _load(tmp_path, _rule(metadata=meta))
        assert rule.metadata["mitre"]["techniques"] == ["T1530"]

    def test_unknown_technique_ids_only_warn(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            _load(tmp_path, _rule(metadata={"mitre": {"techniques": ["T9999", "bogus"]}}))
        messages = " ".join(r.message for r in caplog.records)
        assert "T9999" in messages
        assert "bogus" in messages

    @pytest.mark.parametrize("cwe", ["CWE-312", 312, "312", ["CWE-312", "CWE-319"], "cwe-79"])
    def test_cwe_ids_load(self, tmp_path: Path, cwe: Any) -> None:
        (rule,) = _load(tmp_path, _rule(metadata={"cwe": cwe}))
        assert rule.metadata["cwe"] == cwe

    @pytest.mark.parametrize("cwe", [{"id": 312}, [["CWE-312"]], True, [None]])
    def test_cwe_must_be_an_id_or_a_list_of_ids(self, tmp_path: Path, cwe: Any) -> None:
        assert "metadata.cwe must be an id or a list of ids" in _error(
            tmp_path, _rule(metadata={"cwe": cwe})
        )

    def test_a_malformed_cwe_id_only_warns(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            _load(tmp_path, _rule(metadata={"cwe": ["CWE-312", "weak-crypto"]}))
        messages = " ".join(r.message for r in caplog.records)
        assert "weak-crypto" in messages
        assert "CWE-312" not in messages

    def test_cis_controls_load_and_an_empty_one_is_refused(self, tmp_path: Path) -> None:
        (rule,) = _load(tmp_path, _rule(metadata={"cis": ["CIS AWS 2.1.1", "2.1.2"]}))
        assert list(rule.metadata["cis"]) == ["CIS AWS 2.1.1", "2.1.2"]
        assert "metadata.cis must not hold an empty control id" in _error(
            tmp_path, _rule(metadata={"cis": ["  "]})
        )

    def test_the_references_are_checked_without_a_mitre_block(self, tmp_path: Path) -> None:
        assert "metadata.cwe" in _error(tmp_path, _rule(metadata={"cwe": {"x": 1}}))

    def test_empty_or_null_metadata_is_fine(self, tmp_path: Path) -> None:
        assert _load(tmp_path, _rule(metadata=None))[0].metadata == {}
        assert _load(tmp_path, _rule(metadata={}))[0].metadata == {}


class TestImmutability:
    def _rule(self) -> Rule:
        return next(r for r in load_builtin_rules() if r.id == "S3_NO_ENCRYPTION")

    def test_the_rule_is_frozen(self) -> None:
        rule = self._rule()
        with pytest.raises(AttributeError):
            rule.severity = "low"  # type: ignore[misc]

    def test_condition_cannot_be_changed(self) -> None:
        rule = self._rule()
        with pytest.raises(TypeError, match="read-only"):
            rule.condition["not"] = {}
        with pytest.raises(TypeError, match="read-only"):
            rule.condition["not"]["derived.sse_algorithm"]["matches_any"].append("x")
        with pytest.raises(TypeError, match="read-only"):
            rule.condition["not"]["derived.sse_algorithm"].clear()

    def test_metadata_cannot_be_changed(self) -> None:
        rule = self._rule()
        for mutate in (
            lambda: rule.metadata.update({"x": 1}),
            lambda: rule.metadata.__setitem__("x", 1),
            lambda: rule.metadata.pop("mitre"),
            lambda: rule.metadata.setdefault("x", 1),
            lambda: rule.metadata["mitre"]["techniques"].append("T1"),
            lambda: rule.metadata["mitre"]["techniques"].sort(),
            lambda: rule.metadata.__delitem__("mitre"),
            lambda: rule.metadata.clear(),
        ):
            with pytest.raises(TypeError, match="read-only"):
                mutate()

    def test_a_copy_is_a_plain_mutable_structure(self) -> None:
        rule = self._rule()
        plain = copy.deepcopy(rule.metadata)
        plain["mitre"]["techniques"].append("T1")
        assert type(plain) is dict
        assert type(plain["mitre"]) is dict
        assert type(plain["mitre"]["techniques"]) is list
        assert "T1" not in rule.metadata["mitre"]["techniques"]
        shallow = dict(rule.metadata)
        shallow["x"] = 1
        assert "x" not in rule.metadata
        assert type(copy.copy(rule.metadata)) is dict

    def test_frozen_data_still_serializes_as_json(self) -> None:
        rule = self._rule()
        assert json.loads(json.dumps(rule.metadata)) == json.loads(json.dumps(dict(rule.metadata)))
        assert json.dumps(rule.condition)

    def test_frozen_containers_compare_equal_to_plain_ones(self) -> None:
        assert FrozenDict({"a": FrozenList([1, 2])}) == {"a": [1, 2]}
        assert FrozenList([1]) == [1]

    def test_frozen_containers_pickle_to_plain_ones(self) -> None:
        restored = pickle.loads(pickle.dumps(FrozenDict({"a": FrozenList([1])})))
        assert restored == {"a": [1]}
        assert type(restored) is dict

    def test_rules_are_hashable(self) -> None:
        rule = self._rule()
        assert hash(rule) == hash(self._rule())
        assert len({rule, self._rule()}) == 1

    def test_a_rule_built_by_hand_is_frozen_too(self) -> None:
        rule = Rule(
            "X", "t", "d", "tampering", "low", ("aws_s3_bucket",),
            {"all_of": [{"a": 1}]}, metadata={"mitre": {"techniques": ["T1530"]}},
        )  # fmt: skip
        with pytest.raises(TypeError):
            rule.condition["all_of"].append({"b": 2})
        with pytest.raises(TypeError):
            rule.metadata["mitre"]["techniques"].append("T1")

    def test_the_caller_dict_is_not_aliased(self) -> None:
        condition: dict[str, Any] = {"a": {"equals": 1}}
        rule = Rule("X", "t", "d", "tampering", "low", ("aws_s3_bucket",), condition)
        condition["a"]["equals"] = 2
        assert rule.condition["a"]["equals"] == 1


class TestNoRuleFiresOutsideItsDeclaredTypes:
    """The fixture-wide invariant behind exact typing."""

    @pytest.mark.parametrize(
        "path", _scannable_fixtures(), ids=lambda p: str(p.relative_to(FIXTURES))
    )
    def test_every_rule_finding_is_on_a_declared_type(self, path: Path) -> None:
        rules = {r.id: r for r in load_all_rules()}
        graph = InfraGraph.from_parsed(detect_and_parse(path))
        report = HybridEngine().analyze(graph, input_file=str(path))
        for threat in report.threats:
            if threat.source != ThreatSource.RULE:
                continue
            rule = rules[threat.rule_id]
            node_type = graph.nodes[threat.resource_address].resource_type
            assert rule.matches_type(node_type), (rule.id, node_type, rule.resource_types)


class TestDocumentationExamples:
    """The examples in docs/writing-rules.md must load, so the guide cannot drift."""

    DOC = Path(__file__).parent.parent.parent / "docs" / "writing-rules.md"

    @classmethod
    def _blocks(cls) -> list[str]:
        text = cls.DOC.read_text(encoding="utf-8")
        return re.findall(r"```yaml\n(.*?)```", text, flags=re.DOTALL)

    @classmethod
    def _conditions(cls) -> list[dict[str, Any]]:
        """Every top-level ``condition:`` in the guide's YAML examples, parsed one by one."""
        conditions: list[dict[str, Any]] = []
        for block in cls._blocks():
            for segment in re.split(r"(?m)^(?=condition:)", block):
                if segment.startswith("condition:"):
                    conditions.append(yaml.safe_load(segment)["condition"])
        return conditions

    def test_the_guide_has_examples(self) -> None:
        assert len(self._blocks()) >= 15
        assert len(self._conditions()) >= 24

    def test_every_condition_example_validates(self) -> None:
        for condition in self._conditions():
            validate_condition(condition, rule_id="DOC", source="docs/writing-rules.md")

    def test_the_condition_examples_cover_every_operator(self) -> None:
        used: set[str] = set()

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                for key, value in node.items():
                    used.add(str(key))
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        for condition in self._conditions():
            walk(condition)
        assert VALID_OPERATORS <= used, sorted(VALID_OPERATORS - used)

    def test_every_complete_rule_example_loads(self, tmp_path: Path) -> None:
        loaded: list[Rule] = []
        for index, block in enumerate(self._blocks()):
            if "# ..." in block:
                continue  # a template with placeholders, not a rule
            if block.startswith("rules:"):
                text = block
            elif block.startswith("  - id:"):
                text = "rules:\n" + block
            else:
                continue
            path = tmp_path / f"example{index}.yml"
            path.write_text(text, encoding="utf-8")
            loaded.extend(load_rules_from_file(path))
        ids = {r.id for r in loaded}
        assert {
            "S3_PUBLIC_ACCESS",
            "RDS_NO_ENCRYPTION",
            "MYORG_SG_ADMIN_OPEN",
            "K8S_PRIVILEGED_CONTAINER",
        } <= ids

    def test_the_guide_uses_no_em_dashes(self) -> None:
        assert "\u2014" not in self.DOC.read_text(encoding="utf-8")
