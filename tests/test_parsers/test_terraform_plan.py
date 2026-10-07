"""Tests for Terraform plan JSON parser."""

from __future__ import annotations

import copy
import json
import os
import pickle
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from tests.helpers.scan import real_shape
from threatcode.parsers import detect_and_parse
from threatcode.parsers.base import ParsedOutput, ParsedResource
from threatcode.parsers.terraform_plan import MAX_MODULE_DEPTH, TerraformPlanParser
from threatcode.values import is_unknown


class TestTerraformPlanParser:
    def test_parse_simple_plan(self, simple_s3_plan_data: dict) -> None:
        parser = TerraformPlanParser()
        result = parser.parse(simple_s3_plan_data, source_path="test.json")

        assert isinstance(result, ParsedOutput)
        assert result.format_type == "terraform_plan"
        assert len(result.resources) == 7

    def test_resource_types_extracted(self, simple_s3_parsed: ParsedOutput) -> None:
        types = {r.resource_type for r in simple_s3_parsed.resources}
        assert "aws_s3_bucket" in types
        assert "aws_iam_role" in types
        assert "aws_iam_policy" in types
        assert "aws_instance" in types
        assert "aws_db_instance" in types

    def test_resource_addresses(self, simple_s3_parsed: ParsedOutput) -> None:
        addresses = {r.address for r in simple_s3_parsed.resources}
        assert "aws_s3_bucket.data" in addresses
        assert "aws_s3_bucket.public_assets" in addresses
        assert "aws_s3_bucket.logs" in addresses

    def test_properties_resolved(self, simple_s3_parsed: ParsedOutput) -> None:
        data_bucket = next(
            r for r in simple_s3_parsed.resources if r.address == "aws_s3_bucket.data"
        )
        assert data_bucket.properties["bucket"] == "my-company-data-bucket"
        assert data_bucket.properties["acl"] == "private"

    def test_dependencies_extracted(self, simple_s3_parsed: ParsedOutput) -> None:
        web = next(r for r in simple_s3_parsed.resources if r.address == "aws_instance.web")
        assert "aws_s3_bucket.data" in web.dependencies

    def test_metadata_includes_versions(self, simple_s3_parsed: ParsedOutput) -> None:
        assert simple_s3_parsed.metadata["format_version"] == "1.2"
        assert simple_s3_parsed.metadata["terraform_version"] == "1.7.0"

    def test_provider_name(self, simple_s3_parsed: ParsedOutput) -> None:
        bucket = next(r for r in simple_s3_parsed.resources if r.address == "aws_s3_bucket.data")
        assert "aws" in bucket.provider

    def test_parse_invalid_data_raises(self) -> None:
        parser = TerraformPlanParser()
        with pytest.raises(Exception):
            parser.parse("not a dict")

    def test_parse_empty_plan(self) -> None:
        parser = TerraformPlanParser()
        result = parser.parse({"planned_values": {"root_module": {}}})
        assert len(result.resources) == 0


class TestDependencyOrder:
    def test_dependencies_keep_first_seen_order(self) -> None:
        """Deduplicated dependencies must not depend on hash order, or edges reorder per run."""
        data = {
            "planned_values": {
                "root_module": {
                    "resources": [
                        {"address": a, "type": a.split(".")[0], "name": a.split(".")[1]}
                        for a in (
                            "aws_instance.web",
                            "aws_subnet.a",
                            "aws_security_group.sg",
                            "aws_vpc.main",
                        )
                    ]
                }
            },
            "configuration": {
                "root_module": {
                    "resources": [
                        {
                            "type": "aws_instance",
                            "name": "web",
                            "depends_on": ["aws_vpc.main"],
                            "expressions": {
                                "subnet_id": {"references": ["aws_subnet.a"]},
                                "vpc_security_group_ids": {"references": ["aws_security_group.sg"]},
                                "tags": {"references": ["aws_vpc.main", "var.env"]},
                            },
                        }
                    ]
                }
            },
        }
        parsed = TerraformPlanParser().parse(data)
        web = next(r for r in parsed.resources if r.address == "aws_instance.web")
        assert web.dependencies == ["aws_vpc.main", "aws_subnet.a", "aws_security_group.sg"]


# ---------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------


def _resource(address: str, **values: Any) -> dict[str, Any]:
    """A planned_values entry; the type and name come from the address."""
    local = address.rsplit(".module.", 1)[-1] if ".module." in address else address
    parts = local.split(".")
    if parts[0] == "module":
        parts = parts[2:]
    mode = "managed"
    if parts[0] == "data":
        mode, parts = "data", parts[1:]
    rtype, name = parts[0], re.sub(r"\[.*\]$", "", parts[1])
    return {
        "address": address,
        "mode": mode,
        "type": rtype,
        "name": name,
        "provider_name": "registry.terraform.io/hashicorp/aws",
        "values": values,
    }


def _config(rtype: str, name: str, expressions: dict[str, Any] | None = None, **extra: Any) -> Any:
    return {"type": rtype, "name": name, "expressions": expressions or {}, **extra}


def _refs(*items: str) -> dict[str, list[str]]:
    return {"references": list(items)}


def _plan(
    resources: list[dict[str, Any]],
    config: list[dict[str, Any]] | None = None,
    *,
    child_modules: list[dict[str, Any]] | None = None,
    module_calls: dict[str, Any] | None = None,
    changes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    root: dict[str, Any] = {"resources": resources}
    if child_modules:
        root["child_modules"] = child_modules
    configuration: dict[str, Any] = {"resources": config or []}
    if module_calls:
        configuration["module_calls"] = module_calls
    data: dict[str, Any] = {
        "format_version": "1.2",
        "terraform_version": "1.9.5",
        "planned_values": {"root_module": root},
        "configuration": {"root_module": configuration},
    }
    if changes is not None:
        data["resource_changes"] = changes
    return data


def _change(address: str, after_unknown: dict[str, Any], actions: list[str] | None = None) -> Any:
    return {
        "address": address,
        "change": {
            "actions": actions or ["create"],
            "before": None,
            "after": {},
            "after_unknown": after_unknown,
        },
    }


def _by_address(parsed: ParsedOutput) -> dict[str, ParsedResource]:
    return {r.address: r for r in parsed.resources}


def _corpus(name: str) -> ParsedOutput:
    return detect_and_parse(real_shape(f"terraform/plan/{name}.plan.json"))


# ---------------------------------------------------------------------------------------
# Counted and for_each instances inherit the configuration of their resource
# ---------------------------------------------------------------------------------------


class TestInstancesInheritConfiguration:
    def test_both_counted_instances_depend_on_everything_their_resource_references(self) -> None:
        resources = _by_address(_corpus("webapp"))
        for address in ("aws_instance.app[0]", "aws_instance.app[1]"):
            deps = resources[address].dependencies
            assert "aws_security_group.app" in deps
            assert "aws_iam_instance_profile.app" in deps
            assert {"aws_subnet.private[0]", "aws_subnet.private[1]"} <= set(deps)

    def test_both_instances_carry_the_same_reference_paths(self) -> None:
        resources = _by_address(_corpus("webapp"))
        assert (
            resources["aws_instance.app[0]"].references
            == resources["aws_instance.app[1]"].references
        )

    def test_a_reference_to_a_counted_resource_without_an_index_names_every_instance(self) -> None:
        resources = _by_address(_corpus("webapp"))
        refs = resources["aws_instance.app[0]"].references
        assert refs["subnet_id"] == ["aws_subnet.private[0]", "aws_subnet.private[1]"]

    def test_a_reference_with_an_index_names_only_that_instance(self) -> None:
        data = _plan(
            [
                _resource("aws_subnet.a[0]"),
                _resource("aws_subnet.a[1]"),
                _resource("aws_instance.web"),
            ],
            [
                _config(
                    "aws_instance",
                    "web",
                    {"subnet_id": _refs("aws_subnet.a[1].id", "aws_subnet.a[1]")},
                )
            ],
        )
        web = _by_address(TerraformPlanParser().parse(data))["aws_instance.web"]
        assert web.references == {"subnet_id": ["aws_subnet.a[1]"]}

    def test_a_reference_to_an_instance_that_is_not_planned_names_nothing(self) -> None:
        data = _plan(
            [_resource("aws_subnet.a[0]"), _resource("aws_instance.web")],
            [_config("aws_instance", "web", {"subnet_id": _refs("aws_subnet.a[3].id")})],
        )
        web = _by_address(TerraformPlanParser().parse(data))["aws_instance.web"]
        assert web.references == {"subnet_id": []}
        assert web.dependencies == []

    def test_a_for_each_key_address_finds_its_configuration(self) -> None:
        resources = _by_address(_corpus("modules"))
        rule = resources['aws_security_group_rule.ingress["https"]']
        assert rule.dependencies == ["aws_vpc.main", "aws_security_group.internal"]
        assert rule.references["security_group_id"] == ["aws_security_group.internal"]
        assert rule.meta["index"] == "https"
        assert rule.meta["for_each"] is True

    def test_a_key_with_dots_and_brackets_is_one_instance(self) -> None:
        address = 'aws_s3_bucket.logs["eu.west[1]"]'
        data = _plan(
            [_resource(address), _resource("aws_s3_bucket_policy.logs")],
            [
                _config("aws_s3_bucket", "logs"),
                _config("aws_s3_bucket_policy", "logs", {"bucket": _refs("aws_s3_bucket.logs")}),
            ],
        )
        policy = _by_address(TerraformPlanParser().parse(data))["aws_s3_bucket_policy.logs"]
        assert policy.references["bucket"] == [address]

    def test_instances_keep_the_order_of_the_plan(self) -> None:
        resources = _corpus("webapp").resources
        addresses = [r.address for r in resources if r.address.startswith("aws_instance.")]
        assert addresses == ["aws_instance.app[0]", "aws_instance.app[1]"]

    def test_bookkeeping_records_how_the_resource_was_expressed(self) -> None:
        resources = _by_address(_corpus("webapp"))
        meta = resources["aws_instance.app[1]"].meta
        assert meta["index"] == 1
        assert meta["count"] is True
        assert meta["change_actions"] == ["create"]
        assert "for_each" not in meta
        assert resources["aws_vpc.main"].meta.get("count") is None


# ---------------------------------------------------------------------------------------
# Nested blocks
# ---------------------------------------------------------------------------------------


class TestNestedBlockReferences:
    def test_ingress_security_groups_is_a_reference_path(self) -> None:
        sg = _by_address(_corpus("webapp"))["aws_security_group.app"]
        assert sg.references["ingress[].security_groups"] == ["aws_security_group.alb"]
        assert "aws_security_group.alb" in sg.dependencies

    def test_vpc_config_paths_name_subnets_and_groups(self) -> None:
        fn = _by_address(_corpus("webapp"))["aws_lambda_function.worker"]
        assert fn.references["vpc_config[].subnet_ids"] == [
            "aws_subnet.private[0]",
            "aws_subnet.private[1]",
        ]
        assert fn.references["vpc_config[].security_group_ids"] == ["aws_security_group.app"]

    def test_a_reference_two_levels_down_keeps_its_whole_path(self) -> None:
        data = _plan(
            [
                _resource("aws_kms_key.k"),
                _resource("aws_s3_bucket_server_side_encryption_configuration.b"),
            ],
            [
                _config(
                    "aws_s3_bucket_server_side_encryption_configuration",
                    "b",
                    {
                        "rule": [
                            {
                                "apply_server_side_encryption_by_default": [
                                    {
                                        "kms_master_key_id": _refs(
                                            "aws_kms_key.k.arn", "aws_kms_key.k"
                                        )
                                    }
                                ]
                            }
                        ]
                    },
                )
            ],
        )
        sse = _by_address(TerraformPlanParser().parse(data))[
            "aws_s3_bucket_server_side_encryption_configuration.b"
        ]
        path = "rule[].apply_server_side_encryption_by_default[].kms_master_key_id"
        assert sse.references == {path: ["aws_kms_key.k"]}

    def test_two_blocks_of_one_kind_merge_into_one_path(self) -> None:
        data = _plan(
            [
                _resource("aws_security_group.a"),
                _resource("aws_security_group.b"),
                _resource("aws_security_group.c"),
            ],
            [
                _config("aws_security_group", "a"),
                _config("aws_security_group", "b"),
                _config(
                    "aws_security_group",
                    "c",
                    {
                        "ingress": [
                            {
                                "security_groups": _refs(
                                    "aws_security_group.a.id", "aws_security_group.a"
                                )
                            },
                            {
                                "security_groups": _refs(
                                    "aws_security_group.b.id", "aws_security_group.a"
                                )
                            },
                        ]
                    },
                ),
            ],
        )
        sg = _by_address(TerraformPlanParser().parse(data))["aws_security_group.c"]
        assert sg.references == {
            "ingress[].security_groups": ["aws_security_group.a", "aws_security_group.b"]
        }

    def test_a_block_without_references_adds_no_path(self) -> None:
        sg = _by_address(_corpus("webapp"))["aws_security_group.alb"]
        assert "ingress[].cidr_blocks" not in sg.references
        assert not any(path.startswith("ingress") for path in sg.references)


# ---------------------------------------------------------------------------------------
# Roots that name no resource
# ---------------------------------------------------------------------------------------


class TestRootsThatNameNoResource:
    @pytest.mark.parametrize(
        "reference",
        [
            "var.vpc_id",
            "local.common_tags",
            "each.value",
            "count.index",
            "self.id",
            "path.module",
            "terraform.workspace",
        ],
    )
    def test_the_root_produces_no_dependency(self, reference: str) -> None:
        data = _plan(
            [_resource("aws_vpc.main"), _resource("aws_instance.web")],
            [_config("aws_instance", "web", {"tags": _refs(reference)})],
        )
        web = _by_address(TerraformPlanParser().parse(data))["aws_instance.web"]
        assert web.dependencies == []
        assert web.references == {"tags": []}

    def test_var_local_and_each_in_the_corpus_bind_to_nothing(self) -> None:
        resources = _by_address(_corpus("modules"))
        assert resources["aws_vpc.main"].dependencies == []
        assert resources["aws_vpc.main"].references == {"tags": []}

    def test_a_reference_that_matches_no_resource_is_dropped_not_guessed(self) -> None:
        data = _plan(
            [_resource("aws_vpc.main"), _resource("aws_subnet.a")],
            [_config("aws_subnet", "a", {"vpc_id": _refs("aws_vpc.gone.id", "aws_vpc.gone")})],
        )
        subnet = _by_address(TerraformPlanParser().parse(data))["aws_subnet.a"]
        assert subnet.dependencies == []
        assert subnet.references == {"vpc_id": []}

    def test_a_bare_name_never_binds(self) -> None:
        data = _plan(
            [_resource("aws_vpc.main"), _resource("aws_subnet.a")],
            [_config("aws_subnet", "a", {"vpc_id": _refs("main")})],
        )
        assert _by_address(TerraformPlanParser().parse(data))["aws_subnet.a"].dependencies == []

    def test_a_resource_never_depends_on_itself(self) -> None:
        data = _plan(
            [_resource("aws_instance.app[0]"), _resource("aws_instance.app[1]")],
            [_config("aws_instance", "app", {"user_data": _refs("aws_instance.app")})],
        )
        resources = _by_address(TerraformPlanParser().parse(data))
        assert resources["aws_instance.app[0]"].dependencies == ["aws_instance.app[1]"]
        assert resources["aws_instance.app[1]"].dependencies == ["aws_instance.app[0]"]

    def test_depends_on_names_instances_and_data_sources(self) -> None:
        data = _plan(
            [
                _resource("aws_subnet.a[0]"),
                _resource("aws_subnet.a[1]"),
                _resource("data.aws_ami.base"),
                _resource("aws_instance.web"),
            ],
            [
                _config(
                    "aws_instance",
                    "web",
                    depends_on=["aws_subnet.a", "data.aws_ami.base", "module.gone"],
                )
            ],
        )
        web = _by_address(TerraformPlanParser().parse(data))["aws_instance.web"]
        assert web.dependencies == ["aws_subnet.a[0]", "aws_subnet.a[1]", "data.aws_ami.base"]
        assert web.meta["depends_on"] == ["aws_subnet.a", "data.aws_ami.base", "module.gone"]

    def test_configuration_is_the_source_of_truth_not_resource_changes(self) -> None:
        data = _plan(
            [_resource("aws_vpc.main"), _resource("aws_subnet.a")],
            [_config("aws_subnet", "a")],
            changes=[_change("aws_subnet.a", {"vpc_id": True})],
        )
        subnet = _by_address(TerraformPlanParser().parse(data))["aws_subnet.a"]
        assert subnet.dependencies == []
        assert "vpc_id" in subnet.properties


# ---------------------------------------------------------------------------------------
# Modules
# ---------------------------------------------------------------------------------------


class TestModuleScoping:
    def test_a_module_resource_binds_inside_its_own_module(self) -> None:
        resources = _by_address(_corpus("module_scopes"))
        subnet = resources["module.net.aws_subnet.a"]
        assert subnet.references["vpc_id"] == ["module.net.aws_vpc.main"]
        assert "aws_vpc.main" not in subnet.dependencies

    def test_a_root_resource_with_the_same_name_is_never_bound_to_a_module_resource(self) -> None:
        resources = _by_address(_corpus("module_scopes"))
        assert resources["aws_security_group.shared"].references["vpc_id"] == ["aws_vpc.main"]

    def test_a_module_input_resolves_to_the_parent_resource_not_a_namesake_in_the_module(
        self,
    ) -> None:
        resources = _by_address(_corpus("module_scopes"))
        # module.net has its own aws_security_group.shared, but the variable is the root's
        bastion = resources["module.net.aws_instance.bastion"]
        assert bastion.references["vpc_security_group_ids"] == ["aws_security_group.shared"]
        inner = resources["module.net.aws_instance.inner"]
        assert inner.references["vpc_security_group_ids"] == [
            "module.net.aws_security_group.shared"
        ]

    def test_a_module_output_resolves_to_the_resource_that_produces_it(self) -> None:
        edge = _by_address(_corpus("module_scopes"))["aws_instance.edge"]
        assert edge.references["subnet_id"] == ["module.net.aws_subnet.a"]

    def test_an_output_of_a_nested_module_resolves_through_two_levels(self) -> None:
        flow = _by_address(_corpus("module_scopes"))["module.net.aws_flow_log.net"]
        assert flow.references["log_destination"] == ["module.net.module.leaf.aws_s3_bucket.logs"]

    def test_an_input_passed_through_two_modules_reaches_the_root_resource(self) -> None:
        sse = _by_address(_corpus("module_scopes"))[
            "module.net.module.leaf.aws_s3_bucket_server_side_encryption_configuration.logs"
        ]
        path = "rule[].apply_server_side_encryption_by_default[].kms_master_key_id"
        assert sse.references[path] == ["aws_kms_key.main"]

    def test_an_output_reference_with_an_index_names_only_that_module_instance(self) -> None:
        worker = _by_address(_corpus("modules"))["aws_instance.worker"]
        assert worker.references["subnet_id"] == ["module.subnets[0].aws_subnet.this"]

    def test_a_pinned_module_key_names_only_that_instance(self) -> None:
        pinned = _by_address(_corpus("module_scopes"))["aws_instance.pinned"]
        assert pinned.references["subnet_id"] == ['module.tenant["a"].aws_subnet.this']

    def test_each_instance_of_a_module_resolves_inside_its_own_instance(self) -> None:
        resources = _by_address(_corpus("modules"))
        for index in (0, 1):
            acl = resources[f"module.subnets[{index}].aws_network_acl.this"]
            assert acl.references["subnet_ids"] == [f"module.subnets[{index}].aws_subnet.this"]

    def test_a_module_input_reaches_the_parent_resource_from_every_instance(self) -> None:
        resources = _by_address(_corpus("modules"))
        for index in (0, 1):
            subnet = resources[f"module.subnets[{index}].aws_subnet.this"]
            assert subnet.references["vpc_id"] == ["aws_vpc.main"]

    def test_a_module_without_an_index_names_all_instances_of_the_module(self) -> None:
        data = _plan(
            [_resource("aws_instance.web")],
            [
                _config(
                    "aws_instance",
                    "web",
                    {"subnet_id": _refs("module.net.subnet_id", "module.net")},
                )
            ],
            child_modules=[
                {
                    "address": f"module.net[{i}]",
                    "resources": [_resource(f"module.net[{i}].aws_subnet.a")],
                }
                for i in (0, 1)
            ],
            module_calls={
                "net": {
                    "expressions": {},
                    "module": {
                        "outputs": {"subnet_id": {"expression": _refs("aws_subnet.a.id")}},
                        "resources": [_config("aws_subnet", "a")],
                    },
                }
            },
        )
        web = _by_address(TerraformPlanParser().parse(data))["aws_instance.web"]
        assert web.references["subnet_id"] == [
            "module.net[0].aws_subnet.a",
            "module.net[1].aws_subnet.a",
        ]

    def test_a_whole_module_reference_names_no_resource(self) -> None:
        data = _plan(
            [_resource("aws_instance.web")],
            [
                _config(
                    "aws_instance", "web", {"tags": _refs("module.net")}, depends_on=["module.net"]
                )
            ],
        )
        web = _by_address(TerraformPlanParser().parse(data))["aws_instance.web"]
        assert web.dependencies == []

    def test_the_declaration_order_of_module_calls_does_not_matter(self) -> None:
        def build(order: list[str]) -> dict[str, Any]:
            calls = {
                "a": {
                    "expressions": {"vpc": _refs("aws_vpc.main.id")},
                    "module": {
                        "resources": [_config("aws_subnet", "s", {"vpc_id": _refs("var.vpc")})]
                    },
                },
                "b": {
                    "expressions": {},
                    "module": {
                        "outputs": {"sn": {"expression": _refs("module.inner.x")}},
                        "module_calls": {
                            "inner": {
                                "expressions": {},
                                "module": {
                                    "outputs": {"x": {"expression": _refs("aws_s3_bucket.z.id")}},
                                    "resources": [_config("aws_s3_bucket", "z")],
                                },
                            }
                        },
                    },
                },
            }
            return _plan(
                [_resource("aws_vpc.main"), _resource("aws_instance.web")],
                [_config("aws_instance", "web", {"subnet_id": _refs("module.b.sn")})],
                child_modules=[
                    {"address": "module.a", "resources": [_resource("module.a.aws_subnet.s")]},
                    {
                        "address": "module.b",
                        "child_modules": [
                            {
                                "address": "module.b.module.inner",
                                "resources": [_resource("module.b.module.inner.aws_s3_bucket.z")],
                            }
                        ],
                    },
                ],
                module_calls={k: calls[k] for k in order},
            )

        forward = TerraformPlanParser().parse(build(["a", "b"]))
        backward = TerraformPlanParser().parse(build(["b", "a"]))
        assert forward.resources == backward.resources
        resources = _by_address(forward)
        assert resources["module.a.aws_subnet.s"].dependencies == ["aws_vpc.main"]
        assert resources["aws_instance.web"].dependencies == [
            "module.b.module.inner.aws_s3_bucket.z"
        ]

    def test_the_module_is_kept_in_the_bookkeeping_and_references_are_absolute(self) -> None:
        subnet = _by_address(_corpus("modules"))["module.subnets[1].aws_subnet.this"]
        assert subnet.meta["module"] == "module.subnets[1]"
        assert subnet.module == ""


class TestHostileModules:
    def test_a_cyclic_output_chain_terminates(self) -> None:
        # The root passes module.loop.out into the module, whose output reads that input back
        data = _plan(
            [_resource("aws_instance.web")],
            [_config("aws_instance", "web", {"subnet_id": _refs("module.loop.out")})],
            child_modules=[
                {"address": "module.loop", "resources": [_resource("module.loop.aws_subnet.s")]}
            ],
            module_calls={
                "loop": {
                    "expressions": {"seed": _refs("module.loop.out")},
                    "module": {
                        "outputs": {"out": {"expression": _refs("var.seed")}},
                        "resources": [_config("aws_subnet", "s")],
                    },
                }
            },
        )
        web = _by_address(TerraformPlanParser().parse(data))["aws_instance.web"]
        assert web.dependencies == []

    def test_a_reference_to_itself_through_two_outputs_terminates(self) -> None:
        data = _plan(
            [_resource("aws_instance.web")],
            [_config("aws_instance", "web", {"subnet_id": _refs("module.m.a")})],
            child_modules=[
                {"address": "module.m", "resources": [_resource("module.m.aws_subnet.s")]}
            ],
            module_calls={
                "m": {
                    "expressions": {"x": _refs("module.m.b")},
                    "module": {
                        "outputs": {
                            "a": {"expression": _refs("var.x", "aws_subnet.s.id")},
                            "b": {"expression": _refs("var.x")},
                        },
                        "resources": [_config("aws_subnet", "s")],
                    },
                }
            },
        )
        web = _by_address(TerraformPlanParser().parse(data))["aws_instance.web"]
        # The cycle contributes nothing; the real producer still resolves
        assert web.dependencies == ["module.m.aws_subnet.s"]

    def test_module_nesting_beyond_the_cap_is_ignored_without_crashing(self) -> None:
        depth = MAX_MODULE_DEPTH + 10
        address = ".".join(f"module.m{i}" for i in range(depth))
        node: dict[str, Any] = {
            "address": address,
            "resources": [_resource(f"{address}.aws_vpc.deep")],
        }
        for i in range(depth - 1, 0, -1):
            parent = ".".join(f"module.m{j}" for j in range(i))
            node = {"address": parent, "child_modules": [node]}
        data = _plan([_resource("aws_vpc.main")], child_modules=[node])
        parsed = TerraformPlanParser().parse(data)
        assert [r.address for r in parsed.resources] == ["aws_vpc.main"]

    def test_a_very_wide_reference_list_resolves_each_address_once(self) -> None:
        data = _plan(
            [_resource("aws_vpc.main"), _resource("aws_subnet.a")],
            [_config("aws_subnet", "a", {"vpc_id": _refs(*(["aws_vpc.main.id"] * 5000))})],
        )
        subnet = _by_address(TerraformPlanParser().parse(data))["aws_subnet.a"]
        assert subnet.references == {"vpc_id": ["aws_vpc.main"]}

    def test_a_variable_chain_through_many_modules_stays_linear(self) -> None:
        depth = 40
        address = ".".join(f"module.m{i}" for i in range(depth))
        leaf: dict[str, Any] = {
            "expressions": {"v": _refs("var.v", "var.v")},
            "module": {
                "resources": [_config("aws_subnet", "s", {"vpc_id": _refs("var.v", "var.v")})]
            },
        }
        for i in range(depth - 2, -1, -1):
            leaf = {
                "expressions": {"v": _refs("var.v", "var.v")},
                "module": {"module_calls": {f"m{i + 1}": leaf}, "resources": []},
            }
        calls = {"m0": {**leaf, "expressions": {"v": _refs("aws_vpc.main.id")}}}
        child: dict[str, Any] = {
            "address": address,
            "resources": [_resource(f"{address}.aws_subnet.s")],
        }
        for i in range(depth - 1, 0, -1):
            child = {
                "address": ".".join(f"module.m{j}" for j in range(i)),
                "child_modules": [child],
            }
        data = _plan([_resource("aws_vpc.main")], child_modules=[child], module_calls=calls)
        subnet = _by_address(TerraformPlanParser().parse(data))[f"{address}.aws_subnet.s"]
        assert subnet.dependencies == ["aws_vpc.main"]

    def test_a_reference_with_absurdly_many_parts_names_nothing_and_is_fast(self) -> None:
        reference = ".".join(["a"] * 200_000)
        data = _plan(
            [_resource("aws_vpc.main"), _resource("aws_subnet.a")],
            [_config("aws_subnet", "a", {"vpc_id": _refs(reference, "aws_vpc.main")})],
        )
        started = time.perf_counter()
        subnet = _by_address(TerraformPlanParser().parse(data))["aws_subnet.a"]
        assert time.perf_counter() - started < 2.0
        assert subnet.references == {"vpc_id": ["aws_vpc.main"]}

    def test_thousands_of_indexed_references_resolve_without_scanning_every_instance(self) -> None:
        count = 8_000
        data = _plan(
            [_resource(f"aws_subnet.a[{i}]") for i in range(count)]
            + [_resource("aws_instance.web")],
            [
                _config("aws_subnet", "a"),
                _config(
                    "aws_instance",
                    "web",
                    {f"nic_{i}": _refs(f"aws_subnet.a[{i}].id") for i in range(count)},
                ),
            ],
        )
        started = time.perf_counter()
        web = _by_address(TerraformPlanParser().parse(data))["aws_instance.web"]
        assert time.perf_counter() - started < 5.0
        assert web.references["nic_17"] == ["aws_subnet.a[17]"]
        assert len(web.dependencies) == count

    def test_the_reference_limit_stops_resolution_and_says_so(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("threatcode.parsers.terraform_plan.MAX_REFERENCE_ENTRIES", 3)
        data = _plan(
            [_resource("aws_vpc.main"), _resource("aws_subnet.a"), _resource("aws_subnet.b")]
            + [_resource(f"aws_instance.web[{i}]") for i in range(3)],
            [
                _config("aws_subnet", "a", {"vpc_id": _refs("aws_vpc.main")}),
                _config("aws_subnet", "b", {"vpc_id": _refs("aws_vpc.main")}),
                _config(
                    "aws_instance", "web", {"subnet_id": _refs("aws_subnet.a", "aws_subnet.b")}
                ),
            ],
        )
        parsed = TerraformPlanParser().parse(data)
        resources = _by_address(parsed)
        # Resolution runs resource by resource until the limit is reached, in plan order
        assert resources["aws_subnet.a"].dependencies == ["aws_vpc.main"]
        assert resources["aws_instance.web[2]"].dependencies == []
        assert resources["aws_instance.web[2]"].references == {"subnet_id": []}
        (diagnostic,) = [d for d in parsed.diagnostics if d.code == "plan.reference_limit"]
        assert diagnostic.level == "warning"
        assert "resource(s) are missing" in diagnostic.message

    def test_a_plan_inside_the_limit_has_no_limit_diagnostic(self) -> None:
        assert "plan.reference_limit" not in {d.code for d in _corpus("webapp").diagnostics}

    @pytest.mark.parametrize(
        "mutation",
        [
            lambda d: d["planned_values"]["root_module"].update(resources=["x", 3, None]),
            lambda d: d["planned_values"]["root_module"].update(child_modules="nope"),
            lambda d: d["configuration"]["root_module"].update(resources="nope", module_calls=[1]),
            lambda d: d.update(resource_changes={"a": 1}),
            lambda d: d["configuration"].update(root_module=None),
        ],
    )
    def test_malformed_sections_never_crash_the_parser(self, mutation: Any) -> None:
        data = _plan([_resource("aws_vpc.main")], [_config("aws_vpc", "main")])
        mutation(data)
        TerraformPlanParser().parse(data)  # must not raise

    def test_a_plan_is_not_changed_by_parsing_it(self) -> None:
        path = real_shape("terraform/plan/webapp.plan.json")
        data = json.loads(path.read_text(encoding="utf-8"))
        before = copy.deepcopy(data)
        TerraformPlanParser().parse(data, source_path=str(path))
        assert data == before


# ---------------------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------------------


class TestDataSources:
    def test_a_data_source_is_a_data_node(self) -> None:
        resources = _by_address(_corpus("webapp"))
        data = resources["data.aws_iam_policy_document.assume"]
        assert data.mode == "data"
        assert data.resource_type == "aws_iam_policy_document"
        assert data.name == "assume"

    def test_managed_resources_stay_managed(self) -> None:
        modes = {r.mode for r in _corpus("webapp").resources if not r.address.startswith("data.")}
        assert modes == {"managed"}

    def test_one_diagnostic_counts_the_data_sources(self) -> None:
        diagnostics = [d for d in _corpus("webapp").diagnostics if d.code == "plan.data_source"]
        assert len(diagnostics) == 1
        assert diagnostics[0].level == "info"
        assert diagnostics[0].message.startswith("1 data source(s)")

    def test_no_data_sources_means_no_diagnostic(self) -> None:
        codes = {d.code for d in _corpus("two_vpcs").diagnostics}
        assert "plan.data_source" not in codes

    def test_a_reference_to_a_data_source_resolves_to_the_data_node(self) -> None:
        role = _by_address(_corpus("webapp"))["aws_iam_role.app"]
        assert role.dependencies == ["data.aws_iam_policy_document.assume"]

    def test_a_data_source_in_a_module_keeps_its_mode(self) -> None:
        data = _plan(
            [],
            child_modules=[
                {"address": "module.m", "resources": [_resource("module.m.data.aws_ami.base")]}
            ],
        )
        (res,) = TerraformPlanParser().parse(data).resources
        assert (res.mode, res.address, res.resource_type) == (
            "data",
            "module.m.data.aws_ami.base",
            "aws_ami",
        )

    def test_a_data_source_read_during_planning_is_not_a_node(self) -> None:
        # prior_state holds those; they only matter as context and planned_values lacks them
        resources = _by_address(_corpus("webapp"))
        assert "data.aws_ami.al2023" not in resources
        assert resources["aws_instance.app[0]"].dependencies.count("data.aws_ami.al2023") == 0


# ---------------------------------------------------------------------------------------
# Unknown values
# ---------------------------------------------------------------------------------------


def _unknown_plan(
    values: dict[str, Any],
    after_unknown: dict[str, Any] | None,
    expressions: dict[str, Any] | None = None,
    address: str = "aws_cloudtrail.t",
) -> ParsedResource:
    rtype, name = address.split(".")
    data = _plan(
        [_resource(address, **values)],
        [_config(rtype, name, expressions)],
        changes=[_change(address, after_unknown)] if after_unknown is not None else None,
    )
    return TerraformPlanParser().parse(data).resources[0]


class TestUnknownValues:
    def test_an_unknown_attribute_becomes_an_unknown_not_a_missing_key(self) -> None:
        trail = _unknown_plan({"name": "t"}, {"kms_key_id": True})
        assert "kms_key_id" in trail.properties
        assert is_unknown(trail.properties["kms_key_id"])

    def test_the_unknown_carries_the_reference_written_in_the_configuration(self) -> None:
        trail = _unknown_plan(
            {"name": "t"},
            {"kms_key_id": True},
            {"kms_key_id": _refs("aws_kms_key.k.arn", "aws_kms_key.k")},
        )
        value = trail.properties["kms_key_id"]
        assert is_unknown(value)
        assert value.reference == "aws_kms_key.k.arn"

    def test_a_computed_attribute_has_no_reference(self) -> None:
        value = _unknown_plan({"name": "t"}, {"arn": True}).properties["arn"]
        assert is_unknown(value)
        assert value.reference == ""

    def test_a_known_value_is_never_replaced(self) -> None:
        trail = _unknown_plan({"name": "t", "kms_key_id": "alias/aws/s3"}, {"kms_key_id": True})
        assert trail.properties["kms_key_id"] == "alias/aws/s3"

    def test_a_planned_null_for_an_unknown_attribute_is_unknown(self) -> None:
        trail = _unknown_plan({"name": "t", "kms_key_id": None}, {"kms_key_id": True})
        assert is_unknown(trail.properties["kms_key_id"])

    def test_a_planned_null_that_is_not_unknown_stays_null(self) -> None:
        trail = _unknown_plan({"name": "t", "kms_key_id": None}, {"arn": True})
        assert trail.properties["kms_key_id"] is None

    def test_false_and_empty_subtrees_mark_nothing(self) -> None:
        trail = _unknown_plan({"name": "t"}, {"a": False, "b": {}, "c": [], "d": [{}]})
        assert set(trail.properties) == {"name"}

    def test_a_nested_unknown_is_placed_in_the_existing_block(self) -> None:
        sg = _unknown_plan(
            {"ingress": [{"from_port": 80, "to_port": 80}]},
            {"ingress": [{"security_groups": True}]},
            address="aws_security_group.s",
        )
        (rule,) = sg.properties["ingress"]
        assert rule["from_port"] == 80
        assert is_unknown(rule["security_groups"])

    def test_a_block_that_is_wholly_unknown_is_created_as_a_single_element_list(self) -> None:
        fn = _unknown_plan(
            {"function_name": "f"},
            {"vpc_config": [{"subnet_ids": True}]},
            address="aws_lambda_function.f",
        )
        (block,) = fn.properties["vpc_config"]
        assert is_unknown(block["subnet_ids"])

    def test_a_whole_block_list_can_be_unknown(self) -> None:
        sg = _unknown_plan({}, {"ingress": True}, address="aws_security_group.s")
        assert is_unknown(sg.properties["ingress"])

    def test_list_positions_stay_aligned(self) -> None:
        sg = _unknown_plan(
            {"ingress": [{"from_port": 1}, {"from_port": 2}, {"from_port": 3}]},
            {"ingress": [{}, {}, {"cidr_blocks": True}]},
            address="aws_security_group.s",
        )
        first, second, third = sg.properties["ingress"]
        assert "cidr_blocks" not in first and "cidr_blocks" not in second
        assert is_unknown(third["cidr_blocks"])

    def test_a_list_item_unknown_replaces_its_null_placeholder(self) -> None:
        # Terraform writes null for an unknown item of a list, and true in after_unknown
        lb = _unknown_plan(
            {"subnets": ["subnet-1", None]}, {"subnets": [False, True]}, address="aws_lb.l"
        )
        known, unknown = lb.properties["subnets"]
        assert known == "subnet-1"
        assert is_unknown(unknown)

    def test_unknown_items_before_a_gap_are_padded_so_later_ones_keep_their_index(self) -> None:
        lb = _unknown_plan({}, {"subnets": [False, True]}, address="aws_lb.l")
        assert lb.properties["subnets"][0] is None
        assert is_unknown(lb.properties["subnets"][1])

    def test_a_configured_reference_with_no_planned_value_is_unknown(self) -> None:
        trail = _unknown_plan(
            {"name": "t"}, None, {"kms_key_id": _refs("aws_kms_key.k.arn", "aws_kms_key.k")}
        )
        value = trail.properties["kms_key_id"]
        assert is_unknown(value)
        assert value.reference == "aws_kms_key.k.arn"

    def test_a_configured_constant_with_no_planned_value_is_not_unknown(self) -> None:
        trail = _unknown_plan({"name": "t"}, None, {"kms_key_id": {"constant_value": "k"}})
        assert "kms_key_id" not in trail.properties

    def test_an_attribute_with_no_expression_and_no_value_stays_absent(self) -> None:
        trail = _unknown_plan({"name": "t"}, {"arn": True}, {"name": {"constant_value": "t"}})
        assert "kms_key_id" not in trail.properties

    def test_a_configured_reference_with_a_planned_null_is_a_known_null(self) -> None:
        trail = _unknown_plan(
            {"name": "t", "kms_key_id": None}, None, {"kms_key_id": _refs("var.key")}
        )
        assert trail.properties["kms_key_id"] is None

    def test_a_configuration_block_is_never_invented(self) -> None:
        # A dynamic block that produces nothing is still written in the configuration
        sg = _unknown_plan(
            {"ingress": []},
            None,
            {"ingress": [{"cidr_blocks": _refs("ingress.value.cidrs")}]},
            address="aws_security_group.s",
        )
        assert sg.properties["ingress"] == []

    def test_a_reference_inside_an_existing_block_is_unknown_when_the_block_has_no_value(
        self,
    ) -> None:
        sg = _unknown_plan(
            {"ingress": [{"from_port": 22}]},
            None,
            {
                "ingress": [
                    {
                        "from_port": {"constant_value": 22},
                        "security_groups": _refs("aws_security_group.o.id"),
                    }
                ]
            },
            address="aws_security_group.s",
        )
        assert is_unknown(sg.properties["ingress"][0]["security_groups"])

    def test_one_info_diagnostic_counts_every_unknown(self) -> None:
        data = _plan(
            [_resource("aws_cloudtrail.a"), _resource("aws_cloudtrail.b")],
            changes=[
                _change("aws_cloudtrail.a", {"x": True, "y": True}),
                _change("aws_cloudtrail.b", {"z": True}),
            ],
        )
        diagnostics = [
            d
            for d in TerraformPlanParser().parse(data).diagnostics
            if d.code == "plan.unknown_values"
        ]
        assert len(diagnostics) == 1
        assert diagnostics[0].message.startswith("3 value(s)")

    def test_a_plan_with_no_unknowns_has_no_diagnostic(self) -> None:
        data = _plan([_resource("aws_cloudtrail.a")], changes=[_change("aws_cloudtrail.a", {})])
        codes = {d.code for d in TerraformPlanParser().parse(data).diagnostics}
        assert "plan.unknown_values" not in codes

    def test_an_unknown_is_never_truthy_so_it_is_never_read_as_a_set_value(self) -> None:
        value = _unknown_plan({}, {"associate_public_ip_address": True}, address="aws_instance.i")
        unknown = value.properties["associate_public_ip_address"]
        assert is_unknown(unknown)
        assert not unknown
        assert str(unknown) == "(known after apply)"

    def test_a_placed_unknown_stays_falsy_through_copy_and_pickle(self) -> None:
        unknown = _unknown_plan({}, {"kms_key_id": True}).properties["kms_key_id"]
        for clone in (
            copy.copy(unknown),
            copy.deepcopy(unknown),
            pickle.loads(pickle.dumps(unknown)),
        ):
            assert is_unknown(clone)
            assert not clone

    def test_unknowns_serialize_as_text(self) -> None:
        trail = _unknown_plan({"name": "t"}, {"kms_key_id": True})
        assert json.loads(json.dumps(trail.properties))["kms_key_id"] == "(known after apply)"

    def test_the_corpus_marks_what_a_real_plan_leaves_unknown(self) -> None:
        resources = _by_address(_corpus("webapp"))
        subnet = resources["aws_subnet.private[0]"]
        assert is_unknown(subnet.properties["vpc_id"])
        assert subnet.properties["vpc_id"].reference == "aws_vpc.main.id"
        assert is_unknown(resources["aws_db_instance.orders"].properties["endpoint"])
        assert subnet.properties["cidr_block"] == "10.0.10.0/24"

    def test_unknown_values_inside_a_module_use_the_module_variable_as_reference(self) -> None:
        trail = _by_address(_corpus("unknown_values"))["module.audit.aws_cloudtrail.this"]
        assert is_unknown(trail.properties["kms_key_id"])
        assert trail.properties["kms_key_id"].reference == "var.kms_key_arn"
        assert trail.references["kms_key_id"] == ["aws_kms_key.trail"]

    def test_the_attribute_a_plan_does_not_mention_stays_absent_for_the_trail_without_a_key(
        self,
    ) -> None:
        resources = _by_address(_corpus("unknown_values"))
        assert resources["aws_cloudtrail.plain"].properties["kms_key_id"] is None
        assert is_unknown(resources["aws_cloudtrail.encrypted"].properties["kms_key_id"])


# ---------------------------------------------------------------------------------------
# Source spans
# ---------------------------------------------------------------------------------------


def _line_of_resource(path: Path, address: str) -> int:
    """The line of the `{` of a planned_values entry, found by reading the file by hand."""
    lines = path.read_text(encoding="utf-8").splitlines()
    marker = f'"address": "{address}",'
    first = next(i for i, line in enumerate(lines) if marker in line)
    # In the planned_values section the object opens on the line above its address
    assert lines[first - 1].strip() == "{"
    return first  # 1-based line of the "{": index of the address line, minus one, plus one


class TestSourceSpans:
    def test_a_resource_starts_on_the_line_of_its_object_in_the_plan(self) -> None:
        path = real_shape("terraform/plan/two_vpcs.plan.json")
        resources = _by_address(detect_and_parse(path))
        for address in ("aws_vpc.prod", "aws_subnet.dev", "aws_instance.prod"):
            assert resources[address].start_line == _line_of_resource(path, address)

    def test_the_location_is_the_plan_file(self) -> None:
        path = real_shape("terraform/plan/two_vpcs.plan.json")
        assert {r.source_location for r in detect_and_parse(path).resources} == {str(path)}

    def test_a_resource_of_a_child_module_has_its_own_line(self) -> None:
        path = real_shape("terraform/plan/modules.plan.json")
        resources = _by_address(detect_and_parse(path))
        address = "module.subnets[1].aws_subnet.this"
        assert resources[address].start_line == _line_of_resource(path, address)

    def test_the_end_line_is_not_known(self) -> None:
        path = real_shape("terraform/plan/two_vpcs.plan.json")
        assert all(r.end_line is None for r in detect_and_parse(path).resources)

    def test_text_handed_in_replaces_reading_the_file(self) -> None:
        path = real_shape("terraform/plan/two_vpcs.plan.json")
        text = path.read_text(encoding="utf-8")
        parsed = TerraformPlanParser().parse(
            json.loads(text), source_path="elsewhere.json", text=text
        )
        resources = _by_address(parsed)
        assert resources["aws_vpc.prod"].start_line == _line_of_resource(path, "aws_vpc.prod")
        assert resources["aws_vpc.prod"].source_location == "elsewhere.json"

    def test_a_plan_with_no_file_has_no_lines(self) -> None:
        data = _plan([_resource("aws_vpc.main")])
        assert TerraformPlanParser().parse(data).resources[0].start_line is None
        assert (
            TerraformPlanParser()
            .parse(data, source_path="/no/such/plan.json")
            .resources[0]
            .start_line
            is None
        )

    def test_a_file_that_is_not_the_plan_gives_no_lines(self) -> None:
        data = _plan([_resource("aws_vpc.main")])
        other = real_shape("terraform/plan/two_vpcs.plan.json").with_name("webapp.plan.json")
        text = '{"unrelated": true}\n'
        parsed = TerraformPlanParser().parse(data, source_path=str(other), text=text)
        assert parsed.resources[0].start_line is None

    def test_a_directory_as_source_path_is_ignored(self, tmp_path: Path) -> None:
        data = _plan([_resource("aws_vpc.main")])
        assert (
            TerraformPlanParser().parse(data, source_path=str(tmp_path)).resources[0].start_line
            is None
        )


# ---------------------------------------------------------------------------------------
# Plans that model nothing
# ---------------------------------------------------------------------------------------


class TestZeroResources:
    def test_an_empty_plan_warns(self) -> None:
        parsed = TerraformPlanParser().parse(
            {"planned_values": {"root_module": {}}}, source_path="p.json"
        )
        (diagnostic,) = [d for d in parsed.diagnostics if d.code == "parse.zero_resources"]
        assert diagnostic.level == "warning"
        assert diagnostic.file == "p.json"

    def test_a_plan_of_data_sources_only_warns_and_says_so(self) -> None:
        data = _plan([_resource("data.aws_ami.base")])
        parsed = TerraformPlanParser().parse(data)
        (diagnostic,) = [d for d in parsed.diagnostics if d.code == "parse.zero_resources"]
        assert "1 data source(s) only" in diagnostic.message

    def test_a_plan_with_managed_resources_does_not_warn(self) -> None:
        assert "parse.zero_resources" not in {d.code for d in _corpus("two_vpcs").diagnostics}

    def test_a_plan_without_planned_values_warns(self) -> None:
        parsed = TerraformPlanParser().parse({"format_version": "1.2", "resource_changes": []})
        assert [d.code for d in parsed.diagnostics] == ["parse.zero_resources"]


# ---------------------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------------------


class TestDeterminism:
    @pytest.mark.parametrize(
        "name", ["webapp", "modules", "two_vpcs", "unknown_values", "module_scopes"]
    )
    def test_two_parses_agree_exactly(self, name: str) -> None:
        first, second = _corpus(name), _corpus(name)
        assert first.resources == second.resources
        assert first.diagnostics == second.diagnostics

    def test_references_never_depend_on_set_ordering(self) -> None:
        resources = _by_address(_corpus("module_scopes"))
        assert resources["module.net.aws_instance.bastion"].dependencies == [
            "module.net.aws_subnet.a",
            "aws_security_group.shared",
        ]

    def test_dependencies_are_the_reference_values_without_repeats(self) -> None:
        for res in _corpus("webapp").resources:
            flat = [a for refs in res.references.values() for a in refs]
            assert all(a in res.dependencies for a in flat)
            assert len(res.dependencies) == len(set(res.dependencies))

    def test_hash_randomization_does_not_change_the_output(self) -> None:
        """Two interpreters with different hash seeds produce byte-identical resources."""
        script = (
            "import json, sys\n"
            "from threatcode.parsers import detect_and_parse\n"
            "out = {}\n"
            "for path in sys.argv[1:]:\n"
            "    parsed = detect_and_parse(path)\n"
            "    out[path] = [[r.address, r.dependencies, r.references, r.meta, r.start_line]\n"
            "                 for r in parsed.resources]\n"
            "print(json.dumps(out, sort_keys=True))\n"
        )
        paths = [
            str(real_shape(f"terraform/plan/{name}.plan.json"))
            for name in ("webapp", "modules", "module_scopes", "unknown_values")
        ]
        outputs = []
        for seed in ("1", "2", "3"):
            env = {**os.environ, "PYTHONHASHSEED": seed}
            done = subprocess.run(
                [sys.executable, "-c", script, *paths],
                capture_output=True,
                text=True,
                env=env,
                check=True,
            )
            outputs.append(done.stdout)
        assert outputs[0] == outputs[1] == outputs[2]
        assert json.loads(outputs[0])
