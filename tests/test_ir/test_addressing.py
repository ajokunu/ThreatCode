"""Tests for threatcode.ir.addressing."""

from __future__ import annotations

import pytest

from threatcode.ir.addressing import (
    base_address,
    components,
    module_of,
    split_location,
    strip_attribute_suffix,
)


class TestBaseAddress:
    @pytest.mark.parametrize(
        ("address", "expected"),
        [
            ("aws_instance.app", "aws_instance.app"),
            ("aws_instance.app[0]", "aws_instance.app"),
            ('aws_instance.app["web"]', "aws_instance.app"),
            ("aws_instance.app['web']", "aws_instance.app"),
            ("module.net[0].aws_vpc.main", "module.net.aws_vpc.main"),
            ('module.net["eu"].aws_vpc.main[2]', "module.net.aws_vpc.main"),
            ("module.a[0].module.b[1].aws_vpc.main[2]", "module.a.module.b.aws_vpc.main"),
            ("aws_instance.app[0].id", "aws_instance.app.id"),
            ("MyBucket", "MyBucket"),
            ("", ""),
        ],
    )
    def test_strips_indexes_at_any_level(self, address: str, expected: str) -> None:
        assert base_address(address) == expected

    def test_quoted_key_may_contain_dots_and_brackets(self) -> None:
        assert base_address('aws_s3_bucket.logs["a.b[0].c"]') == "aws_s3_bucket.logs"

    def test_escaped_quote_inside_a_key_does_not_end_the_key(self) -> None:
        assert base_address(r'aws_s3_bucket.logs["a\"]b"].id') == "aws_s3_bucket.logs.id"

    def test_unterminated_bracket_is_left_in_place(self) -> None:
        assert base_address("aws_instance.app[0") == "aws_instance.app[0"
        assert base_address('aws_instance.app["x') == 'aws_instance.app["x'


class TestComponents:
    @pytest.mark.parametrize(
        ("address", "expected"),
        [
            ("aws_vpc.main", ["aws_vpc", "main"]),
            ("module.net[0].aws_vpc.main", ["module", "net[0]", "aws_vpc", "main"]),
            ('aws_s3_bucket.b["x.y"].arn', ["aws_s3_bucket", 'b["x.y"]', "arn"]),
            ("MyBucket", ["MyBucket"]),
            ("", [""]),
            ("aws_instance.app[0", ["aws_instance", "app[0"]),
        ],
    )
    def test_splits_at_dots_outside_brackets(self, address: str, expected: list[str]) -> None:
        assert components(address) == expected


class TestModuleOf:
    @pytest.mark.parametrize(
        ("address", "expected"),
        [
            ("aws_vpc.main", ""),
            ("module.net.aws_vpc.main", "module.net"),
            ("module.a.module.b.aws_vpc.main", "module.a.module.b"),
            ("module.net[0].aws_vpc.main[1]", "module.net"),
            ('module.net["eu"].aws_vpc.main', "module.net"),
            ("module.net.data.aws_vpc.main", "module.net"),
            ("data.aws_vpc.main", ""),
            ("MyBucket", ""),
            ("", ""),
        ],
    )
    def test_module_path(self, address: str, expected: str) -> None:
        assert module_of(address) == expected

    def test_module_call_address_is_its_own_module(self) -> None:
        assert module_of("module.net") == "module.net"


class TestStripAttributeSuffix:
    @pytest.mark.parametrize(
        ("address", "expected"),
        [
            ("aws_vpc.main", "aws_vpc.main"),
            ("aws_vpc.main.id", "aws_vpc.main"),
            ("aws_vpc.main.tags.Name", "aws_vpc.main"),
            ("aws_instance.app[0].id", "aws_instance.app[0]"),
            ("module.net.aws_vpc.main.id", "module.net.aws_vpc.main"),
            ("module.a.module.b.aws_vpc.main.arn", "module.a.module.b.aws_vpc.main"),
            ("data.aws_vpc.main.id", "data.aws_vpc.main"),
            ("module.net.data.aws_vpc.main.id", "module.net.data.aws_vpc.main"),
        ],
    )
    def test_terraform_shape_without_known_ids(self, address: str, expected: str) -> None:
        assert strip_attribute_suffix(address) == expected

    def test_module_output_reference_is_left_alone(self) -> None:
        assert strip_attribute_suffix("module.net.vpc_id") == "module.net.vpc_id"

    def test_single_component_is_left_alone(self) -> None:
        assert strip_attribute_suffix("MyBucket") == "MyBucket"

    def test_known_ids_pick_the_longest_matching_prefix(self) -> None:
        known = {"aws_vpc.main", "aws_vpc.main.id"}
        assert strip_attribute_suffix("aws_vpc.main.id", known) == "aws_vpc.main.id"
        assert strip_attribute_suffix("aws_vpc.main.arn", known) == "aws_vpc.main"

    def test_known_ids_support_cloudformation_logical_ids(self) -> None:
        assert strip_attribute_suffix("MyBucket.Arn", {"MyBucket"}) == "MyBucket"

    def test_known_ids_with_no_matching_prefix_return_the_input(self) -> None:
        assert strip_attribute_suffix("aws_vpc.other.id", {"aws_vpc.main"}) == "aws_vpc.other.id"

    def test_known_ids_keep_the_index_that_was_written(self) -> None:
        known = {"aws_instance.app[1]"}
        assert strip_attribute_suffix("aws_instance.app[1].id", known) == "aws_instance.app[1]"

    def test_dot_inside_a_quoted_key_is_not_a_component_boundary(self) -> None:
        known = {'aws_s3_bucket.b["x.y"]'}
        address = 'aws_s3_bucket.b["x.y"].arn'
        assert strip_attribute_suffix(address, known) == 'aws_s3_bucket.b["x.y"]'


class TestSplitLocation:
    @pytest.mark.parametrize(
        ("location", "expected"),
        [
            ("main.tf", ("main.tf", None)),
            ("main.tf:12", ("main.tf", 12)),
            ("/work/app/Dockerfile:3", ("/work/app/Dockerfile", 3)),
            ("", ("", None)),
        ],
    )
    def test_splits_a_trailing_line(self, location: str, expected: tuple[str, int | None]) -> None:
        assert split_location(location) == expected

    def test_windows_path_without_a_line_is_not_split(self) -> None:
        assert split_location("C:\\work\\main.tf") == ("C:\\work\\main.tf", None)

    def test_windows_path_with_a_line_splits_on_the_last_colon_only(self) -> None:
        assert split_location("C:\\work\\main.tf:7") == ("C:\\work\\main.tf", 7)

    @pytest.mark.parametrize("location", ["main.tf:abc", "main.tf:", "main.tf:1a", "main.tf:-3"])
    def test_non_digit_tail_is_not_a_line(self, location: str) -> None:
        assert split_location(location) == (location, None)

    def test_line_zero_is_not_a_line(self) -> None:
        assert split_location("main.tf:0") == ("main.tf:0", None)

    def test_absurdly_long_digit_tail_is_not_a_line(self) -> None:
        location = "main.tf:" + "9" * 30
        assert split_location(location) == (location, None)

    def test_a_bare_line_has_no_path_to_split_from(self) -> None:
        assert split_location(":12") == (":12", None)
