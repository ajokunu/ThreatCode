"""Tests for threatcode.parsers._hcl_eval: expressions, evaluation and references."""

from __future__ import annotations

import time
from typing import Any

import pytest

from threatcode.parsers import _hcl_eval
from threatcode.parsers._hcl_eval import (
    NOT_BOUND,
    Context,
    ExpressionError,
    IteratorContext,
    evaluate_expression,
    evaluate_string,
    evaluate_value,
    parse_expression,
    parse_template,
    string_references,
)
from threatcode.values import UNKNOWN_TEXT, Unknown, is_unknown


class Module(Context):
    """A module with variables, locals and declared resources, for tests."""

    def __init__(
        self,
        variables: dict[str, Any] | None = None,
        locals_: dict[str, Any] | None = None,
        resources: set[tuple[str, str]] | None = None,
        data: set[tuple[str, str]] | None = None,
        modules: dict[str, list[str]] | None = None,
        prefix: str = "",
    ) -> None:
        self.variables = variables or {}
        self.locals = locals_ or {}
        self.resources = resources or set()
        self.data = data or set()
        self.modules = modules or {}
        self.prefix = prefix

    def variable(self, name: str) -> Any:
        return self.variables.get(name, Unknown(f"var.{name}"))

    def local(self, name: str) -> Any:
        return self.locals.get(name, Unknown(f"local.{name}"))

    def declares(self, root: str, name: str) -> bool:
        return (root, name) in self.resources

    def declares_data(self, kind: str, name: str) -> bool:
        return (kind, name) in self.data

    def reference(self, chain: str) -> str:
        return f"{self.prefix}{chain}"

    def variable_references(self, name: str) -> list[str]:
        return [f"from-var:{name}"] if name in self.variables else []

    def local_references(self, name: str) -> list[str]:
        return [f"from-local:{name}"] if name in self.locals else []

    def module_references(self, module: str, output: str) -> list[str]:
        return self.modules.get(f"{module}.{output}", [])


def unknown_reference(value: Any) -> str:
    assert is_unknown(value), value
    return value.reference


def ev(text: str, **variables: Any) -> Any:
    return evaluate_expression(text, Module(variables))


class TestLiteralsAndOperators:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("1", 1),
            ("1.5", 1.5),
            ("1e3", 1000.0),
            ("true", True),
            ("false", False),
            ("null", None),
            ('"text"', "text"),
            ("'single'", "single"),
            ("[1, 2, 3]", [1, 2, 3]),
            ("[1, 2,]", [1, 2]),
            ("[]", []),
            ("{a = 1, b = 2}", {"a": 1, "b": 2}),
            ("{'a': 1, 'b': 2}", {"a": 1, "b": 2}),
            ('{"a" = 1}', {"a": 1}),
            ("{a = [1, {b = 2}]}", {"a": [1, {"b": 2}]}),
            ("{}", {}),
            ("(1 + 2) * 3", 9),
            ("1 + 2 * 3", 7),
            ("10 - 4 - 3", 3),
            ("10 / 4", 2.5),
            ("10 / 5", 2),
            ("7 % 4", 3),
            ("-3 + 5", 2),
            ("--3", 3),
            ("!true", False),
            ("!false", True),
            ("1 < 2", True),
            ("2 <= 2", True),
            ("3 > 4", False),
            ("4 >= 4", True),
            ("1 == 1", True),
            ('"a" != "b"', True),
            ('1 == "1"', False),
            ("true == 1", False),
            ("[1, 2] == [1, 2]", True),
            ("{a = 1} == {a = 1}", True),
            ("true && false", False),
            ("false || true", True),
            ("true ? 1 : 2", 1),
            ("false ? 1 : 2", 2),
            ("true ? false ? 1 : 2 : 3", 2),
            ('"true" ? 1 : 2', 1),
        ],
    )
    def test_evaluates(self, text: str, expected: Any) -> None:
        assert evaluate_expression(text) == expected

    def test_a_true_value_is_not_the_number_one(self) -> None:
        assert evaluate_expression("true") is True
        assert evaluate_expression("1 == 1") is True
        assert evaluate_expression("true == true") is True

    @pytest.mark.parametrize("text", ["1 / 0", "1 % 0", '"a" - 1', "true + 1", "[1] + [2]"])
    def test_a_failing_operation_is_unknown_not_an_error(self, text: str) -> None:
        assert is_unknown(evaluate_expression(text))

    def test_a_non_boolean_condition_is_unknown(self) -> None:
        assert is_unknown(evaluate_expression("3 ? 1 : 2"))
        assert is_unknown(evaluate_expression('"maybe" ? 1 : 2'))

    def test_only_the_chosen_branch_is_evaluated(self) -> None:
        assert evaluate_expression("true ? 1 : var.missing") == 1
        assert is_unknown(evaluate_expression("false ? 1 : var.missing"))


class TestUnknownPropagation:
    def test_a_variable_with_no_value_is_unknown_and_names_itself(self) -> None:
        assert unknown_reference(ev("var.x")) == "var.x"

    def test_an_operation_on_an_unknown_is_unknown(self) -> None:
        for text in ("var.x + 1", "var.x == 1", "!var.x", "-var.x", "var.x ? 1 : 2"):
            assert is_unknown(ev(text)), text

    def test_the_text_of_an_unresolvable_expression_is_its_reference(self) -> None:
        assert unknown_reference(ev("var.x + 1")) == "var.x + 1"

    def test_and_or_short_circuit_over_an_unknown(self) -> None:
        assert ev("false && var.x") is False
        assert ev("true || var.x") is True
        assert is_unknown(ev("true && var.x"))
        assert is_unknown(ev("false || var.x"))
        assert ev("var.x && false") is False
        assert ev("var.x || true") is True

    def test_an_unknown_equals_nothing(self) -> None:
        assert is_unknown(ev("var.x == var.x"))

    def test_the_text_of_an_unknown_is_the_placeholder(self) -> None:
        assert str(ev("var.x")) == UNKNOWN_TEXT


class TestVariablesAndLocals:
    def test_a_supplied_variable_is_its_value(self) -> None:
        assert ev("var.public", public=False) is False
        assert ev("var.n + 1", n=2) == 3

    def test_attributes_and_indexes_of_a_known_value(self) -> None:
        values = {"cfg": {"ports": [22, 443], "name": "x"}}
        assert ev("var.cfg.name", **values) == "x"
        assert ev("var.cfg.ports[1]", **values) == 443
        assert ev("var.cfg.ports.0", **values) == 22
        assert ev('var.cfg["name"]', **values) == "x"
        assert is_unknown(ev("var.cfg.missing", **values))
        assert is_unknown(ev("var.cfg.ports[9]", **values))

    def test_an_attribute_of_an_unknown_names_the_path(self) -> None:
        assert unknown_reference(ev("var.cfg.name")) == "var.cfg.name"

    def test_a_splat_over_a_known_list(self) -> None:
        values = {"items": [{"id": "a"}, {"id": "b"}]}
        assert ev("var.items[*].id", **values) == ["a", "b"]
        assert ev("var.items.*.id", **values) == ["a", "b"]

    def test_a_splat_over_an_unknown_is_unknown(self) -> None:
        assert is_unknown(ev("var.items[*].id"))

    def test_a_local_is_read_through_the_context(self) -> None:
        module = Module(locals_={"name": "prod-app"})
        assert evaluate_expression("local.name", module) == "prod-app"

    def test_each_count_self_and_path_are_unknown(self) -> None:
        for text in ("each.value", "count.index", "self.id", "path.module", "terraform.workspace"):
            assert is_unknown(ev(text)), text

    def test_an_iterator_binds_key_and_value(self) -> None:
        ctx = IteratorContext(Module(), "ingress", "k", {"port": 22})
        assert evaluate_expression("ingress.key", ctx) == "k"
        assert evaluate_expression("ingress.value.port", ctx) == 22
        assert is_unknown(evaluate_expression("other.key", ctx))


class TestResourceReferences:
    def test_a_resource_attribute_is_unknown_with_its_reference(self) -> None:
        module = Module(resources={("aws_kms_key", "main")})
        value = evaluate_expression("aws_kms_key.main.arn", module)
        assert unknown_reference(value) == "aws_kms_key.main.arn"

    def test_indexes_are_not_part_of_the_reference(self) -> None:
        module = Module(resources={("aws_subnet", "a")})
        value = evaluate_expression("aws_subnet.a[count.index].id", module)
        assert unknown_reference(value) == "aws_subnet.a.id"

    def test_the_context_qualifies_a_declared_reference(self) -> None:
        module = Module(resources={("aws_vpc", "main")}, prefix="module.net.")
        value = evaluate_expression("aws_vpc.main.id", module)
        assert unknown_reference(value) == "module.net.aws_vpc.main.id"

    def test_an_undeclared_reference_is_unknown_and_unqualified(self) -> None:
        module = Module(prefix="module.net.")
        assert (
            unknown_reference(evaluate_expression("aws_vpc.main.id", module)) == "aws_vpc.main.id"
        )

    def test_a_data_source_is_unknown_unless_the_context_has_its_value(self) -> None:
        assert unknown_reference(ev("data.aws_ami.base.id")) == "data.aws_ami.base.id"

    def test_data_values_come_from_the_context(self) -> None:
        class WithData(Module):
            def data_value(self, kind: str, name: str, attribute: str) -> Any:
                return "document" if (kind, name, attribute) == ("k", "n", "json") else NOT_BOUND

        assert evaluate_expression("data.k.n.json", WithData()) == "document"
        assert is_unknown(evaluate_expression("data.k.n.other", WithData()))

    def test_a_module_output_is_unknown_unless_the_context_has_it(self) -> None:
        assert unknown_reference(ev("module.net.subnet_ids")) == "module.net.subnet_ids"

    def test_a_module_output_comes_from_the_context(self) -> None:
        class WithOutput(Module):
            def module_output(self, module: str, output: str) -> Any:
                return ["a", "b"] if (module, output) == ("net", "ids") else Unknown()

        assert evaluate_expression("module.net.ids[1]", WithOutput()) == "b"


class TestTemplates:
    def test_a_template_of_known_parts_is_joined(self) -> None:
        assert evaluate_string("${var.a}-${var.b}", Module({"a": "x", "b": 2})) == "x-2"

    def test_a_lone_interpolation_keeps_its_type(self) -> None:
        assert evaluate_string("${var.n}", Module({"n": 3})) == 3
        assert evaluate_string("${var.flag}", Module({"flag": False})) is False
        assert evaluate_string("${var.items}", Module({"items": [1]})) == [1]

    def test_a_template_with_an_unknown_part_is_unknown(self) -> None:
        assert is_unknown(evaluate_string("${var.a}-x", Module()))

    def test_booleans_and_floats_in_a_template(self) -> None:
        values = Module({"b": True, "f": 2.0, "g": 2.5})
        assert evaluate_string("${var.b}/${var.f}/${var.g}", values) == "true/2/2.5"

    def test_null_and_collections_cannot_be_interpolated(self) -> None:
        assert is_unknown(evaluate_string("x-${var.n}", Module({"n": None})))
        assert is_unknown(evaluate_string("x-${var.l}", Module({"l": [1]})))

    def test_escaped_interpolation_text_is_literal(self) -> None:
        assert evaluate_string("$${var.a} and %%{x}") == "${var.a} and %{x}"

    def test_a_quoted_string_in_an_expression_decodes_its_escapes(self) -> None:
        assert evaluate_expression('"say \\"hi\\" \\\\ \\u00e9 \\n"') == 'say "hi" \\ é \n'

    def test_text_without_interpolation_is_a_literal(self) -> None:
        assert evaluate_string("just text") == "just text"

    def test_a_nested_template_inside_a_string_is_evaluated(self) -> None:
        assert evaluate_expression('"a ${"b ${var.c}"}"', Module({"c": "d"})) == "a b d"

    def test_json_text_is_canonicalized(self) -> None:
        assert evaluate_string('{"b": 1, "a": 2}') == '{"a":2,"b":1}'

    def test_a_template_directive_is_unknown(self) -> None:
        assert is_unknown(evaluate_string("%{ if true }a%{ endif }-${1}"))


class TestFunctions:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("jsonencode({b = 1, a = [true, null]})", '{"a":[true,null],"b":1}'),
            ("jsonencode([1, 2.0])", "[1,2]"),
            ('jsonencode("x")', '"x"'),
            ("merge({a = 1}, {b = 2}, {a = 3})", {"a": 3, "b": 2}),
            ("merge({a = 1}, null)", {"a": 1}),
            ("concat([1], [2, 3])", [1, 2, 3]),
            ('length("abc")', 3),
            ("length([1, 2])", 2),
            ("length({a = 1})", 1),
            ('lookup({a = 1}, "a")', 1),
            ('lookup({a = 1}, "b", 9)', 9),
            ("element([1, 2, 3], 4)", 2),
            ('join("-", ["a", 1, true])', "a-1-true"),
            ('lower("AbC")', "abc"),
            ('upper("AbC")', "ABC"),
            ("tostring(5)", "5"),
            ('tonumber("12")', 12),
            ('tonumber("1.5")', 1.5),
            ('tobool("true")', True),
            ("tolist([1, 2])", [1, 2]),
            ("toset([1, 1, 2])", [1, 2]),
            ("distinct([1, 1, 2])", [1, 2]),
            ("tomap({a = 1})", {"a": 1}),
            ("flatten([[1, [2]], 3])", [1, 2, 3]),
            ("keys({b = 1, a = 2})", ["a", "b"]),
            ("values({b = 1, a = 2})", [2, 1]),
            ('coalesce(null, "", "x")', "x"),
        ],
    )
    def test_evaluates(self, text: str, expected: Any) -> None:
        assert evaluate_expression(text) == expected

    @pytest.mark.parametrize(
        "text",
        [
            "length(5)",
            'lookup({a = 1}, "b")',
            "element([], 0)",
            'tonumber("x")',
            'tobool("maybe")',
            "tolist(5)",
            "merge(1)",
            "concat(1)",
            "flatten(1)",
            "keys(1)",
            "join(1, 2)",
            "unknown_function(1)",
            'file("/etc/passwd")',
            'templatefile("x", {})',
            'cidrsubnet("10.0.0.0/16", 8, 1)',
            "coalesce(var.x, 1)",
        ],
    )
    def test_an_unsupported_or_failing_call_is_unknown(self, text: str) -> None:
        assert is_unknown(ev(text))

    def test_a_function_over_an_unknown_argument_is_unknown(self) -> None:
        assert is_unknown(ev("length(var.items)"))
        assert is_unknown(ev("concat(var.items, [1])"))

    def test_jsonencode_writes_an_unknown_leaf_as_the_placeholder(self) -> None:
        value = ev("jsonencode({a = var.x, b = 1})")
        assert value == f'{{"a":"{UNKNOWN_TEXT}","b":1}}'

    def test_jsonencode_of_an_unknown_value_is_unknown(self) -> None:
        assert is_unknown(ev("jsonencode(var.x)"))

    def test_jsonencode_keeps_text_around_an_unresolved_part(self) -> None:
        value = ev('jsonencode({r = "arn:${var.partition}:s3:::b/*"})')
        assert value == f'{{"r":"arn:{UNKNOWN_TEXT}:s3:::b/*"}}'

    def test_a_template_outside_jsonencode_with_an_unresolved_part_is_unknown(self) -> None:
        assert is_unknown(ev('"arn:${var.partition}:s3:::b/*"'))

    def test_expressions_are_never_executed(self) -> None:
        for text in (
            "__import__('os').system('echo pwned')",
            "().__class__.__bases__",
            "var.__class__",
            "open('/etc/passwd')",
        ):
            assert is_unknown(ev(text)), text


class TestForExpressionsAndUnparsable:
    def test_a_for_expression_is_unknown(self) -> None:
        assert is_unknown(ev("[for p in var.ports : p * 2]"))
        assert is_unknown(ev("{for k, v in var.m : k => v if v != null}"))
        assert is_unknown(ev("{for k, v in var.m : v => k...}"))

    def test_text_that_is_not_an_expression_is_unknown_with_its_text(self) -> None:
        value = evaluate_expression("1 +")
        assert unknown_reference(value) == "1 +"

    def test_an_expanding_call_is_unknown(self) -> None:
        assert is_unknown(ev("concat(var.lists...)"))

    def test_the_object_separator_may_be_a_newline(self) -> None:
        assert evaluate_expression("{a = 1\n b = 2}") == {"a": 1, "b": 2}

    def test_parse_expression_rejects_garbage(self) -> None:
        for text in ("", "1 2", ")", "a.", "a[", "{a}", "[for]", "f(", "@"):
            with pytest.raises(ExpressionError):
                parse_expression(text)

    def test_parse_template_of_plain_text(self) -> None:
        node = parse_template("hello")
        assert node == _hcl_eval.Lit("hello")

    def test_an_unterminated_string_is_an_error(self) -> None:
        with pytest.raises(ExpressionError):
            parse_expression('"open')


class TestLimits:
    def test_a_long_expression_is_unknown(self) -> None:
        text = "1" + " + 1" * (_hcl_eval.MAX_EXPRESSION_LENGTH // 4 + 10)
        assert is_unknown(evaluate_expression(text))

    def test_deep_parentheses_are_unknown_not_a_crash(self) -> None:
        depth = _hcl_eval.MAX_DEPTH * 3
        assert is_unknown(evaluate_expression("(" * depth + "1" + ")" * depth))

    def test_deep_unary_operators_are_unknown_not_a_crash(self) -> None:
        assert is_unknown(evaluate_expression("!" * 500 + "true"))

    def test_deep_nested_templates_are_unknown_not_a_crash(self) -> None:
        text = "1"
        for _ in range(_hcl_eval.MAX_DEPTH * 2):
            text = f'"${{{text}}}"'
        assert is_unknown(evaluate_expression(text)) or evaluate_expression(text) == 1

    def test_deep_lists_are_unknown_not_a_crash(self) -> None:
        depth = _hcl_eval.MAX_DEPTH * 3
        assert is_unknown(evaluate_expression("[" * depth + "]" * depth))

    def test_a_very_large_token_count_is_unknown(self) -> None:
        text = "[" + ", ".join(["1"] * (_hcl_eval.MAX_TOKENS + 10)) + "]"
        assert is_unknown(evaluate_expression(text))

    def test_pathological_text_is_fast(self) -> None:
        started = time.monotonic()
        evaluate_expression("a" * 15000)
        evaluate_expression("1" + " + 1" * 4000)
        string_references("${" + "a." * 5000 + "b}")
        assert time.monotonic() - started < 5

    def test_deeply_nested_values_are_unknown_past_the_limit(self) -> None:
        value: Any = "x"
        for _ in range(_hcl_eval.MAX_DEPTH * 5):
            value = [value]
        result = evaluate_value(value)
        node = result
        while isinstance(node, list):
            node = node[0]
        assert is_unknown(node)

    def test_the_parse_cache_is_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(_hcl_eval, "_MAX_CACHE", 5)
        for i in range(20):
            evaluate_expression(f"{i} + 1")
        assert len(_hcl_eval._PARSE_CACHE) <= 5


class TestEvaluateValue:
    def test_containers_and_scalars(self) -> None:
        raw = {"a": ["${var.n}", 2, None, True], "b": {"c": "${1 + 1}"}}
        assert evaluate_value(raw, Module({"n": 7})) == {"a": [7, 2, None, True], "b": {"c": 2}}

    def test_dictionary_keys_are_kept_as_written(self) -> None:
        assert evaluate_value({"${odd}": 1}) == {"${odd}": 1}

    def test_the_same_template_evaluates_the_same_each_time(self) -> None:
        module = Module({"a": 1})
        assert evaluate_string("x${var.a}", module) == evaluate_string("x${var.a}", module) == "x1"


class TestReferenceScanning:
    RESOURCES = {
        ("aws_subnet", "a"),
        ("aws_subnet", "private"),
        ("aws_security_group", "web"),
        ("aws_vpc", "main"),
        ("aws_instance", "app"),
    }

    def refs(self, text: str, **kw: Any) -> list[str]:
        return string_references(text, Module(resources=self.RESOURCES, **kw))

    def test_a_plain_traversal(self) -> None:
        assert self.refs("${aws_vpc.main.id}") == ["aws_vpc.main.id"]

    def test_indexes_and_splats_are_dropped(self) -> None:
        assert self.refs("${aws_subnet.private[count.index].id}") == ["aws_subnet.private.id"]
        assert self.refs("${aws_subnet.private[*].id}") == ["aws_subnet.private.id"]
        assert self.refs("${aws_subnet.private.*.id}") == ["aws_subnet.private.id"]
        assert self.refs("${aws_subnet.private[0].id}") == ["aws_subnet.private.id"]
        assert self.refs('${aws_subnet.private["x y"].id}') == ["aws_subnet.private.id"]
        assert self.refs("${aws_subnet.private.0.id}") == ["aws_subnet.private.id"]

    def test_a_reference_in_an_index_is_found(self) -> None:
        refs = self.refs("${aws_subnet.private[length(aws_vpc.main.tags)].id}")
        assert refs == ["aws_subnet.private.id", "aws_vpc.main.tags"]

    def test_references_inside_function_calls(self) -> None:
        refs = self.refs("${concat([aws_security_group.web.id], [aws_vpc.main.id])}")
        assert refs == ["aws_security_group.web.id", "aws_vpc.main.id"]
        assert self.refs("${element(aws_subnet.private[*].id, 0)}") == ["aws_subnet.private.id"]

    def test_both_branches_of_a_conditional(self) -> None:
        refs = self.refs("${var.x ? aws_subnet.a.id : aws_subnet.private[0].id}")
        assert refs == ["aws_subnet.a.id", "aws_subnet.private.id"]

    def test_for_expressions_are_scanned_and_the_iterator_is_skipped(self) -> None:
        refs = self.refs("${[for s in aws_subnet.private : s.id if s.cidr != aws_vpc.main.id]}")
        assert refs == ["aws_subnet.private", "aws_vpc.main.id"]

    def test_an_iterator_with_the_name_of_a_resource_type_is_still_skipped(self) -> None:
        refs = self.refs("${{for aws_subnet in aws_vpc.main.subnets : aws_subnet.name => 1}}")
        assert refs == ["aws_vpc.main.subnets"]

    def test_a_two_variable_for_expression(self) -> None:
        refs = self.refs("${{for k, v in aws_vpc.main.tags : k => v.x}}")
        assert refs == ["aws_vpc.main.tags"]

    def test_references_inside_a_template(self) -> None:
        refs = self.refs("prefix-${aws_vpc.main.id}-${aws_subnet.a.id}")
        assert refs == ["aws_vpc.main.id", "aws_subnet.a.id"]

    def test_references_inside_a_nested_string(self) -> None:
        refs = self.refs('${join(",", ["x-${aws_vpc.main.id}"])}')
        assert refs == ["aws_vpc.main.id"]

    def test_references_in_objects_and_lists(self) -> None:
        refs = self.refs("${{a = aws_vpc.main.id, b = [aws_subnet.a.id]}}")
        assert refs == ["aws_vpc.main.id", "aws_subnet.a.id"]

    def test_object_keys_are_not_references(self) -> None:
        assert self.refs("${{aws_vpc = 1, main = 2}}") == []

    @pytest.mark.parametrize(
        "text",
        [
            "${each.value}",
            "${each.key}",
            "${count.index}",
            "${self.id}",
            "${path.module}",
            "${terraform.workspace}",
            "${var.aws_vpc}",
            "${local.aws_vpc}",
            "${aws_vpc.other.id}",
            "${aws_vpc}",
            '${lower("aws_vpc.main")}',
            '${"aws_vpc.main.id"}',
            "plain aws_vpc.main.id text",
            "",
        ],
    )
    def test_these_are_not_references(self, text: str) -> None:
        assert self.refs(text) == []

    def test_a_function_named_like_a_resource_is_not_a_reference(self) -> None:
        assert self.refs("${aws_vpc(1)}") == []

    def test_an_attribute_after_a_function_call_is_not_a_reference(self) -> None:
        assert self.refs("${merge(a, b).aws_vpc}") == []

    def test_variables_and_locals_contribute_what_they_refer_to(self) -> None:
        refs = string_references(
            "${var.subnet}-${local.group}-${var.plain}",
            Module(variables={"subnet": "x"}, locals_={"group": "y"}),
        )
        assert refs == ["from-var:subnet", "from-local:group"]

    def test_a_module_output_contributes_what_the_module_names(self) -> None:
        module = Module(modules={"net.ids": ["module.net.aws_subnet.this.id"]})
        assert string_references("${module.net.ids}", module) == ["module.net.aws_subnet.this.id"]
        assert string_references("${module.net}", module) == []
        assert string_references("${module.other.ids}", module) == []

    def test_a_data_source_reference_keeps_its_attribute(self) -> None:
        module = Module(data={("aws_ami", "base")})
        assert string_references("${data.aws_ami.base.id}", module) == ["data.aws_ami.base.id"]
        assert string_references("${data.aws_ami.other.id}", module) == []

    def test_the_context_qualifies_references(self) -> None:
        module = Module(resources={("aws_vpc", "main")}, prefix="module.n.")
        assert string_references("${aws_vpc.main.id}", module) == ["module.n.aws_vpc.main.id"]

    def test_repeats_are_removed_and_order_is_kept(self) -> None:
        refs = self.refs("${aws_vpc.main.id}${aws_subnet.a.id}${aws_vpc.main.id}")
        assert refs == ["aws_vpc.main.id", "aws_subnet.a.id"]

    def test_python_literals_do_not_confuse_the_scan(self) -> None:
        assert self.refs("${var.x ? True : aws_vpc.main.id}") == ["aws_vpc.main.id"]

    def test_garbage_has_no_references_and_does_not_raise(self) -> None:
        assert self.refs("${@@@ aws_vpc.main.id}") == []
        assert self.refs("${unterminated aws_vpc.main.id") in ([], ["aws_vpc.main.id"])

    def test_a_directive_condition_is_scanned(self) -> None:
        refs = self.refs("%{ if aws_vpc.main.enable }yes%{ endif }")
        assert refs == ["aws_vpc.main.enable"]
