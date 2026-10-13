"""The fallback Helm renderer: scanning, parsing and evaluating the Go template subset charts use.

Templates are rendered through ``render_chart`` on throwaway charts, so these tests cover the
same path a scan takes: reading ``Chart.yaml`` and ``values.yaml``, collecting ``define`` blocks,
evaluating and tracking where each output line came from.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Any

import pytest
import yaml

from threatcode.parsers import _helm_render as hr
from threatcode.parsers._helm_render import (
    MISSING,
    UNKNOWN,
    ChartRender,
    ValuesDict,
    _TemplateError,
    parse_template,
    render_chart,
    tokenize,
)

# ---------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------


def make_chart(
    root: Path,
    templates: dict[str, str],
    values: dict[str, Any] | str | None = None,
    chart: dict[str, Any] | None = None,
    name: str = "demo",
) -> Path:
    """Write a chart under ``root`` and return its directory."""
    directory = root / name
    (directory / "templates").mkdir(parents=True, exist_ok=True)
    meta = {"apiVersion": "v2", "name": name, "version": "1.2.3", "appVersion": "4.5.6"}
    meta.update(chart or {})
    (directory / "Chart.yaml").write_text(yaml.safe_dump(meta), encoding="utf-8")
    if values is not None:
        text = values if isinstance(values, str) else yaml.safe_dump(values)
        (directory / "values.yaml").write_text(text, encoding="utf-8")
    for relative, body in templates.items():
        target = directory / "templates" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    return directory


def render_all(
    root: Path,
    templates: dict[str, str],
    values: dict[str, Any] | str | None = None,
    **kwargs: Any,
) -> ChartRender:
    return render_chart(make_chart(root, templates, values, **kwargs))


def render(
    tmp_path: Path, source: str, values: dict[str, Any] | str | None = None, **kwargs: Any
) -> str:
    """The output of one template named ``t.yaml``."""
    result = render_all(tmp_path, {"t.yaml": source}, values, **kwargs)
    assert not result.aborted, result.warnings
    return "\n".join(f.text for f in result.files) if result.files else ""


def expr(tmp_path: Path, expression: str, values: dict[str, Any] | None = None) -> str:
    """Evaluate one ``{{ expression }}`` and return what it prints."""
    return render(tmp_path, "{{ " + expression + " }}", values)


# ---------------------------------------------------------------------------------------
# The scanner
# ---------------------------------------------------------------------------------------


class TestTokenizer:
    def test_text_and_actions_alternate(self) -> None:
        tokens = tokenize("a {{ .X }} b {{ .Y }} c")
        assert [(t.kind, t.text) for t in tokens] == [
            ("text", "a "),
            ("action", ".X"),
            ("text", " b "),
            ("action", ".Y"),
            ("text", " c"),
        ]

    def test_a_left_trim_marker_removes_the_whitespace_before_the_action(self) -> None:
        tokens = tokenize("a  \n  {{- .X }}b")
        assert [t.text for t in tokens] == ["a", ".X", "b"]

    def test_a_right_trim_marker_removes_the_whitespace_after_the_action(self) -> None:
        tokens = tokenize("a{{ .X -}}  \n  b")
        assert [t.text for t in tokens] == ["a", ".X", "b"]

    def test_both_markers_together(self) -> None:
        tokens = tokenize("a \n{{- .X -}}\n b")
        assert [t.text for t in tokens] == ["a", ".X", "b"]

    def test_a_dash_without_a_space_is_not_a_trim_marker(self) -> None:
        tokens = tokenize("a {{-3}} b")
        assert [t.text for t in tokens] == ["a ", "-3", " b"]

    def test_text_that_trims_to_nothing_is_dropped(self) -> None:
        tokens = tokenize("{{ .A -}}   \n  {{- .B }}")
        assert [t.text for t in tokens] == [".A", ".B"]

    def test_comments_are_actions_that_are_ignored(self) -> None:
        tokens = tokenize("a{{/* hello }} there */}}b{{- /* x */ -}} c")
        assert [t.kind for t in tokens] == ["text", "action", "text", "action", "text"]
        assert tokens[1].text.startswith("/*")
        assert [t.text for t in tokens if t.kind == "text"] == ["a", "b", "c"]

    def test_a_closing_brace_pair_inside_a_string_does_not_end_the_action(self) -> None:
        tokens = tokenize('{{ "}}" }}x{{ `}}` }}')
        assert [t.text for t in tokens] == ['"}}"', "x", "`}}`"]

    def test_an_escaped_quote_inside_a_string(self) -> None:
        tokens = tokenize(r'{{ "a\"}}b" }}')
        assert len(tokens) == 1
        assert tokens[0].text == r'"a\"}}b"'

    def test_lines_are_counted(self) -> None:
        tokens = tokenize("a\nb\n{{ .X }}\nc\n{{ .Y }}")
        assert [(t.kind, t.line) for t in tokens] == [
            ("text", 1),
            ("action", 3),
            ("text", 3),
            ("action", 5),
        ]

    def test_an_unterminated_action_ends_the_scan_and_keeps_the_rest_as_text(self) -> None:
        tokens = tokenize("before {{ .X }} middle {{ .Y after")
        assert [(t.kind, t.text) for t in tokens] == [
            ("text", "before "),
            ("action", ".X"),
            ("text", " middle "),
            ("text", "(( .Y after"),
        ]

    def test_leftover_double_braces_are_defused(self) -> None:
        tokens = tokenize("{{" * 1000)
        assert len(tokens) == 1
        assert "{" not in tokens[0].text
        assert tokens[0].text == "((" * 1000

    def test_an_unterminated_string_ends_the_scan(self) -> None:
        tokens = tokenize('a {{ "oops }} b')
        assert tokens[-1].text.startswith("((")

    def test_an_unterminated_comment_ends_the_scan(self) -> None:
        tokens = tokenize("a {{/* never closed }} b")
        assert tokens[-1].kind == "text"

    def test_text_without_actions(self) -> None:
        assert [t.text for t in tokenize("plain: text\n")] == ["plain: text\n"]
        assert tokenize("") == []

    def test_a_million_openers_cost_linear_time(self) -> None:
        started = time.monotonic()
        tokenize("{{" * 500_000)
        tokenize("{{ if .Values.enabled " * 20_000)
        tokenize("{{-" + " " * 400_000)
        assert time.monotonic() - started < 3

    def test_many_complete_actions_cost_linear_time(self) -> None:
        started = time.monotonic()
        tokens = tokenize("{{ .X }}" * 100_000)
        assert len(tokens) == 100_000
        assert time.monotonic() - started < 3


# ---------------------------------------------------------------------------------------
# The parser
# ---------------------------------------------------------------------------------------


class TestParser:
    def test_blocks_nest(self) -> None:
        parsed = parse_template(
            tokenize("{{ if .A }}{{ range .B }}{{ with .C }}x{{ end }}{{ end }}{{ end }}")
        )
        assert len(parsed.nodes) == 1
        assert isinstance(parsed.nodes[0], hr.IfNode)

    def test_else_if_chains_become_branches(self) -> None:
        parsed = parse_template(
            tokenize("{{ if .A }}a{{ else if .B }}b{{ else if .C }}c{{ else }}d{{ end }}")
        )
        (node,) = parsed.nodes
        assert isinstance(node, hr.IfNode)
        assert len(node.branches) == 3
        assert [n.text for n in node.otherwise if isinstance(n, hr.TextNode)] == ["d"]

    def test_defines_are_collected_by_name(self) -> None:
        parsed = parse_template(tokenize('{{ define "a.b" }}x{{ end }}{{ define "c" }}y{{ end }}'))
        assert sorted(parsed.defines) == ["a.b", "c"]
        assert parsed.nodes == []

    def test_a_block_defines_and_calls(self) -> None:
        parsed = parse_template(tokenize('{{ block "b" . }}default{{ end }}'))
        assert "b" in parsed.defines
        assert isinstance(parsed.nodes[0], hr.TemplateNode)

    @pytest.mark.parametrize(
        "source",
        [
            "{{ if .A }}never closed",
            "{{ end }}",
            "{{ else }}",
            "{{ if .A }}{{ else }}{{ else }}{{ end }}",
            "{{ range .A }}{{ else if .B }}{{ end }}",
            '{{ if .A }}{{ define "x" }}{{ end }}{{ end }}',
            "{{ ( }}",
            "{{ .A | }}",
            "{{ template x }}",
            "{{ .A ) }}",
            "{{ @ }}",
        ],
    )
    def test_malformed_templates_raise(self, source: str) -> None:
        with pytest.raises(_TemplateError):
            parse_template(tokenize(source))

    def test_a_deeply_nested_template_is_refused(self) -> None:
        source = "{{ if .A }}" * 200 + "x" + "{{ end }}" * 200
        with pytest.raises(_TemplateError, match="nested too deeply"):
            parse_template(tokenize(source))

    def test_an_action_over_the_length_cap_is_refused(self) -> None:
        with pytest.raises(_TemplateError, match="too long"):
            parse_template(tokenize("{{ " + "a " * 10_000 + "}}"))

    def test_keywords_need_a_word_boundary(self) -> None:
        parsed = parse_template(tokenize("{{ endpoint }}{{ iffy }}{{ without }}"))
        assert len(parsed.nodes) == 3
        assert all(isinstance(n, hr.ActionNode) for n in parsed.nodes)

    def test_variable_declarations_and_assignments_parse(self) -> None:
        parsed = parse_template(
            tokenize("{{ $x := 1 }}{{ $x = 2 }}{{ range $i, $e := .L }}{{ end }}")
        )
        assert len(parsed.nodes) == 3

    def test_expressions(self) -> None:
        pipeline = hr.parse_expression('default "x" (.Values.a | upper) | quote')
        assert len(pipeline.commands) == 2
        head = pipeline.commands[0].terms
        assert isinstance(head[0], hr.Func) and head[0].name == "default"
        assert isinstance(head[2], hr.Sub)

    def test_field_chains_after_variables_and_parentheses(self) -> None:
        var = hr.parse_expression("$x.a.b").commands[0].terms[0]
        assert isinstance(var, hr.VarRef) and var.chain == ("a", "b")
        sub = hr.parse_expression("(index .L 0).name").commands[0].terms[0]
        assert isinstance(sub, hr.Sub) and sub.chain == ("name",)

    def test_a_field_after_whitespace_is_an_argument_not_a_chain(self) -> None:
        terms = hr.parse_expression("printf $x .a").commands[0].terms
        assert len(terms) == 3

    def test_string_escapes(self) -> None:
        term = hr.parse_expression(r'"a\nb\t\"c\\"').commands[0].terms[0]
        assert isinstance(term, hr.Lit) and term.value == 'a\nb\t"c\\'


# ---------------------------------------------------------------------------------------
# Lookups, literals and variables
# ---------------------------------------------------------------------------------------


class TestLookups:
    def test_values_chart_and_release(self, tmp_path: Path) -> None:
        out = render(
            tmp_path,
            "{{ .Values.a.b }}|{{ .Chart.Name }}|{{ .Chart.Version }}|{{ .Chart.AppVersion }}"
            "|{{ .Release.Name }}|{{ .Release.Namespace }}|{{ .Release.Service }}",
            {"a": {"b": "x"}},
        )
        assert out == "x|demo|1.2.3|4.5.6|release|default|Helm"

    def test_chart_fields_use_their_go_names(self, tmp_path: Path) -> None:
        out = render(
            tmp_path,
            "{{ .Chart.APIVersion }} {{ .Chart.Description }} {{ .Chart.Type }}",
            chart={"description": "d", "type": "application"},
        )
        assert out == "v2 d application"

    def test_numbers_booleans_and_nested_lists(self, tmp_path: Path) -> None:
        out = render(
            tmp_path,
            "{{ .Values.n }} {{ .Values.f }} {{ .Values.t }} {{ index .Values.l 1 }}",
            {"n": 80, "f": 0.5, "t": True, "l": ["a", "b"]},
        )
        assert out == "80 0.5 true b"

    def test_dot_and_root_variable(self, tmp_path: Path) -> None:
        out = render(
            tmp_path,
            "{{ with .Values.a }}{{ . }}-{{ $.Release.Name }}{{ end }}",
            {"a": "inner"},
        )
        assert out == "inner-release"

    def test_variables_declare_assign_and_scope(self, tmp_path: Path) -> None:
        out = render(
            tmp_path,
            '{{ $x := "a" }}{{ if true }}{{ $x = "b" }}{{ $y := "c" }}{{ end }}{{ $x }}'
            "{{ if true }}{{ $x }}{{ end }}",
        )
        assert out == "bb"

    def test_a_variable_declared_inside_a_block_is_gone_after_it(self, tmp_path: Path) -> None:
        out = render(tmp_path, '{{ if true }}{{ $y := "c" }}{{ end }}[{{ $y }}]')
        assert re.fullmatch(r"\[placeholder-templates-t-yaml-0-1\]", out)

    def test_variables_hold_whole_values(self, tmp_path: Path) -> None:
        out = render(tmp_path, "{{ $v := .Values.a }}{{ $v.b }}{{ $v.c }}", {"a": {"b": 1, "c": 2}})
        assert out == "12"

    def test_a_pipeline_into_a_variable(self, tmp_path: Path) -> None:
        out = render(tmp_path, "{{ $n := .Values.name | upper }}{{ $n }}", {"name": "abc"})
        assert out == "ABC"

    def test_comments_print_nothing(self, tmp_path: Path) -> None:
        assert render(tmp_path, "a{{/* c */}}b{{- /* d */ -}}c") == "abc"

    def test_a_raw_string_and_string_escapes(self, tmp_path: Path) -> None:
        assert expr(tmp_path, "`a\\nb`") == "a\\nb"
        assert expr(tmp_path, r'"a\tb"') == "a\tb"

    def test_a_literal_braces_escape(self, tmp_path: Path) -> None:
        assert render(tmp_path, '{{ "{{" }} .X {{ "}}" }}') == "{{ .X }}"

    def test_the_capabilities_object(self, tmp_path: Path) -> None:
        out = render(
            tmp_path,
            '{{ if .Capabilities.APIVersions.Has "apps/v1" }}yes{{ else }}no{{ end }}'
            "{{ .Capabilities.KubeVersion.Version }}",
        )
        assert out == "yesv1.30.0"

    def test_template_name_and_base_path(self, tmp_path: Path) -> None:
        out = render(tmp_path, "{{ .Template.Name }} {{ .Template.BasePath }}")
        assert out == "demo/templates/t.yaml demo/templates"


# ---------------------------------------------------------------------------------------
# Control flow
# ---------------------------------------------------------------------------------------


class TestControlFlow:
    @pytest.mark.parametrize(
        ("value", "branch"),
        [
            (True, "then"),
            (False, "else"),
            (0, "else"),
            (1, "then"),
            ("", "else"),
            ("x", "then"),
            ([], "else"),
            ([0], "then"),
            ({}, "else"),
            ({"a": 1}, "then"),
            (None, "else"),
        ],
    )
    def test_an_if_follows_go_truthiness(self, tmp_path: Path, value: Any, branch: str) -> None:
        out = render(tmp_path, "{{ if .Values.v }}then{{ else }}else{{ end }}", {"v": value})
        assert out == branch

    def test_else_if_takes_the_first_true_branch(self, tmp_path: Path) -> None:
        source = (
            "{{ if .Values.a }}A{{ else if .Values.b }}B{{ else if .Values.c }}C"
            "{{ else }}D{{ end }}"
        )
        assert render(tmp_path, source, {"a": 0, "b": 1, "c": 1}) == "B"
        assert render(tmp_path, source, {"a": 0, "b": 0, "c": 1}) == "C"
        assert render(tmp_path, source, {"a": 0, "b": 0, "c": 0}) == "D"
        assert render(tmp_path, source, {"a": 1, "b": 1, "c": 1}) == "A"

    def test_not_and_comparison_in_conditions(self, tmp_path: Path) -> None:
        source = (
            "{{ if not .Values.off }}a{{ end }}{{ if eq .Values.n 3 }}b{{ end }}"
            "{{ if gt .Values.n 2 }}c{{ end }}"
        )
        assert render(tmp_path, source, {"off": False, "n": 3}) == "abc"

    def test_a_with_rebinds_dot_and_skips_when_empty(self, tmp_path: Path) -> None:
        source = "{{ with .Values.a }}[{{ .x }}]{{ else }}none{{ end }}"
        assert render(tmp_path, source, {"a": {"x": 1}}) == "[1]"
        assert render(tmp_path, source, {"a": {}}) == "none"
        assert render(tmp_path, source, {}) == "none"

    def test_a_with_with_a_variable(self, tmp_path: Path) -> None:
        assert render(tmp_path, "{{ with $v := .Values.a }}{{ $v }}{{ end }}", {"a": "q"}) == "q"

    def test_range_over_a_list_of_scalars(self, tmp_path: Path) -> None:
        out = render(tmp_path, "{{ range .Values.l }}<{{ . }}>{{ end }}", {"l": [1, 2, 3]})
        assert out == "<1><2><3>"

    def test_range_over_a_list_of_mappings(self, tmp_path: Path) -> None:
        out = render(
            tmp_path,
            "{{ range .Values.hosts }}{{ .host }}:{{ range .paths }}{{ . }},{{ end }};{{ end }}",
            {"hosts": [{"host": "a", "paths": ["/x", "/y"]}, {"host": "b", "paths": []}]},
        )
        assert out == "a:/x,/y,;b:;"

    def test_range_over_a_map_visits_keys_in_sorted_order(self, tmp_path: Path) -> None:
        out = render(
            tmp_path,
            "{{ range $k, $v := .Values.m }}{{ $k }}={{ $v }};{{ end }}",
            {"m": {"b": 2, "a": 1, "c": 3}},
        )
        assert out == "a=1;b=2;c=3;"

    def test_range_with_an_index(self, tmp_path: Path) -> None:
        out = render(
            tmp_path, "{{ range $i, $e := .Values.l }}{{ $i }}{{ $e }}{{ end }}", {"l": ["x", "y"]}
        )
        assert out == "0x1y"

    def test_range_with_one_variable_binds_the_element(self, tmp_path: Path) -> None:
        out = render(tmp_path, "{{ range $e := .Values.l }}{{ $e }}{{ end }}", {"l": ["x", "y"]})
        assert out == "xy"

    def test_range_else_runs_for_an_empty_collection(self, tmp_path: Path) -> None:
        source = "{{ range .Values.l }}x{{ else }}empty{{ end }}"
        assert render(tmp_path, source, {"l": []}) == "empty"
        assert render(tmp_path, source, {}) == "empty"

    def test_range_over_an_integer(self, tmp_path: Path) -> None:
        assert render(tmp_path, "{{ range 3 }}x{{ end }}") == "xxx"

    def test_break_and_continue(self, tmp_path: Path) -> None:
        source = (
            "{{ range .Values.l }}{{ if eq . 2 }}{{ continue }}{{ end }}"
            "{{ if eq . 4 }}{{ break }}{{ end }}{{ . }}{{ end }}"
        )
        assert render(tmp_path, source, {"l": [1, 2, 3, 4, 5]}) == "13"

    def test_dot_is_restored_after_a_range(self, tmp_path: Path) -> None:
        out = render(tmp_path, "{{ range .Values.l }}{{ end }}{{ .Chart.Name }}", {"l": [1]})
        assert out == "demo"

    def test_dollar_reaches_the_root_inside_a_range(self, tmp_path: Path) -> None:
        out = render(
            tmp_path,
            "{{ range .Values.l }}{{ $.Values.sep }}{{ . }}{{ end }}",
            {"l": [1, 2], "sep": "-"},
        )
        assert out == "-1-2"

    def test_a_range_over_a_huge_integer_is_capped(self, tmp_path: Path) -> None:
        out = render(tmp_path, "{{ range 10000000000 }}x{{ end }}")
        assert len(out) == hr.MAX_RANGE_ITEMS

    def test_a_stray_break_falls_back_to_an_approximated_file(self, tmp_path: Path) -> None:
        result = render_all(tmp_path, {"t.yaml": "a: 1\n{{ break }}\nb: 2\n"})
        assert result.files[0].approximated is True


# ---------------------------------------------------------------------------------------
# Things the chart did not give a value for
# ---------------------------------------------------------------------------------------


class TestUnknownValues:
    def test_a_missing_value_prints_a_placeholder_token(self, tmp_path: Path) -> None:
        assert (
            render(tmp_path, "name: {{ .Values.gone }}") == "name: placeholder-templates-t-yaml-0-1"
        )

    def test_a_missing_value_is_false_in_a_condition(self, tmp_path: Path) -> None:
        assert render(tmp_path, "{{ if .Values.gone }}on{{ else }}off{{ end }}") == "off"
        assert render(tmp_path, "{{ if .Values.a.b.c }}on{{ else }}off{{ end }}") == "off"

    def test_a_missing_value_skips_with_and_range(self, tmp_path: Path) -> None:
        assert (
            render(tmp_path, "{{ with .Values.gone }}x{{ end }}{{ range .Values.gone }}y{{ end }}")
            == ""
        )

    def test_default_replaces_a_missing_value(self, tmp_path: Path) -> None:
        assert expr(tmp_path, 'default "fallback" .Values.gone') == "fallback"
        assert expr(tmp_path, '.Values.gone | default "fallback"') == "fallback"

    def test_an_unknown_function_is_unknown_and_true_in_a_condition(self, tmp_path: Path) -> None:
        assert render(tmp_path, "{{ if somethingUnheardOf 1 }}on{{ else }}off{{ end }}") == "on"

    def test_files_are_unknown(self, tmp_path: Path) -> None:
        out = render(tmp_path, '{{ .Files.Get "x" }}')
        assert out.startswith("placeholder-")

    def test_random_values_are_unknown(self, tmp_path: Path) -> None:
        assert expr(tmp_path, "randAlphaNum 8").startswith("placeholder-")

    def test_with_and_range_over_an_unknown_value_run_their_body_once(self, tmp_path: Path) -> None:
        out = render(
            tmp_path, "{{ with randAlphaNum 5 }}[w]{{ end }}{{ range randAlphaNum 5 }}[r]{{ end }}"
        )
        assert out == "[w][r]"

    def test_the_same_expression_prints_the_same_token_in_one_document(
        self, tmp_path: Path
    ) -> None:
        out = render(tmp_path, "{{ .Values.a }} {{ .Values.b }} {{ .Values.a }}")
        first, second, third = out.split()
        assert first == third
        assert first != second
        assert (first, second) == (
            "placeholder-templates-t-yaml-0-1",
            "placeholder-templates-t-yaml-0-2",
        )

    def test_whitespace_in_an_expression_does_not_change_its_token(self, tmp_path: Path) -> None:
        out = render(tmp_path, "{{ .Values.a }} {{.Values.a}} {{   .Values.a   }}")
        assert len(set(out.split())) == 1

    def test_each_document_numbers_its_own_tokens(self, tmp_path: Path) -> None:
        out = render(tmp_path, "{{ .Values.a }}\n---\n{{ .Values.a }}\n---\n{{ .Values.b }}\n")
        tokens = [line for line in out.splitlines() if line.startswith("placeholder")]
        assert tokens == [
            "placeholder-templates-t-yaml-0-1",
            "placeholder-templates-t-yaml-1-1",
            "placeholder-templates-t-yaml-2-1",
        ]

    def test_a_leading_separator_does_not_start_a_new_document(self, tmp_path: Path) -> None:
        out = render(tmp_path, "---\n{{ .Values.a }}\n")
        assert "placeholder-templates-t-yaml-0-1" in out

    def test_two_templates_never_share_a_token(self, tmp_path: Path) -> None:
        result = render_all(
            tmp_path, {"one.yaml": "n: {{ .Values.a }}\n", "sub/two.yaml": "n: {{ .Values.a }}\n"}
        )
        texts = {f.path: f.text.strip() for f in result.files}
        assert texts["templates/one.yaml"] == "n: placeholder-templates-one-yaml-0-1"
        assert texts["templates/sub/two.yaml"] == "n: placeholder-templates-sub-two-yaml-0-1"

    def test_two_deployments_named_from_different_values_get_different_names(
        self, tmp_path: Path
    ) -> None:
        source = (
            "kind: Deployment\nmetadata:\n  name: {{ .Values.web.name }}\n---\n"
            "kind: Deployment\nmetadata:\n  name: {{ .Values.worker.name }}\n"
        )
        docs = list(yaml.safe_load_all(render(tmp_path, source)))
        names = [d["metadata"]["name"] for d in docs]
        assert len(set(names)) == 2
        assert all(n.startswith("placeholder-") for n in names)

    def test_quote_of_an_unknown_value_is_a_quoted_token(self, tmp_path: Path) -> None:
        assert expr(tmp_path, ".Values.gone | quote") == '"placeholder-templates-t-yaml-0-1"'

    def test_nindent_of_an_unknown_value_keeps_the_indentation(self, tmp_path: Path) -> None:
        out = render(tmp_path, "a:\n  {{- .Values.gone | nindent 4 }}\nb: 1\n")
        assert out == "a:\n    placeholder-templates-t-yaml-0-1\nb: 1\n"
        assert yaml.safe_load(out) == {"a": "placeholder-templates-t-yaml-0-1", "b": 1}

    def test_toyaml_of_a_missing_value_is_null(self, tmp_path: Path) -> None:
        assert render(tmp_path, "a: {{ toYaml .Values.gone }}") == "a: null"

    def test_the_token_prefix_is_the_shared_marker(self) -> None:
        from threatcode.parsers._k8s_security import PLACEHOLDER_PREFIX

        assert hr.PLACEHOLDER_PREFIX == PLACEHOLDER_PREFIX == "placeholder-"

    def test_holes_are_distinct_and_have_truthiness(self) -> None:
        assert UNKNOWN is not MISSING
        assert bool(UNKNOWN) is True
        assert bool(MISSING) is False
        assert hr.is_hole(UNKNOWN) and hr.is_hole(MISSING) and not hr.is_hole(None)

    def test_values_dicts_know_their_missing_keys_and_plain_dicts_do_not(
        self, tmp_path: Path
    ) -> None:
        # a mapping built by the template is plain: a missing key is nil, which is empty
        out = render(tmp_path, '{{ $d := dict "a" 1 }}{{ if $d.nothing }}x{{ else }}nil{{ end }}')
        assert out == "nil"
        assert isinstance(hr.to_values({"a": {"b": 1}}), ValuesDict)


# ---------------------------------------------------------------------------------------
# Functions
# ---------------------------------------------------------------------------------------


class TestFunctions:
    @pytest.mark.parametrize(
        ("expression", "expected"),
        [
            # logic
            ('default "x" ""', "x"),
            ('default "x" 0', "x"),
            ('default "x" "y"', "y"),
            ('default "x" false', "x"),
            ('default "x" (list)', "x"),
            ("empty 0", "true"),
            ('empty "a"', "false"),
            ('ternary "a" "b" true', "a"),
            ('ternary "a" "b" false', "b"),
            ('coalesce "" 0 "z" "y"', "z"),
            ('and true "x"', "x"),
            ('and "" "x"', ""),
            ('or "" "y"', "y"),
            ('or "a" "y"', "a"),
            ("not 0", "true"),
            ("not 1", "false"),
            ("eq 1 1", "true"),
            ('eq "a" "b" "a"', "true"),
            ('eq "a" "b"', "false"),
            ("ne 1 2", "true"),
            ("lt 1 2", "true"),
            ("le 2 2", "true"),
            ("gt 3 2", "true"),
            ("ge 1 2", "false"),
            ('lt "a" "b"', "true"),
            ("eq true 1", "false"),
            ('kindIs "string" "x"', "true"),
            ('kindIs "int" "x"', "false"),
            ("typeOf 1", "int"),
            ('semverCompare ">=1.19-0" "v1.2.3"', "true"),
            # strings
            ('upper "abc"', "ABC"),
            ('lower "ABC"', "abc"),
            ('title "hello world"', "Hello World"),
            ('trim "  a  "', "a"),
            ('trimAll "$" "$5.00$"', "5.00"),
            ('trimPrefix "ab" "abc"', "c"),
            ('trimSuffix "-" "abc-"', "abc"),
            ('trimSuffix "-" "abc"', "abc"),
            ('trunc 3 "abcdef"', "abc"),
            ('trunc -3 "abcdef"', "def"),
            ('trunc 63 "short"', "short"),
            ('substr 1 3 "abcdef"', "bc"),
            ('replace "+" "_" "a+b+c"', "a_b_c"),
            ('contains "bc" "abcd"', "true"),
            ('contains "x" "abcd"', "false"),
            ('hasPrefix "ab" "abc"', "true"),
            ('hasSuffix "bc" "abc"', "true"),
            ('repeat 3 "ab"', "ababab"),
            ('nospace "a b  c"', "abc"),
            ('abbrev 6 "abcdefghij"', "abc..."),
            ('cat "a" "b" 1', "a b 1"),
            ('print "a" 1 "b"', "a1b"),
            ('kebabcase "FirstName"', "first-name"),
            ('snakecase "FirstName"', "first_name"),
            ('camelcase "http_server"', "HttpServer"),
            ('quote "a" "b"', '"a" "b"'),
            ('squote "a"', "'a'"),
            ('quote "say \\"hi\\""', '"say \\"hi\\""'),
            ('b64enc "hello"', "aGVsbG8="),
            ('b64dec "aGVsbG8="', "hello"),
            ('sha256sum "a"', "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),
            ("toString 5", "5"),
            # printf
            ('printf "%s-%s" "a" "b"', "a-b"),
            ('printf "%d items" 5', "5 items"),
            ('printf "%5s|%-5s|" "a" "b"', "    a|b    |"),
            ('printf "%05d" 42', "00042"),
            ('printf "%q" "a"', '"a"'),
            ('printf "%t" true', "true"),
            ('printf "%.2f" 3.14159', "3.14"),
            ('printf "100%%"', "100%"),
            ('printf "%v" (list "a" "b")', "[a b]"),
            # numbers
            ("add 1 2 3", "6"),
            ("add1 4", "5"),
            ("sub 5 2", "3"),
            ("mul 2 3", "6"),
            ("div 7 2", "3"),
            ("mod 7 2", "1"),
            ("max 1 5 3", "5"),
            ("min 4 2 8", "2"),
            ('int "42"', "42"),
            ('int "oops"', "0"),
            ('atoi "7"', "7"),
            # collections
            ("len (list 1 2 3)", "3"),
            ('len "abc"', "3"),
            ("index (list 1 2 3) 1", "2"),
            ('index (dict "a" 1) "a"', "1"),
            ('hasKey (dict "a" 1) "a"', "true"),
            ('hasKey (dict "a" 1) "b"', "false"),
            ('get (dict "a" 1) "a"', "1"),
            ('get (dict "a" 1) "b"', ""),
            ('list 1 2 | join ","', "1,2"),
            ('splitList "," "a,b,c" | last', "c"),
            ('splitList "," "a,b,c" | first', "a"),
            ('list 1 2 3 | rest | join ","', "2,3"),
            ('list 1 2 3 | initial | join ","', "1,2"),
            ('append (list 1) 2 | join ","', "1,2"),
            ('prepend (list 2) 1 | join ","', "1,2"),
            ('concat (list 1) (list 2 3) | join ","', "1,2,3"),
            ('uniq (list 1 1 2) | join ","', "1,2"),
            ('without (list 1 2 3) 2 | join ","', "1,3"),
            ("has 2 (list 1 2)", "true"),
            ('sortAlpha (list "b" "a") | join ","', "a,b"),
            ('reverse (list 1 2) | join ","', "2,1"),
            ('keys (dict "b" 1 "a" 2) | join ","', "a,b"),
            ('pick (dict "a" 1 "b" 2) "a" | toJson', '{"a": 1}'),
            ('omit (dict "a" 1 "b" 2) "a" | toJson', '{"b": 2}'),
            ('merge (dict "a" 1) (dict "a" 2 "b" 3) | toJson', '{"a": 1, "b": 3}'),
            ('mergeOverwrite (dict "a" 1) (dict "a" 2) | toJson', '{"a": 2}'),
            ('list 1 "a" | toJson', '[1, "a"]'),
            ('fromJson "{\\"a\\": 1}" | toJson', '{"a": 1}'),
            ('(fromYaml "a: 1").a', "1"),
            ('set (dict "a" 1) "b" 2 | toJson', '{"a": 1, "b": 2}'),
        ],
    )
    def test_function(self, tmp_path: Path, expression: str, expected: str) -> None:
        assert expr(tmp_path, expression) == expected

    def test_indent_and_nindent(self, tmp_path: Path) -> None:
        assert expr(tmp_path, 'indent 2 "a\\nb"') == "  a\n  b"
        assert expr(tmp_path, 'nindent 2 "a\\nb"') == "\n  a\n  b"
        assert expr(tmp_path, 'nindent 0 "a"') == "\na"

    def test_toyaml_of_structures(self, tmp_path: Path) -> None:
        out = expr(tmp_path, "toYaml .Values.m", {"m": {"b": [1, 2], "a": {"x": "y"}}})
        assert yaml.safe_load(out) == {"a": {"x": "y"}, "b": [1, 2]}
        assert out.splitlines()[0] == "a:"  # keys are sorted

    def test_toyaml_of_empty_values(self, tmp_path: Path) -> None:
        assert expr(tmp_path, "toYaml .Values.m", {"m": {}}) == "{}"
        assert expr(tmp_path, "toYaml .Values.m", {"m": []}) == "[]"

    def test_toyaml_of_scalars(self, tmp_path: Path) -> None:
        assert expr(tmp_path, "toYaml .Values.s", {"s": "text"}) == "text"
        assert expr(tmp_path, "toYaml .Values.s", {"s": 5}) == "5"
        assert expr(tmp_path, "toYaml .Values.s", {"s": True}) == "true"

    def test_toyaml_nindent_builds_a_valid_nested_mapping(self, tmp_path: Path) -> None:
        source = "spec:\n  {{- toYaml .Values.sc | nindent 2 }}\nother: 1\n"
        out = render(tmp_path, source, {"sc": {"runAsNonRoot": True, "caps": {"drop": ["ALL"]}}})
        assert yaml.safe_load(out) == {
            "spec": {"runAsNonRoot": True, "caps": {"drop": ["ALL"]}},
            "other": 1,
        }

    def test_toyaml_does_not_use_anchors(self, tmp_path: Path) -> None:
        values = "base: &b {a: 1}\nm:\n  x: *b\n  y: *b\n"
        out = expr(tmp_path, "toYaml .Values.m", values)  # type: ignore[arg-type]
        assert "&" not in out and "*" not in out
        assert yaml.safe_load(out) == {"x": {"a": 1}, "y": {"a": 1}}

    def test_a_function_that_fails_on_its_arguments_is_unknown(self, tmp_path: Path) -> None:
        assert expr(tmp_path, "index (list 1) 5").startswith("placeholder-")
        assert expr(tmp_path, "div 1 0").startswith("placeholder-")
        assert expr(tmp_path, "trunc 3").startswith("placeholder-")

    def test_regular_expression_functions_are_never_run(self, tmp_path: Path) -> None:
        # A chart supplies the pattern, so evaluating it would let a chart hang the scan
        for call in (
            'regexMatch "(a+)+$" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"',
            'regexFind "x" "y"',
            'regexReplaceAll "a" "b" "c"',
        ):
            assert expr(tmp_path, call).startswith("placeholder-")

    def test_lookup_is_an_empty_mapping_as_in_helm_template(self, tmp_path: Path) -> None:
        out = render(
            tmp_path,
            '{{ $s := lookup "v1" "Secret" "ns" "name" }}{{ if $s }}found{{ else }}absent{{ end }}',
        )
        assert out == "absent"

    def test_required_and_fail_are_unknown_not_errors(self, tmp_path: Path) -> None:
        assert expr(tmp_path, 'required "needs a value" .Values.gone').startswith("placeholder-")
        assert expr(tmp_path, 'required "needs a value" .Values.here', {"here": "ok"}) == "ok"
        assert expr(tmp_path, 'fail "stop"').startswith("placeholder-")

    def test_sha1sum(self, tmp_path: Path) -> None:
        assert expr(tmp_path, 'sha1sum "a"') == "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"

    def test_functions_pass_holes_through_strictly(self, tmp_path: Path) -> None:
        out = render(
            tmp_path,
            '{{ upper .Values.gone }}|{{ printf "%s" .Values.gone }}|{{ trunc 3 .Values.gone }}',
        )
        assert len(set(out.split("|"))) == 3 or out.count("placeholder-") == 3


# ---------------------------------------------------------------------------------------
# Named templates
# ---------------------------------------------------------------------------------------

HELPERS = """\
{{- define "demo.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "demo.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "demo.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "demo.labels" -}}
app: {{ include "demo.name" . }}
release: {{ .Release.Name }}
{{- end }}
"""


class TestNamedTemplates:
    def test_include_renders_a_helper_with_the_dot_it_is_given(self, tmp_path: Path) -> None:
        result = render_all(
            tmp_path,
            {"_helpers.tpl": HELPERS, "t.yaml": 'name: {{ include "demo.fullname" . }}\n'},
        )
        assert result.files[0].text == "name: release-demo\n"

    def test_helpers_see_values(self, tmp_path: Path) -> None:
        result = render_all(
            tmp_path,
            {"_helpers.tpl": HELPERS, "t.yaml": 'name: {{ include "demo.name" . }}\n'},
            {"nameOverride": "custom"},
        )
        assert result.files[0].text == "name: custom\n"

    def test_include_piped_into_nindent(self, tmp_path: Path) -> None:
        result = render_all(
            tmp_path,
            {
                "_helpers.tpl": HELPERS,
                "t.yaml": (
                    "metadata:\n  labels:\n"
                    '    {{- include "demo.labels" . | nindent 4 }}\nspec: {}\n'
                ),
            },
        )
        assert yaml.safe_load(result.files[0].text) == {
            "metadata": {"labels": {"app": "demo", "release": "release"}},
            "spec": {},
        }

    def test_includes_nest(self, tmp_path: Path) -> None:
        helpers = (
            '{{ define "a" }}A{{ include "b" . }}{{ end }}'
            '{{ define "b" }}B{{ include "c" . }}{{ end }}'
            '{{ define "c" }}C{{ end }}'
        )
        out = render(tmp_path, '{{ include "a" . }}', None, name="x") if False else None
        del out
        result = render_all(tmp_path, {"_h.tpl": helpers, "t.yaml": '{{ include "a" . }}'})
        assert result.files[0].text == "ABC"

    def test_a_custom_dot_through_dict(self, tmp_path: Path) -> None:
        helpers = '{{ define "greet" }}hello {{ .who }} from {{ .root.Chart.Name }}{{ end }}'
        result = render_all(
            tmp_path,
            {"_h.tpl": helpers, "t.yaml": '{{ include "greet" (dict "who" "bob" "root" .) }}'},
        )
        assert result.files[0].text == "hello bob from demo"

    def test_dollar_inside_a_define_is_the_argument(self, tmp_path: Path) -> None:
        helpers = '{{ define "d" }}{{ range .items }}{{ $.prefix }}{{ . }};{{ end }}{{ end }}'
        result = render_all(
            tmp_path,
            {
                "_h.tpl": helpers,
                "t.yaml": '{{ include "d" (dict "items" (list 1 2) "prefix" "p") }}',
            },
        )
        assert result.files[0].text == "p1;p2;"

    def test_the_template_action_writes_in_place(self, tmp_path: Path) -> None:
        result = render_all(
            tmp_path,
            {"_h.tpl": '{{ define "x" }}[{{ . }}]{{ end }}', "t.yaml": 'a{{ template "x" "v" }}b'},
        )
        assert result.files[0].text == "a[v]b"

    def test_a_block_renders_its_default_body(self, tmp_path: Path) -> None:
        result = render_all(
            tmp_path, {"t.yaml": '{{ block "b" . }}default {{ .Chart.Name }}{{ end }}'}
        )
        assert result.files[0].text == "default demo"

    def test_an_include_of_an_unknown_name_is_unknown(self, tmp_path: Path) -> None:
        out = render(tmp_path, '{{ include "nope" . }}')
        assert out.startswith("placeholder-")

    def test_a_define_in_a_manifest_file_is_shared(self, tmp_path: Path) -> None:
        result = render_all(
            tmp_path,
            {
                "a.yaml": '{{ define "shared" }}S{{ end }}',
                "b.yaml": '{{ include "shared" . }}',
            },
        )
        assert [f.text for f in result.files] == ["S"]

    def test_a_define_in_a_helper_is_available_to_every_template_regardless_of_order(
        self, tmp_path: Path
    ) -> None:
        result = render_all(
            tmp_path,
            {"a.yaml": '{{ include "late" . }}', "z_helpers.tpl": '{{ define "late" }}L{{ end }}'},
        )
        assert result.files[0].text == "L"

    def test_infinite_recursion_is_cut_off(self, tmp_path: Path) -> None:
        result = render_all(
            tmp_path,
            {
                "_h.tpl": '{{ define "loop" }}x{{ include "loop" . }}{{ end }}',
                "t.yaml": '{{ include "loop" . }}',
            },
        )
        assert result.aborted is True
        assert any("too deeply" in w for w in result.warnings)

    def test_tpl_renders_a_string_as_a_template(self, tmp_path: Path) -> None:
        values = {"greeting": "hi {{ .Chart.Name }}"}
        assert expr(tmp_path, "tpl .Values.greeting .", values) == "hi demo"

    def test_tpl_leaves_plain_text_alone_and_survives_junk(self, tmp_path: Path) -> None:
        assert expr(tmp_path, 'tpl "plain" .') == "plain"
        assert expr(tmp_path, 'tpl "{{ if }}" .').startswith("placeholder-")

    def test_a_parent_define_replaces_the_subchart_one_of_the_same_name(
        self, tmp_path: Path
    ) -> None:
        parent = make_chart(
            tmp_path,
            {"_h.tpl": '{{ define "who" }}parent{{ end }}', "t.yaml": '{{ include "who" . }}'},
        )
        sub = parent / "charts" / "sub"
        (sub / "templates").mkdir(parents=True)
        (sub / "Chart.yaml").write_text(
            "apiVersion: v2\nname: sub\nversion: 1.0.0\n", encoding="utf-8"
        )
        (sub / "templates" / "_h.tpl").write_text(
            '{{ define "who" }}sub{{ end }}', encoding="utf-8"
        )
        (sub / "templates" / "t.yaml").write_text('{{ include "who" . }}', encoding="utf-8")
        result = render_chart(parent)
        assert {f.path: f.text for f in result.files} == {
            "templates/t.yaml": "parent",
            "charts/sub/templates/t.yaml": "parent",
        }


# ---------------------------------------------------------------------------------------
# Whitespace the way YAML needs it
# ---------------------------------------------------------------------------------------


class TestWhitespace:
    def test_trim_markers_around_a_conditional_keep_the_yaml_valid(self, tmp_path: Path) -> None:
        source = "a: 1\n{{- if .Values.on }}\nb: 2\n{{- end }}\nc: 3\n"
        assert yaml.safe_load(render(tmp_path, source, {"on": True})) == {"a": 1, "b": 2, "c": 3}
        assert yaml.safe_load(render(tmp_path, source, {"on": False})) == {"a": 1, "c": 3}

    def test_a_conditional_around_a_whole_document(self, tmp_path: Path) -> None:
        source = "{{- if .Values.on }}\nkind: A\n{{- end }}\n"
        assert yaml.safe_load(render(tmp_path, source, {"on": True})) == {"kind": "A"}
        result = render_all(tmp_path / "off", {"t.yaml": source}, {"on": False})
        assert result.files == []  # nothing rendered, so no file

    def test_a_template_that_renders_only_whitespace_is_not_a_file(self, tmp_path: Path) -> None:
        result = render_all(tmp_path, {"t.yaml": "{{- if false }}x{{ end }}\n\n  \n"})
        assert result.files == []

    def test_range_builds_a_list(self, tmp_path: Path) -> None:
        source = "items:\n{{- range .Values.l }}\n  - {{ . | quote }}\n{{- end }}\n"
        assert yaml.safe_load(render(tmp_path, source, {"l": ["a", "b"]})) == {"items": ["a", "b"]}

    def test_a_multi_document_template(self, tmp_path: Path) -> None:
        source = "kind: A\n---\nkind: B\n"
        assert [d["kind"] for d in yaml.safe_load_all(render(tmp_path, source))] == ["A", "B"]

    def test_windows_line_endings_trim_too(self, tmp_path: Path) -> None:
        out = render(tmp_path, "a: 1\r\n{{- if true }}\r\nb: 2\r\n{{- end }}\r\n")
        assert yaml.safe_load(out) == {"a": 1, "b": 2}


# ---------------------------------------------------------------------------------------
# Which files are rendered
# ---------------------------------------------------------------------------------------


class TestFiles:
    def test_templates_are_found_in_subdirectories_in_sorted_order(self, tmp_path: Path) -> None:
        result = render_all(
            tmp_path,
            {
                "z.yaml": "z: 1\n",
                "rbac/role.yaml": "role: 1\n",
                "a.yml": "a: 1\n",
                "network/deep/policy.yaml": "policy: 1\n",
            },
        )
        assert [f.path for f in result.files] == [
            "templates/a.yml",
            "templates/network/deep/policy.yaml",
            "templates/rbac/role.yaml",
            "templates/z.yaml",
        ]

    def test_helpers_notes_tests_and_other_files_are_not_rendered(self, tmp_path: Path) -> None:
        result = render_all(
            tmp_path,
            {
                "real.yaml": "kind: Real\n",
                "_helpers.tpl": "kind: NotRendered\n",
                "_partial.yaml": "kind: NotRendered\n",
                "NOTES.txt": "kind: NotRendered\n",
                "notes.txt": "kind: NotRendered\n",
                "README.md": "kind: NotRendered\n",
                "extra.tpl": "kind: NotRendered\n",
                "tests/test-connection.yaml": "kind: NotRendered\n",
            },
        )
        assert [f.path for f in result.files] == ["templates/real.yaml"]

    def test_a_tests_directory_deeper_than_the_top_is_still_rendered(self, tmp_path: Path) -> None:
        result = render_all(tmp_path, {"app/tests/x.yaml": "kind: Nested\n"})
        assert [f.path for f in result.files] == ["templates/app/tests/x.yaml"]

    def test_crds_inside_templates_are_rendered(self, tmp_path: Path) -> None:
        result = render_all(tmp_path, {"crds/widget.yaml": "kind: CustomResourceDefinition\n"})
        assert [f.path for f in result.files] == ["templates/crds/widget.yaml"]

    def test_a_chart_without_templates_renders_nothing(self, tmp_path: Path) -> None:
        directory = tmp_path / "lib"
        directory.mkdir()
        (directory / "Chart.yaml").write_text("apiVersion: v2\nname: lib\nversion: 1.0.0\n")
        assert render_chart(directory).files == []

    def test_symbolic_links_are_never_followed(self, tmp_path: Path) -> None:
        chart = make_chart(tmp_path, {"real.yaml": "kind: Real\n"})
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.yaml").write_text("kind: LeakedFile\n", encoding="utf-8")
        (outside / "values.yaml").write_text("leaked: true\n", encoding="utf-8")
        (chart / "templates" / "link.yaml").symlink_to(outside / "secret.yaml")
        (chart / "templates" / "linked-dir").symlink_to(outside, target_is_directory=True)
        (chart / "values.yaml").symlink_to(outside / "values.yaml")
        result = render_chart(chart)
        assert [f.path for f in result.files] == ["templates/real.yaml"]
        assert any("values.yaml" in w and "regular file" in w for w in result.warnings)

    def test_a_fifo_is_not_opened(self, tmp_path: Path) -> None:
        if not hasattr(os, "mkfifo"):
            pytest.skip("no mkfifo on this platform")
        chart = make_chart(tmp_path, {"real.yaml": "kind: Real\n"})
        os.mkfifo(chart / "templates" / "pipe.yaml")
        started = time.monotonic()
        result = render_chart(chart)
        assert time.monotonic() - started < 5
        assert [f.path for f in result.files] == ["templates/real.yaml"]

    def test_a_binary_template_is_skipped_with_a_warning(self, tmp_path: Path) -> None:
        chart = make_chart(tmp_path, {"real.yaml": "kind: Real\n"})
        (chart / "templates" / "blob.yaml").write_bytes(b"\x00\x01\x02\xff")
        result = render_chart(chart)
        assert [f.path for f in result.files] == ["templates/real.yaml"]
        assert any("blob.yaml" in w for w in result.warnings)


# ---------------------------------------------------------------------------------------
# Values and subcharts
# ---------------------------------------------------------------------------------------


def add_subchart(
    parent: Path, name: str, templates: dict[str, str], values: str = "", meta: str = ""
) -> Path:
    sub = parent / "charts" / name
    (sub / "templates").mkdir(parents=True)
    (sub / "Chart.yaml").write_text(
        f"apiVersion: v2\nname: {name}\nversion: 0.1.0\nappVersion: '9.9.9'\n{meta}",
        encoding="utf-8",
    )
    if values:
        (sub / "values.yaml").write_text(values, encoding="utf-8")
    for relative, body in templates.items():
        (sub / "templates" / relative).write_text(body, encoding="utf-8")
    return sub


class TestUndefinedIncludes:
    """What a template includes that no chart defines is recorded on its rendered file."""

    def test_the_undefined_names_are_listed_in_the_order_they_are_met(self, tmp_path: Path) -> None:
        chart = make_chart(
            tmp_path,
            {
                "t.yaml": 'a: {{ include "lib.one" . }}\nb: {{ include "lib.two" . }}\n'
                'c: {{ include "lib.one" . }}\n'
            },
        )
        (rendered,) = render_chart(chart).files
        assert rendered.undefined == ("lib.one", "lib.two")

    def test_a_template_action_counts_too(self, tmp_path: Path) -> None:
        chart = make_chart(tmp_path, {"t.yaml": 'a: {{ template "lib.named" . }}\n'})
        (rendered,) = render_chart(chart).files
        assert rendered.undefined == ("lib.named",)

    def test_a_defined_include_is_not_listed(self, tmp_path: Path) -> None:
        chart = make_chart(
            tmp_path,
            {
                "_helpers.tpl": '{{- define "d.name" -}}n{{- end -}}\n',
                "t.yaml": 'a: {{ include "d.name" . }}\nb: {{ include "gone" . }}\n',
            },
        )
        (rendered,) = render_chart(chart).files
        assert rendered.undefined == ("gone",)

    def test_a_template_that_includes_nothing_undefined_lists_nothing(self, tmp_path: Path) -> None:
        chart = make_chart(tmp_path, {"t.yaml": "a: 1\n"})
        (rendered,) = render_chart(chart).files
        assert rendered.undefined == ()


class TestMissingDependencies:
    def test_a_listed_dependency_with_no_subchart_is_missing(self, tmp_path: Path) -> None:
        chart = make_chart(
            tmp_path, {"t.yaml": "a: 1\n"}, chart={"dependencies": [{"name": "common"}]}
        )
        assert render_chart(chart).missing_dependencies == ["common"]

    def test_a_vendored_subchart_is_not_missing(self, tmp_path: Path) -> None:
        chart = make_chart(
            tmp_path, {"t.yaml": "a: 1\n"}, chart={"dependencies": [{"name": "common"}]}
        )
        add_subchart(chart, "common", {"t.yaml": "b: 2\n"})
        assert render_chart(chart).missing_dependencies == []

    def test_a_disabled_dependency_is_not_missing(self, tmp_path: Path) -> None:
        chart = make_chart(
            tmp_path,
            {"t.yaml": "a: 1\n"},
            {"redis": {"enabled": False}},
            chart={"dependencies": [{"name": "redis", "condition": "redis.enabled"}]},
        )
        assert render_chart(chart).missing_dependencies == []

    def test_a_dependency_of_a_subchart_counts_and_a_name_is_listed_once(
        self, tmp_path: Path
    ) -> None:
        chart = make_chart(tmp_path, {"t.yaml": "a: 1\n"})
        mid = add_subchart(
            chart,
            "mid",
            {"t.yaml": "b: 2\n"},
            meta="dependencies:\n  - name: common\n  - name: common\n",
        )
        assert render_chart(chart).missing_dependencies == ["common"]
        assert mid.is_dir()

    def test_a_chart_without_dependencies_has_none(self, tmp_path: Path) -> None:
        assert render_chart(make_chart(tmp_path, {"t.yaml": "a: 1\n"})).missing_dependencies == []

    def test_a_malformed_dependency_entry_is_ignored(self, tmp_path: Path) -> None:
        chart = make_chart(
            tmp_path,
            {"t.yaml": "a: 1\n"},
            chart={"dependencies": ["common", {"version": "1"}, {"name": 5}, {"name": ""}]},
        )
        assert render_chart(chart).missing_dependencies == []


class TestSubcharts:
    def test_a_subchart_renders_with_its_own_values_and_chart(self, tmp_path: Path) -> None:
        parent = make_chart(tmp_path, {"t.yaml": "who: parent\n"})
        add_subchart(
            parent,
            "redis",
            {"t.yaml": "image: {{ .Values.image }}\nchart: {{ .Chart.Name }}\n"},
            "image: redis:7\n",
        )
        result = render_chart(parent)
        by_path = {f.path: yaml.safe_load(f.text) for f in result.files}
        assert by_path["charts/redis/templates/t.yaml"] == {"image": "redis:7", "chart": "redis"}

    def test_the_parent_overrides_subchart_values_under_the_subchart_name(
        self, tmp_path: Path
    ) -> None:
        parent = make_chart(
            tmp_path,
            {"t.yaml": "x: 1\n"},
            {"redis": {"image": "redis:8", "extra": {"a": 1}}},
        )
        add_subchart(
            parent,
            "redis",
            {
                "t.yaml": (
                    "image: {{ .Values.image }}\nport: {{ .Values.port }}\n"
                    "extra: {{ toJson .Values.extra }}\n"
                )
            },
            "image: redis:7\nport: 6379\nextra: {b: 2}\n",
        )
        result = render_chart(parent)
        sub = yaml.safe_load(next(f.text for f in result.files if f.path.startswith("charts/")))
        assert sub["image"] == "redis:8"
        assert sub["port"] == 6379
        assert sub["extra"] == {"a": 1, "b": 2}

    def test_global_values_flow_down(self, tmp_path: Path) -> None:
        parent = make_chart(tmp_path, {"t.yaml": "x: 1\n"}, {"global": {"region": "eu"}})
        add_subchart(parent, "sub", {"t.yaml": "region: {{ .Values.global.region }}\n"})
        result = render_chart(parent)
        assert "region: eu" in next(f.text for f in result.files if f.path.startswith("charts/"))

    def test_a_dependency_condition_that_is_false_disables_the_subchart(
        self, tmp_path: Path
    ) -> None:
        parent = make_chart(
            tmp_path,
            {"t.yaml": "x: 1\n"},
            {"redis": {"enabled": False}},
            chart={
                "dependencies": [
                    {"name": "redis", "version": "0.1.0", "condition": "redis.enabled"}
                ]
            },
        )
        add_subchart(parent, "redis", {"t.yaml": "kind: Sub\n"})
        result = render_chart(parent)
        assert [f.path for f in result.files] == ["templates/t.yaml"]
        assert any("disabled" in w for w in result.warnings)

    def test_a_condition_that_is_true_or_unset_keeps_the_subchart(self, tmp_path: Path) -> None:
        for values in ({"redis": {"enabled": True}}, {}):
            root = tmp_path / str(len(values))
            parent = make_chart(
                root,
                {"t.yaml": "x: 1\n"},
                values,
                chart={"dependencies": [{"name": "redis", "condition": "redis.enabled"}]},
            )
            add_subchart(parent, "redis", {"t.yaml": "kind: Sub\n"})
            assert len(render_chart(parent).files) == 2

    def test_the_first_condition_path_that_exists_decides(self, tmp_path: Path) -> None:
        parent = make_chart(
            tmp_path,
            {"t.yaml": "x: 1\n"},
            {"cache": {"enabled": False}},
            chart={"dependencies": [{"name": "redis", "condition": "missing.flag,cache.enabled"}]},
        )
        add_subchart(parent, "redis", {"t.yaml": "kind: Sub\n"})
        assert len(render_chart(parent).files) == 1

    def test_an_alias_names_the_values_scope(self, tmp_path: Path) -> None:
        parent = make_chart(
            tmp_path,
            {"t.yaml": "x: 1\n"},
            {"cache": {"image": "aliased"}},
            chart={"dependencies": [{"name": "redis", "alias": "cache"}]},
        )
        add_subchart(parent, "redis", {"t.yaml": "image: {{ .Values.image }}\n"}, "image: plain\n")
        result = render_chart(parent)
        assert "image: aliased" in next(
            f.text for f in result.files if f.path.startswith("charts/")
        )

    def test_nested_subcharts_render_and_report_their_path(self, tmp_path: Path) -> None:
        parent = make_chart(tmp_path, {"t.yaml": "x: 1\n"})
        mid = add_subchart(parent, "mid", {"t.yaml": "kind: Mid\n"})
        add_subchart(mid, "leaf", {"t.yaml": "kind: Leaf\n"})
        result = render_chart(parent)
        assert [f.path for f in result.files] == [
            "templates/t.yaml",
            "charts/mid/templates/t.yaml",
            "charts/mid/charts/leaf/templates/t.yaml",
        ]

    def test_subcharts_nested_past_the_depth_limit_are_skipped(self, tmp_path: Path) -> None:
        directory = make_chart(tmp_path, {"t.yaml": "x: 1\n"})
        current = directory
        for level in range(hr.MAX_SUBCHART_DEPTH + 2):
            current = add_subchart(current, f"level{level}", {"t.yaml": f"level: {level}\n"})
        result = render_chart(directory)
        assert len(result.files) == hr.MAX_SUBCHART_DEPTH + 1
        assert any("nested too deeply" in w for w in result.warnings)

    def test_a_chart_archive_is_reported_not_rendered(self, tmp_path: Path) -> None:
        parent = make_chart(tmp_path, {"t.yaml": "x: 1\n"})
        (parent / "charts").mkdir()
        (parent / "charts" / "redis-1.0.0.tgz").write_bytes(b"not really a chart")
        result = render_chart(parent)
        assert [f.path for f in result.files] == ["templates/t.yaml"]
        assert any("redis-1.0.0.tgz" in w for w in result.warnings)

    def test_the_number_of_charts_is_capped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(hr, "MAX_CHARTS", 3)
        parent = make_chart(tmp_path, {"t.yaml": "x: 1\n"})
        for index in range(6):
            add_subchart(parent, f"sub{index}", {"t.yaml": "k: 1\n"})
        result = render_chart(parent)
        assert len(result.files) == 3
        assert any("more than 3 charts" in w for w in result.warnings)


# ---------------------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------------------


class TestLimits:
    def test_an_oversized_template_is_skipped_with_a_warning(self, tmp_path: Path) -> None:
        chart = make_chart(tmp_path, {"ok.yaml": "kind: Ok\n"})
        (chart / "templates" / "huge.yaml").write_text(
            "# " + "x" * (hr.MAX_TEMPLATE_BYTES + 10) + "\nkind: Huge\n", encoding="utf-8"
        )
        result = render_chart(chart)
        assert [f.path for f in result.files] == ["templates/ok.yaml"]
        assert any("huge.yaml" in w and "skipped" in w for w in result.warnings)

    def test_a_line_over_the_cap_is_replaced_by_a_comment(self, tmp_path: Path) -> None:
        source = "kind: A\ndata: " + "x" * (hr.MAX_LINE_CHARS + 5) + "\nname: kept\n"
        result = render_all(tmp_path, {"t.yaml": source})
        text = result.files[0].text
        assert "kind: A" in text and "name: kept" in text
        assert "xxxx" not in text
        assert "line 2 skipped" in text
        assert any("line 2" in w for w in result.warnings)

    def test_an_action_over_the_cap_approximates_the_file(self, tmp_path: Path) -> None:
        source = "kind: A\nname: {{ " + "a " * hr.MAX_ACTION_CHARS + "}}\n"
        result = render_all(tmp_path, {"t.yaml": source})
        assert result.files[0].approximated is True
        assert "kind: A" in result.files[0].text

    def test_a_template_with_a_syntax_error_is_approximated_not_lost(self, tmp_path: Path) -> None:
        source = (
            "kind: Service\nmetadata:\n  name: {{ .Values.name }}\n{{ if .Values.x }}\nspec: {}\n"
        )
        result = render_all(tmp_path, {"t.yaml": source})
        (rendered,) = result.files
        assert rendered.approximated is True
        assert "kind: Service" in rendered.text
        assert "{{" not in rendered.text
        assert any("approximated" in w for w in result.warnings)

    def test_unterminated_actions_render_quickly(self, tmp_path: Path) -> None:
        started = time.monotonic()
        source = 'kind: ConfigMap\ndata:\n  v: "' + "{{" * 5_000 + '"\n'
        result = render_all(tmp_path, {"t.yaml": source})
        assert time.monotonic() - started < 2
        # the text after the first unterminated action is kept, with the openers defused
        assert result.files[0].text.startswith("kind: ConfigMap")
        assert "{" not in result.files[0].text.split("v:")[1]

    def test_220_kb_of_unterminated_openers_render_in_under_two_seconds(
        self, tmp_path: Path
    ) -> None:
        started = time.monotonic()
        lines = ["kind: ConfigMap", "data:"]
        for number in range(11):
            lines.append(f'  v{number}: "' + "{{" * 10_000 + '"')
        result = render_all(tmp_path, {"t.yaml": "\n".join(lines) + "\n"})
        assert time.monotonic() - started < 2
        assert result.aborted is False

    def test_the_step_budget_stops_a_runaway_template(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(hr, "MAX_STEPS", 500)
        source = "{{ range 5000 }}{{ range 5000 }}x{{ end }}{{ end }}"
        result = render_all(tmp_path, {"t.yaml": source, "u.yaml": "kind: Never\n"})
        assert result.aborted is True
        assert any("evaluation steps" in w for w in result.warnings)
        assert result.files == []

    def test_the_output_budget_stops_a_template_that_prints_too_much(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(hr, "MAX_OUTPUT_BYTES", 1000)
        source = '{{ range 100 }}{{ repeat 100 "y" }}{{ end }}'
        result = render_all(tmp_path, {"t.yaml": source})
        assert result.aborted is True
        assert any("bytes" in w for w in result.warnings)

    def test_the_time_budget_stops_rendering_between_templates(self, tmp_path: Path) -> None:
        chart = make_chart(tmp_path, {"a.yaml": "kind: A\n", "b.yaml": "kind: B\n"})
        result = render_chart(chart, time_budget=-1.0)
        assert result.aborted is True
        assert result.files == []
        assert any("time budget" in w for w in result.warnings)

    def test_the_time_budget_stops_a_template_in_the_middle(self) -> None:
        env = hr._Env(defines={}, deadline=time.monotonic() - 1.0)
        executor = hr.Executor(env, "t")
        nodes = parse_template(tokenize("{{ range 3000 }}{{ . }}{{ end }}")).nodes
        with pytest.raises(hr.RenderAbortError, match="time budget"):
            executor.run(nodes, ValuesDict())

    def test_a_values_file_made_of_aliases_that_expand_is_ignored(self, tmp_path: Path) -> None:
        refs = ", ".join(["*{}"] * 10)
        bomb = "a: &a [x, x, x, x, x, x, x, x, x, x]\n"
        previous = "a"
        for name in "bcdefghijk":
            bomb += f"{name}: &{name} [{refs.format(*[previous] * 10)}]\n"
            previous = name
        started = time.monotonic()
        result = render_all(tmp_path, {"t.yaml": "kind: A\n"}, bomb)
        assert time.monotonic() - started < 5
        assert [f.path for f in result.files] == ["templates/t.yaml"]
        assert any("values.yaml was ignored" in w for w in result.warnings)

    def test_toyaml_of_a_structure_that_is_too_big_is_unknown(self) -> None:
        big = {f"k{n}": list(range(10)) for n in range(hr.MAX_VALUE_NODES // 8)}
        executor = hr.Executor(hr._Env(defines={}, deadline=time.monotonic() + 60), "t")
        started = time.monotonic()
        assert hr.dump_yaml(executor, big) is UNKNOWN
        assert time.monotonic() - started < 2

    def test_toyaml_of_a_structure_nested_too_deeply_is_unknown(self) -> None:
        deep: Any = "leaf"
        for _ in range(hr.MAX_VALUE_DEPTH + 5):
            deep = {"k": deep}
        executor = hr.Executor(hr._Env(defines={}, deadline=time.monotonic() + 60), "t")
        assert hr.dump_yaml(executor, deep) is UNKNOWN

    def test_a_cyclic_value_cannot_be_dumped(self) -> None:
        cycle: list[Any] = []
        cycle.append(cycle)
        executor = hr.Executor(hr._Env(defines={}, deadline=time.monotonic() + 60), "t")
        assert hr.dump_yaml(executor, cycle) is UNKNOWN

    def test_values_nested_too_deeply_are_ignored(self, tmp_path: Path) -> None:
        deep = "a: " + "[" * 100 + "1" + "]" * 100 + "\n"
        result = render_all(tmp_path, {"t.yaml": "kind: A\n"}, deep)
        assert any("values.yaml was ignored" in w for w in result.warnings)

    def test_an_invalid_values_file_is_reported_and_rendering_continues(
        self, tmp_path: Path
    ) -> None:
        result = render_all(tmp_path, {"t.yaml": "kind: A\nn: {{ .Values.x }}\n"}, "a: [1, 2\n")
        assert any("values.yaml is not valid YAML" in w for w in result.warnings)
        assert result.files[0].text.startswith("kind: A")

    def test_a_values_file_that_is_not_a_mapping_is_empty_values(self, tmp_path: Path) -> None:
        result = render_all(tmp_path, {"t.yaml": "kind: A\n"}, "- a\n- b\n")
        assert result.warnings == []
        assert len(result.files) == 1

    def test_a_template_count_above_the_cap_is_cut_off(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(hr, "MAX_TEMPLATE_FILES", 4)
        result = render_all(tmp_path, {f"t{n}.yaml": f"n: {n}\n" for n in range(10)})
        assert len(result.files) == 4
        assert any("more than 4 template files" in w for w in result.warnings)


class TestValuesThatGrow:
    """A template can build values in a loop, so no function may let one grow without a limit."""

    @staticmethod
    def _run(tmp_path: Path, source: str) -> tuple[ChartRender, float]:
        started = time.monotonic()
        result = render_all(tmp_path, {"t.yaml": "kind: A\n" + source})
        return result, time.monotonic() - started

    def test_printing_a_list_that_contains_itself_twice_at_every_level_is_cut_off(
        self, tmp_path: Path
    ) -> None:
        result, seconds = self._run(
            tmp_path, "{{ $x := list 1 }}{{ range 40 }}{{ $x = list $x $x }}{{ end }}{{ $x }}"
        )
        assert seconds < 5
        assert "..." in result.files[0].text
        assert not result.aborted

    @pytest.mark.parametrize(
        "source",
        [
            '{{ $s := "xxxxxxxxxx" }}{{ range 40 }}{{ $s = cat $s $s }}{{ end }}',
            '{{ $s := "x" }}{{ range 6 }}{{ $s = repeat 1000 $s }}{{ end }}',
            '{{ $s := repeat 1000 "line\\n" }}{{ range 10 }}{{ $s = indent 1000 $s }}{{ end }}',
            '{{ replace "a" (repeat 1000 "bbbbbbbbbb") (repeat 1000 "aaaaaaaaaa") }}',
            '{{ $s := "x" }}{{ range 30 }}{{ $s = printf "%s%s" $s $s }}{{ end }}',
            '{{ $s := repeat 1000 "xxxxxxxxxx" }}{{ $l := list }}'
            '{{ range 5000 }}{{ $l = append $l $s }}{{ end }}{{ join "," $l }}',
            '{{ $s := "x" }}{{ range 25 }}{{ $s = print $s $s }}{{ end }}',
        ],
    )
    def test_a_loop_that_doubles_a_string_is_stopped(self, tmp_path: Path, source: str) -> None:
        result, seconds = self._run(tmp_path, source)
        assert seconds < 10
        assert result.aborted is True
        assert any("characters" in w or "steps" in w for w in result.warnings)

    def test_a_huge_printf_width_is_capped(self, tmp_path: Path) -> None:
        result, seconds = self._run(tmp_path, '{{ printf "%99999999999s" "a" }}')
        assert seconds < 2
        assert len(result.files[0].text) < 2000

    def test_arithmetic_that_grows_without_bound_becomes_unknown(self, tmp_path: Path) -> None:
        result, seconds = self._run(
            tmp_path, "{{ $x := 99999999 }}{{ range 100 }}{{ $x = mul $x $x }}{{ end }}{{ $x }}"
        )
        assert seconds < 2
        assert "placeholder-" in result.files[0].text

    def test_a_loop_that_copies_a_growing_list_runs_out_of_steps(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(hr, "MAX_STEPS", 200_000)
        result, seconds = self._run(
            tmp_path,
            "{{ $l := list }}{{ range 5000 }}{{ range 5000 }}"
            "{{ $l = append $l . }}{{ end }}{{ end }}",
        )
        assert seconds < 10
        assert result.aborted is True
        assert any("evaluation steps" in w for w in result.warnings)

    def test_quadratic_list_functions_refuse_large_inputs(self, tmp_path: Path) -> None:
        result, seconds = self._run(
            tmp_path, '{{ splitList "," (repeat 1000 "a,a,a,a,a,a,") | uniq | len }}'
        )
        assert seconds < 5
        assert "placeholder-" in result.files[0].text

    def test_a_loop_that_deep_copies_a_big_structure_runs_out_of_steps(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(hr, "MAX_STEPS", 100_000)
        values = {"big": {f"k{n}": list(range(20)) for n in range(2000)}}
        result = render_all(
            tmp_path,
            {"t.yaml": "kind: A\n{{ range 100000 }}{{ $c := deepCopy $.Values.big }}{{ end }}"},
            values,
        )
        assert result.aborted is True

    def test_functions_that_are_cheap_stay_cheap(self, tmp_path: Path) -> None:
        values = {"big": {f"k{n}": n for n in range(50)}}
        result = render_all(
            tmp_path,
            {"t.yaml": 'kind: A\n{{ range 3000 }}{{ index $.Values.big "k1" }}{{ end }}'},
            values,
        )
        assert result.aborted is False


# ---------------------------------------------------------------------------------------
# Mapping output back to the template
# ---------------------------------------------------------------------------------------


class TestTemplateLines:
    def test_a_rendered_line_maps_to_the_template_line_that_produced_it(
        self, tmp_path: Path
    ) -> None:
        source = "a: 1\n{{- if .Values.on }}\nb: 2\n{{- end }}\nc: 3\n"
        result = render_all(tmp_path, {"t.yaml": source}, {"on": True})
        rendered = result.files[0]
        lines = rendered.text.split("\n")
        mapped = {
            line.split(":")[0]: rendered.template_line(n) for n, line in enumerate(lines, 1) if line
        }
        assert mapped == {"a": 1, "b": 3, "c": 5}

    def test_lines_of_an_expanded_include_map_to_the_including_line(self, tmp_path: Path) -> None:
        result = render_all(
            tmp_path,
            {
                "_h.tpl": '{{ define "labels" }}x: 1\ny: 2{{ end }}',
                "t.yaml": 'kind: A\nlabels:\n  {{- include "labels" . | nindent 2 }}\nend: 1\n',
            },
        )
        rendered = result.files[0]
        lines = rendered.text.split("\n")
        mapped = {
            line.strip().split(":")[0]: rendered.template_line(n)
            for n, line in enumerate(lines, 1)
            if line
        }
        assert mapped["x"] == mapped["y"] == 3
        assert mapped["kind"] == 1
        assert mapped["end"] == 4

    def test_lines_outside_the_text_have_no_template_line(self, tmp_path: Path) -> None:
        rendered = render_all(tmp_path, {"t.yaml": "a: 1\n"}).files[0]
        assert rendered.template_line(0) is None
        assert rendered.template_line(99) is None


def test_find_document_line() -> None:
    text = "a: 1\nkind: Service\nmetadata: {}\n---\nkind: 'Service'  # again\n"
    assert hr.find_document_line(text, "Service") == 2
    assert hr.find_document_line(text, "Service", 1) == 5
    assert hr.find_document_line(text, "Service", 2) is None
    assert hr.find_document_line(text, "Pod") is None


def test_a_document_starts_at_its_api_version_line_when_that_is_directly_above() -> None:
    text = "apiVersion: v1\nkind: Service\n---\n\napiVersion: v1\nkind: Service\n"
    assert hr.find_document_line(text, "Service") == 1
    assert hr.find_document_line(text, "Service", 1) == 5
    spaced = "apiVersion: v1\n\nkind: Service\n"
    assert hr.find_document_line(spaced, "Service") == 3
