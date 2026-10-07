"""Property tests over the functions that handle untrusted text: JSONC stripping and redaction.

Hypothesis runs with a fixed seed and a small example count, so a failure reproduces and the
suite stays fast on a slow machine. The properties are the ones a reviewer would state in a
sentence: stripping comments never changes a document that has none, and redaction never lets a
secret value through.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

hypothesis = pytest.importorskip("hypothesis")

from hypothesis import example, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from threatcode.engine.llm.redactor import Redactor  # noqa: E402
from threatcode.parsers.mcp_config import strip_jsonc  # noqa: E402

FIXED = settings(max_examples=75, derandomize=True, deadline=None)

_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(10**9), max_value=10**9),
    st.text(max_size=20),
)
json_documents = st.recursive(
    _scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(max_size=8), children, max_size=4),
    ),
    max_leaves=12,
)
# Text with no ',' so the comma-before-bracket cleanup cannot touch a string value
comma_free_documents = st.recursive(
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(),
        st.text(max_size=20).map(lambda t: t.replace(",", "")),
    ),
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(
            st.text(max_size=8).map(lambda t: t.replace(",", "")), children, max_size=4
        ),
    ),
    max_leaves=12,
)


class TestStripJsonc:
    @FIXED
    @given(comma_free_documents)
    def test_a_document_without_comments_is_unchanged(self, document: Any) -> None:
        text = json.dumps(document, indent=2)
        assert json.loads(strip_jsonc(text)) == document

    @FIXED
    @given(st.text(alphabet=st.characters(blacklist_characters=',"\\\n'), max_size=30))
    def test_comment_markers_inside_strings_survive(self, filler: str) -> None:
        text = json.dumps(
            {"url": f"https://example.com/{filler}//not-a-comment", "note": "/* keep */"}
        )
        assert json.loads(strip_jsonc(text)) == json.loads(text)

    @FIXED
    @given(comma_free_documents, st.text(alphabet="abc xyz", max_size=20))
    def test_line_and_block_comments_are_removed(self, document: Any, comment: str) -> None:
        body = json.dumps(document, indent=2)
        commented = f"// {comment}\n{body}\n/* {comment} */\n"
        assert json.loads(strip_jsonc(commented)) == document

    @FIXED
    @given(json_documents)
    @example("abc,}")
    @example(["x,]"])
    def test_a_string_holding_a_comma_before_a_bracket_survives(self, document: Any) -> None:
        text = json.dumps(document, indent=2)
        assert json.loads(strip_jsonc(text)) == document

    def test_trailing_commas_outside_strings_are_dropped(self) -> None:
        assert json.loads(strip_jsonc('{"a": [1, 2,], "b": {"c": 1,},}')) == {
            "a": [1, 2],
            "b": {"c": 1},
        }


_secret = st.text(alphabet="0123456789abcdef", min_size=12, max_size=32)
_sensitive_keys = st.sampled_from(["password", "secret", "token", "api_key", "private_key"])
_plain_keys = st.sampled_from(["engine", "size", "description", "kind"])


def _wrap(secret: str, key: str, depth: int, as_list: bool) -> dict[str, Any]:
    node: Any = {key: [secret] if as_list else secret}
    for level in range(depth):
        node = {f"level{level}": [node] if level % 2 else node}
    return {"resource": node}


class TestRedactor:
    @FIXED
    @given(_secret, _sensitive_keys, st.integers(0, 6), st.booleans())
    def test_a_secret_under_a_sensitive_key_never_reaches_the_output(
        self, secret: str, key: str, depth: int, as_list: bool
    ) -> None:
        redacted = Redactor().redact(_wrap(secret, key, depth, as_list))
        assert secret not in json.dumps(redacted)

    @FIXED
    @given(_secret, _sensitive_keys)
    def test_redaction_is_reversible_for_the_sender_only(self, secret: str, key: str) -> None:
        redactor = Redactor()
        redacted = redactor.redact({key: secret})
        text = json.dumps(redacted)
        assert secret not in text
        assert redactor.unredact_string(redacted[key]) == secret

    @FIXED
    @given(_secret, _secret, _sensitive_keys)
    def test_the_same_secret_gets_the_same_placeholder_and_different_secrets_differ(
        self, a: str, b: str, key: str
    ) -> None:
        redactor = Redactor()
        first = redactor.redact({key: a})[key]
        again = redactor.redact({key: a})[key]
        other = redactor.redact({key: b})[key]
        assert first == again
        assert (first == other) == (a == b)

    @FIXED
    @given(st.text(alphabet="abcdefghij", min_size=1, max_size=10), _plain_keys)
    def test_a_value_under_a_plain_key_is_left_alone(self, value: str, key: str) -> None:
        assert Redactor().redact({key: value}) == {key: value}

    @FIXED
    @given(st.integers(51, 400))
    def test_nesting_deeper_than_the_cap_is_cut_off_not_followed(self, depth: int) -> None:
        node: Any = {"password": "0123456789abcdef"}
        for _ in range(depth):
            node = [node]
        text = json.dumps(Redactor().redact(node))
        assert "0123456789abcdef" not in text
