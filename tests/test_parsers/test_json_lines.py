"""Tests for threatcode.parsers._json_lines: JSON pointer to start line."""

from __future__ import annotations

import json

import pytest

from threatcode.parsers._json_lines import json_line_index

DOCUMENT = (
    '{\n  "a": 1,\n  "b": [\n    10,\n    {"c": true}\n  ],\n  "d": {\n    "e": null\n  }\n}\n'
)


class TestIndex:
    def test_object_members_and_array_items(self) -> None:
        index = json_line_index(DOCUMENT)
        assert index[""] == 1
        assert index["/a"] == 2
        assert index["/b"] == 3
        assert index["/b/0"] == 4
        assert index["/b/1"] == 5
        assert index["/b/1/c"] == 5
        assert index["/d"] == 7
        assert index["/d/e"] == 8

    def test_only_documented_pointers_are_present(self) -> None:
        assert set(json_line_index(DOCUMENT)) == {
            "",
            "/a",
            "/b",
            "/b/0",
            "/b/1",
            "/b/1/c",
            "/d",
            "/d/e",
        }

    def test_every_pointer_resolves_in_the_parsed_document(self) -> None:
        data = json.loads(DOCUMENT)
        for pointer in json_line_index(DOCUMENT):
            node = data
            for token in [t for t in pointer.split("/") if t]:
                node = node[int(token)] if isinstance(node, list) else node[token]

    def test_root_array(self) -> None:
        index = json_line_index("[\n  1,\n  [2]\n]\n")
        assert index == {"": 1, "/0": 2, "/1": 3, "/1/0": 3}

    def test_root_scalar(self) -> None:
        assert json_line_index("42") == {"": 1}
        assert json_line_index('"text"') == {"": 1}

    def test_empty_text(self) -> None:
        assert json_line_index("") == {}
        assert json_line_index("  \n ") == {}

    def test_crlf_line_endings(self) -> None:
        index = json_line_index('{\r\n  "a": 1,\r\n  "b": 2\r\n}\r\n')
        assert index["/a"] == 2
        assert index["/b"] == 3

    def test_byte_order_mark_is_ignored(self) -> None:
        assert json_line_index('﻿{"a": 1}')["/a"] == 1


class TestStrings:
    def test_structural_characters_inside_strings(self) -> None:
        text = '{\n  "s": "} , ] { \\" :",\n  "t": 1\n}\n'
        index = json_line_index(text)
        assert index["/s"] == 2
        assert index["/t"] == 3
        assert set(index) == {"", "/s", "/t"}

    def test_pointer_escaping(self) -> None:
        index = json_line_index('{"a/b": 1,\n "~": 2}')
        assert index["/a~1b"] == 1
        assert index["/~0"] == 2

    def test_escaped_keys_are_decoded(self) -> None:
        index = json_line_index('{"\\u0041": 1,\n"q\\"x": 2}')
        assert index["/A"] == 1
        assert index['/q"x'] == 2

    def test_duplicate_key_keeps_the_last_line(self) -> None:
        index = json_line_index('{"a": 1,\n"a": 2}')
        assert index["/a"] == 2

    def test_array_of_strings(self) -> None:
        index = json_line_index('[\n"x",\n"y"\n]')
        assert index == {"": 1, "/0": 2, "/1": 3}


MALFORMED = [
    "{",
    '{"a": ',
    '{"a" 1}',
    "}",
    "]",
    '{"a": "unterminated',
    "[1, 2",
    "{'a': 1}",
    "\x00",
]


class TestRobustness:
    @pytest.mark.parametrize("text", MALFORMED)
    def test_malformed_input_never_raises(self, text: str) -> None:
        assert isinstance(json_line_index(text), dict)

    def test_deeply_nested_input_does_not_hit_the_recursion_limit(self) -> None:
        depth = 1000
        index = json_line_index("[" * depth + "]" * depth)
        assert len(index) == depth

    def test_large_array(self) -> None:
        text = "[\n" + ",\n".join(str(n) for n in range(20000)) + "\n]"
        index = json_line_index(text)
        assert len(index) == 20001
        assert index["/0"] == 2
        assert index["/19999"] == 20001
