"""Tests for threatcode.parsers._text: size cap, BOM sniffing, strict UTF-8, empty files."""

from __future__ import annotations

import codecs
import re
from pathlib import Path

import pytest

from threatcode.exceptions import ParseError
from threatcode.parsers._text import decode_bytes, decode_input

SAMPLE = "key: value\nname: café\n"


def _write(tmp_path: Path, data: bytes, name: str = "input.yaml") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


class TestEncodings:
    def test_plain_utf8(self, tmp_path: Path) -> None:
        assert decode_input(_write(tmp_path, SAMPLE.encode("utf-8"))) == SAMPLE

    def test_utf8_bom_is_stripped(self, tmp_path: Path) -> None:
        path = _write(tmp_path, codecs.BOM_UTF8 + SAMPLE.encode("utf-8"))
        text = decode_input(path)
        assert text == SAMPLE
        assert not text.startswith("﻿")

    def test_utf16_little_endian(self, tmp_path: Path) -> None:
        path = _write(tmp_path, codecs.BOM_UTF16_LE + SAMPLE.encode("utf-16-le"))
        assert decode_input(path) == SAMPLE

    def test_utf16_big_endian(self, tmp_path: Path) -> None:
        path = _write(tmp_path, codecs.BOM_UTF16_BE + SAMPLE.encode("utf-16-be"))
        assert decode_input(path) == SAMPLE

    def test_utf16_as_written_by_python(self, tmp_path: Path) -> None:
        # The "utf-16" codec writes a BOM in the machine's byte order.
        assert decode_input(_write(tmp_path, SAMPLE.encode("utf-16"))) == SAMPLE

    def test_utf32_little_endian_is_not_taken_for_utf16(self, tmp_path: Path) -> None:
        # The UTF-32 LE byte order mark starts with the UTF-16 LE mark.
        path = _write(tmp_path, codecs.BOM_UTF32_LE + SAMPLE.encode("utf-32-le"))
        assert decode_input(path) == SAMPLE

    def test_utf32_big_endian(self, tmp_path: Path) -> None:
        path = _write(tmp_path, codecs.BOM_UTF32_BE + SAMPLE.encode("utf-32-be"))
        assert decode_input(path) == SAMPLE

    def test_decode_bytes_matches_decode_input(self) -> None:
        assert decode_bytes(codecs.BOM_UTF8 + b"a: 1\n", "x.yaml") == "a: 1\n"


class TestInvalidBytes:
    def test_invalid_utf8_names_the_file(self, tmp_path: Path) -> None:
        path = _write(tmp_path, b"key: \xc3\x28\n", name="broken.yaml")
        with pytest.raises(ParseError, match=r"broken\.yaml is not valid UTF-8 text"):
            decode_input(path)

    def test_binary_file(self, tmp_path: Path) -> None:
        path = _write(tmp_path, b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", name="logo.json")
        with pytest.raises(ParseError, match="not valid UTF-8 text"):
            decode_input(path)

    def test_nul_byte_in_otherwise_valid_utf8(self, tmp_path: Path) -> None:
        path = _write(tmp_path, b"abc\x00def", name="nul.tf")
        with pytest.raises(ParseError, match="not valid UTF-8 text"):
            decode_input(path)

    def test_truncated_utf16_names_the_encoding(self, tmp_path: Path) -> None:
        # A UTF-16 mark followed by an odd number of bytes cannot be complete text.
        path = _write(tmp_path, codecs.BOM_UTF16_LE + b"a\x00b", name="short.json")
        with pytest.raises(ParseError, match=r"short\.json is not valid UTF-16 text"):
            decode_input(path)

    def test_never_raises_unicode_decode_error(self, tmp_path: Path) -> None:
        path = _write(tmp_path, bytes(range(128, 256)))
        with pytest.raises(ParseError):
            decode_input(path)


class TestEmptyFiles:
    @pytest.mark.parametrize("content", [b"", b"   ", b"\n\n", b" \t\r\n "])
    def test_empty_or_whitespace_only_is_rejected(self, tmp_path: Path, content: bytes) -> None:
        path = _write(tmp_path, content, name="blank.tf")
        with pytest.raises(ParseError, match=r"file is empty: blank\.tf"):
            decode_input(path)

    def test_bom_only_file_is_empty(self, tmp_path: Path) -> None:
        with pytest.raises(ParseError, match="file is empty"):
            decode_input(_write(tmp_path, codecs.BOM_UTF8))

    def test_allow_empty_returns_the_text(self, tmp_path: Path) -> None:
        assert decode_input(_write(tmp_path, b"\n  \n"), allow_empty=True) == "\n  \n"
        assert decode_input(_write(tmp_path, b""), allow_empty=True) == ""

    def test_a_comment_is_not_empty(self, tmp_path: Path) -> None:
        assert decode_input(_write(tmp_path, b"# nothing yet\n")) == "# nothing yet\n"


class TestSizeAndAccess:
    def test_size_cap(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("threatcode.parsers._text.MAX_INPUT_SIZE_BYTES", 10)
        path = _write(tmp_path, b"x" * 11, name="big.json")
        with pytest.raises(ParseError, match=r"big\.json.*MB limit"):
            decode_input(path)

    def test_file_at_the_cap_is_read(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("threatcode.parsers._text.MAX_INPUT_SIZE_BYTES", 10)
        assert decode_input(_write(tmp_path, b"x" * 10)) == "x" * 10

    def test_missing_file_stays_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            decode_input(tmp_path / "missing.yaml")

    def test_directory_is_a_parse_error_not_an_os_error(self, tmp_path: Path) -> None:
        with pytest.raises(ParseError, match=re.escape(f"Cannot read {tmp_path.name}")):
            decode_input(tmp_path)
