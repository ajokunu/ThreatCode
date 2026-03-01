"""Tests for threatcode.exceptions."""

from __future__ import annotations

from threatcode.exceptions import (
    ConfigError,
    LLMError,
    ParseError,
    RedactionError,
    RuleLoadError,
    ThreatCodeError,
    UnsupportedFormatError,
)


class TestExceptionHierarchy:
    def test_base_is_exception(self) -> None:
        assert issubclass(ThreatCodeError, Exception)

    def test_parse_error_inherits_base(self) -> None:
        assert issubclass(ParseError, ThreatCodeError)

    def test_unsupported_format_inherits_parse_error(self) -> None:
        assert issubclass(UnsupportedFormatError, ParseError)

    def test_all_exceptions_carry_message(self) -> None:
        for cls in (ParseError, RuleLoadError, ConfigError, LLMError, RedactionError):
            err = cls("test message")
            assert str(err) == "test message"
