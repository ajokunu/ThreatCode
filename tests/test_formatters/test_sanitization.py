"""Security regression tests for formatter output sanitization.

Moved from tests/test_security.py.
"""

from __future__ import annotations


class TestFormatterSanitization:
    def test_markdown_escapes_special_chars(self) -> None:
        """LLM05-01: Markdown formatter escapes < > [ ] ( )."""
        from threatcode.formatters.markdown import _escape_md

        result = _escape_md("test <script>alert(1)</script> [link](http://evil.com)")
        assert "<script>" not in result
        assert "\\<script\\>" in result
        assert "\\[link\\]" in result

    def test_sarif_safe_uri(self) -> None:
        """LLM05-02: SARIF formatter strips non-URI chars."""
        from threatcode.formatters.sarif import _safe_uri

        result = _safe_uri('aws_s3_bucket.test"; DROP TABLE')
        assert '"' not in result
        assert ";" not in result
        assert " " not in result
        assert "aws_s3_bucket.test" in result

    def test_diff_markdown_escapes(self) -> None:
        """LLM05-01: Diff formatter escapes markdown in titles."""
        from threatcode.formatters.diff import _escape_md

        result = _escape_md("<img src=x onerror=alert(1)>")
        assert "\\<img" in result
