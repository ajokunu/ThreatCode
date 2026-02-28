"""Tests for LLM redactor."""

from __future__ import annotations

from threatcode.engine.llm.redactor import Redactor


class TestRedactor:
    def test_redact_arn(self) -> None:
        redactor = Redactor()
        data = {"arn": "arn:aws:s3:::my-bucket"}
        result = redactor.redact(data)
        assert "arn:aws:s3" not in str(result["arn"])
        assert "REDACTED" in str(result["arn"])

    def test_redact_account_id(self) -> None:
        redactor = Redactor()
        data = {"account_id": "123456789012"}
        result = redactor.redact(data)
        assert "123456789012" not in str(result["account_id"])

    def test_redact_tags(self) -> None:
        redactor = Redactor()
        data = {"tags": {"team": "security", "env": "prod"}}
        result = redactor.redact(data)
        assert "security" not in str(result["tags"])

    def test_redact_ip_in_string(self) -> None:
        redactor = Redactor()
        data = {"config": "server at 10.0.1.50 on port 8080"}
        result = redactor.redact(data)
        assert "10.0.1.50" not in result["config"]

    def test_unredact_string(self) -> None:
        redactor = Redactor()
        data = {"arn": "arn:aws:s3:::my-bucket"}
        result = redactor.redact(data)
        unredacted = redactor.unredact_string(result["arn"])
        assert unredacted == "arn:aws:s3:::my-bucket"

    def test_redact_nested_dict(self) -> None:
        redactor = Redactor()
        data = {"resource": {"config": {"account_id": "123456789012"}}}
        result = redactor.redact(data)
        assert "123456789012" not in str(result)

    def test_redact_list(self) -> None:
        redactor = Redactor()
        data = [{"arn": "arn:aws:iam::123456789012:role/test"}]
        result = redactor.redact(data)
        assert "123456789012" not in str(result)

    def test_placeholder_strategy(self) -> None:
        redactor = Redactor(strategy="placeholder")
        data = {"arn": "arn:aws:s3:::bucket1"}
        result = redactor.redact(data)
        assert "REDACTED_arn_" in result["arn"]

    def test_hash_strategy(self) -> None:
        redactor = Redactor(strategy="hash")
        data = {"arn": "arn:aws:s3:::bucket1"}
        result = redactor.redact(data)
        assert "REDACTED_arn_" in result["arn"]

    def test_non_sensitive_fields_untouched(self) -> None:
        redactor = Redactor()
        data = {"bucket": "my-bucket", "acl": "private"}
        result = redactor.redact(data)
        assert result["bucket"] == "my-bucket"
        assert result["acl"] == "private"
