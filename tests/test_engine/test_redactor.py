"""Tests for LLM redactor."""

from __future__ import annotations

import json
import re
from typing import Any

import pytest

from threatcode.engine.llm.redactor import (
    HASH_HEX_LENGTH,
    MAX_REDACTION_MAPPINGS,
    PATTERN_LABELS,
    RESTORABLE_LABELS,
    Redactor,
)
from threatcode.exceptions import LLMError


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
        # Hash strategy should produce a hex digest suffix, not a numeric counter
        placeholder_redactor = Redactor(strategy="placeholder")
        placeholder_result = placeholder_redactor.redact(data)
        assert result["arn"] != placeholder_result["arn"]
        # The hash suffix is a keyed digest of at least 64 bits
        suffix = result["arn"].split("REDACTED_arn_")[1]
        assert len(suffix) == HASH_HEX_LENGTH >= 16
        assert all(c in "0123456789abcdef" for c in suffix)

    def test_non_sensitive_fields_untouched(self) -> None:
        redactor = Redactor()
        data = {"bucket": "my-bucket", "acl": "private"}
        result = redactor.redact(data)
        assert result["bucket"] == "my-bucket"
        assert result["acl"] == "private"


SENSITIVE_KEYS = [
    "db_password",
    "master_password",
    "admin_passwd",
    "client_secret",
    "aws_secret_access_key",
    "access_key_id",
    "authorization",
    "Authorization",
    "user_data",
    "bucket_key_enabled_value",
    "api_token",
    "kms_key_id",
    "connection_string",
    "private_key_pem",
    "tls_certificate_body",
    "session_cookie",
    "credentials_file",
    "DB_PASSWORD",
]


class TestKeyMatching:
    @pytest.mark.parametrize("key", SENSITIVE_KEYS)
    def test_variant_spellings_are_redacted(self, key: str) -> None:
        result = Redactor().redact({key: "plain-looking-value-123"})
        assert "plain-looking-value-123" not in json.dumps(result)
        assert result[key].startswith("REDACTED_")

    @pytest.mark.parametrize("key", ["engine", "acl", "bucket", "instance_type", "encrypted"])
    def test_ordinary_keys_are_left_alone(self, key: str) -> None:
        assert Redactor().redact({key: "value"}) == {key: "value"}

    def test_a_flag_under_a_sensitive_looking_key_stays_readable(self) -> None:
        result = Redactor().redact({"enable_key_rotation": True, "kms_key_id": "abc"})
        assert result["enable_key_rotation"] is True
        assert result["kms_key_id"].startswith("REDACTED_")

    def test_numbers_under_a_sensitive_key_are_redacted(self) -> None:
        result = Redactor().redact({"pin_secret": 123456})
        assert "123456" not in json.dumps(result)

    def test_secrets_nested_in_lists_and_dicts_are_redacted(self) -> None:
        data = {"env": [{"variables": {"db_password": "hunter2hunter2"}}]}
        assert "hunter2" not in json.dumps(Redactor().redact(data))


class TestExtraFields:
    def test_a_custom_field_is_redacted_at_any_depth_and_case(self) -> None:
        redactor = Redactor(extra_fields=["My_Field"])
        data = {"a": {"b": [{"MY_FIELD": "value-one"}]}, "my_field": "value-two"}
        out = json.dumps(redactor.redact(data))
        assert "value-one" not in out and "value-two" not in out

    def test_extra_fields_match_the_exact_name_not_a_substring(self) -> None:
        redactor = Redactor(extra_fields=["arn"])
        assert redactor.redact({"warning": "careful"}) == {"warning": "careful"}

    def test_without_the_extra_field_the_value_passes(self) -> None:
        assert Redactor().redact({"my_field": "value-one"}) == {"my_field": "value-one"}


class TestValueDetectors:
    @pytest.mark.parametrize(
        "secret",
        [
            "AKIAQWERTYUIOP123456",
            "ASIAQWERTYUIOP123456",
            "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB",
            "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz",
            "sk_live_0123456789abcdefghijkl",
            "sk-ant-api03-abcdefghijklmnop0123456789",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r",
            "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXX",
            "xoxb-1234567890-abcdefghij",
        ],
    )
    def test_secret_shapes_are_redacted_under_a_plain_key(self, secret: str) -> None:
        result = Redactor().redact({"description": f"value is {secret} here"})
        assert secret not in json.dumps(result)
        assert "REDACTED_secret_" in result["description"]

    def test_a_pem_block_is_redacted_whole(self) -> None:
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----"
        result = Redactor().redact({"note": f"key:\n{pem}\nend"})
        assert "MIIEabc" not in json.dumps(result)

    def test_url_userinfo_is_redacted_with_the_host(self) -> None:
        result = Redactor().redact({"note": "see https://admin:p4ss@db.internal:5432/app now"})
        text = result["note"]
        assert "p4ss" not in text and "admin" not in text and "db.internal" not in text
        assert "REDACTED_url_userinfo_" in text
        assert "email" not in text

    def test_a_connection_string_does_not_become_an_email(self) -> None:
        result = Redactor().redact({"note": "postgres://admin:p4ss@host/db"})
        assert "p4ss" not in json.dumps(result)
        assert "REDACTED_email" not in json.dumps(result)

    def test_emails_are_redacted(self) -> None:
        assert "a@b.example" not in Redactor().redact({"note": "mail a@b.example"})["note"]

    def test_arns_are_redacted_whole_with_their_account(self) -> None:
        result = Redactor().redact({"note": "role arn:aws:iam::123456789012:role/admin ok"})
        assert "123456789012" not in result["note"]
        assert "role/admin" not in result["note"]

    @pytest.mark.parametrize(
        "text",
        [
            'account_id: "123456789012"',
            '"aws:SourceAccount": "123456789012"',
            '"AWS": "123456789012"',
            "sourceaccount=123456789012",
        ],
    )
    def test_bare_account_ids_next_to_a_condition_word_are_redacted(self, text: str) -> None:
        assert "123456789012" not in Redactor().redact({"policy_text": text})["policy_text"]

    def test_a_plain_twelve_digit_number_is_left_alone(self) -> None:
        assert "123456789012" in Redactor().redact({"note": "order 123456789012 shipped"})["note"]

    def test_ipv4_is_redacted_and_the_prefix_kept(self) -> None:
        out = Redactor().redact({"c": "10.0.1.0/24 and 192.168.5.5"})["c"]
        assert "10.0.1.0" not in out and "192.168.5.5" not in out
        assert re.search(r"REDACTED_ip_v4_\d+/24", out)

    @pytest.mark.parametrize(
        "address", ["2001:db8::1", "fe80::1ff:fe23:4567:890a", "2001:db8:85a3::8a2e:370:7334"]
    )
    def test_compressed_ipv6_is_redacted(self, address: str) -> None:
        out = Redactor().redact({"c": f"addr {address}/64 end"})["c"]
        assert address not in out
        assert "/64" in out

    @pytest.mark.parametrize("kept", ["0.0.0.0/0", "::/0", "0.0.0.0", "127.0.0.1"])
    def test_the_any_address_stays_readable(self, kept: str) -> None:
        assert Redactor().redact({"c": kept})["c"] == kept

    @pytest.mark.parametrize(
        "text", ["12:30:45", "Fn::GetAtt", "aws_s3::x", "AWS::S3::Bucket", "a:b"]
    )
    def test_things_that_only_look_like_ipv6_are_left_alone(self, text: str) -> None:
        assert Redactor().redact({"c": text})["c"] == text

    def test_an_already_redacted_value_is_not_redacted_again(self) -> None:
        redactor = Redactor()
        first = redactor.redact({"c": "token = 'abcdefghijklmnopqrstuvwxyz0123'"})
        again = redactor.redact(first)
        assert again == first

    def test_every_pattern_label_is_documented(self) -> None:
        assert set(PATTERN_LABELS) >= {"secret", "aws_arn", "aws_account_id", "email", "ip_v4"}


class TestHashStrategy:
    def test_two_runs_disagree_about_the_same_value(self) -> None:
        a = Redactor(strategy="hash").redact({"arn": "arn:aws:s3:::same"})["arn"]
        b = Redactor(strategy="hash").redact({"arn": "arn:aws:s3:::same"})["arn"]
        assert a != b  # the key is random per run, so a provider cannot confirm a guess

    def test_one_run_is_consistent(self) -> None:
        redactor = Redactor(strategy="hash")
        assert redactor.redact({"arn": "x"})["arn"] == redactor.redact({"arn": "x"})["arn"]
        assert redactor.redact({"arn": "x"})["arn"] != redactor.redact({"arn": "y"})["arn"]

    def test_the_digest_is_not_a_plain_sha256_prefix(self) -> None:
        import hashlib

        value = "arn:aws:s3:::bucket1"
        placeholder = Redactor(strategy="hash").redact({"arn": value})["arn"]
        assert hashlib.sha256(value.encode()).hexdigest()[:HASH_HEX_LENGTH] not in placeholder

    def test_it_is_reversible_for_the_sender(self) -> None:
        redactor = Redactor(strategy="hash")
        placeholder = redactor.redact({"password": "p4ssw0rd-long"})["password"]
        assert redactor.unredact_string(f"is {placeholder}") == "is p4ssw0rd-long"


class TestMappingCap:
    def test_redaction_fails_closed_past_the_cap(self) -> None:
        redactor = Redactor()
        for i in range(MAX_REDACTION_MAPPINGS):
            redactor.placeholder_for(f"value_{i}", "test")
        assert redactor.mapping_size == MAX_REDACTION_MAPPINGS
        with pytest.raises(LLMError, match="mapping limit"):
            redactor.placeholder_for("one-too-many", "test")

    def test_a_known_value_still_resolves_at_the_cap(self) -> None:
        redactor = Redactor()
        first = redactor.placeholder_for("value_0", "test")
        for i in range(1, MAX_REDACTION_MAPPINGS):
            redactor.placeholder_for(f"value_{i}", "test")
        assert redactor.placeholder_for("value_0", "test") == first

    def test_two_values_past_the_cap_never_share_a_placeholder(self) -> None:
        redactor = Redactor()
        for i in range(MAX_REDACTION_MAPPINGS):
            redactor.placeholder_for(f"value_{i}", "test")
        for value in ("late-a", "late-b"):
            with pytest.raises(LLMError):
                redactor.redact({"password": value})
        assert "late-a" not in redactor.unredact_string("REDACTED_password_overflow")


class TestAllowlisted:
    def test_only_named_keys_survive(self) -> None:
        data = {"publicly_accessible": True, "password": "hunter2hunter2", "name": "prod-db"}
        out = Redactor().redact_allowlisted(data, {"publicly_accessible": True})
        assert out == {"publicly_accessible": True}

    def test_nested_allowlists_apply_to_each_list_element(self) -> None:
        data = {
            "ingress": [
                {"from_port": 22, "cidr_blocks": ["0.0.0.0/0"], "description": "ssh for bob"},
                {"from_port": 80, "cidr_blocks": ["10.0.0.0/8"], "secret_note": "x"},
            ]
        }
        allowed: dict[str, Any] = {"ingress": {"from_port": True, "cidr_blocks": True}}
        out = Redactor().redact_allowlisted(data, allowed)
        assert [r["from_port"] for r in out["ingress"]] == [22, 80]
        assert out["ingress"][0]["cidr_blocks"] == ["0.0.0.0/0"]
        assert "10.0.0.0" not in json.dumps(out)
        assert all(set(r) == {"from_port", "cidr_blocks"} for r in out["ingress"])

    def test_kept_strings_are_still_scrubbed(self) -> None:
        out = Redactor().redact_allowlisted(
            {"protocol": "token ghp_0123456789abcdefghijklmnopqrstuvwxyzAB"}, {"protocol": True}
        )
        assert "ghp_" not in json.dumps(out)

    def test_containers_under_a_kept_key_go_through_full_redaction(self) -> None:
        out = Redactor().redact_allowlisted(
            {"vpc_config": {"endpoint_public_access": True, "api_token": "abc123abc123"}},
            {"vpc_config": True},
        )
        assert out["vpc_config"]["endpoint_public_access"] is True
        assert "abc123" not in json.dumps(out)

    def test_key_matching_is_case_insensitive(self) -> None:
        assert Redactor().redact_allowlisted({"ACL": "private"}, {"acl": True}) == {
            "ACL": "private"
        }

    def test_a_scalar_where_a_mapping_is_expected_is_dropped(self) -> None:
        assert Redactor().redact_allowlisted({"ingress": "oops"}, {"ingress": {"x": True}}) == {}


class TestRestoring:
    def test_full_unredact_restores_everything(self) -> None:
        redactor = Redactor()
        text = redactor.redact({"password": "p4ssw0rd-long", "arn": "arn:aws:s3:::b"})
        joined = f"{text['password']} {text['arn']}"
        assert redactor.unredact_string(joined) == "p4ssw0rd-long arn:aws:s3:::b"

    def test_a_secret_placeholder_is_not_restored_when_labels_are_given(self) -> None:
        redactor = Redactor()
        secret = redactor.redact({"password": "p4ssw0rd-long"})["password"]
        out = redactor.unredact_string(f"leaks {secret}", labels=RESTORABLE_LABELS)
        assert "p4ssw0rd" not in out
        assert secret in out

    def test_only_the_scoped_resource_gets_its_placeholders_back(self) -> None:
        redactor = Redactor()
        with redactor.scope("res-a"):
            a = redactor.redact({"c": "10.0.0.1"})["c"]
        with redactor.scope("res-b"):
            b = redactor.redact({"c": "10.0.0.2"})["c"]
        restored = redactor.unredact_string(f"{a} {b}", scope="res-a", labels=RESTORABLE_LABELS)
        assert restored == f"10.0.0.1 {b}"

    def test_a_value_seen_in_two_scopes_is_restorable_in_both(self) -> None:
        redactor = Redactor()
        with redactor.scope("res-a"):
            a = redactor.redact({"c": "10.0.0.1"})["c"]
        with redactor.scope("res-b"):
            redactor.redact({"c": "10.0.0.1"})
        assert redactor.unredact_string(a, scope="res-b", labels=RESTORABLE_LABELS) == "10.0.0.1"


class TestExtraFieldsBeatTheAllowlist:
    def test_a_user_named_field_is_redacted_even_when_allowlisted(self) -> None:
        redactor = Redactor(extra_fields=["engine"])
        out = redactor.redact_allowlisted(
            {"engine": "postgres", "acl": "private"}, {"engine": True, "acl": True}
        )
        assert out["acl"] == "private"
        assert out["engine"].startswith("REDACTED_engine_")


class TestPlaceholderFormat:
    """The documented shape: REDACTED_<label>_<n>, or REDACTED_<label>_<16 hex> for hash."""

    def test_counter_placeholders(self) -> None:
        out = Redactor().redact(
            {"note": "role arn:aws:iam::1:role/x from 10.0.0.9 mail a@b.example"}
        )["note"]
        assert re.findall(r"REDACTED_[a-z0-9_]+_\d+", out) == [
            "REDACTED_aws_arn_1",
            "REDACTED_ip_v4_3",
            "REDACTED_email_2",
        ]

    def test_hash_placeholders(self) -> None:
        out = Redactor(strategy="hash").redact({"arn": "arn:aws:s3:::b"})["arn"]
        assert re.fullmatch(r"REDACTED_arn_[0-9a-f]{16}", out)

    def test_labels_are_lowercase_words(self) -> None:
        out = Redactor().redact({"Some-Odd.Password": "p4ssw0rd-long"})
        assert re.fullmatch(r"REDACTED_some_odd_password_1", out["Some-Odd.Password"])
