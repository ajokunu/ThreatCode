"""Tests for the Unknown value type and the shared vocabulary."""

from __future__ import annotations

import copy
import json
import pickle

import pytest

from threatcode import vocab
from threatcode.values import UNKNOWN, UNKNOWN_TEXT, Unknown, is_unknown


class TestUnknown:
    def test_text_is_known_after_apply(self) -> None:
        assert str(Unknown("aws_kms_key.logs.arn")) == "(known after apply)"
        assert UNKNOWN_TEXT == "(known after apply)"

    def test_carries_the_reference_that_could_not_be_resolved(self) -> None:
        assert Unknown("var.encrypted").reference == "var.encrypted"

    def test_reference_defaults_to_empty(self) -> None:
        assert Unknown().reference == ""
        assert UNKNOWN.reference == ""

    def test_is_a_string_so_json_serialization_needs_no_help(self) -> None:
        assert isinstance(Unknown("x"), str)
        assert json.dumps({"kms_key_id": Unknown("aws_kms_key.k.arn")}) == (
            '{"kms_key_id": "(known after apply)"}'
        )

    def test_survives_a_nested_structure_in_json(self) -> None:
        props = {"rule": [{"kms_master_key_id": UNKNOWN}]}
        assert json.loads(json.dumps(props)) == {"rule": [{"kms_master_key_id": UNKNOWN_TEXT}]}

    def test_deepcopy_and_pickle_keep_the_reference(self) -> None:
        original = Unknown("module.net.vpc_id")
        assert copy.deepcopy(original).reference == "module.net.vpc_id"
        assert copy.copy(original).reference == "module.net.vpc_id"
        restored = pickle.loads(pickle.dumps(original))
        assert is_unknown(restored)
        assert restored.reference == "module.net.vpc_id"

    def test_deepcopy_of_a_container_keeps_unknowns_recognizable(self) -> None:
        props = {"a": [Unknown("x")]}
        assert is_unknown(copy.deepcopy(props)["a"][0])

    def test_repr_shows_the_reference(self) -> None:
        assert repr(Unknown("var.x")) == "Unknown('var.x')"


class TestIsUnknown:
    def test_true_for_unknown_instances(self) -> None:
        assert is_unknown(Unknown("a"))
        assert is_unknown(UNKNOWN)

    @pytest.mark.parametrize(
        "value",
        [UNKNOWN_TEXT, "", None, 0, False, [], {}, [Unknown("a")], {"a": Unknown("a")}],
    )
    def test_false_for_everything_else(self, value: object) -> None:
        assert not is_unknown(value)

    def test_the_same_text_as_a_plain_string_is_not_unknown(self) -> None:
        assert not is_unknown("(known after apply)")


class TestVocab:
    def test_world_sources(self) -> None:
        assert {"0.0.0.0/0", "::/0", "*", "internet", "any"} == vocab.WORLD_SOURCES

    @pytest.mark.parametrize("value", ["0.0.0.0/0", "::/0", "*", "Internet", "ANY", " any "])
    def test_is_world_source_ignores_case_and_whitespace(self, value: str) -> None:
        assert vocab.is_world_source(value)

    @pytest.mark.parametrize("value", ["10.0.0.0/8", "0.0.0.0/1", "", "VirtualNetwork", None, 0])
    def test_is_world_source_rejects_everything_else(self, value: object) -> None:
        assert not vocab.is_world_source(value)

    def test_admin_ports(self) -> None:
        assert {22, 23, 3389, 5985, 5986} == vocab.ADMIN_PORTS

    def test_database_ports(self) -> None:
        assert {1433, 1521, 3306, 5432, 5984, 6379, 7000, 7001} <= vocab.DATABASE_PORTS
        assert {9042, 9200, 9300, 11211, 27017} <= vocab.DATABASE_PORTS
        assert len(vocab.DATABASE_PORTS) == 13
        assert not vocab.ADMIN_PORTS & vocab.DATABASE_PORTS

    def test_dangerous_capabilities(self) -> None:
        assert len(vocab.DANGEROUS_CAPABILITIES) == 16
        assert {"ALL", "SYS_ADMIN", "NET_RAW", "CHOWN", "BPF"} <= vocab.DANGEROUS_CAPABILITIES

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("net_admin", "NET_ADMIN"),
            ("CAP_SYS_ADMIN", "SYS_ADMIN"),
            ("cap_sys_ptrace", "SYS_PTRACE"),
            (" all ", "ALL"),
            ("SYS_MODULE", "SYS_MODULE"),
        ],
    )
    def test_normalize_capability(self, raw: str, expected: str) -> None:
        assert vocab.normalize_capability(raw) == expected

    def test_normalized_names_can_be_looked_up(self) -> None:
        assert vocab.normalize_capability("cap_net_raw") in vocab.DANGEROUS_CAPABILITIES
        assert vocab.normalize_capability("net_bind_service") not in vocab.DANGEROUS_CAPABILITIES

    def test_only_a_leading_cap_prefix_is_removed(self) -> None:
        assert vocab.normalize_capability("SYS_CAP_X") == "SYS_CAP_X"
