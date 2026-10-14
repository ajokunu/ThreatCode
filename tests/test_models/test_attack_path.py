"""Tests for threatcode.models.attack_path."""

from __future__ import annotations

import hashlib
import json

from threatcode.models.attack_path import AttackHop, AttackPath, attack_path_id
from threatcode.models.threat import Severity


def _path() -> AttackPath:
    return AttackPath(
        id=attack_path_id(["internet", "aws_lb.web", "aws_db_instance.db"]),
        entry="internet",
        target="aws_db_instance.db",
        hops=[
            AttackHop(
                node_id="internet",
                resource_type="internet",
                zone="internet",
                edge_type_to_next="network_flow",
                via={"ports": [443], "protocol": "tcp", "relation": "ingress"},
                enabled_by=["t1"],
                techniques=["T1190"],
            ),
            AttackHop(
                node_id="aws_lb.web",
                resource_type="aws_lb",
                zone="dmz",
                edge_type_to_next="data_flow",
            ),
            AttackHop(node_id="aws_db_instance.db", resource_type="aws_db_instance", zone="data"),
        ],
        severity=Severity.CRITICAL,
        score=8.5,
        rationale="Internet reaches the database through the load balancer.",
        techniques=["T1190", "T1530"],
        tactics=["TA0001", "TA0009"],
    )


class TestAttackPathId:
    def test_is_first_twelve_hex_of_sha256_over_joined_nodes(self) -> None:
        nodes = ["internet", "aws_lb.web", "aws_db_instance.db"]
        expected = hashlib.sha256("->".join(nodes).encode()).hexdigest()[:12]
        assert attack_path_id(nodes) == expected
        assert len(expected) == 12

    def test_is_deterministic(self) -> None:
        nodes = ["a", "b", "c"]
        assert attack_path_id(nodes) == attack_path_id(list(nodes))
        assert attack_path_id(iter(nodes)) == attack_path_id(nodes)

    def test_depends_on_order(self) -> None:
        assert attack_path_id(["a", "b", "c"]) != attack_path_id(["c", "b", "a"])

    def test_depends_on_every_node(self) -> None:
        assert attack_path_id(["a", "b", "c"]) != attack_path_id(["a", "x", "c"])
        assert attack_path_id(["a", "b", "c"]) != attack_path_id(["a", "b"])

    def test_node_ids_are_not_merged_by_the_separator(self) -> None:
        assert attack_path_id(["ab", "c"]) != attack_path_id(["a", "bc"])


class TestAttackHop:
    def test_to_dict_keys_and_defaults(self) -> None:
        d = AttackHop(node_id="n").to_dict()
        assert d == {
            "node_id": "n",
            "resource_type": "",
            "zone": "",
            "edge_type_to_next": None,
            "via": {},
            "enabled_by": [],
            "techniques": [],
        }

    def test_mutable_defaults_are_not_shared(self) -> None:
        a, b = AttackHop(node_id="a"), AttackHop(node_id="b")
        a.enabled_by.append("t1")
        a.via["ports"] = [22]
        assert b.enabled_by == []
        assert b.via == {}

    def test_to_dict_copies_collections(self) -> None:
        hop = AttackHop(node_id="a", enabled_by=["t1"], via={"ports": [22]})
        d = hop.to_dict()
        d["enabled_by"].append("t2")
        d["via"]["ports"] = [80]
        assert hop.enabled_by == ["t1"]
        assert hop.via == {"ports": [22]}


class TestAttackPath:
    def test_to_dict_is_json_serializable_and_complete(self) -> None:
        d = _path().to_dict()
        json.dumps(d)
        assert set(d) == {
            "id",
            "entry",
            "target",
            "hops",
            "severity",
            "score",
            "rationale",
            "techniques",
            "tactics",
        }
        assert d["severity"] == "critical"
        assert d["score"] == 8.5
        assert [h["node_id"] for h in d["hops"]] == [
            "internet",
            "aws_lb.web",
            "aws_db_instance.db",
        ]
        assert d["hops"][0]["via"] == {"ports": [443], "protocol": "tcp", "relation": "ingress"}
        assert d["hops"][-1]["edge_type_to_next"] is None

    def test_to_dict_is_stable_across_calls(self) -> None:
        p = _path()
        assert p.to_dict() == p.to_dict()

    def test_node_ids_follow_hop_order(self) -> None:
        p = _path()
        assert p.node_ids == ["internet", "aws_lb.web", "aws_db_instance.db"]
        assert p.id == attack_path_id(p.node_ids)

    def test_defaults(self) -> None:
        p = AttackPath(id="x", entry="e", target="t")
        assert p.hops == []
        assert p.severity is Severity.MEDIUM
        assert p.score == 0.0
        assert p.to_dict()["techniques"] == []
