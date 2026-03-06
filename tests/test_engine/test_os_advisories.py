"""Tests for OS advisory parsing."""

from __future__ import annotations

from typing import Any

from threatcode.engine.vulns.os_advisories import (
    _parse_alpine_secdb,
    _parse_debian_tracker,
)


class TestParseAlpineSecdb:
    def test_basic_parsing(self) -> None:
        data: dict[str, Any] = {
            "packages": [
                {
                    "pkg": {
                        "name": "openssl",
                        "secfixes": {
                            "3.1.4-r0": ["CVE-2023-5363", "CVE-2023-5678"],
                            "3.1.3-r1": ["CVE-2023-4807"],
                        },
                    }
                }
            ]
        }
        records = _parse_alpine_secdb(data, os_version="3.19")
        assert len(records) == 3
        assert all(r["os_family"] == "alpine" for r in records)
        assert all(r["os_version"] == "3.19" for r in records)
        cves = {r["id"] for r in records}
        assert "CVE-2023-5363" in cves
        assert "CVE-2023-4807" in cves

    def test_skips_x_prefixed_entries(self) -> None:
        data: dict[str, Any] = {
            "packages": [
                {
                    "pkg": {
                        "name": "busybox",
                        "secfixes": {
                            "1.36.1-r0": ["CVE-2023-1234", "X-internal-ref"],
                        },
                    }
                }
            ]
        }
        records = _parse_alpine_secdb(data, os_version="3.18")
        ids = {r["id"] for r in records}
        assert "CVE-2023-1234" in ids
        assert "X-internal-ref" not in ids

    def test_invalid_data_returns_empty(self) -> None:
        assert _parse_alpine_secdb("not a dict", os_version="3.19") == []
        assert _parse_alpine_secdb(None, os_version="3.19") == []

    def test_empty_packages(self) -> None:
        assert _parse_alpine_secdb({"packages": []}, os_version="3.19") == []


class TestParseDebianTracker:
    def test_basic_parsing(self) -> None:
        data: dict[str, Any] = {
            "CVE-2024-1234": {
                "description": "Test vulnerability",
                "scope": "openssl",
                "releases": {
                    "bookworm": {
                        "status": "resolved",
                        "fixed_version": "1.1.1w-0+deb12u1",
                        "urgency": "high",
                    }
                },
            }
        }
        records = _parse_debian_tracker(data)
        assert len(records) == 1
        assert records[0]["id"] == "CVE-2024-1234"
        assert records[0]["os_family"] == "debian"
        assert records[0]["os_version"] == "12"
        assert records[0]["severity"] == "high"

    def test_ignores_not_affected_status(self) -> None:
        data: dict[str, Any] = {
            "CVE-2024-9999": {
                "description": "Not affected",
                "releases": {
                    "bookworm": {
                        "status": "not-affected",
                        "urgency": "unimportant",
                    }
                },
            }
        }
        records = _parse_debian_tracker(data)
        assert len(records) == 0

    def test_invalid_data_returns_empty(self) -> None:
        assert _parse_debian_tracker("not a dict") == []
        assert _parse_debian_tracker(None) == []
