"""Tests for new lockfile parsers (mix.lock, pubspec.lock, conan.lock)."""

from __future__ import annotations

import pytest

from threatcode.parsers.lockfile import LockfileParser


@pytest.fixture
def parser() -> LockfileParser:
    return LockfileParser()


class TestMixLockParser:
    def test_parse_mix_lock(self, parser: LockfileParser) -> None:
        content = """\
%{
  "cowboy": {:hex, :cowboy, "2.10.0", "ff9ffeff91dae4ae270dd975642997afe2a"},
  "jason": {:hex, :jason, "1.4.1", "af1c1b15006a15eca38e7e39c37b4c5e50a28db"},
  "phoenix": {:hex, :phoenix, "1.7.10", "02189140a61b2ce85a50a0f40e2e"},
}
"""
        result = parser.parse(content, source_path="mix.lock")
        assert result.format_type == "lockfile"
        names = {r.properties["name"] for r in result.resources}
        assert "cowboy" in names
        assert "jason" in names
        assert "phoenix" in names
        assert len(result.resources) == 3

    def test_mix_lock_ecosystem(self, parser: LockfileParser) -> None:
        content = '"plug": {:hex, :plug, "1.15.2", "abc123"}\n'
        result = parser.parse(content, source_path="mix.lock")
        for r in result.resources:
            assert r.resource_type == "dependency_hex"
            assert r.properties["ecosystem"] == "hex"

    def test_mix_lock_empty(self, parser: LockfileParser) -> None:
        result = parser.parse("%{}\n", source_path="mix.lock")
        assert result.resources == []


class TestPubspecLockParser:
    def test_parse_pubspec_lock(self, parser: LockfileParser) -> None:
        content = """\
sdks:
  dart: ">=3.0.0 <4.0.0"

packages:
  http:
    dependency: "direct main"
    description:
      name: http
      url: "https://pub.dev"
    source: hosted
    version: "1.2.0"
  path:
    dependency: "direct main"
    description:
      name: path
      url: "https://pub.dev"
    source: hosted
    version: "1.8.3"
  crypto:
    dependency: transitive
    description:
      name: crypto
      url: "https://pub.dev"
    source: hosted
    version: "3.0.3"
"""
        result = parser.parse(content, source_path="pubspec.lock")
        assert result.format_type == "lockfile"
        names = {r.properties["name"] for r in result.resources}
        assert "http" in names
        assert "path" in names
        assert "crypto" in names
        assert len(result.resources) == 3

    def test_pubspec_ecosystem(self, parser: LockfileParser) -> None:
        content = 'packages:\n  test_pkg:\n    version: "1.0.0"\n'
        result = parser.parse(content, source_path="pubspec.lock")
        for r in result.resources:
            assert r.resource_type == "dependency_pub"
            assert r.properties["ecosystem"] == "pub"

    def test_pubspec_empty(self, parser: LockfileParser) -> None:
        result = parser.parse("packages: {}\n", source_path="pubspec.lock")
        assert result.resources == []

    def test_pubspec_invalid_yaml(self, parser: LockfileParser) -> None:
        result = parser.parse("{{invalid yaml", source_path="pubspec.lock")
        assert result.resources == []


class TestConanLockParser:
    def test_parse_conan_lock(self, parser: LockfileParser) -> None:
        import json

        data = json.dumps(
            {
                "version": "0.5",
                "requires": [
                    "zlib/1.3.1#hash123",
                    "openssl/3.2.0#hash456",
                    "boost/1.84.0#hash789",
                ],
            }
        )
        result = parser.parse(data, source_path="conan.lock")
        assert result.format_type == "lockfile"
        names = {r.properties["name"] for r in result.resources}
        assert "zlib" in names
        assert "openssl" in names
        assert "boost" in names
        assert len(result.resources) == 3

    def test_conan_ecosystem(self, parser: LockfileParser) -> None:
        import json

        data = json.dumps({"requires": ["fmt/10.2.1#abc"]})
        result = parser.parse(data, source_path="conan.lock")
        for r in result.resources:
            assert r.resource_type == "dependency_conan"
            assert r.properties["ecosystem"] == "conan"

    def test_conan_version_extraction(self, parser: LockfileParser) -> None:
        import json

        data = json.dumps({"requires": ["spdlog/1.13.0#deadbeef"]})
        result = parser.parse(data, source_path="conan.lock")
        assert result.resources[0].properties["version"] == "1.13.0"

    def test_conan_empty(self, parser: LockfileParser) -> None:
        import json

        data = json.dumps({"requires": []})
        result = parser.parse(data, source_path="conan.lock")
        assert result.resources == []

    def test_conan_invalid_json(self, parser: LockfileParser) -> None:
        result = parser.parse("{invalid", source_path="conan.lock")
        assert result.resources == []

    def test_conan_dict_input(self, parser: LockfileParser) -> None:
        data = {"requires": ["pkg/1.0.0#hash"]}
        result = parser.parse(data, source_path="conan.lock")
        assert len(result.resources) == 1
        assert result.resources[0].properties["name"] == "pkg"
