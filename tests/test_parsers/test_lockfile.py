"""Tests for lockfile parser."""

from pathlib import Path

import pytest

from threatcode.parsers.lockfile import LockfileParser


@pytest.fixture
def parser() -> LockfileParser:
    return LockfileParser()


class TestNpmParser:
    def test_parse_package_lock_v3(self, parser: LockfileParser) -> None:
        import json

        data = json.loads(Path("tests/fixtures/lockfiles/package-lock.json").read_text())
        result = parser.parse(data, source_path="package-lock.json")
        assert result.format_type == "lockfile"
        names = {r.properties["name"] for r in result.resources}
        assert "lodash" in names
        assert "express" in names
        assert "axios" in names

    def test_npm_resource_type(self, parser: LockfileParser) -> None:
        import json

        data = json.loads(Path("tests/fixtures/lockfiles/package-lock.json").read_text())
        result = parser.parse(data, source_path="package-lock.json")
        for r in result.resources:
            assert r.resource_type == "dependency_npm"
            assert r.provider == "npm"


class TestRequirementsParser:
    def test_parse_requirements(self, parser: LockfileParser) -> None:
        content = Path("tests/fixtures/lockfiles/requirements.txt").read_text()
        result = parser.parse(content, source_path="requirements.txt")
        names = {r.properties["name"] for r in result.resources}
        assert "flask" in names
        assert "requests" in names
        assert len(result.resources) == 5

    def test_pypi_ecosystem(self, parser: LockfileParser) -> None:
        content = Path("tests/fixtures/lockfiles/requirements.txt").read_text()
        result = parser.parse(content, source_path="requirements.txt")
        for r in result.resources:
            assert r.properties["ecosystem"] == "pypi"


class TestCargoParser:
    def test_parse_cargo_lock(self, parser: LockfileParser) -> None:
        content = Path("tests/fixtures/lockfiles/Cargo.lock").read_text()
        result = parser.parse(content, source_path="Cargo.lock")
        names = {r.properties["name"] for r in result.resources}
        assert "serde" in names
        assert "tokio" in names

    def test_crates_ecosystem(self, parser: LockfileParser) -> None:
        content = Path("tests/fixtures/lockfiles/Cargo.lock").read_text()
        result = parser.parse(content, source_path="Cargo.lock")
        for r in result.resources:
            assert r.properties["ecosystem"] == "crates.io"


class TestGoSumParser:
    def test_parse_go_sum(self, parser: LockfileParser) -> None:
        content = Path("tests/fixtures/lockfiles/go.sum").read_text()
        result = parser.parse(content, source_path="go.sum")
        names = {r.properties["name"] for r in result.resources}
        assert "github.com/gin-gonic/gin" in names
        assert "golang.org/x/crypto" in names

    def test_dedup_go_versions(self, parser: LockfileParser) -> None:
        content = Path("tests/fixtures/lockfiles/go.sum").read_text()
        result = parser.parse(content, source_path="go.sum")
        # go.sum has h1: and go.mod entries, should be deduped
        versions = {(r.properties["name"], r.properties["version"]) for r in result.resources}
        assert len(versions) == len(result.resources)


class TestNpmDepthLimit:
    def test_deeply_nested_npm_deps_capped(self, parser: LockfileParser) -> None:
        """npm v1 recursive dependencies stop at _MAX_NPM_DEPTH."""
        from threatcode.parsers.lockfile import _MAX_NPM_DEPTH

        # Build a chain of nested deps deeper than the limit
        depth = _MAX_NPM_DEPTH + 10
        inner: dict = {"version": "1.0.0"}
        for i in range(depth):
            inner = {"version": "1.0.0", "dependencies": {f"pkg-{i}": inner}}
        data = {"dependencies": {"root-pkg": inner}}
        result = parser.parse(data, source_path="package-lock.json")
        # Should have parsed some deps but not infinitely deep
        assert len(result.resources) <= _MAX_NPM_DEPTH + 1

    def test_malformed_toml_fallback(self, parser: LockfileParser) -> None:
        """Malformed TOML in poetry.lock falls back to regex parsing."""
        content = 'invalid toml {{{\nname = "fallback-pkg"\nversion = "1.0.0"\n'
        result = parser.parse(content, source_path="poetry.lock")
        names = {r.properties["name"] for r in result.resources}
        assert "fallback-pkg" in names
