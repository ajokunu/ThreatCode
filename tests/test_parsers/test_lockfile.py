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
