"""Tests for version comparison utilities."""

from threatcode.engine.vulns.version import compare_versions, is_vulnerable


class TestCompareVersions:
    def test_semver_equal(self) -> None:
        assert compare_versions("1.2.3", "1.2.3", "npm") == 0

    def test_semver_less(self) -> None:
        assert compare_versions("1.2.3", "1.2.4", "npm") == -1

    def test_semver_greater(self) -> None:
        assert compare_versions("2.0.0", "1.9.9", "npm") == 1

    def test_semver_with_v_prefix(self) -> None:
        assert compare_versions("v1.2.3", "1.2.3", "go") == 0

    def test_pypi_versions(self) -> None:
        assert compare_versions("2.0.1", "2.1.0", "pypi") == -1

    def test_pre_release(self) -> None:
        assert compare_versions("1.0.0-alpha", "1.0.0", "npm") == 0  # pre-release stripped


class TestIsVulnerable:
    def test_in_range(self) -> None:
        assert is_vulnerable("1.5.0", "1.0.0", "2.0.0", "npm") is True

    def test_before_range(self) -> None:
        assert is_vulnerable("0.9.0", "1.0.0", "2.0.0", "npm") is False

    def test_at_fix(self) -> None:
        assert is_vulnerable("2.0.0", "1.0.0", "2.0.0", "npm") is False

    def test_no_fix(self) -> None:
        assert is_vulnerable("1.5.0", "1.0.0", "", "npm") is True

    def test_no_introduced(self) -> None:
        assert is_vulnerable("1.5.0", "", "2.0.0", "npm") is True

    def test_empty_version(self) -> None:
        assert is_vulnerable("", "1.0.0", "2.0.0", "npm") is False
