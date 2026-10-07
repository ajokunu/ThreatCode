"""Self-tests for the pending marker: it skips with its reason and rejects typos."""

from __future__ import annotations

import pytest

from tests.helpers.pending import KNOWN_PACKAGE_IDS, pending, validate_pending

PLUGIN_CONFTEST = "pytest_plugins = ['tests.helpers.pending']"


class TestValidation:
    def test_accepts_a_known_package(self) -> None:
        assert validate_pending("WP-3-1", "  exposure flags  ") == ("WP-3-1", "exposure flags")

    @pytest.mark.parametrize(
        "package_id",
        ["", "WP-2", "wp-2-1", "WP-9-1", "WP-2-01", "2-1", "WP-2-1 ", "WP-2-99", "WP-6-1"],
    )
    def test_rejects_ids_that_no_package_owns(self, package_id: str) -> None:
        with pytest.raises(ValueError):
            validate_pending(package_id, "reason")

    @pytest.mark.parametrize("reason", ["", "   ", None, 3])
    def test_rejects_a_missing_reason(self, reason: object) -> None:
        with pytest.raises(ValueError, match="reason"):
            validate_pending("WP-2-1", reason)

    def test_pending_builds_a_marker_and_fails_at_import_for_a_typo(self) -> None:
        marker = pending("WP-2-1", "references")
        assert marker.name == "pending"
        assert marker.args == ("WP-2-1", "references")
        with pytest.raises(ValueError):
            pending("WP-2-7x", "references")

    def test_every_plan_package_is_known(self) -> None:
        assert len(KNOWN_PACKAGE_IDS) == 30
        assert "WP-1-6" in KNOWN_PACKAGE_IDS
        assert "WP-5-2" in KNOWN_PACKAGE_IDS


class TestMarkerBehaviour:
    def test_pending_test_is_skipped_with_package_and_reason(
        self, pytester: pytest.Pytester
    ) -> None:
        pytester.makeconftest(PLUGIN_CONFTEST)
        pytester.makepyfile(
            """
            from tests.helpers.pending import pending

            @pending("WP-2-1", "instances inherit the references of their resource")
            def test_not_yet():
                assert False, "must not run"

            def test_regular():
                assert True
            """
        )
        result = pytester.runpytest("-rs")
        result.assert_outcomes(passed=1, skipped=1)
        result.stdout.fnmatch_lines(
            ["*pending WP-2-1: instances inherit the references of their resource*"]
        )

    def test_a_pending_test_never_flips_to_a_failure_or_xpass(
        self, pytester: pytest.Pytester
    ) -> None:
        pytester.makeconftest(PLUGIN_CONFTEST)
        pytester.makepyfile(
            """
            from tests.helpers.pending import pending

            @pending("WP-3-1", "already true by accident")
            def test_passes_anyway():
                assert True
            """
        )
        result = pytester.runpytest()
        result.assert_outcomes(skipped=1)

    def test_module_level_marker_covers_every_test(self, pytester: pytest.Pytester) -> None:
        pytester.makeconftest(PLUGIN_CONFTEST)
        pytester.makepyfile(
            """
            from tests.helpers.pending import pending

            pytestmark = pending("WP-4-1", "attack paths")

            def test_one():
                assert False

            def test_two():
                assert False
            """
        )
        pytester.runpytest().assert_outcomes(skipped=2)

    def test_bad_package_id_is_a_usage_error_not_a_silent_skip(
        self, pytester: pytest.Pytester
    ) -> None:
        pytester.makeconftest(PLUGIN_CONFTEST)
        pytester.makepyfile(
            """
            import pytest

            @pytest.mark.pending("WP-7-7", "typo")
            def test_typo():
                pass
            """
        )
        result = pytester.runpytest()
        assert result.ret != 0
        result.stderr.fnmatch_lines(["*pending() needs a package id like 'WP-2-1'*"])

    def test_well_formed_but_unowned_id_is_a_usage_error(self, pytester: pytest.Pytester) -> None:
        pytester.makeconftest(PLUGIN_CONFTEST)
        pytester.makepyfile(
            """
            import pytest

            @pytest.mark.pending("WP-1-99", "no such package")
            def test_typo():
                pass
            """
        )
        result = pytester.runpytest()
        assert result.ret != 0
        result.stderr.fnmatch_lines(["*not a package of the rework plan*"])

    def test_run_pending_switch_runs_only_the_named_package(
        self, pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pytester.makeconftest(PLUGIN_CONFTEST)
        pytester.makepyfile(
            """
            from tests.helpers.pending import pending

            @pending("WP-2-1", "mine")
            def test_mine():
                assert True

            @pending("WP-2-2", "someone else")
            def test_other():
                assert False
            """
        )
        monkeypatch.setenv("THREATCODE_RUN_PENDING", "WP-2-1")
        pytester.runpytest().assert_outcomes(passed=1, skipped=1)

    def test_run_pending_all_runs_everything_and_reports_failures(
        self, pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pytester.makeconftest(PLUGIN_CONFTEST)
        pytester.makepyfile(
            """
            from tests.helpers.pending import pending

            @pending("WP-2-2", "not delivered")
            def test_other():
                assert False
            """
        )
        monkeypatch.setenv("THREATCODE_RUN_PENDING", "all")
        pytester.runpytest().assert_outcomes(failed=1)

    def test_fail_on_pending_turns_a_remaining_marker_into_an_error(
        self, pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pytester.makeconftest(PLUGIN_CONFTEST)
        pytester.makepyfile(
            """
            from tests.helpers.pending import pending

            @pending("WP-4-3", "lint")
            def test_left_behind():
                pass
            """
        )
        monkeypatch.setenv("THREATCODE_FAIL_ON_PENDING", "1")
        result = pytester.runpytest()
        assert result.ret != 0
        result.stderr.fnmatch_lines(["*pending marker still present (WP-4-3)*"])
