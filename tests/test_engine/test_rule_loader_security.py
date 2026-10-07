"""Security regression tests for the rule loader (symlinks, file size, load logging).

Moved from tests/test_security.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest


class TestRuleLoaderHardening:
    def test_symlink_blocked(self, tmp_path: Path) -> None:
        """A04-03: Symlinks in extra rule paths are blocked."""
        from threatcode.engine.rules.loader import load_all_rules
        from threatcode.exceptions import RuleLoadError

        real_file = tmp_path / "real.yml"
        real_file.write_text("rules:\n  - id: TEST\n    title: Test\n")
        link = tmp_path / "link.yml"
        try:
            link.symlink_to(real_file)
        except OSError:
            pytest.skip("Symlinks not supported on this platform")

        with pytest.raises(RuleLoadError, match="symlink"):
            load_all_rules([link])

    def test_large_rule_file_rejected(self, tmp_path: Path) -> None:
        """A08-01: Rule files over 1 MB rejected."""
        from threatcode.engine.rules.loader import MAX_RULE_FILE_SIZE, load_rules_from_file
        from threatcode.exceptions import RuleLoadError

        large_file = tmp_path / "large.yml"
        large_file.write_text("x" * (MAX_RULE_FILE_SIZE + 1))
        with pytest.raises(RuleLoadError, match="byte limit"):
            load_rules_from_file(large_file)

    def test_builtin_rules_log_file_info(self, caplog: pytest.LogCaptureFixture) -> None:
        """A08-01: Built-in rule files log file info at DEBUG level."""
        import logging

        from threatcode.engine.rules.loader import load_builtin_rules

        with caplog.at_level(logging.DEBUG):
            load_builtin_rules()
        assert any("Loading built-in rules:" in r.message for r in caplog.records)
