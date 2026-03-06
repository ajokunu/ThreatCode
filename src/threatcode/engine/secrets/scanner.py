"""Secret scanning engine."""

from __future__ import annotations

import fnmatch
import logging
import os
import re
import uuid
from pathlib import Path

from threatcode.constants import _severity_map
from threatcode.engine.secrets.builtin import get_builtin_rules
from threatcode.engine.secrets.config import SecretScanConfig
from threatcode.engine.secrets.rules import SecretRule
from threatcode.models.finding import SecretFinding
from threatcode.models.threat import Severity

logger = logging.getLogger(__name__)

# Binary file detection: if first 8KB contains null bytes, skip
_BINARY_CHECK_SIZE = 8192

# Max allow pattern length to prevent ReDoS
_MAX_PATTERN_LENGTH = 500


class SecretScanner:
    """Scan files for hardcoded secrets."""

    def __init__(
        self,
        config: SecretScanConfig | None = None,
        extra_rules: list[SecretRule] | None = None,
    ) -> None:
        self.config = config or SecretScanConfig()
        self.rules = get_builtin_rules()
        if extra_rules:
            self.rules.extend(extra_rules)

        # Compile global allow patterns with length check
        self._global_allow: list[re.Pattern[str]] = []
        for pattern in self.config.allow_patterns:
            if len(pattern) > _MAX_PATTERN_LENGTH:
                logger.warning("Allow pattern too long (%d chars), skipping", len(pattern))
                continue
            try:
                self._global_allow.append(re.compile(pattern))
            except re.error:
                logger.warning("Invalid allow pattern: %s", pattern)

        # Pre-compile skip path patterns using fnmatch for proper escaping
        self._skip_patterns: list[str] = []
        for p in self.config.skip_paths:
            try:
                self._skip_patterns.append(fnmatch.translate(p))
            except re.error:
                logger.warning("Invalid skip pattern: %s", p)

    def scan(self, path: str | Path) -> list[SecretFinding]:
        """Scan a file or directory for secrets."""
        path = Path(path)
        findings: list[SecretFinding] = []

        if path.is_file():
            findings.extend(self._scan_file(path))
        elif path.is_dir():
            for file_path in self._walk_directory(path):
                findings.extend(self._scan_file(file_path))

        return findings

    def _walk_directory(self, directory: Path) -> list[Path]:
        """Walk directory, skipping configured paths."""
        files: list[Path] = []
        for root, dirs, filenames in os.walk(directory):
            root_path = Path(root)
            rel_root = str(root_path.relative_to(directory))

            # Skip hidden directories and configured paths
            dirs[:] = [
                d
                for d in dirs
                if not d.startswith(".") and not self._should_skip(f"{rel_root}/{d}/")
            ]

            for fname in filenames:
                rel_path = f"{rel_root}/{fname}" if rel_root != "." else fname
                if not self._should_skip(rel_path):
                    files.append(root_path / fname)

        return files

    def _should_skip(self, rel_path: str) -> bool:
        """Check if a path should be skipped."""
        for pattern in self._skip_patterns:
            if re.search(pattern, rel_path):
                return True
        return False

    def _scan_file(self, file_path: Path) -> list[SecretFinding]:
        """Scan a single file for secrets."""
        findings: list[SecretFinding] = []

        # Check file size
        try:
            size = file_path.stat().st_size
        except OSError:
            return findings

        if size > self.config.max_file_size or size == 0:
            return findings

        # Check for binary file
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(_BINARY_CHECK_SIZE)
                if b"\x00" in chunk:
                    return findings
        except OSError:
            return findings

        # Read file content
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            return findings

        file_str = str(file_path)

        for rule in self.rules:
            # Path filter check
            if not rule.matches_path(file_str):
                continue

            # Keyword pre-filter — fast check before regex
            if rule.keywords and not any(kw in content for kw in rule.keywords):
                continue

            # Regex matching
            for line_num, line in enumerate(content.splitlines(), 1):
                for match in rule.regex.finditer(line):
                    matched_text = match.group(0)

                    # Check allow-lists
                    if rule.is_allowed(matched_text):
                        continue
                    if any(a.search(matched_text) for a in self._global_allow):
                        continue

                    # Redact the match for the finding
                    redacted = self._redact(matched_text)

                    sev_map = _severity_map()
                    finding = SecretFinding(
                        id=f"SECRET-{uuid.uuid4().hex[:8]}",
                        title=rule.title,
                        severity=sev_map.get(rule.severity, Severity.MEDIUM),
                        file_path=file_str,
                        line_number=line_num,
                        secret_type=rule.category,
                        match=redacted,
                        rule_id=rule.id,
                    )
                    findings.append(finding)

        return findings

    def _redact(self, text: str) -> str:
        """Redact a secret value, showing only first/last 4 chars."""
        if len(text) <= 12:
            return text[:2] + "****" + text[-2:]
        return text[:4] + "****" + text[-4:]
