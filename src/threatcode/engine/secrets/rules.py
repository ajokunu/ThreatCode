"""Secret detection rule definitions."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class SecretRule:
    """A single secret detection pattern."""

    id: str
    category: str
    title: str
    severity: str  # critical, high, medium, low
    regex: re.Pattern[str]
    keywords: list[str] = field(default_factory=list)
    path_filter: re.Pattern[str] | None = None
    allow_rules: list[re.Pattern[str]] = field(default_factory=list)

    def matches_path(self, file_path: str) -> bool:
        """Check if this rule applies to the given file path."""
        if self.path_filter and not self.path_filter.search(file_path):
            return False
        return True

    def is_allowed(self, match_text: str) -> bool:
        """Check if the match is in the allow list."""
        for allow in self.allow_rules:
            if allow.search(match_text):
                return True
        return False
