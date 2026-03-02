"""Shared utilities for formatters."""

from __future__ import annotations

import re


def escape_md(text: str) -> str:
    """Escape characters that have special meaning in Markdown."""
    return re.sub(r"([<>\[\]()`])", r"\\\1", text)
