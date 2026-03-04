"""Secret scanner configuration."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SecretScanConfig:
    """Configuration for secret scanning."""

    # Paths to skip (relative patterns)
    skip_paths: list[str] = field(
        default_factory=lambda: [
            "node_modules/",
            "vendor/",
            ".git/",
            "__pycache__/",
            ".mypy_cache/",
            "dist/",
            "build/",
            ".tox/",
            ".venv/",
            "venv/",
            "*.min.js",
            "*.min.css",
            "*.map",
            "*.lock",
            "go.sum",
        ]
    )

    # Max file size to scan (bytes)
    max_file_size: int = 1 * 1024 * 1024  # 1 MB

    # Global allow-list patterns
    allow_patterns: list[str] = field(default_factory=list)

    # Custom rule definitions (YAML path)
    custom_rules_path: str = ""
