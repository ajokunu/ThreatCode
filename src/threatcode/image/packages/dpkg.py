"""Debian/Ubuntu dpkg package database parser."""

from __future__ import annotations

import logging
from email.parser import Parser as EmailParser
from pathlib import Path

from threatcode.image.packages import OSPackage

logger = logging.getLogger(__name__)

_EMAIL_PARSER = EmailParser()


def _parse_stanza(stanza: str) -> OSPackage | None:
    """Parse a single RFC822 stanza into an OSPackage, or None if not installed."""
    msg = _EMAIL_PARSER.parsestr(stanza)

    status = msg.get("Status", "")
    # Skip packages that are deinstalled or purged
    status_words = status.lower().split()
    if "deinstall" in status_words or "purge" in status_words:
        return None

    name = msg.get("Package", "").strip()
    if not name:
        return None

    version = msg.get("Version", "").strip()
    arch = msg.get("Architecture", "").strip()

    # Source field: "source-name" or "source-name (source-version)"
    source_raw = (msg.get("Source") or name).strip()
    source_name = source_raw
    source_version = version
    if "(" in source_raw:
        paren_idx = source_raw.index("(")
        source_name = source_raw[:paren_idx].strip()
        source_version = source_raw[paren_idx + 1 :].rstrip(")").strip()

    return OSPackage(
        name=name,
        version=version,
        arch=arch,
        source_name=source_name,
        source_version=source_version,
    )


def parse_dpkg_status(content: str) -> list[OSPackage]:
    """Parse /var/lib/dpkg/status (RFC822 stanzas separated by blank lines)."""
    packages: list[OSPackage] = []
    for stanza in content.split("\n\n"):
        if not stanza.strip():
            continue
        pkg = _parse_stanza(stanza)
        if pkg is not None:
            packages.append(pkg)
    return packages


def parse_dpkg_status_d(directory: Path) -> list[OSPackage]:
    """Parse /var/lib/dpkg/status.d/* (distroless images).

    Each file is a single stanza; all present packages are installed.
    """
    packages: list[OSPackage] = []
    for fpath in directory.iterdir():
        if not fpath.is_file():
            continue
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # Distroless stanzas have no Status field — all are installed
        msg = _EMAIL_PARSER.parsestr(content)
        name = msg.get("Package", "").strip()
        if not name:
            continue
        version = msg.get("Version", "").strip()
        arch = msg.get("Architecture", "").strip()
        source_raw = (msg.get("Source") or name).strip()
        source_name = source_raw
        source_version = version
        if "(" in source_raw:
            paren_idx = source_raw.index("(")
            source_name = source_raw[:paren_idx].strip()
            source_version = source_raw[paren_idx + 1 :].rstrip(")").strip()
        packages.append(
            OSPackage(
                name=name,
                version=version,
                arch=arch,
                source_name=source_name,
                source_version=source_version,
            )
        )
    return packages
