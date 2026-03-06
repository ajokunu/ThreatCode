"""Application dependency detection inside container images."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from threatcode.image.layer import ExtractedImage

from threatcode.constants import LOCKFILE_NAMES

logger = logging.getLogger(__name__)

# Directories to skip (no useful dependencies)
_SKIP_DIRS = frozenset(
    {
        "proc",
        "sys",
        "dev",
        "run",
        "tmp",
        ".git",
        "__pycache__",
        ".cache",
    }
)


def find_app_dependencies(image: ExtractedImage) -> list[dict[str, Any]]:
    """Walk the image filesystem and extract application dependencies.

    Finds lockfiles and parses them using the existing LockfileParser.
    Also scans Python site-packages for pip-installed packages.

    Returns a flat list of dependency property dicts (same format as
    what VulnerabilityScanner.scan_dependencies() expects).
    """
    from threatcode.parsers import detect_and_parse

    all_deps: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for dirpath, dirnames, filenames in os.walk(image.root):
        # Prune skip directories in-place
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]

        for fname in filenames:
            if fname not in LOCKFILE_NAMES:
                continue

            abs_path = os.path.join(dirpath, fname)
            if abs_path in seen_paths:
                continue
            seen_paths.add(abs_path)

            try:
                parsed = detect_and_parse(abs_path)
                for resource in parsed.resources:
                    if resource.resource_type.startswith("dependency_"):
                        all_deps.append(resource.properties)
            except Exception as e:
                logger.debug("Could not parse lockfile %s: %s", abs_path, e)

    # Scan Python site-packages for installed packages
    site_pkgs = _find_site_packages(image.root)
    all_deps.extend(site_pkgs)

    return all_deps


def _find_site_packages(root: Path) -> list[dict[str, Any]]:
    """Find Python packages installed via pip by reading METADATA files.

    Looks for: **/site-packages/*/METADATA or **/dist-packages/*/METADATA
    These follow PEP 566 (email header format).
    """
    from email.parser import Parser as EmailParser

    parser = EmailParser()
    deps: list[dict[str, Any]] = []
    seen: set[str] = set()

    for dirpath, dirnames, filenames in os.walk(root):
        dirname = os.path.basename(dirpath)
        if dirname in ("site-packages", "dist-packages"):
            # Look for *.dist-info/METADATA or *.egg-info/PKG-INFO
            for sub in os.listdir(dirpath):
                sub_path = Path(dirpath) / sub
                if not sub_path.is_dir():
                    continue
                for meta_file in ("METADATA", "PKG-INFO"):
                    meta_path = sub_path / meta_file
                    if not meta_path.is_file():
                        continue
                    try:
                        content = meta_path.read_text(encoding="utf-8", errors="replace")
                        msg = parser.parsestr(content)
                        name = msg.get("Name", "").strip()
                        version = msg.get("Version", "").strip()
                        license_str = msg.get("License", "").strip()
                        if name and version:
                            key = f"pypi/{name}@{version}"
                            if key not in seen:
                                seen.add(key)
                                deps.append(
                                    {
                                        "name": name,
                                        "version": version,
                                        "ecosystem": "pypi",
                                        "license": license_str,
                                    }
                                )
                    except Exception:
                        pass

    return deps
