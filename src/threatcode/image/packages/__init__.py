"""OS package database parsers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from threatcode.image.os_detect import OSInfo


@dataclass
class OSPackage:
    """A package installed in a container image OS."""

    name: str
    version: str
    release: str = ""  # Empty for APK (included in version)
    epoch: int = 0
    arch: str = ""
    source_name: str = ""  # Source/origin package name
    source_version: str = ""
    license: str = ""


def parse_os_packages(root: Path, os_info: OSInfo) -> list[OSPackage]:
    """Parse OS packages from image filesystem root, dispatching by package manager."""
    pm = os_info.pkg_manager

    if pm == "apk":
        from threatcode.image.packages.apk import parse_apk_db

        db_path = root / "lib" / "apk" / "db" / "installed"
        if not db_path.is_file():
            return []
        return parse_apk_db(db_path.read_text(encoding="utf-8", errors="replace"))

    if pm == "dpkg":
        from threatcode.image.packages.dpkg import parse_dpkg_status, parse_dpkg_status_d

        status_path = root / "var" / "lib" / "dpkg" / "status"
        status_d = root / "var" / "lib" / "dpkg" / "status.d"
        pkgs: list[OSPackage] = []
        if status_path.is_file():
            pkgs.extend(
                parse_dpkg_status(status_path.read_text(encoding="utf-8", errors="replace"))
            )
        if status_d.is_dir():
            pkgs.extend(parse_dpkg_status_d(status_d))
        return pkgs

    if pm == "rpm":
        from threatcode.image.packages.rpm import parse_rpm_db

        return parse_rpm_db(root)

    return []
