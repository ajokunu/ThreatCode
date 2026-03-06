"""OS detection from container image filesystems."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@runtime_checkable
class ImageLike(Protocol):
    """Protocol for objects that can read text files from an image filesystem."""

    def read_text(self, path: str) -> str | None: ...


_RPM_FAMILIES = frozenset(
    {
        "rhel",
        "centos",
        "rocky",
        "almalinux",
        "fedora",
        "amzn",
        "ol",
        "sles",
        "opensuse-leap",
        "opensuse-tumbleweed",
        "photon",
    }
)
_APK_FAMILIES = frozenset({"alpine", "wolfi", "chainguard"})
_DEB_FAMILIES = frozenset({"debian", "ubuntu"})


@dataclass
class OSInfo:
    family: str  # "alpine", "debian", "ubuntu", "rhel", "amzn", etc.
    name: str  # "Alpine Linux", "Ubuntu"
    version: str  # "3.19.1", "22.04", "9.3"
    version_codename: str  # "bookworm", "jammy", ""
    pkg_manager: str  # "apk", "dpkg", "rpm", "pacman"
    id_like: list[str] = field(default_factory=list)


def _parse_shell_vars(text: str) -> dict[str, str]:
    """Parse a shell key=value file (os-release format)."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        # Strip surrounding quotes
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        result[key.strip()] = value
    return result


def _family_to_pkg_manager(family: str, id_like: list[str]) -> str:
    if family in _APK_FAMILIES:
        return "apk"
    if family in _DEB_FAMILIES:
        return "dpkg"
    if family in _RPM_FAMILIES:
        return "rpm"
    if family == "arch":
        return "pacman"
    # Fall back to id_like
    for like in id_like:
        if like in _DEB_FAMILIES:
            return "dpkg"
        if like in _APK_FAMILIES:
            return "apk"
        if like in {"rhel", "fedora", "suse"}:
            return "rpm"
    return "unknown"


class OSDetector:
    """Detect the OS family and version from an extracted image filesystem."""

    def detect(self, image: ImageLike) -> OSInfo | None:
        """Return OSInfo or None if OS cannot be determined."""
        # 1. /etc/os-release (authoritative on modern systems)
        for path in ("etc/os-release", "usr/lib/os-release"):
            text = image.read_text(path)
            if text:
                info = self._from_os_release(text)
                if info:
                    return info

        # 2. /etc/alpine-release
        text = image.read_text("etc/alpine-release")
        if text:
            version = text.strip().split()[0] if text.strip() else ""
            return OSInfo(
                family="alpine",
                name="Alpine Linux",
                version=version,
                version_codename="",
                pkg_manager="apk",
            )

        # 3. /etc/debian_version
        text = image.read_text("etc/debian_version")
        if text:
            version = text.strip()
            return OSInfo(
                family="debian",
                name="Debian GNU/Linux",
                version=version,
                version_codename="",
                pkg_manager="dpkg",
            )

        # 4. /etc/redhat-release
        for path in ("etc/redhat-release", "etc/centos-release"):
            text = image.read_text(path)
            if text:
                info = self._from_redhat_release(text)
                if info:
                    return info

        # 5. /etc/lsb-release
        text = image.read_text("etc/lsb-release")
        if text:
            info = self._from_lsb_release(text)
            if info:
                return info

        return None

    def detect_from_root(self, root: Path) -> OSInfo | None:
        """Detect OS from a filesystem root path (for testing)."""

        class _RootImage:
            def __init__(self, root_path: Path) -> None:
                self._root = root_path

            def read_text(self, path: str) -> str | None:
                full = self._root / path
                if full.is_file():
                    try:
                        return full.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        return None
                return None

        return self.detect(_RootImage(root))

    @staticmethod
    def _from_os_release(text: str) -> OSInfo | None:
        v = _parse_shell_vars(text)
        family = v.get("ID", "").lower()
        if not family:
            return None
        id_like = [x.strip().lower() for x in v.get("ID_LIKE", "").split() if x.strip()]
        return OSInfo(
            family=family,
            name=v.get("NAME", family),
            version=v.get("VERSION_ID", ""),
            version_codename=v.get("VERSION_CODENAME", ""),
            pkg_manager=_family_to_pkg_manager(family, id_like),
            id_like=id_like,
        )

    @staticmethod
    def _from_redhat_release(text: str) -> OSInfo | None:
        # e.g. "Red Hat Enterprise Linux release 9.3 (Plow)"
        #      "CentOS Linux release 7.9.2009 (Core)"
        text = text.strip()
        version_match = re.search(r"release\s+([\d.]+)", text, re.IGNORECASE)
        version = version_match.group(1) if version_match else ""

        lower = text.lower()
        if "red hat" in lower:
            family = "rhel"
            name = "Red Hat Enterprise Linux"
        elif "centos" in lower:
            family = "centos"
            name = "CentOS Linux"
        elif "amazon" in lower:
            family = "amzn"
            name = "Amazon Linux"
        else:
            family = "rhel"
            name = text.split("release")[0].strip() if "release" in text.lower() else text
        return OSInfo(
            family=family, name=name, version=version, version_codename="", pkg_manager="rpm"
        )

    @staticmethod
    def _from_lsb_release(text: str) -> OSInfo | None:
        v = _parse_shell_vars(text)
        distrib_id = v.get("DISTRIB_ID", "").lower()
        if not distrib_id:
            return None
        id_like: list[str] = []
        return OSInfo(
            family=distrib_id,
            name=v.get("DISTRIB_DESCRIPTION", distrib_id),
            version=v.get("DISTRIB_RELEASE", ""),
            version_codename=v.get("DISTRIB_CODENAME", ""),
            pkg_manager=_family_to_pkg_manager(distrib_id, id_like),
            id_like=id_like,
        )
