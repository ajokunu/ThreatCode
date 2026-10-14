"""Path helpers that give the same answer on every platform.

A report names files with forward slashes, relative to a root, whatever the machine that made it.
The helpers take the path module the paths belong to (``os.path`` by default), so the answer on
Windows is the one ``ntpath`` gives and can be checked on any platform.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Sequence
from functools import cached_property
from types import ModuleType

__all__ = [
    "WINDOWS_DRIVE_PATH",
    "ReportPaths",
    "common_directory",
    "drive_anchors",
    "drive_label",
    "drive_of",
    "inside",
    "is_absolute",
    "is_windows_flavor",
    "posix_separators",
    "relative_posix",
]

# A path with a drive letter once its backslashes are slashes: ``C:/work/main.tf``
WINDOWS_DRIVE_PATH = re.compile(r"^[A-Za-z]:/")


def posix_separators(path: str, *, sep: str | None = None) -> str:
    """``path`` with the separator of this platform written as ``/``.

    On Windows ``C:\\work\\main.tf`` becomes ``C:/work/main.tf``, which every Windows call reads
    as before and which no longer depends on the platform.
    Elsewhere a backslash is a character of a file name, so the path is returned as it is.
    ``sep`` names a separator other than ``os.sep``.
    """
    separator = os.sep if sep is None else sep
    if separator == "/" or not isinstance(path, str):  # a caller may hold None or a Path here
        return path
    return path.replace(separator, "/")


def is_windows_flavor(pathmod: ModuleType = os.path) -> bool:
    """Whether ``pathmod`` (``os.path`` by default) follows the rules of Windows paths."""
    return bool(pathmod.sep == "\\")


def is_absolute(path: str, *, pathmod: ModuleType = os.path) -> bool:
    """Whether ``path`` starts at the root of a file system or drive, with or without a drive.

    ``/work`` is rooted on Windows, where it means the root of the current drive, although
    ``ntpath.isabs`` has called it absolute only up to Python 3.12.
    A drive-relative path (``C:work``) is not absolute.
    """
    if pathmod.isabs(path):
        return True
    return is_windows_flavor(pathmod) and path[:1] in ("/", "\\")


def drive_of(path: str, *, pathmod: ModuleType = os.path) -> str:
    """The drive or share a path is on (``C:``), empty where paths have none.

    Windows compares drives without regard to case, so the answer is upper case there.
    """
    drive = str(pathmod.splitdrive(path)[0])
    return drive.upper() if is_windows_flavor(pathmod) else drive


def drive_label(drive: str) -> str:
    """A drive as path segments: ``D:`` is ``D``, the share ``\\\\host\\data`` is ``host/data``."""
    return re.sub(r"[\\/:?]+", "/", drive).strip("/") or "drive"


def relative_posix(path: str, start: str, *, pathmod: ModuleType = os.path) -> str | None:
    """``path`` relative to ``start`` as a POSIX path, ``..`` segments included.

    Returns None when there is no relative form: the two are on different drives.
    """
    if drive_of(pathmod.abspath(path), pathmod=pathmod) != drive_of(
        pathmod.abspath(start), pathmod=pathmod
    ):
        return None
    try:
        relative = str(pathmod.relpath(path, start))
    except ValueError:
        return None
    return relative.replace(pathmod.sep, "/")


def inside(relative: str) -> bool:
    """Whether a relative POSIX path (``relative_posix``) stays at or below its start."""
    return relative != ".." and not relative.startswith("../")


def common_directory(directories: Sequence[str], *, pathmod: ModuleType = os.path) -> str | None:
    """The deepest directory that holds all of ``directories``, else None.

    None means there is none: on Windows the directories are on different drives.
    """
    if len({drive_of(directory, pathmod=pathmod) for directory in directories}) > 1:
        return None
    try:
        return str(pathmod.commonpath(directories))
    except ValueError:
        return None


def drive_anchors(
    directories: Sequence[str], root: str, *, pathmod: ModuleType = os.path
) -> list[str]:
    """One directory for each drive other than the root's that holds any of ``directories``.

    It is the common parent of the directories on that drive, the root a scan of them alone
    would have, and ``ReportPaths`` names the files of the drive relative to it.
    """
    root_drive = drive_of(root, pathmod=pathmod)
    groups: dict[str, list[str]] = {}
    for directory in directories:
        drive = drive_of(directory, pathmod=pathmod)
        if drive != root_drive:
            groups.setdefault(drive, []).append(directory)
    return sorted(common_directory(group, pathmod=pathmod) or group[0] for group in groups.values())


class ReportPaths:
    """How a report names a file: a POSIX path relative to the scan root, whatever the machine.

    A path on the drive of the root is relative to it, ``..`` segments included for one outside it.
    A scan on Windows may name paths on other drives, and a path has no relative form to another
    drive, so a report that carried it as it is (``D:/work/infra/main.tf``) would carry the
    machine it ran on, give two files of one name the same name in SARIF and change every
    fingerprint with the checkout.
    ``anchors`` holds one directory for each such drive (``drive_anchors``), and a path on that
    drive is named by the drive and then its path from the anchor.
    With the anchor ``D:\\work\\infra``, ``D:\\work\\infra\\net\\main.tf`` is ``D/net/main.tf``.
    The directories above the anchor stay out of the name, so the same tree has the same names
    wherever it is checked out, as under the root.
    A path on a drive that no input is on, or above the anchor of its drive (a local module in a
    parent directory), is named from the top of its drive: ``D/shared/modules/net/main.tf``.
    ``pathmod`` names the path rules when they are not the ones of this machine.
    """

    def __init__(
        self,
        root: str | os.PathLike[str],
        anchors: Iterable[str | os.PathLike[str]] = (),
        *,
        pathmod: ModuleType = os.path,
    ) -> None:
        self.root = os.fspath(root)
        self.pathmod = pathmod
        self.anchors: dict[str, str] = {
            drive_of(os.fspath(anchor), pathmod=pathmod): os.fspath(anchor) for anchor in anchors
        }

    def posix(self, path: str | os.PathLike[str]) -> str:
        """``path`` as the report names it."""
        text = os.fspath(path)
        relative = relative_posix(text, self.root, pathmod=self.pathmod)
        if relative is not None:
            return relative
        return self._on_another_drive(str(self.pathmod.abspath(text)))

    def holds(self, path: str | os.PathLike[str]) -> bool:
        """Whether ``path`` is at or below the root, or at or below the anchor of its drive."""
        text = os.fspath(path)
        relative = relative_posix(text, self.root, pathmod=self.pathmod)
        if relative is None:
            anchor = self.anchors.get(self._drive(text))
            relative = (
                None if anchor is None else relative_posix(text, anchor, pathmod=self.pathmod)
            )
        return relative is not None and inside(relative)

    @cached_property
    def resolved(self) -> ReportPaths:
        """The same root and anchors with their symbolic links resolved."""
        return ReportPaths(
            self.pathmod.realpath(self.root),
            (self.pathmod.realpath(anchor) for anchor in self.anchors.values()),
            pathmod=self.pathmod,
        )

    def _drive(self, path: str) -> str:
        return drive_of(str(self.pathmod.abspath(path)), pathmod=self.pathmod)

    def _on_another_drive(self, absolute: str) -> str:
        label = drive_label(self._drive(absolute))
        anchor = self.anchors.get(self._drive(absolute))
        if anchor is not None:
            relative = relative_posix(absolute, anchor, pathmod=self.pathmod)
            if relative is not None and inside(relative):
                return label if relative == "." else f"{label}/{relative}"
        below = self.pathmod.splitdrive(absolute)[1].replace(self.pathmod.sep, "/").strip("/")
        return f"{label}/{below}" if below else label
