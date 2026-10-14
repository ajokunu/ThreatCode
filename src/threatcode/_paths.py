"""Path helpers that give the same answer on every platform.

A report names files with forward slashes, relative to a root, whatever the machine that made it.
The helpers take the path module the paths belong to (``os.path`` by default), so the answer on
Windows is the one ``ntpath`` gives and can be checked on any platform.
"""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from types import ModuleType

__all__ = [
    "WINDOWS_DRIVE_PATH",
    "common_directory",
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
    return path if separator == "/" else path.replace(separator, "/")


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


def relative_posix(path: str, start: str, *, pathmod: ModuleType = os.path) -> str | None:
    """``path`` relative to ``start`` as a POSIX path, ``..`` segments included.

    Returns None when there is no relative form: the two are on different drives.
    """
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
    try:
        return str(pathmod.commonpath(directories))
    except ValueError:
        return None
