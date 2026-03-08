"""OCI image layer extraction and filesystem merging."""

from __future__ import annotations

import io
import logging
import os
import shutil
import tarfile
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from threatcode.exceptions import ThreatCodeError

logger = logging.getLogger(__name__)

_WHITEOUT_PREFIX = ".wh."
_OPAQUE_WHITEOUT = ".wh..wh..opq"

_MAX_LAYER_SIZE = 2_000_000_000  # 2 GB
_MAX_TOTAL_SIZE = 10_000_000_000  # 10 GB
_MAX_FILE_COUNT = 500_000


@dataclass
class ExtractedImage:
    """An OCI image extracted into a temporary directory."""

    root: Path
    config: dict[str, Any]
    layer_count: int
    total_size: int = 0
    _cleaned: bool = field(default=False, repr=False, compare=False)

    def read_file(self, path: str) -> bytes | None:
        """Read a file from the merged filesystem (relative path, no leading /)."""
        try:
            full = (self.root / path.lstrip("/")).resolve()
            if not str(full).startswith(str(self.root.resolve())):
                return None
            if not full.is_file():
                return None
            return full.read_bytes()
        except (OSError, ValueError):
            return None

    def read_text(self, path: str, encoding: str = "utf-8") -> str | None:
        """Read a text file. Returns None if not found."""
        data = self.read_file(path)
        if data is None:
            return None
        return data.decode(encoding, errors="replace")

    def file_exists(self, path: str) -> bool:
        """Return True only if the path exists INSIDE the image root."""
        try:
            target = (self.root / path.lstrip("/")).resolve()
            # Reject anything that resolves outside the root
            if not str(target).startswith(str(self.root.resolve())):
                return False
            return target.exists()
        except (OSError, ValueError):
            return False

    def walk(self) -> Iterator[tuple[Path, list[str], list[str]]]:
        """Walk the merged filesystem like os.walk."""
        for dirpath, dirnames, filenames in os.walk(self.root):
            yield Path(dirpath), dirnames, filenames

    def cleanup(self) -> None:
        """Remove the temporary directory."""
        if not self._cleaned and self.root.exists():
            shutil.rmtree(self.root, ignore_errors=True)
            self._cleaned = True

    def __del__(self) -> None:
        try:
            self.cleanup()
        except Exception:
            pass


class LayerExtractor:
    """Extract OCI/Docker image layers into a merged filesystem."""

    def __init__(self) -> None:
        pass

    def extract_from_blobs(
        self,
        layer_blobs: list[bytes],
        config: dict[str, Any],
    ) -> ExtractedImage:
        """Extract layers from in-memory blobs into a temp directory.

        Layers are applied in order (index 0 = base layer).
        Returns an ExtractedImage; caller must call .cleanup() when done.
        """
        tmp_dir = Path(tempfile.mkdtemp(prefix="threatcode-image-"))
        total_size = 0
        file_count = 0

        for i, blob in enumerate(layer_blobs):
            if len(blob) > _MAX_LAYER_SIZE:
                raise ThreatCodeError(
                    f"Layer {i} size {len(blob)} exceeds limit of {_MAX_LAYER_SIZE} bytes"
                )
            extracted, count = self._apply_layer(blob, tmp_dir)
            total_size += extracted
            file_count += count
            if total_size > _MAX_TOTAL_SIZE:
                shutil.rmtree(tmp_dir, ignore_errors=True)
                raise ThreatCodeError(f"Total extracted size exceeds {_MAX_TOTAL_SIZE} bytes")
            if file_count > _MAX_FILE_COUNT:
                shutil.rmtree(tmp_dir, ignore_errors=True)
                raise ThreatCodeError(f"File count exceeds limit of {_MAX_FILE_COUNT}")

        return ExtractedImage(
            root=tmp_dir,
            config=config,
            layer_count=len(layer_blobs),
            total_size=total_size,
        )

    def _apply_layer(self, tar_bytes: bytes, dest: Path) -> tuple[int, int]:
        """Apply a single compressed layer to the destination directory.

        Returns (bytes_extracted, files_extracted).

        Processing order:
        1. Collect all entries from the tar
        2. Process opaque whiteouts (.wh..wh..opq) — clear directory
        3. Process regular whiteouts (.wh.{name}) — delete named entries
        4. Extract all regular entries
        """
        try:
            tf = tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:*")
        except tarfile.TarError as e:
            logger.warning("Could not open layer tar: %s", e)
            return 0, 0

        with tf:
            return self._process_tar(tf, dest)

    def _process_tar(self, tf: tarfile.TarFile, dest: Path) -> tuple[int, int]:
        """Process a tarfile, extracting entries into dest. Returns (bytes, files)."""
        members = tf.getmembers()
        total_bytes = 0
        total_files = 0

        # Build a name → TarInfo map for safe extraction
        member_map: dict[str, tarfile.TarInfo] = {}
        for m in members:
            raw_name = m.name
            # Reject paths with .. traversal before any normalization
            raw_parts = raw_name.replace("\\", "/").split("/")
            if ".." in raw_parts:
                logger.debug("Skipping path traversal entry: %s", raw_name)
                continue
            # Normalize name: strip leading ./ and /
            name = raw_name.lstrip("./").lstrip("/")
            if not name:
                continue
            m.name = name
            member_map[name] = m

        # Pass 1: opaque whiteouts
        for name, m in list(member_map.items()):
            basename = os.path.basename(name)
            dirname = os.path.dirname(name)
            if basename == _OPAQUE_WHITEOUT:
                target_dir = dest / dirname if dirname else dest
                if target_dir.is_dir():
                    shutil.rmtree(target_dir)
                    target_dir.mkdir(parents=True, exist_ok=True)
                del member_map[name]

        # Pass 2: regular whiteouts
        for name in list(member_map.keys()):
            basename = os.path.basename(name)
            dirname = os.path.dirname(name)
            if basename.startswith(_WHITEOUT_PREFIX) and basename != _OPAQUE_WHITEOUT:
                real_name = basename[len(_WHITEOUT_PREFIX) :]
                target = dest / dirname / real_name if dirname else dest / real_name
                if target.is_dir():
                    shutil.rmtree(target, ignore_errors=True)
                elif target.exists():
                    target.unlink(missing_ok=True)
                del member_map[name]

        # Pass 3: extract regular entries
        for name, m in member_map.items():
            if not self._is_safe_path(dest, name):
                logger.debug("Skipping unsafe path: %s", name)
                continue

            target = dest / name

            try:
                if m.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif m.isfile():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    f = tf.extractfile(m)
                    if f is not None:
                        data = f.read()
                        target.write_bytes(data)
                        total_bytes += len(data)
                        total_files += 1
                elif m.issym():
                    # Symlink — validate target stays inside extraction dir
                    if os.path.isabs(m.linkname):
                        logger.debug("Skipping absolute symlink: %s -> %s", name, m.linkname)
                        continue
                    link_target = (target.parent / m.linkname).resolve()
                    dest_resolved = str(dest.resolve())
                    if (
                        not str(link_target).startswith(dest_resolved + os.sep)
                        and link_target != dest.resolve()
                    ):
                        logger.debug(
                            "Skipping symlink escaping extraction dir: %s -> %s",
                            name,
                            m.linkname,
                        )
                        continue
                    if target.exists() or target.is_symlink():
                        target.unlink(missing_ok=True)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    os.symlink(m.linkname, target)
                # Skip: devices, FIFOs, hardlinks to outside dest
            except OSError as e:
                logger.debug("Could not extract %s: %s", name, e)

        return total_bytes, total_files

    @staticmethod
    def _is_safe_path(dest: Path, member_name: str) -> bool:
        """Return True if member_name resolves to a path inside dest."""
        if not member_name:
            return False
        # Reject any path component that is ".." before normalization
        parts = member_name.replace("\\", "/").split("/")
        if ".." in parts:
            return False
        # Resolve to catch any remaining traversal
        try:
            target = (dest / member_name).resolve()
            return str(target).startswith(str(dest.resolve()))
        except (OSError, ValueError):
            return False
