"""Tests for OCI layer extraction."""

from __future__ import annotations

import io
import tarfile

import pytest

from threatcode.image.layer import LayerExtractor


def make_tar_gz(files: dict[str, bytes], dirs: list[str] | None = None) -> bytes:
    """Create an in-memory .tar.gz with the given files."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for d in dirs or []:
            info = tarfile.TarInfo(name=d)
            info.type = tarfile.DIRTYPE
            tar.addfile(info)
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


class TestLayerExtractor:
    def test_basic_extraction(self, tmp_path: object) -> None:
        blob = make_tar_gz({"etc/passwd": b"root:x:0:0", "usr/bin/app": b"\x7fELF"})
        extractor = LayerExtractor()
        result = extractor.extract_from_blobs([blob], config={})
        try:
            assert result.file_exists("etc/passwd")
            assert result.file_exists("usr/bin/app")
            assert result.read_file("etc/passwd") == b"root:x:0:0"
        finally:
            result.cleanup()

    def test_layer_ordering_later_overwrites(self) -> None:
        layer1 = make_tar_gz({"app/config.txt": b"version=1"})
        layer2 = make_tar_gz({"app/config.txt": b"version=2"})
        extractor = LayerExtractor()
        result = extractor.extract_from_blobs([layer1, layer2], config={})
        try:
            assert result.read_file("app/config.txt") == b"version=2"
        finally:
            result.cleanup()

    def test_regular_whiteout_deletes_file(self) -> None:
        layer1 = make_tar_gz({"etc/secret.txt": b"secret"})
        layer2 = make_tar_gz({"etc/.wh.secret.txt": b""})
        extractor = LayerExtractor()
        result = extractor.extract_from_blobs([layer1, layer2], config={})
        try:
            assert not result.file_exists("etc/secret.txt")
        finally:
            result.cleanup()

    def test_opaque_whiteout_clears_directory(self) -> None:
        layer1 = make_tar_gz(
            {
                "etc/old_file.txt": b"old",
                "etc/another.txt": b"also old",
            }
        )
        layer2 = make_tar_gz(
            {
                "etc/.wh..wh..opq": b"",
                "etc/new_file.txt": b"new",
            }
        )
        extractor = LayerExtractor()
        result = extractor.extract_from_blobs([layer1, layer2], config={})
        try:
            assert not result.file_exists("etc/old_file.txt")
            assert not result.file_exists("etc/another.txt")
            assert result.file_exists("etc/new_file.txt")
        finally:
            result.cleanup()

    def test_path_traversal_blocked(self) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info = tarfile.TarInfo(name="../../etc/passwd")
            info.size = 6
            tar.addfile(info, io.BytesIO(b"hacked"))
        blob = buf.getvalue()
        extractor = LayerExtractor()
        result = extractor.extract_from_blobs([blob], config={})
        try:
            # Traversal entry must not land as etc/passwd inside the image root
            assert not result.file_exists("etc/passwd")
            # file_exists with a traversal path must not escape the root
            # (on Linux /etc/passwd exists on the host — this must still return False)
            assert not result.file_exists("../../etc/passwd")
        finally:
            result.cleanup()

    def test_empty_layer_is_fine(self) -> None:
        blob = make_tar_gz({})
        extractor = LayerExtractor()
        result = extractor.extract_from_blobs([blob], config={})
        try:
            assert result.layer_count == 1
        finally:
            result.cleanup()

    def test_cleanup_removes_temp_dir(self) -> None:
        blob = make_tar_gz({"file.txt": b"hello"})
        extractor = LayerExtractor()
        result = extractor.extract_from_blobs([blob], config={})
        root = result.root
        assert root.exists()
        result.cleanup()
        assert not root.exists()

    def test_read_text(self) -> None:
        blob = make_tar_gz({"config.yml": b"key: value\n"})
        extractor = LayerExtractor()
        result = extractor.extract_from_blobs([blob], config={})
        try:
            text = result.read_text("config.yml")
            assert text == "key: value\n"
        finally:
            result.cleanup()

    def test_file_exists_false_for_missing(self) -> None:
        blob = make_tar_gz({"exists.txt": b"yes"})
        extractor = LayerExtractor()
        result = extractor.extract_from_blobs([blob], config={})
        try:
            assert not result.file_exists("missing.txt")
        finally:
            result.cleanup()

    def test_absolute_symlink_blocked(self) -> None:
        """Absolute symlinks should be rejected."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info = tarfile.TarInfo(name="etc/evil_link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tar.addfile(info)
        blob = buf.getvalue()
        extractor = LayerExtractor()
        result = extractor.extract_from_blobs([blob], config={})
        try:
            assert not result.file_exists("etc/evil_link")
        finally:
            result.cleanup()

    def test_relative_symlink_escape_blocked(self) -> None:
        """Relative symlinks that escape the extraction dir should be rejected."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            # Create a directory first
            d = tarfile.TarInfo(name="app/")
            d.type = tarfile.DIRTYPE
            tar.addfile(d)
            # Symlink that tries to go up and out
            info = tarfile.TarInfo(name="app/escape_link")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../../etc/passwd"
            tar.addfile(info)
        blob = buf.getvalue()
        extractor = LayerExtractor()
        result = extractor.extract_from_blobs([blob], config={})
        try:
            assert not result.file_exists("app/escape_link")
        finally:
            result.cleanup()

    @pytest.mark.skipif(
        __import__("sys").platform == "win32",
        reason="Symlink creation requires elevated privileges on Windows",
    )
    def test_valid_relative_symlink_allowed(self) -> None:
        """Relative symlinks within the extraction dir should work."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            # Create target file
            info = tarfile.TarInfo(name="app/target.txt")
            info.size = 5
            tar.addfile(info, io.BytesIO(b"hello"))
            # Create symlink to sibling
            link = tarfile.TarInfo(name="app/link.txt")
            link.type = tarfile.SYMTYPE
            link.linkname = "target.txt"
            tar.addfile(link)
        blob = buf.getvalue()
        extractor = LayerExtractor()
        result = extractor.extract_from_blobs([blob], config={})
        try:
            assert result.file_exists("app/target.txt")
            assert result.file_exists("app/link.txt")
        finally:
            result.cleanup()
