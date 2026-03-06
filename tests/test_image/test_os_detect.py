"""Tests for OS detection from container image filesystems."""

from __future__ import annotations

import io
import tarfile

from threatcode.image.layer import LayerExtractor
from threatcode.image.os_detect import OSDetector


def make_image_with_file(path: str, content: str) -> object:
    """Helper: create an ExtractedImage with a single file."""
    blob_buf = io.BytesIO()
    data = content.encode("utf-8")
    with tarfile.open(fileobj=blob_buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name=path)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    extractor = LayerExtractor()
    return extractor.extract_from_blobs([blob_buf.getvalue()], config={})


class TestOSDetector:
    def test_alpine_from_os_release(self) -> None:
        content = 'ID=alpine\nNAME="Alpine Linux"\nVERSION_ID=3.19.1\n'
        img = make_image_with_file("etc/os-release", content)
        try:
            info = OSDetector().detect(img)
            assert info is not None
            assert info.family == "alpine"
            assert info.version == "3.19.1"
            assert info.pkg_manager == "apk"
        finally:
            img.cleanup()

    def test_debian_from_os_release(self) -> None:
        content = 'ID=debian\nNAME="Debian GNU/Linux"\nVERSION_ID=12\nVERSION_CODENAME=bookworm\n'
        img = make_image_with_file("etc/os-release", content)
        try:
            info = OSDetector().detect(img)
            assert info is not None
            assert info.family == "debian"
            assert info.version_codename == "bookworm"
            assert info.pkg_manager == "dpkg"
        finally:
            img.cleanup()

    def test_ubuntu_from_os_release(self) -> None:
        content = "ID=ubuntu\nNAME=Ubuntu\nVERSION_ID=22.04\nVERSION_CODENAME=jammy\n"
        img = make_image_with_file("etc/os-release", content)
        try:
            info = OSDetector().detect(img)
            assert info is not None
            assert info.family == "ubuntu"
            assert info.version == "22.04"
            assert info.pkg_manager == "dpkg"
        finally:
            img.cleanup()

    def test_rhel_from_os_release(self) -> None:
        content = 'ID="rhel"\nNAME="Red Hat Enterprise Linux"\nVERSION_ID=9.3\n'
        img = make_image_with_file("etc/os-release", content)
        try:
            info = OSDetector().detect(img)
            assert info is not None
            assert info.family == "rhel"
            assert info.pkg_manager == "rpm"
        finally:
            img.cleanup()

    def test_amazon_linux_from_os_release(self) -> None:
        content = 'ID="amzn"\nNAME="Amazon Linux"\nVERSION_ID=2023\n'
        img = make_image_with_file("etc/os-release", content)
        try:
            info = OSDetector().detect(img)
            assert info is not None
            assert info.family == "amzn"
            assert info.pkg_manager == "rpm"
        finally:
            img.cleanup()

    def test_alpine_from_alpine_release_file(self) -> None:
        img = make_image_with_file("etc/alpine-release", "3.18.4\n")
        try:
            info = OSDetector().detect(img)
            assert info is not None
            assert info.family == "alpine"
            assert info.version == "3.18.4"
            assert info.pkg_manager == "apk"
        finally:
            img.cleanup()

    def test_debian_from_debian_version_file(self) -> None:
        img = make_image_with_file("etc/debian_version", "12.2\n")
        try:
            info = OSDetector().detect(img)
            assert info is not None
            assert info.family == "debian"
            assert info.pkg_manager == "dpkg"
        finally:
            img.cleanup()

    def test_unknown_os_returns_none(self) -> None:
        # Image with no OS identification files
        extractor = LayerExtractor()
        img = extractor.extract_from_blobs([], config={})
        try:
            info = OSDetector().detect(img)
            assert info is None
        finally:
            img.cleanup()

    def test_wolfi_is_apk(self) -> None:
        content = 'ID=wolfi\nNAME="Wolfi"\nVERSION_ID=20230201\n'
        img = make_image_with_file("etc/os-release", content)
        try:
            info = OSDetector().detect(img)
            assert info is not None
            assert info.pkg_manager == "apk"
        finally:
            img.cleanup()

    def test_id_like_debian_gives_dpkg(self) -> None:
        content = 'ID=linuxmint\nID_LIKE=debian\nNAME="Linux Mint"\nVERSION_ID=21\n'
        img = make_image_with_file("etc/os-release", content)
        try:
            info = OSDetector().detect(img)
            assert info is not None
            assert info.pkg_manager == "dpkg"
        finally:
            img.cleanup()
