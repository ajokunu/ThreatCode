"""Tests for OS package database parsers."""

from __future__ import annotations

import struct

from threatcode.image.packages.apk import parse_apk_db
from threatcode.image.packages.dpkg import parse_dpkg_status, parse_dpkg_status_d
from threatcode.image.packages.rpm import _TAG_NAME, _TAG_VERSION, _TYPE_STRING, _parse_rpm_header

_APK_SAMPLE = """\
C:Q1abcdef1234567890abcdef==
P:musl
V:1.2.4-r2
A:x86_64
o:musl
L:MIT
T:The musl c library (libc) implementation

C:Q1xyz987654321abcdef==
P:openssl
V:3.1.4-r5
A:x86_64
o:openssl
L:OpenSSL
T:Toolkit for TLS

C:Q1zzz000==
P:zlib
V:1.3.1-r0
A:x86_64
L:zlib
T:A compression library

"""

_DPKG_SAMPLE = """\
Package: bash
Version: 5.2.21-2
Architecture: amd64
Status: install ok installed
Source: bash

Package: old-pkg
Version: 1.0.0
Architecture: amd64
Status: deinstall ok config-files

Package: libssl3
Version: 3.0.11-1~deb12u2
Architecture: amd64
Status: install ok installed
Source: openssl (3.0.11)

"""


class TestAPKParser:
    def test_parses_packages(self) -> None:
        pkgs = parse_apk_db(_APK_SAMPLE)
        assert len(pkgs) == 3

    def test_package_fields(self) -> None:
        pkgs = parse_apk_db(_APK_SAMPLE)
        musl = next(p for p in pkgs if p.name == "musl")
        assert musl.version == "1.2.4-r2"
        assert musl.arch == "x86_64"
        assert musl.source_name == "musl"
        assert musl.license == "MIT"

    def test_source_defaults_to_name(self) -> None:
        content = "P:zlib\nV:1.3.1-r0\nA:x86_64\n\n"
        pkgs = parse_apk_db(content)
        assert pkgs[0].source_name == "zlib"

    def test_empty_content(self) -> None:
        assert parse_apk_db("") == []


class TestDPKGParser:
    def test_parses_installed(self) -> None:
        pkgs = parse_dpkg_status(_DPKG_SAMPLE)
        names = [p.name for p in pkgs]
        assert "bash" in names
        assert "libssl3" in names
        # deinstalled package excluded
        assert "old-pkg" not in names

    def test_source_with_version(self) -> None:
        pkgs = parse_dpkg_status(_DPKG_SAMPLE)
        libssl = next(p for p in pkgs if p.name == "libssl3")
        assert libssl.source_name == "openssl"
        assert libssl.source_version == "3.0.11"

    def test_source_defaults_to_package_name(self) -> None:
        pkgs = parse_dpkg_status(_DPKG_SAMPLE)
        bash = next(p for p in pkgs if p.name == "bash")
        assert bash.source_name == "bash"

    def test_empty_content(self) -> None:
        assert parse_dpkg_status("") == []


class TestDPKGStatusD:
    def test_parses_status_d(self, tmp_path: object) -> None:
        from pathlib import Path

        d = Path(str(tmp_path)) / "status.d"
        d.mkdir()
        (d / "bash").write_text("Package: bash\nVersion: 5.1.16-1\nArchitecture: amd64\n")
        pkgs = parse_dpkg_status_d(d)
        assert len(pkgs) == 1
        assert pkgs[0].name == "bash"
        assert pkgs[0].version == "5.1.16-1"


class TestRPMHeaderParser:
    def _make_rpm_header(self, name: str, version: str) -> bytes:
        """Build a minimal synthetic RPM header blob."""
        magic = b"\x8e\xad\xe8\x01\x00\x00\x00\x00"
        tags = [
            (_TAG_NAME, _TYPE_STRING, name.encode() + b"\x00"),
            (_TAG_VERSION, _TYPE_STRING, version.encode() + b"\x00"),
        ]
        store = b""
        entries = b""
        for tag, typ, data in tags:
            offset = len(store)
            store += data
            entries += struct.pack(">IIII", tag, typ, offset, 1)

        nindex = len(tags)
        hsize = len(store)
        header = magic + struct.pack(">II", nindex, hsize) + entries + store
        return header

    def test_parse_name_and_version(self) -> None:
        blob = self._make_rpm_header("openssl-libs", "3.0.7")
        pkg = _parse_rpm_header(blob)
        assert pkg is not None
        assert pkg.name == "openssl-libs"
        assert pkg.version == "3.0.7"

    def test_missing_magic_returns_none(self) -> None:
        assert _parse_rpm_header(b"\x00" * 64) is None

    def test_empty_bytes_returns_none(self) -> None:
        assert _parse_rpm_header(b"") is None
