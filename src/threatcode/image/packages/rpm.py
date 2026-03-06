"""RPM package database parser (SQLite and BerkeleyDB Hash formats)."""

from __future__ import annotations

import logging
import sqlite3
import struct
from pathlib import Path

from threatcode.image.packages import OSPackage

logger = logging.getLogger(__name__)

# RPM header magic bytes
_HEADER_MAGIC = b"\x8e\xad\xe8\x01"

# RPM tag numbers
_TAG_NAME = 1000
_TAG_VERSION = 1001
_TAG_RELEASE = 1002
_TAG_EPOCH = 1003
_TAG_LICENSE = 1014
_TAG_ARCH = 1022
_TAG_SOURCE_RPM = 1044

# RPM data types
_TYPE_STRING = 6
_TYPE_INT32 = 4

# BerkeleyDB Hash page type
_BDB_HASH_PAGE_TYPE = 13
# BerkeleyDB metadata magic
_BDB_META_MAGIC = 0x00061561


def _parse_rpm_header(blob: bytes) -> OSPackage | None:
    """Parse an RPM header binary blob into an OSPackage."""
    # Locate the header magic
    magic_idx = blob.find(_HEADER_MAGIC)
    if magic_idx < 0:
        return None

    pos = magic_idx + 8  # skip magic (4) + reserved (4)
    if pos + 8 > len(blob):
        return None

    nindex = struct.unpack(">I", blob[pos : pos + 4])[0]
    hsize = struct.unpack(">I", blob[pos + 4 : pos + 8])[0]
    pos += 8

    entries_end = pos + nindex * 16
    store_start = entries_end
    store_end = store_start + hsize
    if store_end > len(blob):
        return None

    store = blob[store_start:store_end]
    fields: dict[int, object] = {}

    for i in range(nindex):
        entry_pos = pos + i * 16
        if entry_pos + 16 > len(blob):
            break
        tag, typ, offset, _count = struct.unpack(">IIII", blob[entry_pos : entry_pos + 16])

        if tag not in (
            _TAG_NAME,
            _TAG_VERSION,
            _TAG_RELEASE,
            _TAG_EPOCH,
            _TAG_LICENSE,
            _TAG_ARCH,
            _TAG_SOURCE_RPM,
        ):
            continue

        if typ == _TYPE_STRING:
            if offset < len(store):
                null_pos = store.find(b"\x00", offset)
                if null_pos < 0:
                    null_pos = len(store)
                fields[tag] = store[offset:null_pos].decode("utf-8", errors="replace")

        elif typ == _TYPE_INT32:
            if offset + 4 <= len(store):
                fields[tag] = struct.unpack(">I", store[offset : offset + 4])[0]

    name = str(fields.get(_TAG_NAME, ""))
    if not name:
        return None

    version = str(fields.get(_TAG_VERSION, ""))
    release = str(fields.get(_TAG_RELEASE, ""))
    epoch_raw = fields.get(_TAG_EPOCH, 0)
    epoch = int(epoch_raw) if isinstance(epoch_raw, int) else 0
    arch = str(fields.get(_TAG_ARCH, ""))
    source_rpm = str(fields.get(_TAG_SOURCE_RPM, ""))
    license_str = str(fields.get(_TAG_LICENSE, ""))

    # Derive source name from source RPM filename
    # e.g. "openssl-3.0.7-2.el9.src.rpm" → "openssl"
    source_name = name
    source_version = version
    if source_rpm:
        # Strip .src.rpm suffix and parse NEVR
        srpm = source_rpm.removesuffix(".src.rpm")
        # NEVR format: name-version-release (name may contain hyphens)
        parts = srpm.rsplit("-", 2)
        if len(parts) >= 3:
            source_name = parts[0]
            source_version = parts[1]

    return OSPackage(
        name=name,
        version=version,
        release=release,
        epoch=epoch,
        arch=arch,
        source_name=source_name,
        source_version=source_version,
        license=license_str,
    )


def _parse_sqlite_rpm_db(db_path: Path) -> list[OSPackage]:
    """Parse an RPM SQLite database (RHEL 9+, Fedora 33+)."""
    packages: list[OSPackage] = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            for (blob,) in conn.execute("SELECT blob FROM Packages"):
                if not isinstance(blob, bytes):
                    continue
                pkg = _parse_rpm_header(blob)
                if pkg:
                    packages.append(pkg)
        finally:
            conn.close()
    except (sqlite3.Error, OSError) as e:
        logger.debug("Could not read RPM SQLite DB at %s: %s", db_path, e)
    return packages


def _iter_bdb_hash_values(data: bytes) -> list[bytes]:
    """Extract all value blobs from a BerkeleyDB Hash v9 file.

    Returns a list of RPM header blobs (values only, keys are integers).
    """
    blobs: list[bytes] = []

    if len(data) < 512:
        return blobs

    # Read pagesize from metadata page (offset 20, 4 bytes, little-endian)
    try:
        pagesize = struct.unpack("<I", data[20:24])[0]
        if pagesize < 512 or pagesize > 65536:
            pagesize = 4096
    except struct.error:
        pagesize = 4096

    num_pages = len(data) // pagesize
    for page_num in range(1, num_pages):
        page_start = page_num * pagesize
        page = data[page_start : page_start + pagesize]
        if len(page) < 26:
            continue

        # Page type is at byte 25 (0-indexed)
        page_type = page[25]
        if page_type != _BDB_HASH_PAGE_TYPE:
            continue

        # Number of entries on page: bytes 20-21 (little-endian uint16)
        num_entries = struct.unpack("<H", page[20:22])[0]
        if num_entries == 0:
            continue

        # Entry offsets start at byte 26, each 2 bytes (little-endian)
        # Entries come in key-data pairs so iterate in steps of 2
        offsets: list[int] = []
        for i in range(num_entries):
            offset_pos = 26 + i * 2
            if offset_pos + 2 > len(page):
                break
            offset = struct.unpack("<H", page[offset_pos : offset_pos + 2])[0]
            offsets.append(offset)

        # Process data entries (every other entry, starting at index 1)
        for i in range(1, len(offsets), 2):
            off = offsets[i]
            if off + 3 > pagesize:
                continue
            # Entry: len(2) + type(1) + data(len)
            try:
                entry_len = struct.unpack("<H", page[off : off + 2])[0]
                entry_type = page[off + 2]
            except (struct.error, IndexError):
                continue

            if entry_type == 1:  # BKEYDATA
                blob_data = page[off + 3 : off + 3 + entry_len]
                if _HEADER_MAGIC in blob_data:
                    blobs.append(blob_data)

    return blobs


def _parse_bdb_rpm_db(db_path: Path) -> list[OSPackage]:
    """Parse an RPM BerkeleyDB Hash database (RHEL 7/8, Amazon Linux 2)."""
    packages: list[OSPackage] = []
    try:
        data = db_path.read_bytes()
    except OSError as e:
        logger.debug("Could not read RPM BDB at %s: %s", db_path, e)
        return packages

    blobs = _iter_bdb_hash_values(data)
    for blob in blobs:
        pkg = _parse_rpm_header(blob)
        if pkg:
            packages.append(pkg)

    return packages


def parse_rpm_db(root: Path) -> list[OSPackage]:
    """Parse RPM packages from an image filesystem root.

    Tries SQLite databases first (newer format), falls back to BerkeleyDB.
    """
    sqlite_paths = [
        root / "usr" / "lib" / "sysimage" / "rpm" / "rpmdb.sqlite",
        root / "var" / "lib" / "rpm" / "rpmdb.sqlite",
    ]
    for path in sqlite_paths:
        if path.is_file():
            logger.debug("Reading RPM SQLite DB: %s", path)
            pkgs = _parse_sqlite_rpm_db(path)
            if pkgs:
                return pkgs

    bdb_path = root / "var" / "lib" / "rpm" / "Packages"
    if bdb_path.is_file():
        logger.debug("Reading RPM BerkeleyDB: %s", bdb_path)
        pkgs = _parse_bdb_rpm_db(bdb_path)
        if pkgs:
            return pkgs
        logger.warning(
            "RPM BerkeleyDB at %s could not be parsed (format not supported); "
            "no OS packages will be reported.",
            bdb_path,
        )

    return []
