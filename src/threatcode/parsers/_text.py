"""Read an input file as text: size cap, BOM sniffing, strict UTF-8, empty-file check.

Every parser entry point reads files through ``decode_input`` so that a file with a
byte order mark, a UTF-16 file written by PowerShell redirection, a binary file or an
empty file behaves the same for every format instead of surfacing as a raw
``UnicodeDecodeError`` or a misleading "cannot detect format".
"""

from __future__ import annotations

import codecs
from pathlib import Path

from threatcode.exceptions import ParseError

# Reject input files larger than 50 MB to prevent resource exhaustion
MAX_INPUT_SIZE_BYTES = 50 * 1024 * 1024

# (byte order mark, Python codec, label for messages). The UTF-32 marks must come before
# the UTF-16 marks because the UTF-32 LE mark starts with the UTF-16 LE mark. The
# "utf-16" and "utf-32" codecs consume the mark and pick the byte order from it, and
# "utf-8-sig" drops the mark.
_BOMS: tuple[tuple[bytes, str, str], ...] = (
    (codecs.BOM_UTF32_LE, "utf-32", "UTF-32"),
    (codecs.BOM_UTF32_BE, "utf-32", "UTF-32"),
    (codecs.BOM_UTF8, "utf-8-sig", "UTF-8"),
    (codecs.BOM_UTF16_LE, "utf-16", "UTF-16"),
    (codecs.BOM_UTF16_BE, "utf-16", "UTF-16"),
)


def _too_large(name: str, size: int) -> ParseError:
    return ParseError(
        f"Input file {name} is {size / 1024 / 1024:.1f} MB, "
        f"exceeding the {MAX_INPUT_SIZE_BYTES // 1024 // 1024} MB limit."
    )


def decode_bytes(raw: bytes, name: str) -> str:
    """Decode input bytes to text, honouring a BOM and otherwise requiring UTF-8.

    Raises:
        ParseError: The bytes are not valid text in the detected encoding.
    """
    encoding, label = "utf-8", "UTF-8"
    for bom, codec, bom_label in _BOMS:
        if raw.startswith(bom):
            encoding, label = codec, bom_label
            break
    try:
        text = raw.decode(encoding)
    except UnicodeDecodeError as exc:
        raise ParseError(f"{name} is not valid {label} text (is it a binary file?)") from exc
    if encoding == "utf-8" and "\x00" in text:
        # Valid UTF-8 never needs NUL; a NUL means binary data or UTF-16 without a BOM.
        raise ParseError(
            f"{name} is not valid UTF-8 text (it contains NUL bytes; "
            "is it a binary file or UTF-16 without a byte order mark?)"
        )
    return text


def decode_input(path: Path, *, allow_empty: bool = False) -> str:
    """Read ``path`` and return its text.

    Args:
        path: File to read.
        allow_empty: Return an empty or whitespace-only file as is. Directory loading
            sets this because an empty ``outputs.tf`` is normal in a Terraform module.

    Raises:
        FileNotFoundError: ``path`` does not exist.
        ParseError: The file is over the size cap, unreadable, not valid text, or empty.
    """
    try:
        size = path.stat().st_size
        if size > MAX_INPUT_SIZE_BYTES:
            raise _too_large(path.name, size)
        with path.open("rb") as handle:
            raw = handle.read(MAX_INPUT_SIZE_BYTES + 1)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ParseError(f"Cannot read {path.name}: {exc.strerror or exc}") from exc
    if len(raw) > MAX_INPUT_SIZE_BYTES:
        raise _too_large(path.name, len(raw))

    text = decode_bytes(raw, path.name)
    if not allow_empty and not text.strip():
        raise ParseError(f"file is empty: {path.name}")
    return text
