"""Helpers for resource addresses and source locations.

An address names one resource: `aws_vpc.main`, `module.net.aws_vpc.main`,
`aws_instance.app[0]`, `aws_s3_bucket.logs["eu west"]` or a CloudFormation
logical id such as `MyBucket`.
Index suffixes (`[0]`, `["key"]`) may follow any component, including a module
call (`module.net[0].aws_vpc.main`).
Quoted keys may contain dots and brackets, so the scanners here honour quotes.
"""

from __future__ import annotations

import re
from collections.abc import Container

_MAX_LINE_DIGITS = 9
_LOCATION_LINE = re.compile(r"^(?P<path>.+):(?P<line>\d+)$")


def _skip_bracket(text: str, start: int) -> int:
    """Return the index just after the `]` that closes the `[` at `start`.

    Returns -1 when the bracket is never closed.
    """
    quote = ""
    i = start + 1
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in ('"', "'"):
            quote = ch
        elif ch == "]":
            return i + 1
        i += 1
    return -1


def base_address(address: str) -> str:
    """Strip every `[index]` and `["key"]` from an address.

    `module.net[0].aws_subnet.a["x.y"]` becomes `module.net.aws_subnet.a`.
    An unterminated bracket is left in place.
    """
    if "[" not in address:
        return address
    out: list[str] = []
    i = 0
    while i < len(address):
        if address[i] == "[":
            end = _skip_bracket(address, i)
            if end != -1:
                i = end
                continue
            out.append(address[i:])
            break
        out.append(address[i])
        i += 1
    return "".join(out)


def _components(address: str) -> list[str]:
    """Split an address at the dots that are outside brackets, keeping indexes."""
    parts: list[str] = []
    current: list[str] = []
    i = 0
    while i < len(address):
        ch = address[i]
        if ch == "[":
            end = _skip_bracket(address, i)
            if end != -1:
                current.append(address[i:end])
                i = end
                continue
        if ch == ".":
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
        i += 1
    parts.append("".join(current))
    return parts


def _module_prefix_length(parts: list[str]) -> int:
    """Count the components taken by leading `module.<name>` pairs."""
    i = 0
    while i + 1 < len(parts) and parts[i] == "module":
        i += 2
    return i


def module_of(address: str) -> str:
    """Return the module path of an address, without indexes, or '' at the root.

    `module.a.module.b.aws_vpc.main` gives `module.a.module.b`.
    """
    parts = base_address(address).split(".")
    return ".".join(parts[: _module_prefix_length(parts)])


def strip_attribute_suffix(address: str, known: Container[str] | None = None) -> str:
    """Remove a trailing attribute from a reference such as `aws_vpc.main.id`.

    With `known`, the longest prefix of the address that is in `known` wins, so
    nothing is guessed; an address with no known prefix is returned unchanged.
    Without `known`, the Terraform shape is assumed: after any `module.<name>`
    pairs and an optional `data.`, a resource address is `type.name`, and
    whatever follows is an attribute.
    Indexes stay on the components they were written on.
    """
    parts = _components(address)
    if known is not None:
        for count in range(len(parts), 0, -1):
            candidate = ".".join(parts[:count])
            if candidate in known:
                return candidate
        return address
    start = _module_prefix_length(parts)
    if start < len(parts) and parts[start] == "data":
        start += 1
    keep = start + 2
    if keep >= len(parts):
        return address
    return ".".join(parts[:keep])


def split_location(location: str) -> tuple[str, int | None]:
    """Split a legacy `path:line` location into the path and the 1-based line.

    Only an all-digit tail counts as a line, so `C:\\work\\main.tf` stays whole
    and `C:\\work\\main.tf:7` splits into `C:\\work\\main.tf` and 7.
    """
    match = _LOCATION_LINE.match(location)
    if match is None:
        return location, None
    digits = match.group("line")
    if len(digits) > _MAX_LINE_DIGITS or int(digits) < 1:
        return location, None
    return match.group("path"), int(digits)
