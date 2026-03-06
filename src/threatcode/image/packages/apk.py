"""Alpine APK package database parser."""

from __future__ import annotations

from threatcode.image.packages import OSPackage


def parse_apk_db(content: str) -> list[OSPackage]:
    """Parse /lib/apk/db/installed.

    Format: single-letter keys (P=name, V=version, A=arch, o=origin, L=license).
    Packages are delimited by blank lines.
    """
    packages: list[OSPackage] = []
    current: dict[str, str] = {}

    for line in content.splitlines():
        if not line.strip():
            # Blank line = end of package block
            if "P" in current:
                name = current.get("P", "")
                version = current.get("V", "")
                packages.append(
                    OSPackage(
                        name=name,
                        version=version,
                        arch=current.get("A", ""),
                        source_name=current.get("o", name),
                        source_version=version,
                        license=current.get("L", ""),
                    )
                )
            current = {}
            continue

        if len(line) >= 2 and line[1] == ":":
            key = line[0]
            value = line[2:]
            current[key] = value

    # Handle file with no trailing newline
    if "P" in current:
        name = current.get("P", "")
        version = current.get("V", "")
        packages.append(
            OSPackage(
                name=name,
                version=version,
                arch=current.get("A", ""),
                source_name=current.get("o", name),
                source_version=version,
                license=current.get("L", ""),
            )
        )

    return packages
