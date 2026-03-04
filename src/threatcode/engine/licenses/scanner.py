"""License compliance scanner."""

from __future__ import annotations

import uuid
from typing import Any

from threatcode.models.finding import LicenseFinding
from threatcode.models.threat import Severity

# SPDX license classifications
_PERMISSIVE_LICENSES = frozenset(
    {
        "MIT",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "0BSD",
        "Unlicense",
        "CC0-1.0",
        "Zlib",
        "BSL-1.0",
        "MIT-0",
        "Apache-1.1",
        "Artistic-2.0",
        "PostgreSQL",
        "PSF-2.0",
        "Python-2.0",
        "BlueOak-1.0.0",
    }
)

_WEAKLY_COPYLEFT_LICENSES = frozenset(
    {
        "LGPL-2.0-only",
        "LGPL-2.0-or-later",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "MPL-2.0",
        "EPL-1.0",
        "EPL-2.0",
        "CDDL-1.0",
        "CDDL-1.1",
        "CPL-1.0",
        "OSL-3.0",
    }
)

_COPYLEFT_LICENSES = frozenset(
    {
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "AGPL-1.0-only",
        "SSPL-1.0",
        "EUPL-1.1",
        "EUPL-1.2",
        "CC-BY-SA-4.0",
        "CC-BY-SA-3.0",
    }
)

_RESTRICTIVE_LICENSES = frozenset(
    {
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "AGPL-1.0-only",
        "SSPL-1.0",
    }
)


def classify_license(license_id: str) -> str:
    """Classify a license by its SPDX identifier.

    Returns: 'permissive', 'weakly_copyleft', 'copyleft', 'restrictive', or 'unknown'
    """
    if not license_id:
        return "unknown"

    # Normalize
    normalized = license_id.strip()

    if normalized in _PERMISSIVE_LICENSES:
        return "permissive"
    if normalized in _RESTRICTIVE_LICENSES:
        return "restrictive"
    if normalized in _COPYLEFT_LICENSES:
        return "copyleft"
    if normalized in _WEAKLY_COPYLEFT_LICENSES:
        return "weakly_copyleft"
    return "unknown"


_CLASSIFICATION_SEVERITY = {
    "permissive": Severity.INFO,
    "weakly_copyleft": Severity.LOW,
    "copyleft": Severity.MEDIUM,
    "restrictive": Severity.HIGH,
    "unknown": Severity.LOW,
}


class LicenseScanner:
    """Scan dependencies for license compliance issues."""

    def __init__(
        self,
        *,
        warn_copyleft: bool = True,
        alert_unknown: bool = True,
        alert_restrictive: bool = True,
    ) -> None:
        self.warn_copyleft = warn_copyleft
        self.alert_unknown = alert_unknown
        self.alert_restrictive = alert_restrictive

    def scan_dependencies(self, dependencies: list[dict[str, Any]]) -> list[LicenseFinding]:
        """Scan dependencies for license compliance.

        Args:
            dependencies: List of dicts with keys: name, version, ecosystem, license
        """
        findings: list[LicenseFinding] = []

        for dep in dependencies:
            name = dep.get("name", "")
            version = dep.get("version", "")
            ecosystem = dep.get("ecosystem", "")
            license_id = dep.get("license", "")

            if not name:
                continue

            classification = classify_license(license_id)

            # Decide whether to create a finding
            should_report = False
            title = ""

            if classification == "restrictive" and self.alert_restrictive:
                should_report = True
                title = f"Restrictive license: {license_id or 'unknown'}"
            elif classification == "copyleft" and self.warn_copyleft:
                should_report = True
                title = f"Copyleft license: {license_id}"
            elif classification == "unknown" and self.alert_unknown:
                should_report = True
                if license_id:
                    title = f"Unknown license classification: {license_id}"
                else:
                    title = "No license information available"
            elif classification == "weakly_copyleft" and self.warn_copyleft:
                should_report = True
                title = f"Weakly copyleft license: {license_id}"

            if should_report:
                severity = _CLASSIFICATION_SEVERITY.get(classification, Severity.LOW)
                finding = LicenseFinding(
                    id=f"LIC-{uuid.uuid4().hex[:8]}",
                    title=title,
                    severity=severity,
                    package_name=name,
                    package_version=version,
                    ecosystem=ecosystem,
                    license_id=license_id,
                    license_name=license_id,  # Use SPDX ID as name for now
                    metadata={"classification": classification},
                )
                findings.append(finding)

        return findings
