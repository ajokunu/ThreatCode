"""CycloneDX 1.5 SBOM output formatter."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from threatcode import __version__


def _make_purl(ecosystem: str, name: str, version: str) -> str:
    """Generate Package URL (PURL) identifier."""
    purl_type_map = {
        "npm": "npm",
        "pypi": "pypi",
        "go": "golang",
        "crates.io": "cargo",
        "rubygems": "gem",
        "packagist": "composer",
    }
    purl_type = purl_type_map.get(ecosystem, ecosystem)

    # Handle scoped npm packages
    if purl_type == "npm" and name.startswith("@"):
        parts = name.split("/", 1)
        if len(parts) == 2:
            return f"pkg:{purl_type}/{parts[0]}/{parts[1]}@{version}"

    # Handle Go modules
    if purl_type == "golang" and "/" in name:
        return f"pkg:{purl_type}/{name}@{version}"

    return f"pkg:{purl_type}/{name}@{version}"


def format_cyclonedx(
    dependencies: list[dict[str, Any]],
    *,
    source_path: str = "",
    vulnerabilities: list[dict[str, Any]] | None = None,
) -> str:
    """Generate CycloneDX 1.5 JSON SBOM from parsed dependencies.

    Args:
        dependencies: List of dicts with keys: name, version, ecosystem, license
        source_path: Path to the source lockfile
        vulnerabilities: Optional vulnerability findings to include
    """
    serial = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    components: list[dict[str, Any]] = []
    dep_list: list[dict[str, Any]] = []

    for dep in dependencies:
        name = dep.get("name", "")
        version = dep.get("version", "")
        ecosystem = dep.get("ecosystem", "")
        license_id = dep.get("license", "")

        if not name or not version:
            continue

        purl = _make_purl(ecosystem, name, version)
        bom_ref = purl

        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": bom_ref,
            "name": name,
            "version": version,
            "purl": purl,
        }

        if license_id:
            component["licenses"] = [{"license": {"id": license_id}}]

        # Add ecosystem as property
        component["properties"] = [
            {"name": "ecosystem", "value": ecosystem},
        ]

        components.append(component)
        dep_list.append({"ref": bom_ref, "dependsOn": []})

    sbom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "threatcode",
                        "version": __version__,
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": source_path or "unknown",
                "bom-ref": "root-component",
            },
        },
        "components": components,
        "dependencies": dep_list,
    }

    # Add vulnerabilities if provided
    if vulnerabilities:
        vuln_entries: list[dict[str, Any]] = []
        for v in vulnerabilities:
            vuln_entry: dict[str, Any] = {
                "id": v.get("cve_id", v.get("id", "")),
                "source": {
                    "name": "ThreatCode",
                    "url": "https://github.com/threatcode",
                },
                "description": v.get("title", ""),
                "affects": [
                    {
                        "ref": _make_purl(
                            v.get("ecosystem", ""),
                            v.get("package_name", ""),
                            v.get("package_version", ""),
                        ),
                    }
                ],
            }

            # Add ratings
            cvss = v.get("cvss_score", 0.0)
            if cvss > 0:
                vuln_entry["ratings"] = [
                    {
                        "score": cvss,
                        "severity": v.get("severity", "medium"),
                        "method": "CVSSv3",
                    }
                ]

            vuln_entries.append(vuln_entry)

        sbom["vulnerabilities"] = vuln_entries

    return json.dumps(sbom, indent=2)
