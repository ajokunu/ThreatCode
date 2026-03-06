"""OS-specific vulnerability advisory downloaders."""

from __future__ import annotations

import json
import logging
import urllib.request
from typing import Any

from threatcode.engine.vulns.db import VulnDB

logger = logging.getLogger(__name__)

# Alpine SecDB branches
_ALPINE_BRANCHES = ["v3.16", "v3.17", "v3.18", "v3.19", "v3.20", "edge"]
_ALPINE_SECDB_BASE = "https://secdb.alpinelinux.org"

# Debian Security Tracker
_DEBIAN_TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"
_DEBIAN_RELEASES = {
    "buster": "10",
    "bullseye": "11",
    "bookworm": "12",
    "trixie": "13",
}

# Ubuntu CVE tracker
_UBUNTU_CVE_URL = "https://people.canonical.com/~ubuntu-security/cve/nvd/nvd-database.json"
_UBUNTU_RELEASES = {
    "focal": "20.04",
    "jammy": "22.04",
    "lunar": "23.04",
    "mantic": "23.10",
    "noble": "24.04",
}

# Amazon Linux ALAS
_ALAS_URLS = {
    "amzn": {
        "2": "https://alas.aws.amazon.com/alas2.rss",
        "2023": "https://alas.aws.amazon.com/alas2023.rss",
    },
}

_CVSS_SEVERITY = {
    range(90, 101): "critical",  # 9.0-10.0
    range(70, 90): "high",  # 7.0-8.9
    range(40, 70): "medium",  # 4.0-6.9
    range(0, 40): "low",  # 0.0-3.9
}


def _cvss_to_severity(score: float) -> str:
    scaled = int(score * 10)
    for r, sev in _CVSS_SEVERITY.items():
        if scaled in r:
            return sev
    return "medium"


def _fetch_json(url: str, timeout: int = 60) -> Any:
    """Download JSON from a URL."""
    req = urllib.request.Request(url, headers={"User-Agent": "ThreatCode/0.7.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


class OSAdvisoryDownloader:
    """Download and store OS-specific vulnerability advisories."""

    def __init__(self, db: VulnDB) -> None:
        self._db = db
        self._db.init_db()

    def update_all(self) -> dict[str, int]:
        """Download advisories for all supported OS families."""
        counts: dict[str, int] = {}
        for name, method in [
            ("alpine", self.update_alpine),
            ("debian", self.update_debian),
        ]:
            try:
                counts[name] = method()
            except Exception as e:
                logger.warning("Failed to update %s advisories: %s", name, e)
                counts[name] = 0
        return counts

    def update_alpine(self) -> int:
        """Download Alpine SecDB advisories for all supported branches."""
        total = 0
        for branch in _ALPINE_BRANCHES:
            # The version is the branch without leading "v"
            os_version = branch.lstrip("v")
            url = f"{_ALPINE_SECDB_BASE}/{branch}/main.json"
            try:
                data = _fetch_json(url)
            except Exception as e:
                logger.debug("Could not fetch Alpine SecDB %s: %s", branch, e)
                continue

            records = _parse_alpine_secdb(data, os_version=os_version)
            count = self._db.bulk_insert_os(records)
            total += count
            logger.debug("Alpine %s: %d advisories", branch, count)

            # Also fetch community repo
            url2 = f"{_ALPINE_SECDB_BASE}/{branch}/community.json"
            try:
                data2 = _fetch_json(url2)
                records2 = _parse_alpine_secdb(data2, os_version=os_version)
                count2 = self._db.bulk_insert_os(records2)
                total += count2
            except Exception:
                pass

        return total

    def update_debian(self) -> int:
        """Download Debian Security Tracker advisories."""
        try:
            data = _fetch_json(_DEBIAN_TRACKER_URL, timeout=120)
        except Exception as e:
            logger.warning("Could not fetch Debian Security Tracker: %s", e)
            return 0

        records = _parse_debian_tracker(data)
        return self._db.bulk_insert_os(records)


def _parse_alpine_secdb(data: Any, os_version: str) -> list[dict[str, Any]]:
    """Parse Alpine SecDB JSON into advisory records.

    Format:
    {
      "packages": [
        {
          "pkg": {
            "name": "openssl",
            "secfixes": {
              "3.1.4-r0": ["CVE-2023-5363", "CVE-2023-5678"],
              "3.1.3-r1": ["CVE-2023-4807"]
            }
          }
        }
      ]
    }
    """
    records: list[dict[str, Any]] = []
    if not isinstance(data, dict):
        return records

    for entry in data.get("packages", []):
        if not isinstance(entry, dict):
            continue
        pkg = entry.get("pkg", {})
        pkg_name = pkg.get("name", "")
        secfixes = pkg.get("secfixes", {})
        if not isinstance(secfixes, dict):
            continue

        for fixed_version, cve_list in secfixes.items():
            if not isinstance(cve_list, list):
                continue
            for cve in cve_list:
                cve_str = str(cve).strip()
                if not cve_str or cve_str.startswith("X-"):
                    continue
                records.append(
                    {
                        "id": cve_str,
                        "os_family": "alpine",
                        "os_version": os_version,
                        "package": pkg_name,
                        "version_fixed": fixed_version,
                        "severity": "medium",
                        "cvss_score": 0.0,
                        "summary": f"{cve_str} in {pkg_name}",
                    }
                )
    return records


def _parse_debian_tracker(data: Any) -> list[dict[str, Any]]:
    """Parse Debian Security Tracker JSON.

    Format:
    {
      "CVE-2024-1234": {
        "description": "...",
        "releases": {
          "bookworm": {
            "status": "resolved",
            "fixed_version": "1.2.3-1",
            "urgency": "medium"
          }
        }
      }
    }
    """
    records: list[dict[str, Any]] = []
    if not isinstance(data, dict):
        return records

    for cve_id, cve_data in data.items():
        if not isinstance(cve_data, dict):
            continue
        description = cve_data.get("description", "")[:500]
        releases = cve_data.get("releases", {})
        if not isinstance(releases, dict):
            continue

        for codename, rel_data in releases.items():
            if not isinstance(rel_data, dict):
                continue
            os_version = _DEBIAN_RELEASES.get(codename, codename)
            status = rel_data.get("status", "")
            fixed_version = rel_data.get("fixed_version", "")
            urgency = rel_data.get("urgency", "unimportant")

            # Only report if resolved (fixed) or still open
            if status not in ("resolved", "open", "undetermined"):
                continue

            # Map urgency to severity
            severity = {
                "unimportant": "info",
                "low": "low",
                "low*": "low",
                "medium": "medium",
                "medium*": "medium",
                "high": "high",
                "high*": "high",
            }.get(urgency.lower(), "medium")

            # Get affected package from the scope key
            # Debian tracker wraps CVEs per source package separately
            pkg = cve_data.get("scope", cve_id)

            records.append(
                {
                    "id": cve_id,
                    "os_family": "debian",
                    "os_version": os_version,
                    "package": pkg,
                    "version_fixed": fixed_version,
                    "severity": severity,
                    "cvss_score": 0.0,
                    "summary": description,
                }
            )

    return records
