"""OS-specific vulnerability advisory downloaders."""

from __future__ import annotations

import bz2
import json
import logging
import urllib.request
import xml.etree.ElementTree as ET
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

# Ubuntu OVAL data
_UBUNTU_RELEASES = {"bionic": "18.04", "focal": "20.04", "jammy": "22.04", "noble": "24.04"}
_UBUNTU_OVAL_BASE = "https://security-data.ubuntu.com/oval"

# Amazon Linux ALAS
_AMZN_RELEASES = {"AL2": "2", "AL2023": "2023"}

# Red Hat CVE API
_RHEL_VERSIONS = ["8", "9"]
_RHEL_API_BASE = "https://access.redhat.com/hydra/rest/securitydata"


def _cvss_to_severity(score: float) -> str:
    from threatcode.constants import cvss_to_severity as _cvss_sev

    return _cvss_sev(score).value


_MAX_RESPONSE_SIZE = 100 * 1024 * 1024  # 100 MB


def _fetch_json(url: str, timeout: int = 60) -> Any:
    """Download JSON from a URL."""
    from threatcode import __version__

    req = urllib.request.Request(url, headers={"User-Agent": f"ThreatCode/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(_MAX_RESPONSE_SIZE)
        return json.loads(data)


def _fetch_bytes(url: str, timeout: int = 120) -> bytes:
    """Download raw bytes from a URL."""
    from threatcode import __version__

    req = urllib.request.Request(url, headers={"User-Agent": f"ThreatCode/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read(_MAX_RESPONSE_SIZE)


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
            ("ubuntu", self.update_ubuntu),
            ("amzn", self.update_amazon_linux),
            ("rhel", self.update_rhel),
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
                logger.debug("Alpine community fetch failed for %s", branch, exc_info=True)

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

    def update_ubuntu(self) -> int:
        """Download Ubuntu OVAL advisory data."""
        total = 0
        for codename, version in _UBUNTU_RELEASES.items():
            url = f"{_UBUNTU_OVAL_BASE}/com.ubuntu.{codename}.cve.oval.xml.bz2"
            try:
                compressed = _fetch_bytes(url, timeout=180)
                xml_data = bz2.decompress(compressed)
            except Exception as e:
                logger.debug("Could not fetch Ubuntu OVAL %s: %s", codename, e)
                continue

            records = _parse_ubuntu_oval(xml_data, os_version=version)
            count = self._db.bulk_insert_os(records)
            total += count
            logger.debug("Ubuntu %s (%s): %d advisories", codename, version, count)
        return total

    def update_amazon_linux(self) -> int:
        """Download Amazon Linux ALAS advisory data."""
        total = 0
        urls = {
            "2": "https://alas.aws.amazon.com/AL2/alas.rss",
            "2023": "https://alas.aws.amazon.com/AL2023/alas.rss",
        }
        for version, url in urls.items():
            try:
                xml_data = _fetch_bytes(url, timeout=120)
            except Exception as e:
                logger.debug("Could not fetch Amazon Linux ALAS %s: %s", version, e)
                continue

            records = _parse_amzn_alas(xml_data, os_version=version)
            count = self._db.bulk_insert_os(records)
            total += count
            logger.debug("Amazon Linux %s: %d advisories", version, count)
        return total

    def update_rhel(self) -> int:
        """Download Red Hat CVE advisory data via API."""
        total = 0
        for version in _RHEL_VERSIONS:
            page = 1
            max_retries = 3
            all_entries: list[dict[str, Any]] = []
            while True:
                url = f"{_RHEL_API_BASE}/cve.json?per_page=500&page={page}"
                retries = 0
                data: list[dict[str, Any]] | None = None
                while retries < max_retries:
                    try:
                        data = _fetch_json(url, timeout=120)
                        break
                    except Exception:
                        retries += 1
                        if retries >= max_retries:
                            break
                if not data or not isinstance(data, list) or len(data) == 0:
                    break
                all_entries.extend(data)
                if len(data) < 500:
                    break
                page += 1

            records = _parse_rhel_cve_api(all_entries, os_version=version)
            count = self._db.bulk_insert_os(records)
            total += count
            logger.debug("RHEL %s: %d advisories", version, count)
        return total


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


def _parse_ubuntu_oval(xml_data: bytes, os_version: str) -> list[dict[str, Any]]:
    """Parse Ubuntu OVAL XML into advisory records.

    OVAL definitions contain CVE, package, fixed version, and severity info.
    """
    records: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError:
        return records

    # OVAL uses namespaces
    ns = {"oval": "http://oval.mitre.org/XMLSchema/oval-definitions-5"}

    for definition in root.iter("{http://oval.mitre.org/XMLSchema/oval-definitions-5}definition"):
        metadata = definition.find("oval:metadata", ns)
        if metadata is None:
            continue

        title_el = metadata.find("oval:title", ns)
        title = title_el.text if title_el is not None and title_el.text else ""

        # Extract CVE references
        cve_ids: list[str] = []
        for ref in metadata.findall("oval:reference", ns):
            ref_id = ref.get("ref_id", "")
            if ref_id.startswith("CVE-"):
                cve_ids.append(ref_id)

        if not cve_ids:
            continue

        # Extract severity from advisory element
        severity = "medium"
        for advisory in metadata.findall("oval:advisory", ns):
            sev_el = advisory.find("oval:severity", ns)
            if sev_el is not None and sev_el.text:
                sev_text = sev_el.text.lower()
                severity = {
                    "negligible": "info",
                    "low": "low",
                    "medium": "medium",
                    "high": "high",
                    "critical": "critical",
                }.get(sev_text, "medium")

        # Extract package name from title: "CVE-... in packagename"
        # or from the definition metadata
        pkg_name = ""
        if " in " in title:
            pkg_name = title.split(" in ")[-1].strip().split()[0]

        for cve_id in cve_ids:
            records.append(
                {
                    "id": cve_id,
                    "os_family": "ubuntu",
                    "os_version": os_version,
                    "package": pkg_name,
                    "version_fixed": "",
                    "severity": severity,
                    "cvss_score": 0.0,
                    "summary": title[:500],
                }
            )

    return records


def _parse_amzn_alas(xml_data: bytes, os_version: str) -> list[dict[str, Any]]:
    """Parse Amazon Linux ALAS RSS XML into advisory records."""
    records: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError:
        return records

    for item in root.iter("item"):
        title_el = item.find("title")
        title = title_el.text if title_el is not None and title_el.text else ""
        desc_el = item.find("description")
        description = desc_el.text if desc_el is not None and desc_el.text else ""

        # Extract severity from title: "ALAS-2024-1234 (important)"
        severity = "medium"
        title_lower = title.lower()
        if "(critical)" in title_lower:
            severity = "critical"
        elif "(important)" in title_lower:
            severity = "high"
        elif "(medium)" in title_lower:
            severity = "medium"
        elif "(low)" in title_lower:
            severity = "low"

        # Extract CVE IDs from description
        import re

        cve_ids = re.findall(r"CVE-\d{4}-\d+", description)
        if not cve_ids:
            cve_ids = re.findall(r"CVE-\d{4}-\d+", title)

        # Extract ALAS ID for summary
        alas_id = ""
        alas_match = re.match(r"(ALAS\S*-\d{4}-\d+)", title)
        if alas_match:
            alas_id = alas_match.group(1)

        for cve_id in cve_ids:
            records.append(
                {
                    "id": cve_id,
                    "os_family": "amzn",
                    "os_version": os_version,
                    "package": "",
                    "version_fixed": "",
                    "severity": severity,
                    "cvss_score": 0.0,
                    "summary": f"{alas_id}: {cve_id}" if alas_id else cve_id,
                }
            )

    return records


def _parse_rhel_cve_api(entries: list[dict[str, Any]], os_version: str) -> list[dict[str, Any]]:
    """Parse Red Hat CVE API JSON responses into advisory records."""
    records: list[dict[str, Any]] = []
    if not isinstance(entries, list):
        return records

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        cve_id = entry.get("CVE", "")
        if not cve_id:
            continue

        severity = entry.get("severity", "moderate")
        severity = {
            "low": "low",
            "moderate": "medium",
            "important": "high",
            "critical": "critical",
        }.get(severity.lower(), "medium")

        cvss_score = 0.0
        cvss3 = entry.get("cvss3_score", "")
        if cvss3:
            try:
                cvss_score = float(cvss3)
            except (ValueError, TypeError):
                pass

        summary = entry.get("bugzilla_description", "")[:500]

        # Extract affected packages from affected_packages field
        affected_pkgs = entry.get("affected_packages", [])
        if not isinstance(affected_pkgs, list):
            affected_pkgs = []

        # Filter to relevant RHEL version
        pkg_names: set[str] = set()
        for pkg in affected_pkgs:
            if not isinstance(pkg, str):
                continue
            # Format: "package-version.el8" or similar
            if f"el{os_version}" in pkg or f"rhel{os_version}" in pkg.lower():
                # Extract package name (before version)
                name = pkg.rsplit("-", 2)[0] if "-" in pkg else pkg
                pkg_names.add(name)

        if not pkg_names:
            # Still record the CVE even without specific package info
            records.append(
                {
                    "id": cve_id,
                    "os_family": "rhel",
                    "os_version": os_version,
                    "package": "",
                    "version_fixed": "",
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "summary": summary,
                }
            )
        else:
            for pkg_name in pkg_names:
                records.append(
                    {
                        "id": cve_id,
                        "os_family": "rhel",
                        "os_version": os_version,
                        "package": pkg_name,
                        "version_fixed": "",
                        "severity": severity,
                        "cvss_score": cvss_score,
                        "summary": summary,
                    }
                )

    return records
