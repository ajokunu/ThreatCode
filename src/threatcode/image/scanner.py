"""Container image vulnerability scanner."""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from threatcode.engine.vulns.db import VulnDB
from threatcode.image.misconfig import check_image_config
from threatcode.image.os_detect import OSDetector, OSInfo
from threatcode.image.packages import OSPackage, parse_os_packages
from threatcode.models.finding import SecretFinding, VulnerabilityFinding
from threatcode.models.threat import Severity

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _cvss_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


@dataclass
class ImageScanResult:
    """Complete result of scanning a container image."""

    image_ref: str
    os_info: OSInfo | None
    os_packages: list[OSPackage]
    os_vulnerabilities: list[VulnerabilityFinding]
    app_dependencies: list[dict[str, Any]]
    app_vulnerabilities: list[VulnerabilityFinding]
    secrets: list[SecretFinding]
    misconfigs: list[dict[str, Any]]
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def total_vulnerabilities(self) -> int:
        return len(self.os_vulnerabilities) + len(self.app_vulnerabilities)

    def to_dict(self) -> dict[str, Any]:
        os_dict = None
        if self.os_info:
            os_dict = {
                "family": self.os_info.family,
                "name": self.os_info.name,
                "version": self.os_info.version,
            }

        return {
            "image": self.image_ref,
            "os": os_dict,
            "metadata": self.metadata,
            "summary": {
                "os_packages": len(self.os_packages),
                "os_vulnerabilities": len(self.os_vulnerabilities),
                "app_dependencies": len(self.app_dependencies),
                "app_vulnerabilities": len(self.app_vulnerabilities),
                "secrets": len(self.secrets),
                "misconfigs": len(self.misconfigs),
                "total_vulnerabilities": self.total_vulnerabilities,
            },
            "os_vulnerabilities": [f.to_dict() for f in self.os_vulnerabilities],
            "app_vulnerabilities": [f.to_dict() for f in self.app_vulnerabilities],
            "secrets": [f.to_dict() for f in self.secrets],
            "misconfigs": self.misconfigs,
        }


class ImageScanner:
    """Orchestrate a full container image security scan."""

    def __init__(
        self,
        db: VulnDB | None = None,
        *,
        ignore_unfixed: bool = False,
        scan_secrets: bool = False,
        scan_misconfig: bool = True,
    ) -> None:
        self._db = db or VulnDB()
        self._ignore_unfixed = ignore_unfixed
        self._scan_secrets = scan_secrets
        self._scan_misconfig = scan_misconfig

    def scan_extracted(
        self,
        image_ref: str,
        image: Any,  # ExtractedImage
    ) -> ImageScanResult:
        """Scan an already-extracted image (ExtractedImage object).

        This is the main analysis entry point once layers are extracted.
        """
        config = image.config

        # Collect image metadata from config
        metadata = self._extract_metadata(config)

        # Detect OS
        detector = OSDetector()
        os_info = detector.detect(image)

        # Parse OS packages
        os_packages: list[OSPackage] = []
        if os_info:
            try:
                os_packages = parse_os_packages(image.root, os_info)
                logger.debug(
                    "Found %d OS packages (%s %s)",
                    len(os_packages),
                    os_info.name,
                    os_info.version,
                )
            except Exception as e:
                logger.warning("Could not parse OS packages: %s", e)

        # Scan OS packages for vulnerabilities
        os_vulns: list[VulnerabilityFinding] = []
        if os_info and os_packages and self._db.exists():
            os_vulns = self._scan_os_packages(os_info, os_packages)

        # Find application dependencies
        from threatcode.image.app_deps import find_app_dependencies

        app_deps: list[dict[str, Any]] = []
        try:
            app_deps = find_app_dependencies(image)
            logger.debug("Found %d application dependencies", len(app_deps))
        except Exception as e:
            logger.warning("Could not scan app dependencies: %s", e)

        # Scan app dependencies for vulnerabilities
        app_vulns: list[VulnerabilityFinding] = []
        if app_deps and self._db.exists():
            from threatcode.engine.vulns.scanner import VulnerabilityScanner

            vuln_scanner = VulnerabilityScanner(db=self._db)
            app_vulns = vuln_scanner.scan_dependencies(
                app_deps, ignore_unfixed=self._ignore_unfixed
            )

        # Secret scanning
        secrets: list[SecretFinding] = []
        if self._scan_secrets:
            try:
                from threatcode.engine.secrets.config import SecretScanConfig
                from threatcode.engine.secrets.scanner import SecretScanner

                secret_cfg = SecretScanConfig(
                    skip_paths=["proc/", "sys/", "dev/", "run/"],
                    max_file_size=1_000_000,
                )
                secret_scanner = SecretScanner(config=secret_cfg)
                secrets = secret_scanner.scan(str(image.root))
            except Exception as e:
                logger.warning("Secret scan failed: %s", e)

        # Image config misconfiguration checks
        misconfigs: list[dict[str, Any]] = []
        if self._scan_misconfig:
            misconfigs = check_image_config(config)

        return ImageScanResult(
            image_ref=image_ref,
            os_info=os_info,
            os_packages=os_packages,
            os_vulnerabilities=os_vulns,
            app_dependencies=app_deps,
            app_vulnerabilities=app_vulns,
            secrets=secrets,
            misconfigs=misconfigs,
            metadata=metadata,
        )

    def _scan_os_packages(
        self,
        os_info: OSInfo,
        packages: list[OSPackage],
    ) -> list[VulnerabilityFinding]:
        """Match OS packages against OS advisory database."""
        findings: list[VulnerabilityFinding] = []

        # Determine the version key to use in the DB query
        # For Alpine: major.minor (e.g. "3.19")
        # For Debian: codename (e.g. "bookworm") or major (e.g. "12")
        os_version = _normalise_os_version(os_info)

        for pkg in packages:
            # Query by source package name (more accurate for advisories)
            names_to_try = list({pkg.source_name, pkg.name})
            for pkg_name in names_to_try:
                rows = self._db.query_os(os_info.family, os_version, pkg_name)
                for row in rows:
                    fixed = row.get("version_fixed", "")
                    if self._ignore_unfixed and not fixed:
                        continue

                    # Build a full version string for comparison
                    pkg_ver = _build_rpm_evr(pkg) if os_info.pkg_manager == "rpm" else pkg.version

                    if fixed and not _is_pkg_vulnerable(pkg_ver, fixed, os_info.pkg_manager):
                        continue

                    severity_str = row.get("severity", "medium")
                    severity = _SEVERITY_MAP.get(severity_str, Severity.MEDIUM)
                    cvss = float(row.get("cvss_score", 0.0))
                    if severity == Severity.MEDIUM and cvss > 0:
                        severity = _cvss_to_severity(cvss)

                    findings.append(
                        VulnerabilityFinding(
                            id=f"VULN-{uuid.uuid4().hex[:8]}",
                            title=row.get("summary", f"{row.get('id', '')} in {pkg.name}"),
                            severity=severity,
                            package_name=pkg.name,
                            package_version=pkg_ver,
                            ecosystem=os_info.family,
                            cve_id=row.get("id", ""),
                            fixed_version=fixed,
                            cvss_score=cvss,
                            metadata={"os_family": os_info.family, "os_version": os_version},
                        )
                    )

        return findings

    @staticmethod
    def _extract_metadata(config: dict[str, Any]) -> dict[str, Any]:
        img_config = config.get("config", {}) or {}
        return {
            "architecture": config.get("architecture", ""),
            "os": config.get("os", ""),
            "created": config.get("created", ""),
            "user": img_config.get("User", ""),
            "cmd": img_config.get("Cmd", []),
            "entrypoint": img_config.get("Entrypoint", []),
            "env": img_config.get("Env", []),
            "labels": img_config.get("Labels", {}),
            "exposed_ports": list((img_config.get("ExposedPorts") or {}).keys()),
            "working_dir": img_config.get("WorkingDir", ""),
        }


def _normalise_os_version(os_info: OSInfo) -> str:
    """Return the version key used in os_vulnerabilities table."""
    v = os_info.version
    family = os_info.family
    if family == "alpine":
        # "3.19.1" → "3.19"
        parts = v.split(".")
        return ".".join(parts[:2]) if len(parts) >= 2 else v
    if family == "debian":
        # "12.2" → "12", also accept codename "bookworm" → "12"
        codename_map = {"buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13"}
        if v in codename_map:
            return codename_map[v]
        # numeric: take major
        return v.split(".")[0] if "." in v else v
    if family == "ubuntu":
        # "22.04.3" → "22.04"
        parts = v.split(".")
        return ".".join(parts[:2]) if len(parts) >= 2 else v
    if family == "amzn":
        # "2023.x.y" → "2023", "2" → "2"
        return v.split(".")[0] if "." in v else v
    # RHEL/CentOS: "9.3" → "9"
    return v.split(".")[0] if "." in v else v


def _build_rpm_evr(pkg: OSPackage) -> str:
    """Build epoch:version-release string for RPM version comparison."""
    evr = pkg.version
    if pkg.release:
        evr = f"{evr}-{pkg.release}"
    if pkg.epoch:
        evr = f"{pkg.epoch}:{evr}"
    return evr


def _is_pkg_vulnerable(pkg_version: str, fixed_version: str, pkg_manager: str) -> bool:
    """Return True if pkg_version < fixed_version (i.e. package is vulnerable)."""
    if not fixed_version:
        return True  # No fix = still vulnerable
    try:
        if pkg_manager in ("rpm",):
            return _rpm_version_lt(pkg_version, fixed_version)
        # For APK and DPKG, use packaging library
        from packaging.version import InvalidVersion, Version

        try:
            return Version(pkg_version) < Version(fixed_version)
        except InvalidVersion:
            # Fall back to lexicographic
            return pkg_version < fixed_version
    except Exception:
        return True


def _rpm_version_lt(v1: str, v2: str) -> bool:
    """Return True if RPM version v1 < v2 (simplified epoch:ver-rel comparison)."""

    def parse_evr(evr: str) -> tuple[int, str, str]:
        epoch = 0
        if ":" in evr:
            e, _, evr = evr.partition(":")
            try:
                epoch = int(e)
            except ValueError:
                pass
        version, _, release = evr.partition("-")
        return epoch, version, release

    e1, ver1, rel1 = parse_evr(v1)
    e2, ver2, rel2 = parse_evr(v2)

    if e1 != e2:
        return e1 < e2

    def vercmp_simple(a: str, b: str) -> int:
        """Simple segment-by-segment version comparison."""
        import re

        def split_ver(s: str) -> list[str]:
            return re.findall(r"\d+|[a-zA-Z]+", s)

        pa, pb = split_ver(a), split_ver(b)
        for i in range(max(len(pa), len(pb))):
            sa = pa[i] if i < len(pa) else "0"
            sb = pb[i] if i < len(pb) else "0"
            if sa.isdigit() and sb.isdigit():
                if int(sa) != int(sb):
                    return -1 if int(sa) < int(sb) else 1
            else:
                if sa != sb:
                    return -1 if sa < sb else 1
        return 0

    cmp = vercmp_simple(ver1, ver2)
    if cmp != 0:
        return cmp < 0
    return vercmp_simple(rel1, rel2) < 0
