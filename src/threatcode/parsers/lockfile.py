"""Lockfile parsers for dependency extraction."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from threatcode.parsers.base import BaseParser, ParsedOutput, ParsedResource

logger = logging.getLogger(__name__)


class LockfileParser(BaseParser):
    """Parse various lockfile formats to extract dependencies."""

    def parse(self, data: Any, source_path: str = "") -> ParsedOutput:
        path = Path(source_path) if source_path else None
        filename = path.name if path else ""

        resources: list[ParsedResource] = []

        if filename == "package-lock.json":
            resources = self._parse_npm(data, source_path)
        elif filename == "yarn.lock":
            resources = self._parse_yarn(data if isinstance(data, str) else str(data), source_path)
        elif filename == "pnpm-lock.yaml":
            resources = self._parse_pnpm(data, source_path)
        elif filename == "requirements.txt":
            resources = self._parse_requirements(
                data if isinstance(data, str) else str(data), source_path
            )
        elif filename == "Pipfile.lock":
            resources = self._parse_pipfile(data, source_path)
        elif filename == "poetry.lock":
            resources = self._parse_poetry(
                data if isinstance(data, str) else str(data), source_path
            )
        elif filename == "go.sum":
            resources = self._parse_gosum(data if isinstance(data, str) else str(data), source_path)
        elif filename == "Cargo.lock":
            resources = self._parse_cargo(data if isinstance(data, str) else str(data), source_path)
        elif filename == "Gemfile.lock":
            resources = self._parse_gemfile(
                data if isinstance(data, str) else str(data), source_path
            )
        elif filename == "composer.lock":
            resources = self._parse_composer(data, source_path)

        return ParsedOutput(
            resources=resources,
            source_path=source_path,
            format_type="lockfile",
        )

    def _parse_npm(self, data: Any, source_path: str) -> list[ParsedResource]:
        """Parse package-lock.json (v1, v2, v3)."""
        resources: list[ParsedResource] = []
        if not isinstance(data, dict):
            return resources

        # v2/v3 format uses "packages"
        packages = data.get("packages", {})
        if packages:
            for pkg_path, info in packages.items():
                if not pkg_path or not isinstance(info, dict):
                    continue
                name = info.get("name") or pkg_path.split("node_modules/")[-1]
                version = info.get("version", "")
                if not name or not version:
                    continue
                resources.append(
                    self._make_dep(
                        name=name,
                        version=version,
                        ecosystem="npm",
                        source_path=source_path,
                        license_id=info.get("license", ""),
                    )
                )

        # v1 format uses "dependencies"
        if not packages:
            deps = data.get("dependencies", {})
            resources.extend(self._parse_npm_deps(deps, source_path))

        return resources

    def _parse_npm_deps(self, deps: dict[str, Any], source_path: str) -> list[ParsedResource]:
        resources: list[ParsedResource] = []
        if not isinstance(deps, dict):
            return resources
        for name, info in deps.items():
            if not isinstance(info, dict):
                continue
            version = info.get("version", "")
            if version:
                resources.append(
                    self._make_dep(
                        name=name,
                        version=version,
                        ecosystem="npm",
                        source_path=source_path,
                    )
                )
            # Recurse into nested deps
            nested = info.get("dependencies", {})
            if nested:
                resources.extend(self._parse_npm_deps(nested, source_path))
        return resources

    def _parse_yarn(self, content: str, source_path: str) -> list[ParsedResource]:
        """Parse yarn.lock (v1 format)."""
        resources: list[ParsedResource] = []
        current_name = ""

        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Package header line (no leading space)
            if not line.startswith(" ") and not line.startswith("\t"):
                # Extract name from header like '"lodash@^4.17.0", "lodash@^4.17.15":'
                match = re.match(r'^"?(@?[^@"]+)@', stripped)
                if match:
                    current_name = match.group(1)

            # Version line
            elif current_name and stripped.startswith("version "):
                version = stripped.split('"')[1] if '"' in stripped else stripped.split()[-1]
                resources.append(
                    self._make_dep(
                        name=current_name,
                        version=version,
                        ecosystem="npm",
                        source_path=source_path,
                    )
                )
                current_name = ""

        return resources

    def _parse_pnpm(self, data: Any, source_path: str) -> list[ParsedResource]:
        """Parse pnpm-lock.yaml."""
        resources: list[ParsedResource] = []
        if not isinstance(data, dict):
            return resources

        packages = data.get("packages", {})
        if not isinstance(packages, dict):
            return resources

        for pkg_key, info in packages.items():
            if not isinstance(info, dict):
                continue
            # Key format: /package@version or /@scope/package@version
            match = re.match(r"/?(@?[^@]+)@(.+)$", pkg_key)
            if match:
                name = match.group(1)
                version = match.group(2)
                resources.append(
                    self._make_dep(
                        name=name,
                        version=version,
                        ecosystem="npm",
                        source_path=source_path,
                    )
                )

        return resources

    def _parse_requirements(self, content: str, source_path: str) -> list[ParsedResource]:
        """Parse requirements.txt (pip freeze format)."""
        resources: list[ParsedResource] = []
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                continue
            # Handle pkg==version
            match = re.match(r"^([A-Za-z0-9_.\-\[\]]+)==([^\s;#]+)", stripped)
            if match:
                resources.append(
                    self._make_dep(
                        name=match.group(1),
                        version=match.group(2),
                        ecosystem="pypi",
                        source_path=source_path,
                    )
                )
        return resources

    def _parse_pipfile(self, data: Any, source_path: str) -> list[ParsedResource]:
        """Parse Pipfile.lock (JSON)."""
        resources: list[ParsedResource] = []
        if not isinstance(data, dict):
            return resources

        for section in ("default", "develop"):
            pkgs = data.get(section, {})
            if not isinstance(pkgs, dict):
                continue
            for name, info in pkgs.items():
                if not isinstance(info, dict):
                    continue
                version = info.get("version", "").lstrip("=")
                if version:
                    resources.append(
                        self._make_dep(
                            name=name,
                            version=version,
                            ecosystem="pypi",
                            source_path=source_path,
                        )
                    )

        return resources

    def _parse_poetry(self, content: str, source_path: str) -> list[ParsedResource]:
        """Parse poetry.lock (TOML format)."""
        resources: list[ParsedResource] = []
        try:
            import sys

            if sys.version_info >= (3, 11):
                import tomllib
            else:
                import tomli as tomllib  # type: ignore[no-redef,import-not-found,unused-ignore]

            data = tomllib.loads(content)
        except Exception:
            # Fallback: simple regex parsing
            return self._parse_poetry_fallback(content, source_path)

        for pkg in data.get("package", []):
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            if name and version:
                resources.append(
                    self._make_dep(
                        name=name,
                        version=version,
                        ecosystem="pypi",
                        source_path=source_path,
                    )
                )

        return resources

    def _parse_poetry_fallback(self, content: str, source_path: str) -> list[ParsedResource]:
        resources: list[ParsedResource] = []
        name = ""
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith('name = "'):
                name = stripped.split('"')[1]
            elif stripped.startswith('version = "') and name:
                version = stripped.split('"')[1]
                resources.append(
                    self._make_dep(
                        name=name,
                        version=version,
                        ecosystem="pypi",
                        source_path=source_path,
                    )
                )
                name = ""
        return resources

    def _parse_gosum(self, content: str, source_path: str) -> list[ParsedResource]:
        """Parse go.sum."""
        resources: list[ParsedResource] = []
        seen: set[str] = set()

        for line in content.splitlines():
            parts = line.strip().split()
            if len(parts) < 3:
                continue
            module = parts[0]
            version = parts[1].split("/")[0].lstrip("v")
            key = f"{module}@{version}"
            if key not in seen:
                seen.add(key)
                resources.append(
                    self._make_dep(
                        name=module,
                        version=version,
                        ecosystem="go",
                        source_path=source_path,
                    )
                )

        return resources

    def _parse_cargo(self, content: str, source_path: str) -> list[ParsedResource]:
        """Parse Cargo.lock (TOML)."""
        resources: list[ParsedResource] = []
        try:
            import sys

            if sys.version_info >= (3, 11):
                import tomllib
            else:
                import tomli as tomllib  # type: ignore[no-redef,import-not-found,unused-ignore]

            data = tomllib.loads(content)
        except Exception:
            return self._parse_cargo_fallback(content, source_path)

        for pkg in data.get("package", []):
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            if name and version:
                resources.append(
                    self._make_dep(
                        name=name,
                        version=version,
                        ecosystem="crates.io",
                        source_path=source_path,
                    )
                )

        return resources

    def _parse_cargo_fallback(self, content: str, source_path: str) -> list[ParsedResource]:
        resources: list[ParsedResource] = []
        name = ""
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith('name = "'):
                name = stripped.split('"')[1]
            elif stripped.startswith('version = "') and name:
                version = stripped.split('"')[1]
                resources.append(
                    self._make_dep(
                        name=name,
                        version=version,
                        ecosystem="crates.io",
                        source_path=source_path,
                    )
                )
                name = ""
        return resources

    def _parse_gemfile(self, content: str, source_path: str) -> list[ParsedResource]:
        """Parse Gemfile.lock."""
        resources: list[ParsedResource] = []
        in_specs = False

        for line in content.splitlines():
            stripped = line.strip()
            if stripped == "specs:":
                in_specs = True
                continue
            if in_specs and not line.startswith(" "):
                in_specs = False
                continue
            if in_specs:
                match = re.match(r"^\s{4}(\S+)\s+\((\S+)\)", line)
                if match:
                    resources.append(
                        self._make_dep(
                            name=match.group(1),
                            version=match.group(2),
                            ecosystem="rubygems",
                            source_path=source_path,
                        )
                    )

        return resources

    def _parse_composer(self, data: Any, source_path: str) -> list[ParsedResource]:
        """Parse composer.lock (JSON)."""
        resources: list[ParsedResource] = []
        if not isinstance(data, dict):
            return resources

        for section in ("packages", "packages-dev"):
            pkgs = data.get(section, [])
            if not isinstance(pkgs, list):
                continue
            for pkg in pkgs:
                if not isinstance(pkg, dict):
                    continue
                name = pkg.get("name", "")
                version = pkg.get("version", "").lstrip("v")
                if name and version:
                    license_ids = pkg.get("license", [])
                    lic = license_ids[0] if isinstance(license_ids, list) and license_ids else ""
                    resources.append(
                        self._make_dep(
                            name=name,
                            version=version,
                            ecosystem="packagist",
                            source_path=source_path,
                            license_id=lic,
                        )
                    )

        return resources

    def _make_dep(
        self,
        *,
        name: str,
        version: str,
        ecosystem: str,
        source_path: str,
        license_id: str = "",
    ) -> ParsedResource:
        return ParsedResource(
            resource_type=f"dependency_{ecosystem}",
            address=f"{ecosystem}/{name}@{version}",
            name=name,
            provider=ecosystem,
            properties={
                "name": name,
                "version": version,
                "ecosystem": ecosystem,
                "license": license_id,
            },
            source_location=source_path,
        )
