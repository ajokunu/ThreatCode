"""Tests for application dependency detection inside images."""

from __future__ import annotations

import json
from pathlib import Path

from threatcode.image.app_deps import find_app_dependencies
from threatcode.image.layer import ExtractedImage


def _make_image(tmp_path: Path, files: dict[str, str]) -> ExtractedImage:
    """Create a minimal ExtractedImage with given files."""
    for rel_path, content in files.items():
        fp = tmp_path / rel_path
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(content)
    return ExtractedImage(root=tmp_path, config={}, layer_count=1)


class TestFindAppDependencies:
    def test_finds_requirements_txt(self, tmp_path: Path) -> None:
        image = _make_image(tmp_path, {
            "app/requirements.txt": "flask==2.3.0\nrequests==2.31.0\n",
        })
        deps = find_app_dependencies(image)
        names = {d["name"] for d in deps}
        assert "flask" in names
        assert "requests" in names
        for d in deps:
            assert d["ecosystem"] == "pypi"

    def test_finds_package_lock_json(self, tmp_path: Path) -> None:
        lockfile = {
            "name": "myapp",
            "version": "1.0.0",
            "lockfileVersion": 2,
            "packages": {
                "node_modules/lodash": {"version": "4.17.21"},
            },
        }
        image = _make_image(tmp_path, {
            "app/package-lock.json": json.dumps(lockfile),
        })
        deps = find_app_dependencies(image)
        assert any(d["name"] == "lodash" for d in deps)

    def test_skips_proc_sys_dirs(self, tmp_path: Path) -> None:
        image = _make_image(tmp_path, {
            "proc/requirements.txt": "evil==1.0\n",
            "sys/requirements.txt": "evil==1.0\n",
            "app/requirements.txt": "flask==2.3.0\n",
        })
        deps = find_app_dependencies(image)
        names = {d["name"] for d in deps}
        assert "evil" not in names
        assert "flask" in names

    def test_empty_image_returns_empty(self, tmp_path: Path) -> None:
        image = ExtractedImage(root=tmp_path, config={}, layer_count=0)
        deps = find_app_dependencies(image)
        assert deps == []
