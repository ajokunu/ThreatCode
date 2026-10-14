"""SARIF and Bitbucket name files from the repository root, whatever directory the scan ran in.

GitHub resolves ``%SRCROOT%`` against the repository, so a scan started from a subdirectory (a
monorepo's working directory, the action's ``path`` input) must still write ``infra/main.tf``,
not ``main.tf`` or ``prod/main.tf``.
These tests build a real checkout in a temporary directory, with ``.git`` as a directory (a clone)
and as a file (a worktree), and run the real scan through the CLI from several directories.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from threatcode.cli import cli
from threatcode.formatters import RepoPaths, find_repo_root
from threatcode.formatters.bitbucket import format_bitbucket
from threatcode.formatters.sarif import format_sarif
from threatcode.models.report import ThreatReport
from threatcode.models.threat import Severity, Threat, ThreatSource

BUCKET = 'resource "aws_s3_bucket" "logs" {\n  bucket = "logs"\n}\n'


@pytest.fixture(autouse=True)
def hermetic(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    for name in list(os.environ):
        if name.startswith("THREATCODE_"):
            monkeypatch.delenv(name)


def make_repo(root: Path, *, git_file: bool = False) -> Path:
    """A checkout with ``infra/prod/main.tf`` in it; returns the scan root ``infra/prod``."""
    root.mkdir(parents=True, exist_ok=True)
    if git_file:
        (root / ".git").write_text("gitdir: /elsewhere/.git/worktrees/x\n", encoding="utf-8")
    else:
        (root / ".git").mkdir()
    prod = root / "infra" / "prod"
    prod.mkdir(parents=True)
    (prod / "main.tf").write_text(BUCKET, encoding="utf-8")
    return prod


def threat(file: str, line: int = 2) -> Threat:
    return Threat(
        id="t1",
        title="Bucket",
        description="d",
        stride_category="information_disclosure",
        severity=Severity.HIGH,
        source=ThreatSource.RULE,
        resource_type="aws_s3_bucket",
        resource_address="aws_s3_bucket.logs",
        rule_id="R1",
        location_file=file,
        location_start_line=line,
    )


def sarif_uris(text: str) -> set[str]:
    run = json.loads(text)["runs"][0]
    return {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"]
    }


def notification_codes(text: str) -> list[str]:
    run = json.loads(text)["runs"][0]
    return [n["descriptor"]["id"] for n in run["invocations"][0]["toolExecutionNotifications"]]


class TestFindRepoRoot:
    @pytest.mark.parametrize("git_file", [False, True])
    def test_a_git_directory_or_file_marks_the_top(self, tmp_path: Path, git_file: bool) -> None:
        prod = make_repo(tmp_path / "repo", git_file=git_file)
        assert find_repo_root(prod) == (tmp_path / "repo").resolve()

    def test_no_checkout_gives_none(self, tmp_path: Path) -> None:
        (tmp_path / "plain").mkdir()
        assert find_repo_root(tmp_path / "plain") is None

    def test_the_nearest_checkout_wins(self, tmp_path: Path) -> None:
        make_repo(tmp_path / "outer")
        inner = tmp_path / "outer" / "vendor" / "lib"
        inner.mkdir(parents=True)
        (inner / ".git").mkdir()
        assert find_repo_root(inner) == inner.resolve()


class TestRepoPaths:
    def test_a_relative_path_is_joined_to_the_scan_root_then_made_repo_relative(
        self, tmp_path: Path
    ) -> None:
        prod = make_repo(tmp_path / "repo")
        paths = RepoPaths.resolve(prod)
        assert paths.locate("main.tf") == "infra/prod/main.tf"
        assert paths.locate("sub/dir/a.tf") == "infra/prod/sub/dir/a.tf"
        assert paths.anchored
        assert not paths.outside

    def test_a_file_in_a_sibling_directory_is_still_inside_the_repository(
        self, tmp_path: Path
    ) -> None:
        prod = make_repo(tmp_path / "repo")
        assert RepoPaths.resolve(prod).locate("../dev/main.tf") == "infra/dev/main.tf"

    def test_the_uri_is_percent_encoded(self, tmp_path: Path) -> None:
        prod = make_repo(tmp_path / "repo")
        assert RepoPaths.resolve(prod).uri("a b/c@d.tf") == "infra/prod/a%20b/c%40d.tf"

    def test_an_absolute_path_inside_the_repository_is_made_relative(self, tmp_path: Path) -> None:
        prod = make_repo(tmp_path / "repo")
        absolute = str(prod.resolve() / "main.tf")
        assert RepoPaths.resolve(prod).locate(absolute) == "infra/prod/main.tf"

    def test_a_path_that_climbs_out_of_the_repository_is_never_written_with_dots(
        self, tmp_path: Path
    ) -> None:
        prod = make_repo(tmp_path / "repo")
        paths = RepoPaths.resolve(prod)
        located = paths.locate("../../../../etc/passwd")
        assert ".." not in located.split("/")
        assert located == "etc/passwd"
        assert paths.outside

    def test_an_absolute_path_outside_the_repository_is_reduced_to_its_name(
        self, tmp_path: Path
    ) -> None:
        prod = make_repo(tmp_path / "repo")
        paths = RepoPaths.resolve(prod)
        assert paths.locate(str(tmp_path / "elsewhere" / "modules" / "vpc.tf")) == "vpc.tf"
        assert paths.locate("C:\\Users\\me\\vpc.tf") == "vpc.tf"
        assert len(paths.outside) == 2

    def test_an_explicit_repo_root_wins_over_the_git_top_level(self, tmp_path: Path) -> None:
        prod = make_repo(tmp_path / "repo")
        paths = RepoPaths.resolve(prod, repo_root=tmp_path / "repo" / "infra")
        assert paths.locate("main.tf") == "prod/main.tf"

    def test_no_checkout_and_below_the_current_directory_is_relative_to_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "plain" / "infra").mkdir(parents=True)
        monkeypatch.chdir(tmp_path / "plain")
        paths = RepoPaths.resolve(tmp_path / "plain" / "infra")
        assert paths.locate("main.tf") == "infra/main.tf"
        assert paths.anchored

    def test_no_checkout_and_not_below_the_current_directory_is_unanchored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "plain").mkdir()
        (tmp_path / "cwd").mkdir()
        monkeypatch.chdir(tmp_path / "cwd")
        paths = RepoPaths.resolve(tmp_path / "plain")
        assert paths.locate("sub/main.tf") == "sub/main.tf"
        assert not paths.anchored

    def test_a_hand_built_report_is_relative_to_the_current_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        make_repo(tmp_path / "repo")
        monkeypatch.chdir(tmp_path / "repo" / "infra")
        assert RepoPaths.resolve().locate("prod/main.tf") == "infra/prod/main.tf"


class TestAFileOnAnotherDrive:
    """The scan names it ``D/net/main.tf``; it keeps that name, not put below the scan root."""

    def paths(self, tmp_path: Path) -> RepoPaths:
        return RepoPaths.resolve(make_repo(tmp_path / "repo"), other_drives=("D", "HOST/SHARE"))

    def test_the_file_keeps_its_name_and_is_counted_as_outside(self, tmp_path: Path) -> None:
        paths = self.paths(tmp_path)
        assert paths.locate("D/net/main.tf") == "D/net/main.tf"
        assert paths.locate("HOST/SHARE/x.tf") == "HOST/SHARE/x.tf"
        assert paths.locate("D") == "D"
        assert paths.outside == {"D/net/main.tf", "HOST/SHARE/x.tf", "D"}

    def test_a_name_that_only_begins_like_a_drive_is_a_file_of_the_repository(
        self, tmp_path: Path
    ) -> None:
        paths = self.paths(tmp_path)
        assert paths.locate("Data/main.tf") == "infra/prod/Data/main.tf"
        assert paths.locate("D.tf") == "infra/prod/D.tf"
        assert not paths.outside

    def test_without_drives_a_directory_named_d_is_a_directory_of_the_repository(
        self, tmp_path: Path
    ) -> None:
        paths = RepoPaths.resolve(make_repo(tmp_path / "repo"))
        assert paths.locate("D/main.tf") == "infra/prod/D/main.tf"
        assert not paths.outside

    def test_the_uri_is_the_name_percent_encoded(self, tmp_path: Path) -> None:
        assert self.paths(tmp_path).uri("D/a b/main.tf") == "D/a%20b/main.tf"

    def test_sarif_reports_the_file_as_outside_the_repository_and_keeps_its_directory(
        self, tmp_path: Path
    ) -> None:
        prod = make_repo(tmp_path / "repo")
        report = ThreatReport(threats=[threat("main.tf"), threat("D/net/main.tf")])
        text = format_sarif(report, source_root=prod, other_drives=("D",))
        assert sarif_uris(text) == {"infra/prod/main.tf", "D/net/main.tf"}
        assert "sarif.paths.outside_repository" in notification_codes(text)

    def test_bitbucket_reports_the_file_as_outside_the_repository_and_keeps_its_directory(
        self, tmp_path: Path
    ) -> None:
        prod = make_repo(tmp_path / "repo")
        report = ThreatReport(threats=[threat("main.tf"), threat("D/net/main.tf")])
        output = json.loads(format_bitbucket(report, source_root=prod, other_drives=("D",)))
        assert {a["path"] for a in output["annotations"]} == {"infra/prod/main.tf", "D/net/main.tf"}
        assert "1 file outside the repository root" in output["report"]["details"]


class TestSarifFromAnywhere:
    @pytest.mark.parametrize("git_file", [False, True])
    def test_the_uri_is_the_same_from_every_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git_file: bool
    ) -> None:
        prod = make_repo(tmp_path / "repo", git_file=git_file)
        report = ThreatReport(threats=[threat("main.tf")], input_file="infra/prod")
        found = set()
        for cwd in (tmp_path / "repo", tmp_path / "repo" / "infra", prod, tmp_path):
            monkeypatch.chdir(cwd)
            found.add(frozenset(sarif_uris(format_sarif(report, source_root=prod))))
        assert found == {frozenset({"infra/prod/main.tf"})}

    def test_a_scan_outside_any_checkout_says_the_paths_cannot_be_placed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "plain").mkdir()
        (tmp_path / "cwd").mkdir()
        monkeypatch.chdir(tmp_path / "cwd")
        report = ThreatReport(threats=[threat("main.tf")], input_file="plain")
        text = format_sarif(report, source_root=tmp_path / "plain")
        assert "sarif.paths.unanchored" in notification_codes(text)
        invocation = json.loads(text)["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is True
        assert not any(".." in u.split("/") for u in sarif_uris(text))

    def test_a_scan_inside_a_checkout_says_nothing(self, tmp_path: Path) -> None:
        prod = make_repo(tmp_path / "repo")
        report = ThreatReport(threats=[threat("main.tf")], input_file="infra/prod")
        assert notification_codes(format_sarif(report, source_root=prod)) == []

    def test_a_file_outside_the_checkout_is_named_by_file_and_reported(
        self, tmp_path: Path
    ) -> None:
        prod = make_repo(tmp_path / "repo")
        outside = str(tmp_path / "elsewhere" / "modules" / "vpc.tf")
        report = ThreatReport(threats=[threat(outside)], input_file="infra/prod")
        text = format_sarif(report, source_root=prod)
        assert sarif_uris(text) == {"vpc.tf"}
        assert "sarif.paths.outside_repository" in notification_codes(text)

    def test_the_machine_path_never_reaches_the_document(self, tmp_path: Path) -> None:
        prod = make_repo(tmp_path / "repo")
        outside = str(tmp_path / "elsewhere" / "vpc.tf")
        report = ThreatReport(threats=[threat(outside)], input_file="infra/prod")
        text = format_sarif(report, source_root=prod)
        assert str(tmp_path) not in text
        assert "originalUriBaseIds" not in text


class TestScanThroughTheCli:
    """The same answer from the real command, run from three directories."""

    def scan(self, cwd: Path, monkeypatch: pytest.MonkeyPatch, *args: str) -> dict[str, Any]:
        monkeypatch.chdir(cwd)
        result = CliRunner().invoke(cli, ["-q", "scan", *args, "--fail-on", "none"])
        assert result.exit_code == 0, result.output
        return json.loads(result.stdout)  # type: ignore[no-any-return]

    def uris(self, sarif: dict[str, Any]) -> set[str]:
        run = sarif["runs"][0]
        return {
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"]
        }

    @pytest.mark.parametrize("git_file", [False, True])
    def test_sarif_uris_are_repository_relative_from_the_root_a_subdirectory_and_the_target(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git_file: bool
    ) -> None:
        prod = make_repo(tmp_path / "repo", git_file=git_file)
        repo = tmp_path / "repo"
        from_root = self.scan(repo, monkeypatch, "infra/prod", "-f", "sarif")
        from_sub = self.scan(repo / "infra", monkeypatch, "prod", "-f", "sarif")
        from_target = self.scan(prod, monkeypatch, ".", "-f", "sarif")
        from_file = self.scan(prod, monkeypatch, "main.tf", "-f", "sarif")
        for sarif in (from_root, from_sub, from_target, from_file):
            assert self.uris(sarif) == {"infra/prod/main.tf"}

    def test_bitbucket_paths_are_repository_relative_from_a_subdirectory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        make_repo(tmp_path / "repo")
        report = self.scan(tmp_path / "repo" / "infra", monkeypatch, "prod", "-f", "bitbucket")
        assert {a["path"] for a in report["annotations"]} == {"infra/prod/main.tf"}

    def test_the_sarif_is_deterministic_across_directories(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        prod = make_repo(tmp_path / "repo")
        a = self.scan(tmp_path / "repo", monkeypatch, "infra/prod", "-f", "sarif")
        b = self.scan(prod, monkeypatch, ".", "-f", "sarif")
        fingerprints = [
            [r["partialFingerprints"] for r in run["runs"][0]["results"]] for run in (a, b)
        ]
        assert fingerprints[0] == fingerprints[1]


class TestBitbucketPaths:
    def test_paths_are_repository_relative_and_cannot_escape(self, tmp_path: Path) -> None:
        prod = make_repo(tmp_path / "repo")
        report = ThreatReport(threats=[threat("main.tf"), threat("../../../../etc/passwd")])
        paths = {
            a["path"] for a in json.loads(format_bitbucket(report, source_root=prod))["annotations"]
        }
        assert paths == {"infra/prod/main.tf", "etc/passwd"}

    def test_a_file_outside_the_repository_is_mentioned_in_the_report(self, tmp_path: Path) -> None:
        prod = make_repo(tmp_path / "repo")
        outside = str(tmp_path / "elsewhere" / "vpc.tf")
        report = ThreatReport(threats=[threat(outside)])
        details = json.loads(format_bitbucket(report, source_root=prod))["report"]["details"]
        assert "outside the repository root" in details
        assert str(tmp_path) not in details
