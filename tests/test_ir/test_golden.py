"""Golden test: IaC threat models must not change by accident.

Every input has its own directory under ``tests/fixtures/golden/``, named after the
input path below ``tests/fixtures`` with ``/`` replaced by ``__``::

    tests/fixtures/golden/terraform__simple_s3.plan.json/
        meta.json            {"input": "tests/fixtures/terraform/simple_s3.plan.json"}
        graph.json           node category, zone and exposure; edges
        findings/<group>.json  rule findings of one rule file, such as aws__s3
        secrets.json         findings whose source is "secret"
        model.json           boundary threats, attack paths, effective severity changes

A section with no content has no file.
Inputs are discovered from the ``meta.json`` files, so adding an input means adding a
directory that holds a ``meta.json``, and a later contract field needs no harness change.
Several packages can re-record different sections of the same input in parallel because
each section is a separate file (see ``scripts/check_golden_scope.py``).

Optional attributes render the same whether they are absent or at their contract default:
``exposure`` is omitted when absent or ``unknown``, ``target_address`` when absent or empty,
``effective_severity`` when absent or ``None`` and ``attack_paths`` when absent or empty.
That keeps a package that adds a default value to every node from changing every recording.

To re-record after an intended change, run::

    THREATCODE_UPDATE_GOLDEN=1 pytest tests/test_ir/test_golden.py

then run ``python scripts/check_golden_scope.py --allow '<globs you own>'`` and review the
diff of ``tests/fixtures/golden/`` before committing it.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Iterable, Mapping
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.rules.loader import load_builtin_rules
from threatcode.ir.edges import EdgeType
from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import NodeCategory, TrustZone
from threatcode.models.threat import Severity
from threatcode.parsers import detect_and_parse

REPO_ROOT = Path(__file__).parent.parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures"
GOLDEN_DIR = FIXTURES / "golden"
UPDATE = os.environ.get("THREATCODE_UPDATE_GOLDEN") == "1"

META = "meta.json"
GRAPH = "graph.json"
SECRETS = "secrets.json"
MODEL = "model.json"
FINDINGS_DIR = "findings"


# ---------------------------------------------------------------------------
# Naming and discovery
# ---------------------------------------------------------------------------


def golden_key(relpath: str) -> str:
    """Directory name for an input given its repo-relative path."""
    return relpath.removeprefix("tests/fixtures/").replace("/", "__")


def discover_inputs(golden_dir: Path) -> list[tuple[str, str]]:
    """Return (directory name, input path) for every directory that holds a meta.json."""
    found: list[tuple[str, str]] = []
    if not golden_dir.is_dir():
        return found
    for meta in sorted(golden_dir.glob(f"*/{META}")):
        data = json.loads(meta.read_text(encoding="utf-8"))
        found.append((meta.parent.name, str(data["input"])))
    return found


DISCOVERED = discover_inputs(GOLDEN_DIR)
GOLDEN_INPUTS: list[str] = [relpath for _name, relpath in DISCOVERED]


# ---------------------------------------------------------------------------
# Projection: report and graph -> section files
# ---------------------------------------------------------------------------


def _plain(value: Any) -> Any:
    """Enum members render as their value; everything else is untouched."""
    return value.value if isinstance(value, Enum) else value


def _node_id(value: Any) -> str:
    if isinstance(value, str):
        return value
    for attr in ("node_id", "id", "address"):
        found = getattr(value, attr, None)
        if isinstance(found, str):
            return found
    return str(value)


def project_graph(graph: Any) -> dict[str, Any] | None:
    nodes: dict[str, dict[str, Any]] = {}
    for node_id, node in sorted(graph.nodes.items()):
        entry: dict[str, Any] = {
            "category": _plain(node.category),
            "zone": _plain(node.trust_zone),
        }
        exposure = _plain(getattr(node, "exposure", None))
        if exposure not in (None, "", "unknown"):
            entry["exposure"] = exposure
        nodes[node_id] = entry
    if not nodes:
        return None
    edges = sorted(
        (
            {
                "source": edge.source,
                "target": edge.target,
                "type": _plain(edge.edge_type),
                "crosses_trust_boundary": bool(edge.crosses_trust_boundary),
            }
            for edge in graph.edges
        ),
        key=lambda e: (e["source"], e["target"], e["type"]),
    )
    return {"nodes": nodes, "edges": edges}


def _source(threat: Any) -> str:
    return str(_plain(threat.source))


def project_findings(
    threats: Iterable[Any], rule_groups: Mapping[str, str]
) -> dict[str, list[dict[str, Any]]]:
    """Rule findings grouped by the rule file that holds the rule."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for threat in threats:
        if _source(threat) != "rule":
            continue
        if threat.rule_id not in rule_groups:
            raise AssertionError(f"Finding from unknown rule id {threat.rule_id!r}")
        grouped.setdefault(rule_groups[threat.rule_id], []).append(
            {
                "rule_id": threat.rule_id,
                "resource_address": threat.resource_address,
                "severity": _plain(threat.severity),
                "stride": threat.stride_category,
                "techniques": sorted(threat.mitre_techniques),
            }
        )
    for entries in grouped.values():
        entries.sort(key=lambda e: (e["rule_id"], e["resource_address"]))
    return grouped


def project_secrets(threats: Iterable[Any]) -> list[dict[str, Any]]:
    entries = [
        {
            "rule_id": threat.rule_id,
            "resource_address": threat.resource_address,
            "file": getattr(threat, "location_file", "") or "",
            "line": getattr(threat, "location_start_line", None),
            "severity": _plain(threat.severity),
        }
        for threat in threats
        if _source(threat) == "secret"
    ]
    entries.sort(
        key=lambda e: (e["rule_id"], e["resource_address"], e["file"], e["line"] or 0),
    )
    return entries


def project_model(report: Any) -> dict[str, Any]:
    """Boundary threats, attack paths and effective-severity changes; empty keys omitted."""
    threats = list(report.threats)
    model: dict[str, Any] = {}

    boundary: list[dict[str, Any]] = []
    for threat in threats:
        if _source(threat) != "boundary":
            continue
        entry: dict[str, Any] = {
            "source": threat.resource_address,
            "severity": _plain(threat.severity),
            "stride": threat.stride_category,
        }
        target = getattr(threat, "target_address", "")
        if target:
            entry["target"] = target
        boundary.append(entry)
    boundary.sort(key=lambda e: (e["source"], e.get("target", ""), e["severity"], e["stride"]))
    if boundary:
        model["boundary"] = boundary

    paths: list[dict[str, Any]] = []
    for path in getattr(report, "attack_paths", None) or []:
        paths.append(
            {
                "entry": _node_id(path.entry),
                "target": _node_id(path.target),
                "nodes": [_node_id(hop) for hop in path.hops],
                "severity": _plain(path.severity),
            }
        )
    paths.sort(key=lambda p: (p["entry"], p["target"], p["nodes"]))
    if paths:
        model["attack_paths"] = paths

    changes: list[dict[str, Any]] = []
    for threat in threats:
        effective = _plain(getattr(threat, "effective_severity", None))
        base = _plain(threat.severity)
        if effective is None or effective == base:
            continue
        changes.append(
            {
                "rule_id": threat.rule_id,
                "resource_address": threat.resource_address,
                "base": base,
                "effective": effective,
            }
        )
    changes.sort(key=lambda e: (e["rule_id"], e["resource_address"]))
    if changes:
        model["effective_severity"] = changes

    return model


def project_sections(
    relpath: str, graph: Any, report: Any, rule_groups: Mapping[str, str]
) -> dict[str, Any]:
    """Map section file name (relative to the input's directory) to its JSON content."""
    threats = list(report.threats)
    sections: dict[str, Any] = {META: {"input": relpath}}
    graph_section = project_graph(graph)
    if graph_section is not None:
        sections[GRAPH] = graph_section
    for group, entries in project_findings(threats, rule_groups).items():
        sections[f"{FINDINGS_DIR}/{group}.json"] = entries
    secrets = project_secrets(threats)
    if secrets:
        sections[SECRETS] = secrets
    model = project_model(report)
    if model:
        sections[MODEL] = model
    return json.loads(json.dumps(sections, sort_keys=True))


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


def _optional_attr(module: str, name: str) -> Any:
    """Look up module.name without importing anything that is not there yet."""
    try:
        if importlib.util.find_spec(module) is None:
            return None
    except ModuleNotFoundError:
        return None
    return getattr(importlib.import_module(module), name, None)


def analyze_input(relpath: str, repo_root: Path = REPO_ROOT) -> tuple[Any, Any]:
    """Parse, build the graph and analyze one input without an LLM."""
    path = repo_root / relpath
    parsed = detect_and_parse(path)
    graph = InfraGraph.from_parsed(parsed)
    find_secrets = _optional_attr("threatcode.engine.secrets.iac", "find_secrets_in_file")
    context_cls = _optional_attr("threatcode.engine.context", "AnalysisContext")
    engine = HybridEngine()
    if find_secrets is not None and context_cls is not None:
        text = path.read_text(encoding="utf-8", errors="replace")
        secret_findings = list(find_secrets(path, text, parsed, graph, repo_root))
        context = context_cls(input_label=relpath, secret_findings=secret_findings)
        report = engine.analyze(graph, input_file=relpath, context=context)
    else:
        report = engine.analyze(graph, input_file=relpath)
    return graph, report


def builtin_rule_groups() -> dict[str, str]:
    return {rule.id: rule.source_group for rule in load_builtin_rules()}


def snapshot(relpath: str) -> dict[str, Any]:
    graph, report = analyze_input(relpath)
    return project_sections(relpath, graph, report, builtin_rule_groups())


# ---------------------------------------------------------------------------
# Recording on disk
# ---------------------------------------------------------------------------


def _render(content: Any) -> str:
    return json.dumps(content, indent=2, sort_keys=True) + "\n"


def read_recording(directory: Path) -> dict[str, Any]:
    """Every JSON file below a recording directory, keyed by posix path."""
    recorded: dict[str, Any] = {}
    if directory.is_dir():
        for path in sorted(directory.rglob("*")):
            if path.is_file():
                rel = path.relative_to(directory).as_posix()
                recorded[rel] = json.loads(path.read_text(encoding="utf-8"))
    return recorded


def diff_recording(directory: Path, actual: Mapping[str, Any]) -> list[str]:
    """Describe every missing, unexpected and differing section file."""
    recorded = read_recording(directory)
    problems: list[str] = []
    for rel in sorted(set(actual) - set(recorded)):
        problems.append(f"missing section file {rel}")
    for rel in sorted(set(recorded) - set(actual)):
        problems.append(f"unexpected section file {rel}")
    for rel in sorted(set(actual) & set(recorded)):
        if actual[rel] != recorded[rel]:
            problems.append(f"section file {rel} differs")
    return problems


def write_recording(directory: Path, actual: Mapping[str, Any]) -> list[str]:
    """Rewrite changed sections and delete stale ones; return the changed files."""
    recorded = read_recording(directory)
    changed: list[str] = []
    for rel, content in actual.items():
        if recorded.get(rel, _MISSING) != content:
            target = directory / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(_render(content), encoding="utf-8")
            changed.append(f"{directory.name}/{rel}")
    for rel in sorted(set(recorded) - set(actual)):
        (directory / rel).unlink()
        changed.append(f"{directory.name}/{rel} (deleted)")
    for sub in sorted(directory.rglob("*"), reverse=True):
        if sub.is_dir() and not any(sub.iterdir()):
            sub.rmdir()
    return changed


_MISSING = object()


def _announce(request: pytest.FixtureRequest, lines: list[str]) -> None:
    """Show the changed files even when output capture is on."""
    reporter = request.config.pluginmanager.get_plugin("terminalreporter")
    text = "golden files changed:\n" + "\n".join(f"  {line}" for line in lines)
    if reporter is not None:
        reporter.write_line("")
        for line in text.splitlines():
            reporter.write_line(line)
    else:  # pragma: no cover - only without the terminal reporter
        print(text, file=sys.stderr)


# ---------------------------------------------------------------------------
# The golden test
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("relpath", GOLDEN_INPUTS)
def test_iac_output_matches_golden(relpath: str, request: pytest.FixtureRequest) -> None:
    directory = GOLDEN_DIR / golden_key(relpath)
    assert (REPO_ROOT / relpath).is_file(), f"Golden input {relpath} does not exist"
    actual = snapshot(relpath)
    problems = diff_recording(directory, actual)
    if UPDATE and problems:
        _announce(request, write_recording(directory, actual))
        problems = diff_recording(directory, actual)
    assert not problems, (
        f"{relpath}: golden recording out of date ({'; '.join(problems)}). "
        "See the module docstring to re-record."
    )


def test_recording_directories_are_named_after_their_input() -> None:
    for name, relpath in DISCOVERED:
        assert name == golden_key(relpath), (
            f"{name}/meta.json points at {relpath}, which belongs in {golden_key(relpath)}/"
        )


def test_every_realistic_fixture_has_a_recording() -> None:
    expected = {
        str(p.relative_to(REPO_ROOT)) for p in (FIXTURES / "realistic").iterdir() if p.is_file()
    }
    assert expected <= set(GOLDEN_INPUTS), sorted(expected - set(GOLDEN_INPUTS))


def test_findings_files_are_named_after_a_rule_group() -> None:
    groups = set(builtin_rule_groups().values())
    for name, _relpath in DISCOVERED:
        for path in (GOLDEN_DIR / name / FINDINGS_DIR).glob("*.json"):
            assert path.stem in groups, f"{name}/{FINDINGS_DIR}/{path.name}: no such rule group"


# ---------------------------------------------------------------------------
# Harness self-tests
# ---------------------------------------------------------------------------


def _node(
    category: NodeCategory = NodeCategory.STORAGE,
    zone: TrustZone = TrustZone.DATA,
    **extra: Any,
) -> SimpleNamespace:
    return SimpleNamespace(category=category, trust_zone=zone, **extra)


def _graph(**node_extra: Any) -> SimpleNamespace:
    nodes = {
        "a": _node(**node_extra),
        "b": _node(NodeCategory.NETWORK, TrustZone.DMZ, **node_extra),
    }
    edge = SimpleNamespace(
        source="a",
        target="b",
        edge_type=EdgeType.DEPENDENCY,
        crosses_trust_boundary=True,
    )
    return SimpleNamespace(nodes=nodes, edges=[edge])


def _threat(source: str = "rule", **extra: Any) -> SimpleNamespace:
    fields: dict[str, Any] = {
        "source": source,
        "rule_id": "S3_NO_LOGGING",
        "resource_address": "aws_s3_bucket.a",
        "severity": Severity.MEDIUM,
        "stride_category": "repudiation",
        "mitre_techniques": ["T1530", "T1190"],
    }
    fields.update(extra)
    return SimpleNamespace(**fields)


GROUPS = {"S3_NO_LOGGING": "aws__s3"}


class TestProjection:
    def test_optional_attributes_render_the_same_absent_and_at_their_default(self) -> None:
        bare = project_sections(
            "x", _graph(), SimpleNamespace(threats=[_threat(), _threat("boundary")]), GROUPS
        )
        defaulted = project_sections(
            "x",
            _graph(exposure="unknown"),
            SimpleNamespace(
                threats=[
                    _threat(target_address="", effective_severity=None),
                    _threat("boundary", target_address="", effective_severity=None),
                ],
                attack_paths=[],
            ),
            GROUPS,
        )
        assert bare == defaulted
        assert "exposure" not in bare[GRAPH]["nodes"]["a"]
        assert "target" not in bare[MODEL]["boundary"][0]
        assert "attack_paths" not in bare[MODEL]
        assert "effective_severity" not in bare[MODEL]

    def test_non_default_optional_attributes_are_rendered(self) -> None:
        hop = SimpleNamespace(node_id="aws_lb.web")
        path = SimpleNamespace(
            entry="internet",
            target="aws_s3_bucket.a",
            hops=[SimpleNamespace(node_id="internet"), hop, SimpleNamespace(node_id="a")],
            severity=Severity.CRITICAL,
        )
        sections = project_sections(
            "x",
            _graph(exposure="public"),
            SimpleNamespace(
                threats=[
                    _threat(effective_severity=Severity.HIGH),
                    _threat("boundary", target_address="b"),
                ],
                attack_paths=[path],
            ),
            GROUPS,
        )
        assert sections[GRAPH]["nodes"]["a"]["exposure"] == "public"
        model = sections[MODEL]
        assert model["boundary"][0]["target"] == "b"
        assert model["attack_paths"][0]["nodes"] == ["internet", "aws_lb.web", "a"]
        assert model["effective_severity"] == [
            {
                "rule_id": "S3_NO_LOGGING",
                "resource_address": "aws_s3_bucket.a",
                "base": "medium",
                "effective": "high",
            }
        ]

    def test_an_effective_severity_equal_to_the_base_is_not_a_change(self) -> None:
        report = SimpleNamespace(threats=[_threat(effective_severity=Severity.MEDIUM)])
        assert "effective_severity" not in project_model(report)

    def test_sections_without_content_have_no_file(self) -> None:
        sections = project_sections("x", _graph(), SimpleNamespace(threats=[]), GROUPS)
        assert set(sections) == {META, GRAPH}

    def test_findings_are_grouped_by_rule_file_and_sorted(self) -> None:
        threats = [
            _threat(resource_address="aws_s3_bucket.z"),
            _threat(resource_address="aws_s3_bucket.a"),
        ]
        sections = project_sections("x", _graph(), SimpleNamespace(threats=threats), GROUPS)
        entries = sections["findings/aws__s3.json"]
        assert [e["resource_address"] for e in entries] == ["aws_s3_bucket.a", "aws_s3_bucket.z"]
        assert entries[0]["techniques"] == ["T1190", "T1530"]
        assert set(entries[0]) == {
            "rule_id",
            "resource_address",
            "severity",
            "stride",
            "techniques",
        }

    def test_secret_findings_get_their_own_section(self) -> None:
        secret = _threat(
            "secret", rule_id="AWS_KEY", location_file="main.tf", location_start_line=7
        )
        sections = project_sections("x", _graph(), SimpleNamespace(threats=[secret]), GROUPS)
        assert sections[SECRETS] == [
            {
                "rule_id": "AWS_KEY",
                "resource_address": "aws_s3_bucket.a",
                "file": "main.tf",
                "line": 7,
                "severity": "medium",
            }
        ]
        assert not any(name.startswith(FINDINGS_DIR) for name in sections)

    def test_a_finding_from_an_unknown_rule_is_an_error(self) -> None:
        with pytest.raises(AssertionError, match="unknown rule id"):
            project_findings([_threat(rule_id="NOT_A_RULE")], GROUPS)

    def test_edges_are_sorted_by_source_target_and_type(self) -> None:
        graph = _graph()
        graph.edges.insert(
            0,
            SimpleNamespace(
                source="b",
                target="a",
                edge_type=EdgeType.DATA_FLOW,
                crosses_trust_boundary=False,
            ),
        )
        edges = project_graph(graph)["edges"]  # type: ignore[index]
        assert [(e["source"], e["target"]) for e in edges] == [("a", "b"), ("b", "a")]


class TestRecordingDiff:
    def _sections(self) -> dict[str, Any]:
        return {META: {"input": "x"}, GRAPH: {"nodes": {}, "edges": []}, MODEL: {"a": 1}}

    def _record(self, tmp_path: Path) -> Path:
        directory = tmp_path / "x"
        write_recording(directory, self._sections())
        return directory

    def test_identical_recording_has_no_problems(self, tmp_path: Path) -> None:
        directory = self._record(tmp_path)
        assert diff_recording(directory, self._sections()) == []

    def test_a_missing_section_file_is_detected(self, tmp_path: Path) -> None:
        directory = self._record(tmp_path)
        (directory / MODEL).unlink()
        assert diff_recording(directory, self._sections()) == [f"missing section file {MODEL}"]

    def test_an_unexpected_section_file_is_detected(self, tmp_path: Path) -> None:
        directory = self._record(tmp_path)
        (directory / FINDINGS_DIR).mkdir()
        (directory / FINDINGS_DIR / "aws__s3.json").write_text("[]\n", encoding="utf-8")
        assert diff_recording(directory, self._sections()) == [
            "unexpected section file findings/aws__s3.json"
        ]

    def test_a_changed_section_file_is_detected(self, tmp_path: Path) -> None:
        directory = self._record(tmp_path)
        changed = self._sections()
        changed[MODEL] = {"a": 2}
        assert diff_recording(directory, changed) == [f"section file {MODEL} differs"]

    def test_a_missing_recording_directory_reports_every_section(self, tmp_path: Path) -> None:
        problems = diff_recording(tmp_path / "nope", self._sections())
        assert len(problems) == 3
        assert all(p.startswith("missing") for p in problems)

    def test_update_rewrites_changed_sections_and_deletes_stale_ones(self, tmp_path: Path) -> None:
        directory = self._record(tmp_path)
        (directory / FINDINGS_DIR).mkdir()
        (directory / FINDINGS_DIR / "aws__s3.json").write_text("[]\n", encoding="utf-8")
        new = self._sections()
        new[MODEL] = {"a": 2}
        changed = write_recording(directory, new)
        assert sorted(changed) == [
            "x/findings/aws__s3.json (deleted)",
            "x/model.json",
        ]
        assert diff_recording(directory, new) == []
        assert not (directory / FINDINGS_DIR).exists()

    def test_update_leaves_unchanged_files_alone(self, tmp_path: Path) -> None:
        directory = self._record(tmp_path)
        assert write_recording(directory, self._sections()) == []

    def test_discovery_reads_meta_files_only(self, tmp_path: Path) -> None:
        (tmp_path / "terraform__a.tf").mkdir()
        (tmp_path / "terraform__a.tf" / META).write_text(
            json.dumps({"input": "tests/fixtures/terraform/a.tf"}), encoding="utf-8"
        )
        (tmp_path / "stray").mkdir()
        (tmp_path / "not_a_dir.json").write_text("{}", encoding="utf-8")
        assert discover_inputs(tmp_path) == [("terraform__a.tf", "tests/fixtures/terraform/a.tf")]

    def test_golden_key_replaces_slashes(self) -> None:
        assert golden_key("tests/fixtures/mcp/fixed/.mcp.json") == "mcp__fixed__.mcp.json"
        assert golden_key("tests/fixtures/terraform/simple.tf") == "terraform__simple.tf"


# ---------------------------------------------------------------------------
# scripts/check_golden_scope.py
# ---------------------------------------------------------------------------


def _load_scope_script() -> Any:
    path = REPO_ROOT / "scripts" / "check_golden_scope.py"
    spec = importlib.util.spec_from_file_location("check_golden_scope", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


scope = _load_scope_script()
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

GOLDEN_REL = "tests/fixtures/golden"
ALL = f"{GOLDEN_REL}/**"


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        [
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A git repository with two recorded inputs and one source file, committed once."""
    _git(tmp_path, "init", "-q", "-b", "main")
    for name in ("a", "b"):
        folder = tmp_path / GOLDEN_REL / name
        (folder / "findings").mkdir(parents=True)
        (folder / "meta.json").write_text("{}\n", encoding="utf-8")
        (folder / "graph.json").write_text("{}\n", encoding="utf-8")
        (folder / "findings" / "aws__s3.json").write_text("[]\n", encoding="utf-8")
        (folder / "findings" / "aws__vpc.json").write_text("[]\n", encoding="utf-8")
    (tmp_path / "src.py").write_text("x = 1\n", encoding="utf-8")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "base")
    return tmp_path


def _run(repo: Path, *args: str, capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    code = scope.main(["--repo", str(repo), *args])
    captured = capsys.readouterr()
    return code, captured.out + captured.err


class TestGlobTranslation:
    @pytest.mark.parametrize(
        ("pattern", "path", "expected"),
        [
            (ALL, f"{GOLDEN_REL}/a/graph.json", True),
            (ALL, f"{GOLDEN_REL}/a/findings/aws__s3.json", True),
            (ALL, "src/threatcode/cli.py", False),
            (f"{GOLDEN_REL}/*/graph.json", f"{GOLDEN_REL}/a/graph.json", True),
            (f"{GOLDEN_REL}/*/graph.json", f"{GOLDEN_REL}/a/b/graph.json", False),
            (
                f"{GOLDEN_REL}/*/findings/aws__s3.json",
                f"{GOLDEN_REL}/a/findings/aws__s3.json",
                True,
            ),
            (
                f"{GOLDEN_REL}/*/findings/aws__s3.json",
                f"{GOLDEN_REL}/a/findings/aws__vpc.json",
                False,
            ),
            (
                f"{GOLDEN_REL}/*/findings/aws__s3.json",
                f"{GOLDEN_REL}/a/x/findings/aws__s3.json",
                False,
            ),
            (f"{GOLDEN_REL}/**/graph.json", f"{GOLDEN_REL}/graph.json", True),
            (f"{GOLDEN_REL}/**/graph.json", f"{GOLDEN_REL}/a/b/graph.json", True),
            (
                f"{GOLDEN_REL}/*/findings/aws__*.json",
                f"{GOLDEN_REL}/a/findings/aws__vpc.json",
                True,
            ),
            (f"{GOLDEN_REL}/*/findings/aws__*.json", f"{GOLDEN_REL}/a/findings/gcp__x.json", False),
            (f"{GOLDEN_REL}/?/graph.json", f"{GOLDEN_REL}/a/graph.json", True),
            (f"{GOLDEN_REL}/?/graph.json", f"{GOLDEN_REL}/ab/graph.json", False),
            (f"{GOLDEN_REL}/[ab]/graph.json", f"{GOLDEN_REL}/b/graph.json", True),
            (f"{GOLDEN_REL}/[ab]/graph.json", f"{GOLDEN_REL}/c/graph.json", False),
            (f"./{GOLDEN_REL}/a/graph.json", f"{GOLDEN_REL}/a/graph.json", True),
            (f"{GOLDEN_REL}/a.b/graph.json", f"{GOLDEN_REL}/aXb/graph.json", False),
            (f"{GOLDEN_REL}/a", f"{GOLDEN_REL}/a/graph.json", False),
        ],
    )
    def test_glob_matching(self, pattern: str, path: str, expected: bool) -> None:
        assert bool(scope.glob_to_regex(pattern).fullmatch(path)) is expected


@needs_git
class TestCheckGoldenScope:
    def test_unchanged_tree_passes(self, repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
        code, out = _run(repo, capsys=capsys)
        assert code == 0
        assert "0 golden file(s) changed" in out

    def test_the_base_that_was_used_is_printed(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        sha = _git(repo, "rev-parse", "HEAD")
        _code, out = _run(repo, "--allow", ALL, capsys=capsys)
        assert f"HEAD ({sha[:12]})" in out

    def test_a_change_inside_the_scope_passes(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (repo / GOLDEN_REL / "a" / "findings" / "aws__s3.json").write_text(
            "[1]\n", encoding="utf-8"
        )
        code, out = _run(repo, "--allow", f"{GOLDEN_REL}/*/findings/aws__s3.json", capsys=capsys)
        assert code == 0
        assert "1 golden file(s) changed" in out

    def test_a_modified_file_outside_the_scope_fails_and_is_named(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (repo / GOLDEN_REL / "a" / "findings" / "aws__s3.json").write_text(
            "[1]\n", encoding="utf-8"
        )
        (repo / GOLDEN_REL / "b" / "findings" / "aws__vpc.json").write_text(
            "[1]\n", encoding="utf-8"
        )
        code, out = _run(repo, "--allow", f"{GOLDEN_REL}/*/findings/aws__s3.json", capsys=capsys)
        assert code == 1
        assert f"modified: {GOLDEN_REL}/b/findings/aws__vpc.json" in out
        assert "aws__s3.json" not in out.split("outside")[1]

    def test_a_deleted_file_outside_the_scope_fails(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (repo / GOLDEN_REL / "a" / "graph.json").unlink()
        code, out = _run(repo, "--allow", f"{GOLDEN_REL}/*/findings/*.json", capsys=capsys)
        assert code == 1
        assert f"deleted: {GOLDEN_REL}/a/graph.json" in out

    def test_an_untracked_new_file_outside_the_scope_fails(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        folder = repo / GOLDEN_REL / "c"
        folder.mkdir()
        (folder / "meta.json").write_text("{}\n", encoding="utf-8")
        code, out = _run(repo, "--allow", f"{GOLDEN_REL}/*/graph.json", capsys=capsys)
        assert code == 1
        assert f"added: {GOLDEN_REL}/c/meta.json" in out

    def test_a_new_input_directory_is_in_scope_when_every_file_is_allowed(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        folder = repo / GOLDEN_REL / "c"
        folder.mkdir()
        (folder / "meta.json").write_text("{}\n", encoding="utf-8")
        assert _run(repo, "--allow", ALL, capsys=capsys)[0] == 0

    def test_a_staged_change_outside_the_scope_fails(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = repo / GOLDEN_REL / "a" / "graph.json"
        path.write_text('{"x": 1}\n', encoding="utf-8")
        _git(repo, "add", str(path))
        code, out = _run(repo, "--allow", f"{GOLDEN_REL}/*/findings/*.json", capsys=capsys)
        assert code == 1
        assert "a/graph.json" in out

    def test_a_committed_change_is_seen_against_an_earlier_base(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        base = _git(repo, "rev-parse", "HEAD")
        path = repo / GOLDEN_REL / "a" / "graph.json"
        path.write_text('{"x": 1}\n', encoding="utf-8")
        _git(repo, "commit", "-q", "-am", "leak")
        assert _run(repo, "--allow", f"{GOLDEN_REL}/*/findings/*.json", capsys=capsys)[0] == 0
        code, out = _run(
            repo, "--base", base, "--allow", f"{GOLDEN_REL}/*/findings/*.json", capsys=capsys
        )
        assert code == 1
        assert "a/graph.json" in out

    def test_the_base_can_come_from_the_environment(
        self, repo: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        base = _git(repo, "rev-parse", "HEAD")
        (repo / GOLDEN_REL / "a" / "graph.json").write_text('{"x": 1}\n', encoding="utf-8")
        _git(repo, "commit", "-q", "-am", "leak")
        monkeypatch.setenv("THREATCODE_GOLDEN_BASE", base)
        code, _out = _run(repo, "--allow", f"{GOLDEN_REL}/*/findings/*.json", capsys=capsys)
        assert code == 1

    def test_the_flag_wins_over_the_environment(
        self, repo: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("THREATCODE_GOLDEN_BASE", "does-not-exist")
        assert _run(repo, "--base", "HEAD", capsys=capsys)[0] == 0

    def test_an_unknown_base_is_a_usage_error(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, out = _run(repo, "--base", "no-such-ref", "--allow", ALL, capsys=capsys)
        assert code == 2
        assert "no-such-ref" in out

    def test_outside_a_repository_is_a_usage_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, out = _run(tmp_path, "--allow", ALL, capsys=capsys)
        assert code == 2
        assert "not inside a git repository" in out

    def test_with_no_allow_glob_nothing_may_change(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (repo / GOLDEN_REL / "a" / "graph.json").write_text('{"x": 1}\n', encoding="utf-8")
        assert _run(repo, capsys=capsys)[0] == 1

    def test_changes_outside_the_golden_directory_are_not_its_business(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (repo / "src.py").write_text("x = 2\n", encoding="utf-8")
        assert _run(repo, "--allow", f"{GOLDEN_REL}/a/graph.json", capsys=capsys)[0] == 0

    def test_it_works_from_a_subdirectory(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (repo / GOLDEN_REL / "a" / "graph.json").write_text('{"x": 1}\n', encoding="utf-8")
        sub = repo / GOLDEN_REL / "a"
        code, out = _run(sub, "--allow", f"{GOLDEN_REL}/*/findings/*.json", capsys=capsys)
        assert code == 1
        assert f"{GOLDEN_REL}/a/graph.json" in out

    def test_several_allow_flags_and_globs_are_combined(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        for name in ("graph.json", "findings/aws__s3.json"):
            (repo / GOLDEN_REL / "a" / name).write_text("[1]\n", encoding="utf-8")
        code, _out = _run(
            repo,
            "--allow",
            f"{GOLDEN_REL}/*/graph.json",
            "--allow",
            f"{GOLDEN_REL}/*/findings/aws__s3.json",
            capsys=capsys,
        )
        assert code == 0
        code, _out = _run(
            repo,
            "--allow",
            f"{GOLDEN_REL}/*/graph.json",
            f"{GOLDEN_REL}/*/findings/aws__s3.json",
            capsys=capsys,
        )
        assert code == 0

    def test_paths_with_spaces_are_handled(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        folder = repo / GOLDEN_REL / "with space"
        folder.mkdir()
        (folder / "meta.json").write_text("{}\n", encoding="utf-8")
        code, out = _run(repo, "--allow", f"{GOLDEN_REL}/a/*", capsys=capsys)
        assert code == 1
        assert "with space/meta.json" in out

    def test_a_custom_golden_directory(
        self, repo: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (repo / "other").mkdir()
        (repo / "other" / "x.json").write_text("{}\n", encoding="utf-8")
        code, out = _run(repo, "--golden-dir", "other", "--allow", "nothing", capsys=capsys)
        assert code == 1
        assert "other/x.json" in out

    def test_running_the_script_directly_uses_exit_codes(self, repo: Path) -> None:
        script = REPO_ROOT / "scripts" / "check_golden_scope.py"
        ok = subprocess.run(
            [sys.executable, str(script), "--repo", str(repo), "--allow", ALL],
            capture_output=True,
            text=True,
        )
        assert ok.returncode == 0
        (repo / GOLDEN_REL / "a" / "graph.json").write_text("[1]\n", encoding="utf-8")
        bad = subprocess.run(
            [sys.executable, str(script), "--repo", str(repo)],
            capture_output=True,
            text=True,
        )
        assert bad.returncode == 1
        assert "a/graph.json" in bad.stderr


@needs_git
def test_the_real_golden_directory_passes_a_scope_that_covers_it() -> None:
    if not (REPO_ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    script = REPO_ROOT / "scripts" / "check_golden_scope.py"
    result = subprocess.run(
        [sys.executable, str(script), "--repo", str(REPO_ROOT), "--allow", ALL],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
