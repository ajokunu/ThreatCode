"""The documentation is executable: what it shows is run, and what it counts is computed.

A page that quotes a command, a rule count or a benchmark goes stale the day the code changes.
This module makes that a test failure instead.

Runnable blocks.
A fenced block that the line above marks with an HTML comment is run:

    <!-- runnable exit=1 -->

    ```bash
    threatcode scan examples/aws-webapp
    ```

``bash`` blocks run under ``bash -e -o pipefail`` in a scratch directory that holds ``examples``
and ``tests`` (symlinks to the repository's), with a ``threatcode`` command that runs this
checkout, and must exit with the annotated status (``exit=N``, default 0).
Because of ``-e`` every command but the last must succeed, so a block that expects findings puts
the failing scan last or reports with ``--fail-on none``.
``python`` blocks run in a fresh interpreter with the checkout on the path.
A ``<!-- rules-file -->`` marker on a ``yaml`` block loads it as a custom rule file next to the
built-in rules, so an example whose ids collide with a built-in rule fails.
A ``<!-- ci-script only=threatcode -->`` marker on a CI ``yaml`` block runs the lines of its
``script`` lists (``only=`` keeps the lines that start with the word, ``pip install`` lines are
always skipped) with ``infra/`` standing for the demo stack.
A ``<!-- bitbucket-upload -->`` marker on a ``python`` block runs the Bitbucket helper against a
local server that records the requests.
The marker is an HTML comment because the info string of a fence is not safe: MkDocs'
``pymdownx.superfences`` drops a fence whose info string it does not understand, and GitHub and
PyPI show the extra words.

Every ``threatcode ...`` command in any ``bash``, ``sh``, ``console`` or ``yaml`` block, runnable
or not, is parsed with the real click command, so an option that does not exist, a value outside
a choice and a command that was removed fail here.

Generated content.
``scripts/gen_docs_counts.py`` computes counts, tables and the benchmark from the code, and the
pages must equal its output.
Run ``python scripts/gen_docs_counts.py --write`` after a change to a rule, a format or a parser.

A harness that cannot fail proves nothing, so ``TestTheHarnessCanFail`` feeds it deliberately
broken snippets.
"""

from __future__ import annotations

import ast
import copy
import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

import click
import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src"
DOC_FILES: list[Path] = [
    REPO / "README.md",
    REPO / "SECURITY.md",
    *sorted((REPO / "docs").glob("*.md")),
    *sorted((REPO / "examples").rglob("README.md")),
]
DOC_FILES = [p for p in DOC_FILES if p.is_file()]
CHANGELOG = REPO / "CHANGELOG.md"

SHELL_LANGS = {"bash", "sh", "shell", "console", "zsh"}
COMMAND_LANGS = SHELL_LANGS | {"yaml", "yml"}
NEEDS_BASH = pytest.mark.skipif(
    sys.platform == "win32", reason="runnable blocks run in a scratch directory of symlinks"
)

# ---------------------------------------------------------------------------------------
# Reading fenced blocks
# ---------------------------------------------------------------------------------------

_FENCE = re.compile(r"^(?P<indent>[ \t]*)(?P<fence>`{3,}|~{3,})[ \t]*(?P<info>[^`\n]*)$")
_KINDS = "runnable|rules-file|ci-script|bitbucket-upload"
_MARKER = re.compile(rf"^[ \t]*<!--\s*(?P<kind>{_KINDS})(?P<attrs>[^>]*?)\s*-->\s*$")


@dataclass(frozen=True)
class Block:
    path: Path
    line: int  # 1-based line of the opening fence
    lang: str
    text: str
    marker: str | None = None  # "runnable" or "rules-file"
    attrs: dict[str, str] = field(default_factory=dict)

    @property
    def where(self) -> str:
        try:
            shown = self.path.relative_to(REPO)
        except ValueError:
            shown = self.path
        return f"{shown}:{self.line}"

    @property
    def expected_exit(self) -> int:
        return int(self.attrs.get("exit", "0"))


def _attrs(raw: str) -> dict[str, str]:
    return dict(part.split("=", 1) for part in raw.split() if "=" in part)


def extract_blocks(text: str, path: Path) -> list[Block]:
    """Every fenced code block of ``text``, with the runnable marker above it if there is one."""
    lines = text.split("\n")
    blocks: list[Block] = []
    i = 0
    while i < len(lines):
        match = _FENCE.match(lines[i])
        if not match:
            i += 1
            continue
        indent, fence = match.group("indent"), match.group("fence")
        info = match.group("info").strip()
        lang = info.split()[0].lower() if info else ""
        body: list[str] = []
        j = i + 1
        while j < len(lines):
            closing = lines[j].strip()
            if closing.startswith(fence[0] * len(fence)) and not closing.strip(fence[0]):
                break
            body.append(lines[j])
            j += 1
        marker: str | None = None
        attrs: dict[str, str] = {}
        k = i - 1
        while k >= 0 and not lines[k].strip():
            k -= 1
        if k >= 0 and (found := _MARKER.match(lines[k])):
            marker = found.group("kind")
            attrs = _attrs(found.group("attrs"))
        dedented = [line[len(indent) :] if line.startswith(indent) else line for line in body]
        blocks.append(Block(path, i + 1, lang, "\n".join(dedented) + "\n", marker, attrs))
        i = j + 1
    return blocks


def all_blocks() -> list[Block]:
    return [b for path in DOC_FILES for b in extract_blocks(path.read_text("utf-8"), path)]


def _id(block: Block) -> str:
    return block.where


RUNNABLE = [b for b in all_blocks() if b.marker == "runnable"]
RULE_FILES = [b for b in all_blocks() if b.marker == "rules-file"]
CI_SCRIPTS = [b for b in all_blocks() if b.marker == "ci-script"]
UPLOADS = [b for b in all_blocks() if b.marker == "bitbucket-upload"]

# Paths a CI recipe names that stand for a demo stack when the recipe runs here.
SUBSTITUTIONS = {"infra/": "examples/aws-webapp", "../base/infra": "examples/aws-webapp"}

# ---------------------------------------------------------------------------------------
# Running blocks
# ---------------------------------------------------------------------------------------


def scratch(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    """A working directory with the repository's examples and tests, and an environment."""
    work = tmp_path / "work"
    work.mkdir(parents=True)
    for name in ("examples", "tests"):
        (work / name).symlink_to(REPO / name, target_is_directory=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True)
    shim = bin_dir / "threatcode"
    shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" -m threatcode "$@"\n', encoding="utf-8")
    shim.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir(parents=True)
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("THREATCODE_") and key not in {"CI", "NO_COLOR", "COLUMNS"}
    }
    env.update(
        {
            "PATH": f"{bin_dir}{os.pathsep}{env.get('PATH', '')}",
            "PYTHONPATH": f"{SRC}{os.pathsep}{REPO}",
            "PYTHONDONTWRITEBYTECODE": "1",
            "HOME": str(home),
            "NO_COLOR": "1",
            "SOURCE_DATE_EPOCH": "1700000000",
            "COLUMNS": "100",
        }
    )
    return work, env


def run_runnable(block: Block, tmp_path: Path) -> list[str]:
    """Run one runnable block; the problems found, empty when it behaved as annotated."""
    work, env = scratch(tmp_path)
    if block.lang in SHELL_LANGS:
        command = ["bash", "-e", "-o", "pipefail", "-c", block.text]
    elif block.lang == "python":
        script = work / "block.py"
        script.write_text(block.text, encoding="utf-8")
        command = [sys.executable, str(script)]
    else:
        return [f"{block.where}: a {block.lang or 'plain'} block cannot be runnable"]
    try:
        done = subprocess.run(
            command, cwd=work, env=env, capture_output=True, text=True, timeout=180, check=False
        )
    except subprocess.TimeoutExpired:
        return [f"{block.where}: timed out after 180 seconds"]
    if done.returncode != block.expected_exit:
        tail = "\n".join((done.stdout + done.stderr).strip().splitlines()[-12:])
        return [
            f"{block.where}: exited {done.returncode}, the block says exit={block.expected_exit}\n"
            f"{tail}"
        ]
    missing = [
        name
        for name in block.attrs.get("creates", "").split(",")
        if name and not (work / name).exists()
    ]
    if missing:
        return [f"{block.where}: the block should have created {missing}"]
    return []


def _script_lines(node: Any) -> Iterator[str]:
    """Every string in a ``script:`` list of a CI document, in order."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "script" and isinstance(value, list):
                yield from (str(v) for v in value)
            else:
                yield from _script_lines(value)
    elif isinstance(node, list):
        for value in node:
            yield from _script_lines(value)


def run_ci_script(block: Block, tmp_path: Path) -> list[str]:
    """Run the script lines of a CI recipe with the demo stack standing in for ``infra/``."""
    document = yaml.safe_load(block.text)
    lines = [line for line in _script_lines(document) if not line.startswith("pip install")]
    only = block.attrs.get("only")
    if only:
        lines = [line for line in lines if line.startswith(only)]
    if not lines:
        return [f"{block.where}: the recipe has no script line to run"]
    script = "\n".join(lines)
    for placeholder, real in SUBSTITUTIONS.items():
        script = script.replace(placeholder, real)
    return run_runnable(
        Block(block.path, block.line, "bash", script + "\n", "runnable", block.attrs), tmp_path
    )


class _Recorder:
    """A local HTTP server that records every request it gets."""

    def __init__(self) -> None:
        import http.server
        import threading

        self.requests: list[tuple[str, str, Any]] = []
        recorder = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _record(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length) or b"null")
                recorder.requests.append((self.command, self.path, body))
                self.send_response(200)
                self.end_headers()

            do_PUT = _record  # noqa: N815
            do_POST = _record  # noqa: N815

            def log_message(self, *args: object) -> None:
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/2.0"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> _Recorder:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()


def run_bitbucket_upload(block: Block, tmp_path: Path, annotations: int) -> list[str]:
    """Run the documented upload helper against a recorder; the problems found."""
    work, env = scratch(tmp_path)
    batch = [
        {"external_id": f"a{i}", "annotation_type": "VULNERABILITY", "summary": f"finding {i}"}
        for i in range(annotations)
    ]
    document = {
        "report": {"title": "ThreatCode", "details": "d", "report_type": "SECURITY"},
        "annotations": batch,
        "annotation_batches": [batch[i : i + 100] for i in range(0, len(batch), 100)],
    }
    (work / "insights.json").write_text(json.dumps(document), encoding="utf-8")
    (work / "upload.py").write_text(block.text, encoding="utf-8")
    with _Recorder() as recorder:
        env.update(
            {
                "BITBUCKET_API": recorder.url,
                "BITBUCKET_PROXY": "",
                "BITBUCKET_REPO_FULL_NAME": "acme/shop",
                "BITBUCKET_COMMIT": "abc123",
            }
        )
        done = subprocess.run(
            [sys.executable, "upload.py"],
            cwd=work,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    if done.returncode:
        return [f"{block.where}: the helper failed: {done.stderr.strip()[-400:]}"]
    problems: list[str] = []
    base = "/2.0/repositories/acme/shop/commit/abc123/reports/threatcode"
    first = recorder.requests[0] if recorder.requests else None
    if first is None or first[:2] != ("PUT", base) or first[2] != document["report"]:
        problems.append(f"{block.where}: the report must be PUT alone at {base}: {first}")
    posts = recorder.requests[1:]
    if any(m != "POST" or path != base + "/annotations" for m, path, _b in posts):
        problems.append(f"{block.where}: annotations must be POSTed to {base}/annotations")
    sizes = [len(body) for _m, _p, body in posts]
    if any(not isinstance(b, list) or len(b) > 100 for _m, _p, b in posts):
        problems.append(f"{block.where}: each POST must be a list of at most 100: {sizes}")
    if sum(sizes) != annotations:
        problems.append(f"{block.where}: {sum(sizes)} annotations sent, expected {annotations}")
    return problems


def check_rules_file(block: Block, tmp_path: Path) -> list[str]:
    """Load a rules-file block next to the built-in rules; the problems found."""
    from threatcode.engine.rules.loader import load_all_rules
    from threatcode.exceptions import RuleLoadError

    path = tmp_path / "rules.yml"
    path.write_text(block.text, encoding="utf-8")
    try:
        rules = load_all_rules([path])
    except RuleLoadError as exc:
        return [f"{block.where}: {exc}"]
    from threatcode.engine.rules.loader import load_builtin_rules

    builtin = {r.id for r in load_builtin_rules()}
    custom = [r for r in rules if r.id not in builtin]
    if not custom:
        return [f"{block.where}: the block defines no rule"]
    return []


# ---------------------------------------------------------------------------------------
# threatcode command lines against the real click commands
# ---------------------------------------------------------------------------------------

_OPERATORS = {"|", "||", "&&", ";", "&", ">", ">>", "<", "2>", "2>>", "(", ")", "<<", "<<<"}
_COMMAND_LINE = re.compile(
    r"(?:^|[\s;&|(\"'`])(?:python3?\s+-m\s+)?threatcode\s+(?P<rest>[^\s<>|&;].*)$"
)


def logical_lines(text: str) -> Iterator[tuple[int, str]]:
    """Lines of a shell or YAML block with ``\\`` continuations joined; (offset, line)."""
    pending = ""
    start = 0
    for offset, raw in enumerate(text.split("\n")):
        line = raw.rstrip()
        if line.endswith("\\"):
            if not pending:
                start = offset
            pending += line[:-1] + " "
            continue
        if pending:
            yield start, pending + line
            pending = ""
        else:
            yield offset, line
    if pending:
        yield start, pending


def command_tokens(line: str) -> list[str] | None:
    """The arguments of the ``threatcode`` command on a line, or ``None`` if there is none."""
    stripped = re.sub(r"^\s*(?:\$|>)\s+", "", line)
    if stripped.lstrip().startswith("#"):
        return None
    match = _COMMAND_LINE.search(stripped)
    if not match:
        return None
    lexer = shlex.shlex(match.group("rest"), posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = "#"
    try:
        tokens = list(lexer)
    except ValueError:
        # An unbalanced quote: a YAML scalar or prose that ends the command with a quote.
        tokens = match.group("rest").replace("'", " ").replace('"', " ").split()
    arguments: list[str] = []
    for token in tokens:
        if token in _OPERATORS or re.fullmatch(r"[0-9]*[<>&|;]+[0-9]*", token):
            break
        arguments.append(token)
    return arguments


def _lenient(command: click.Command) -> click.Command:
    """A copy of ``command`` whose Path parameters accept any text (the files need not exist)."""
    clone = copy.copy(command)
    clone.params = []
    for param in command.params:
        twin = copy.copy(param)
        if isinstance(param.type, click.Path):
            twin.type = click.STRING
        clone.params.append(twin)
    return clone


def _group_rest(ctx: click.Context) -> list[str]:
    """The command name and arguments left after the group's own options, in any click 8.x."""
    held = ctx.__dict__.get("_protected_args") or ctx.__dict__.get("protected_args") or []
    return [*held, *ctx.args]


def check_command(arguments: list[str], where: str) -> list[str]:
    """Parse ``threatcode <arguments>`` with click; the problems found."""
    from threatcode.cli import cli

    try:
        ctx = cli.make_context("threatcode", list(arguments), resilient_parsing=False)
        rest = _group_rest(ctx)
        if not rest:
            return [f"{where}: threatcode {' '.join(arguments)}: no command given"]
        name, command, remaining = cli.resolve_command(ctx, rest)
        if command is None or name is None:
            return [f"{where}: threatcode {' '.join(arguments)}: no such command"]
        _lenient(command).make_context(name, remaining, parent=ctx)
    except click.exceptions.Exit:
        return []  # --help and --version exit on purpose
    except click.UsageError as exc:
        return [f"{where}: threatcode {' '.join(arguments)}: {exc.format_message()}"]
    return []


def command_problems(block: Block) -> list[str]:
    problems: list[str] = []
    for offset, line in logical_lines(block.text):
        arguments = command_tokens(line)
        if arguments is None:
            continue
        problems += check_command(arguments, f"{block.where}+{offset + 1}")
    return problems


# ---------------------------------------------------------------------------------------
# The generator
# ---------------------------------------------------------------------------------------


def load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "gen_docs_counts", REPO / "scripts" / "gen_docs_counts.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["gen_docs_counts"] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------------------
# Prose rules
# ---------------------------------------------------------------------------------------

EM_DASH = "\u2014"
_EMOJI = re.compile(
    "[\U0001f000-\U0001faff\u2600-\u26ff\u2700-\u27bf\u2b50\u2b55\ufe0f\u200d\u20e3]"
)
_ABBREVIATIONS = ("e.g.", "i.e.", "etc.", "vs.", "cf.", "approx.", "a.k.a.")


def prose_lines(text: str) -> Iterator[tuple[int, str]]:
    """The prose of a Markdown page: no code fences, tables, comments, headings or html."""
    in_fence = False
    in_comment = False
    fence = ""
    for number, raw in enumerate(text.split("\n"), start=1):
        stripped = raw.strip()
        if in_fence:
            if stripped.startswith(fence) and not stripped.strip(fence[0]):
                in_fence = False
            continue
        opening = _FENCE.match(raw)
        if opening:
            in_fence, fence = True, opening.group("fence")
            continue
        if in_comment:
            in_comment = "-->" not in raw
            continue
        if stripped.startswith("<!--") and "-->" not in stripped:
            in_comment = True
            continue
        if not stripped or stripped.startswith(("|", "<", "#", "![")):
            continue
        yield number, raw


def two_sentences(line: str) -> bool:
    """Whether a prose line holds a sentence end followed by another sentence."""
    cleaned = re.sub(r"^\s*(?:[-*+]|\d+\.)\s+", "", line)
    cleaned = re.sub(r"`[^`]*`", "", cleaned)
    cleaned = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", cleaned)
    cleaned = re.sub(r"<!--.*?-->", "", cleaned)
    for abbreviation in _ABBREVIATIONS:
        cleaned = cleaned.replace(abbreviation, "")
    return bool(re.search(r"[a-z0-9\)\"][.!?](?:\"|\))?\s+[A-Z]", cleaned))


# ---------------------------------------------------------------------------------------
# Tests: generated content
# ---------------------------------------------------------------------------------------


class TestGeneratedContent:
    def test_every_generated_page_and_count_matches_the_code(self) -> None:
        gen = load_generator()
        facts = gen.collect()
        stale = [
            str(path.relative_to(REPO))
            for path, text in gen.compute(facts).items()
            if path.read_text("utf-8") != text
        ]
        assert not stale, f"out of date: {stale}. Run: python scripts/gen_docs_counts.py --write"

    def test_the_generator_command_line_agrees(self) -> None:
        done = subprocess.run(
            [sys.executable, str(REPO / "scripts" / "gen_docs_counts.py"), "--check"],
            capture_output=True,
            text=True,
            cwd=REPO,
            timeout=300,
            check=False,
        )
        assert done.returncode == 0, done.stderr

    def test_the_counts_the_documentation_states_are_the_ones_in_the_code(self) -> None:
        gen = load_generator()
        facts = gen.collect()
        assert facts.counts["rules"] == len({r.id for r in facts.rules}), "rule ids must be unique"
        stated = {
            (path.name, m.group("name")): m.group("value")
            for path in DOC_FILES
            for m in gen.COUNT_RE.finditer(path.read_text("utf-8"))
        }
        assert stated, "no page states a computed count"
        assert ("README.md", "rules") in stated

    def test_a_count_marker_that_lies_is_caught(self) -> None:
        gen = load_generator()
        facts = gen.collect()
        wrong = f"{facts.counts['rules'] + 1}<!-- count:rules --> rules"
        fixed, unknown = gen.replace_counts(wrong, facts.counts)
        assert unknown == []
        assert fixed != wrong
        assert fixed.startswith(str(facts.counts["rules"]))


# ---------------------------------------------------------------------------------------
# Tests: runnable blocks
# ---------------------------------------------------------------------------------------


class TestRunnableBlocks:
    def test_the_documentation_has_runnable_blocks(self) -> None:
        assert len(RUNNABLE) >= 10

    @NEEDS_BASH
    @pytest.mark.parametrize("block", RUNNABLE, ids=_id)
    def test_the_block_behaves_as_annotated(self, block: Block, tmp_path: Path) -> None:
        problems = run_runnable(block, tmp_path)
        assert not problems, "\n".join(problems)

    @NEEDS_BASH
    @pytest.mark.parametrize("block", CI_SCRIPTS, ids=_id)
    def test_a_ci_recipe_runs_its_threatcode_lines(self, block: Block, tmp_path: Path) -> None:
        problems = run_ci_script(block, tmp_path)
        assert not problems, "\n".join(problems)

    @NEEDS_BASH
    @pytest.mark.parametrize("block", UPLOADS, ids=_id)
    @pytest.mark.parametrize("annotations", [0, 3, 100, 101, 250])
    def test_the_bitbucket_helper_puts_the_report_and_posts_batches_of_at_most_100(
        self, block: Block, annotations: int, tmp_path: Path
    ) -> None:
        problems = run_bitbucket_upload(block, tmp_path, annotations)
        assert not problems, "\n".join(problems)

    @pytest.mark.parametrize("block", RULE_FILES, ids=_id)
    def test_a_rules_file_block_loads_beside_the_builtin_rules(
        self, block: Block, tmp_path: Path
    ) -> None:
        problems = check_rules_file(block, tmp_path)
        assert not problems, "\n".join(problems)


class TestCommandLines:
    def test_the_documentation_shows_commands(self) -> None:
        count = sum(
            1
            for b in all_blocks()
            if b.lang in COMMAND_LANGS
            for _o, line in logical_lines(b.text)
            if command_tokens(line) is not None
        )
        assert count >= 40

    @pytest.mark.parametrize(
        "block",
        [b for b in all_blocks() if b.lang in COMMAND_LANGS and "threatcode" in b.text],
        ids=_id,
    )
    def test_every_threatcode_command_parses_against_the_real_cli(self, block: Block) -> None:
        problems = command_problems(block)
        assert not problems, "\n".join(problems)


class TestStructuredBlocks:
    @pytest.mark.parametrize(
        "block", [b for b in all_blocks() if b.lang in {"yaml", "yml"}], ids=_id
    )
    def test_yaml_blocks_are_valid_yaml(self, block: Block) -> None:
        try:
            list(yaml.safe_load_all(block.text))
        except yaml.YAMLError as exc:
            pytest.fail(f"{block.where}: {exc}")

    @pytest.mark.parametrize(
        "block",
        [b for b in all_blocks() if b.lang == "json" and "..." not in b.text],
        ids=_id,
    )
    def test_json_blocks_are_valid_json(self, block: Block) -> None:
        try:
            json.loads(block.text)
        except json.JSONDecodeError as exc:
            pytest.fail(f"{block.where}: {exc}")

    def test_action_inputs_in_workflow_examples_exist(self) -> None:
        action = yaml.safe_load((REPO / ".github/actions/threatcode/action.yml").read_text("utf-8"))
        inputs = set(action["inputs"])
        used = 0
        for block in all_blocks():
            if block.lang not in {"yaml", "yml"} or "actions/threatcode" not in block.text:
                continue
            document = yaml.safe_load(block.text)
            for step in _steps(document):
                if "actions/threatcode" in str(step.get("uses", "")):
                    used += 1
                    unknown = set(step.get("with") or {}) - inputs
                    assert not unknown, f"{block.where}: the action has no input {sorted(unknown)}"
        assert used >= 1, "no documented workflow uses the action"


def _steps(node: Any) -> Iterator[dict[str, Any]]:
    if isinstance(node, dict):
        if "uses" in node:
            yield node
        for value in node.values():
            yield from _steps(value)
    elif isinstance(node, list):
        for value in node:
            yield from _steps(value)


# ---------------------------------------------------------------------------------------
# Tests: claims that were wrong before and must stay right
# ---------------------------------------------------------------------------------------


def _text(path: Path) -> str:
    return path.read_text("utf-8")


def _fenced_lines(language: set[str]) -> Iterator[tuple[Block, int, str]]:
    for block in all_blocks():
        if block.lang in language:
            for offset, line in enumerate(block.text.split("\n")):
                yield block, offset, line


class TestClaimsStayTrue:
    def test_terraform_show_always_names_the_plan_file(self) -> None:
        """`terraform show -json` alone prints state, which scans as an empty plan."""
        bad = [
            f"{b.where}+{o + 1}: {line.strip()}"
            for path in DOC_FILES
            for b, o, line in _fenced_lines({"bash", "sh", "shell", "console", "yaml", "yml"})
            if b.path == path and re.search(r"terraform show -json(?!\s+[^\s>|])", line)
        ]
        assert not bad, bad

    def test_a_plan_is_always_written_before_it_is_shown(self) -> None:
        for block in all_blocks():
            if block.lang in COMMAND_LANGS and "terraform show -json" in block.text:
                assert "terraform plan" in block.text or "plan.tfplan" in block.text, block.where

    def test_no_page_documents_the_old_redaction_placeholders(self) -> None:
        for path in DOC_FILES:
            text = _text(path)
            assert "__REDACTED_" not in text, path
            assert "__HASH_" not in text, path

    def test_redaction_placeholder_formats_match_the_redactor(self) -> None:
        from threatcode.engine.llm.redactor import Redactor

        sample = {"arn": "arn:aws:s3:::acme-prod-data", "owner_contact": "ops@example.com"}
        placeholder = Redactor("placeholder").redact(sample)
        hashed = Redactor("hash").redact(sample)
        assert re.fullmatch(r"REDACTED_arn_\d+", placeholder["arn"])
        assert re.fullmatch(r"REDACTED_arn_[0-9a-f]{16}", hashed["arn"])
        text = _text(REPO / "docs" / "security.md")
        assert "REDACTED_<label>_<n>" in text
        assert "REDACTED_<label>_<16 hex digits>" in text

    def test_the_readme_has_no_stray_table_fragment(self) -> None:
        assert not re.search(r"^-{3,}\|", _text(REPO / "README.md"), re.MULTILINE)

    def test_no_page_repeats_a_count_that_the_code_changed(self) -> None:
        stale = re.compile(
            r"eight output formats|\b10 (?:lockfile )?formats\b|\b13 lockfile\b|\b228 rules\b"
            r"|\b221 rules\b|\b233 rules\b|\b131 rules\b"
        )
        for path in DOC_FILES:
            assert not stale.search(_text(path)), path

    def test_the_install_text_does_not_promise_pypi_before_it_is_live(self) -> None:
        """`pip install threatcode` is a different project until the release is published."""
        bare = re.compile(
            r"pip install\s+(?:--upgrade\s+)?[\"']?threatcode(?:\[[a-z,]+\])?[\"']?\s*$"
        )
        offenders = [
            f"{b.where}+{o + 1}"
            for b, o, line in _fenced_lines(SHELL_LANGS)
            if bare.search(line.strip())
        ]
        assert not offenders, offenders
        assert "git+https://github.com/ajokunu/ThreatCode" in _text(REPO / "README.md")

    def test_the_dotfile_restriction_comes_before_any_llm_example(self) -> None:
        for relative in ("README.md", "docs/configuration.md"):
            text = _text(REPO / relative)
            restriction = text.find("auto-discovered")
            example = min(
                (i for i in (text.find("\nllm:"), text.find("\n  llm:")) if i >= 0),
                default=len(text),
            )
            assert 0 <= restriction < example, relative

    def test_no_removed_command_or_function_is_documented(self) -> None:
        removed = re.compile(
            r"threatcode (?:fs|repo|image|sbom|license|vuln|secret|db)\b"
            r"|\bscan_(?:filesystem|repository|image|secrets|vulnerabilities|all)\("
            r"|--scanners\b|--ignore-unfixed\b|--min-severity high -f cyclonedx"
        )
        for path in DOC_FILES:
            if path.name == "migrating.md":
                continue
            for block in extract_blocks(_text(path), path):
                assert not removed.search(block.text), (
                    f"{block.where}: {removed.search(block.text)}"
                )

    def test_no_page_claims_lockfile_support(self) -> None:
        """There is no lockfile parser: dependencies come in through --ingest."""
        lockfiles = re.compile(
            r"package-lock\.json|yarn\.lock|pnpm-lock|Pipfile\.lock|composer\.lock|poetry\.lock"
            r"|Cargo\.lock|Gemfile\.lock|go\.sum|requirements\.txt|mix\.lock|pubspec\.lock"
        )
        for path in DOC_FILES:
            assert not lockfiles.search(_text(path)), f"{path} names a lockfile"

    def test_gitlab_is_not_told_to_read_sarif_as_a_sast_report(self) -> None:
        """GitLab's SAST report is another schema; SARIF stays a plain artifact."""
        text = _text(REPO / "docs" / "cicd.md")
        assert not re.search(r"reports:\s*\n\s*sast", text)
        assert "gl-sast-report" not in text

    def test_azure_and_gcp_have_rule_findings_and_no_attack_paths(self) -> None:
        """The documented caveat: topology and attack paths are AWS, Kubernetes and MCP."""
        from tests.test_quality.harness import scan_fixture

        gen = load_generator()
        for provider in gen.NO_TOPOLOGY_PROVIDERS:
            fixture = REPO / gen.PROVIDER_FIXTURES[provider]
            scan = scan_fixture(fixture.name, fixture.parent)
            assert scan.threats, f"{provider} fixture yields no findings"
            assert scan.report.attack_paths == [], f"{provider} now has attack paths: update docs"
        for provider in gen.TOPOLOGY_PROVIDERS:
            fixture = REPO / gen.PROVIDER_FIXTURES[provider]
            scan = scan_fixture(fixture.name, fixture.parent)
            assert scan.threats, f"{provider} fixture yields no findings"

    def test_every_documented_input_round_trips_through_a_fixture(self) -> None:
        """Each supported-input claim is backed by a scan that parses and is evaluated."""
        from tests.test_quality.harness import scan_fixture

        gen = load_generator()
        facts = gen.collect()
        for kind in gen.INPUTS:
            rule_ids = {r.id for p in kind.families for r in facts.by_provider[p]}
            for fixture in kind.fixtures:
                path = REPO / fixture
                assert path.exists(), f"{kind.key}: fixture {fixture} is missing"
                scan = scan_fixture(path.name, path.parent) if path.is_file() else _scan_dir(path)
                assert scan.graph.node_count > 0, f"{kind.key}: {fixture} models nothing"
                fired = {t.rule_id for t in scan.threats if t.rule_id}
                assert fired & rule_ids, f"{kind.key}: no {kind.families} rule fires on {fixture}"

    def test_every_provider_has_a_fixture_that_fires_one_of_its_rules(self) -> None:
        from tests.test_quality.harness import scan_fixture

        gen = load_generator()
        facts = gen.collect()
        for provider, relative in gen.PROVIDER_FIXTURES.items():
            path = REPO / relative
            scan = scan_fixture(path.name, path.parent)
            rules = {r.id for r in facts.by_provider[provider]}
            assert {t.rule_id for t in scan.threats} & rules, f"{provider}: {relative}"

    def test_every_kubernetes_kind_marked_evaluated_has_a_round_trip(self, tmp_path: Path) -> None:
        """A kind the docs call 'parsed and evaluated' must produce a node and a finding."""
        from tests.test_quality.harness import scan_fixture

        gen = load_generator()
        facts = gen.collect()
        directory = REPO / "tests" / "fixtures" / "kubernetes"
        nodes_by_type: dict[str, set[str]] = {}
        findings_by_type: dict[str, set[str]] = {}
        for fixture in sorted(directory.iterdir()):
            scan = scan_fixture(fixture.name, directory)
            for node in scan.graph.nodes.values():
                nodes_by_type.setdefault(node.resource_type, set()).add(fixture.name)
            for threat in scan.threats:
                if threat.rule_id:
                    findings_by_type.setdefault(threat.resource_type, set()).add(fixture.name)
        from threatcode.parsers.kubernetes import _KIND_TO_RESOURCE_TYPE

        # A kind no fixture holds is checked with a minimal manifest of its own.
        for kind, resource_type in _KIND_TO_RESOURCE_TYPE.items():
            if resource_type in nodes_by_type:
                continue
            probe = tmp_path / f"{kind}.yaml"
            probe.write_text(
                f"apiVersion: v1\nkind: {kind}\nmetadata:\n  name: probe\n  namespace: default\n",
                encoding="utf-8",
            )
            scan = scan_fixture(probe.name, tmp_path)
            if any(n.resource_type == resource_type for n in scan.graph.nodes.values()):
                nodes_by_type[resource_type] = {probe.name}
        missing_nodes, missing_findings = [], []
        for kind, resource_type in _KIND_TO_RESOURCE_TYPE.items():
            evaluated = any(r.matches_type(resource_type) for r in facts.rules)
            if resource_type not in nodes_by_type:
                missing_nodes.append(kind)
            elif evaluated and resource_type not in findings_by_type:
                # The rule test suite proves every rule fires on its bad example.
                cases = REPO / "tests" / "test_rules" / "cases"
                proven = any(
                    (cases / rule.source_group / rule.id / "bad.k8s.yaml").is_file()
                    for rule in facts.rules
                    if rule.matches_type(resource_type)
                )
                if not proven:
                    missing_findings.append(kind)
        assert not missing_nodes, f"no fixture parses these kinds: {missing_nodes}"
        assert not missing_findings, f"no fixture gets a finding on: {missing_findings}"


def _scan_dir(path: Path) -> Any:
    from threatcode.pipeline import prepare_request, run_scan

    prepared = prepare_request([path], min_severity="info", no_ignore=True, env={})
    result = run_scan(prepared.request)
    assert not result.coverage.errors, result.coverage.errors
    return type("DirScan", (), {"graph": result.graph, "threats": list(result.report.threats)})()


NETWORK_MODULES = frozenset(
    {
        "socket", "urllib.request", "http.client", "http.server", "ftplib", "smtplib",
        "telnetlib", "requests", "httpx", "urllib3", "aiohttp", "anthropic", "openai",
        "webbrowser", "xmlrpc", "xmlrpc.client", "ssl",
    }
)  # fmt: skip
PROCESS_MODULES = frozenset({"subprocess", "pty", "multiprocessing", "concurrent.futures"})
# The only modules of the package that may connect or start a process, and why.
NETWORK_ALLOWED = {"engine/llm/client.py": "the optional model client and its address check"}
PROCESS_ALLOWED = {"parsers/helm.py": "helm template, when helm is installed"}
PROCESS_CALLS = frozenset({"system", "popen", "execv", "execvp", "spawnv", "spawnl", "fork"})


def imported_modules(source: str) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
            modules.update(f"{node.module}.{alias.name}" for alias in node.names)
    return modules


def process_calls(source: str) -> set[str]:
    return {
        node.func.attr
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "os"
        and node.func.attr in PROCESS_CALLS
    }


def connection_offenders(root: Path) -> list[str]:
    """Modules under ``root`` that import a network or process module without being allowed."""
    offenders: list[str] = []
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root).as_posix()
        source = path.read_text("utf-8")
        modules = imported_modules(source)
        network = sorted(m for m in modules if m in NETWORK_MODULES)
        process = sorted(m for m in modules if m in PROCESS_MODULES)
        if network and relative not in NETWORK_ALLOWED:
            offenders.append(f"{relative} imports {network}")
        if (process or process_calls(source)) and relative not in PROCESS_ALLOWED:
            offenders.append(
                f"{relative} starts processes: {process or sorted(process_calls(source))}"
            )
    return offenders


def _is_pending_marker(node: ast.expr) -> bool:
    """True for ``pending(...)``, as a decorator or as a module-level ``pytestmark``."""
    return (
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "pending"
    )


_DEFS = (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)


def cited_pending_tests(cited: list[tuple[str, str]], root: Path) -> list[str]:
    """The cited ``(file, "Class::test")`` pairs that the suite skips as pending.

    It sees the two forms a marker takes on a whole test or class: a ``@pending(...)`` decorator
    and a module-level ``pytestmark = pending(...)``. A marker applied to one parameter through
    ``pytest.param(..., marks=...)`` is not seen.
    A citation of a whole file (an empty name) is pending when any test in the file carries
    either form. A citation of a class or a test is pending when it, an enclosing class, or the
    module does.
    """
    found: list[str] = []
    for relative, name in cited:
        tree = ast.parse((root / relative).read_text("utf-8"))
        pending_here = any(
            isinstance(stmt, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "pytestmark" for t in stmt.targets)
            and _is_pending_marker(stmt.value)
            for stmt in tree.body
        )
        scope: ast.AST = tree
        for part in filter(None, name.split("::")):
            scope = next(
                (n for n in getattr(scope, "body", []) if isinstance(n, _DEFS) and n.name == part),
                scope,
            )
            if isinstance(scope, _DEFS):
                pending_here = pending_here or any(
                    _is_pending_marker(d) for d in scope.decorator_list
                )
        pending_here = pending_here or any(
            _is_pending_marker(d)
            for node in ast.walk(scope)
            if isinstance(node, _DEFS)
            for d in node.decorator_list
        )
        if pending_here:
            found.append(f"{relative}::{name}" if name else relative)
    return found


class TestClaimsAreProven:
    """docs/claims.md lists what may be said about ThreatCode, and the proof of each."""

    CLAIMS = REPO / "docs" / "claims.md"

    def test_every_test_a_claim_cites_exists(self) -> None:
        text = self.CLAIMS.read_text("utf-8")
        cited = re.findall(r"`(tests/[\w/.-]+\.py)(?:::([\w:]+))?`", text)
        assert len(cited) >= 12, "the claims page should cite its tests"
        missing: list[str] = []
        for relative, names in cited:
            path = REPO / relative
            if not path.is_file():
                missing.append(relative)
                continue
            source = path.read_text("utf-8")
            for name in filter(None, names.split("::")):
                if not re.search(rf"(?:def|class) {re.escape(name)}\b", source):
                    missing.append(f"{relative}::{name}")
        assert not missing, f"claims cite tests that do not exist: {missing}"

    def test_no_claim_rests_on_a_test_that_is_skipped_as_pending(self) -> None:
        """A pending test is skipped, so a claim that cites one is proven by nothing."""
        cited = re.findall(r"`(tests/[\w/.-]+\.py)(?:::([\w:]+))?`", self.CLAIMS.read_text("utf-8"))
        pending_cited = cited_pending_tests(cited, REPO)
        assert not pending_cited, f"claims cite tests that are skipped as pending: {pending_cited}"

    def test_the_pending_check_would_catch_a_claim_that_cites_a_pending_test(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_one.py").write_text(
            "from tests.helpers.pending import pending\n"
            "class TestOne:\n"
            '    @pending("WP-9-9", "later")\n'
            "    def test_skipped(self) -> None: ...\n"
            "    def test_runs(self) -> None: ...\n",
            encoding="utf-8",
        )
        (tmp_path / "tests" / "test_two.py").write_text(
            'from tests.helpers.pending import pending\npytestmark = pending("WP-9-9", "later")\n'
            "def test_anything() -> None: ...\n",
            encoding="utf-8",
        )
        (tmp_path / "tests" / "test_three.py").write_text(
            "class TestThree:\n    def test_runs(self) -> None: ...\n", encoding="utf-8"
        )
        cited = [
            ("tests/test_one.py", "TestOne::test_skipped"),
            ("tests/test_one.py", "TestOne::test_runs"),
            ("tests/test_one.py", "TestOne"),
            ("tests/test_one.py", ""),
            ("tests/test_two.py", "test_anything"),
            ("tests/test_two.py", ""),
            ("tests/test_three.py", "TestThree::test_runs"),
            ("tests/test_three.py", ""),
        ]
        assert cited_pending_tests(cited, tmp_path) == [
            "tests/test_one.py::TestOne::test_skipped",
            "tests/test_one.py::TestOne",
            "tests/test_one.py",
            "tests/test_two.py::test_anything",
            "tests/test_two.py",
        ]

    @NEEDS_BASH
    def test_the_pitch_claim_checks_that_the_cve_enables_the_instance_hop(
        self, tmp_path: Path
    ) -> None:
        """The CVE-as-a-step claim fails if the block asks about a hop the CVE does not enable."""
        text = self.CLAIMS.read_text("utf-8")
        (block,) = [
            b
            for b in extract_blocks(text, self.CLAIMS)
            if b.marker == "runnable" and "trivy-app-image.json" in b.text
        ]
        assert run_runnable(block, tmp_path / "real") == []
        asked = 'hops["aws_instance.app[0]"]'
        assert asked in block.text
        wrong_hop = Block(
            block.path,
            block.line,
            block.lang,
            block.text.replace(asked, 'hops["aws_lb.front"]'),
            block.marker,
            block.attrs,
        )
        problems = run_runnable(wrong_hop, tmp_path / "wrong")
        assert problems and "AssertionError" in problems[0]

    def test_every_claim_link_has_a_section(self) -> None:
        text = self.CLAIMS.read_text("utf-8")
        for number in re.findall(r"\]\(#claim-(\d+)\)", text):
            assert f"\n## Claim {number}\n" in text, f"claim {number} has no section"

    def test_every_claim_section_is_a_runnable_block(self) -> None:
        blocks = extract_blocks(self.CLAIMS.read_text("utf-8"), self.CLAIMS)
        sections = len(re.findall(r"^## Claim \d+$", self.CLAIMS.read_text("utf-8"), re.M))
        assert len([b for b in blocks if b.marker == "runnable"]) >= sections

    def test_only_the_model_client_opens_a_connection(self) -> None:
        """security.md: only the model client connects, and only helm is started."""
        assert connection_offenders(SRC / "threatcode") == []

    def test_the_connection_check_would_catch_a_new_network_module(self, tmp_path: Path) -> None:
        sneaky = tmp_path / "telemetry.py"
        sneaky.write_text("import urllib.request\nurllib.request.urlopen('https://x')\n")
        runner = tmp_path / "run.py"
        runner.write_text("import os\nos.system('true')\n")
        found = connection_offenders(tmp_path)
        assert any("telemetry.py imports" in f for f in found)
        assert any("run.py starts processes" in f for f in found)


class TestChangelog:
    """The Unreleased section records every behavior change made by the rework."""

    @staticmethod
    def unreleased() -> str:
        text = _text(CHANGELOG)
        start = text.index("## [Unreleased]")
        return text[start : text.index("\n## [", start + 1)]

    def test_the_sections_come_in_the_documented_order(self) -> None:
        headings = re.findall(r"^### (.+)$", self.unreleased(), re.MULTILINE)
        order = ["Added", "Changed", "Removed", "Fixed", "Security"]
        assert [h for h in headings if h in order] == order

    def test_every_removed_rule_id_is_recorded(self) -> None:
        from threatcode.engine.rules.loader import deprecated_rule_ids

        removed = self.unreleased().split("### Removed", 1)[1].split("### Fixed", 1)[0]
        missing = sorted(i for i in deprecated_rule_ids() if f"`{i}`" not in removed)
        assert not missing, f"removed rule ids missing from the changelog: {missing}"

    def test_the_headline_behavior_changes_are_recorded(self) -> None:
        text = self.unreleased()
        for phrase in (
            "default `--fail-on` is `high`",
            "Errors exit 2",
            "opt-in",
            "threatcode[llm]",
            "claude-sonnet-5-5",
            "`-f matrix` is now `-f navigator`",
            "`image`, `vuln`, `db`, `sbom`, `license`, `repo`, `fs` and `secret` commands are gone",
            "Azure and GCP",
        ):
            assert phrase in text, phrase

    def test_the_fragments_of_the_earlier_packages_are_assembled_and_gone(self) -> None:
        left = sorted(p.name for p in (REPO / "changelog.d").glob("WP-[1-4]-*.md"))
        assert not left, f"assembled into CHANGELOG.md, delete them: {left}"


# ---------------------------------------------------------------------------------------
# Tests: style and links
# ---------------------------------------------------------------------------------------


class TestStyle:
    @pytest.mark.parametrize("path", [*DOC_FILES, CHANGELOG], ids=lambda p: p.name)
    def test_no_em_dash_and_no_emoji(self, path: Path) -> None:
        text = _text(path)
        assert EM_DASH not in text, f"{path}: contains an em dash"
        found = _EMOJI.findall(text)
        assert not found, f"{path}: contains emoji {sorted(set(found))}"

    @pytest.mark.parametrize("path", DOC_FILES, ids=lambda p: str(p.relative_to(REPO)))
    def test_one_sentence_per_line(self, path: Path) -> None:
        crowded = [
            f"{path.name}:{n}: {line.strip()[:90]}"
            for n, line in prose_lines(_text(path))
            if two_sentences(line)
        ]
        assert not crowded, "\n".join(crowded[:10])

    def test_the_unreleased_changelog_has_one_sentence_per_line(self) -> None:
        text = _text(CHANGELOG)
        unreleased = text.split("\n## [", 2)
        section = unreleased[1] if len(unreleased) > 1 else text
        crowded = [
            f"CHANGELOG.md: {line.strip()[:90]}"
            for _n, line in prose_lines(section)
            if two_sentences(line)
        ]
        assert not crowded, "\n".join(crowded[:10])

    @pytest.mark.parametrize("path", DOC_FILES, ids=lambda p: str(p.relative_to(REPO)))
    def test_relative_links_resolve(self, path: Path) -> None:
        broken = []
        for match in re.finditer(r"\]\((?P<target>[^)\s]+)\)", _text(path)):
            target = match.group("target")
            if re.match(r"^(?:[a-z]+:|#|mailto:)", target):
                continue
            file_part = target.split("#", 1)[0]
            if file_part and not (path.parent / file_part).exists():
                broken.append(target)
        assert not broken, f"{path}: broken links {broken}"

    def test_the_readme_links_are_absolute_because_pypi_shows_it_too(self) -> None:
        relative = [
            m.group("target")
            for m in re.finditer(r"\]\((?P<target>[^)\s]+)\)", _text(REPO / "README.md"))
            if not re.match(r"^(?:https?:|#|mailto:)", m.group("target"))
        ]
        assert not relative, f"README links that break on PyPI: {relative}"

    def test_every_docs_page_is_in_the_navigation(self) -> None:
        nav = yaml.safe_load(_text(REPO / "mkdocs.yml"))["nav"]
        listed = set(re.findall(r"[\w./-]+\.md", json.dumps(nav)))
        pages = {p.name for p in (REPO / "docs").glob("*.md")}
        assert pages <= listed, f"pages missing from mkdocs nav: {sorted(pages - listed)}"
        assert listed <= pages, f"nav entries without a page: {sorted(listed - pages)}"

    def test_the_site_url_ends_with_a_slash(self) -> None:
        site_url = yaml.safe_load(_text(REPO / "mkdocs.yml"))["site_url"]
        assert site_url.endswith("/")


# ---------------------------------------------------------------------------------------
# Tests: the harness fails when it should
# ---------------------------------------------------------------------------------------


def _block(text: str, lang: str, marker: str | None = "runnable", **attrs: str) -> Block:
    return Block(Path("synthetic.md"), 1, lang, text, marker, dict(attrs))


class TestTheHarnessCanFail:
    @NEEDS_BASH
    def test_a_command_that_exits_with_the_wrong_status_fails(self, tmp_path: Path) -> None:
        broken = _block("threatcode scan examples/no-such-directory\n", "bash")
        problems = run_runnable(broken, tmp_path)
        assert problems and "exited 2" in problems[0]

    @NEEDS_BASH
    def test_the_annotated_status_is_what_passes(self, tmp_path: Path) -> None:
        ok = _block("threatcode scan examples/no-such-directory\n", "bash", exit="2")
        assert run_runnable(ok, tmp_path) == []

    @NEEDS_BASH
    def test_a_real_scan_exits_one_on_findings_and_the_harness_sees_it(
        self, tmp_path: Path
    ) -> None:
        scan = "threatcode scan examples/aws-webapp -o out.json\n"
        assert run_runnable(_block(scan, "bash", exit="1"), tmp_path / "a") == []
        assert run_runnable(_block(scan, "bash", exit="0"), tmp_path / "b")

    @NEEDS_BASH
    def test_a_python_block_that_raises_fails(self, tmp_path: Path) -> None:
        broken = _block("import threatcode\nassert threatcode.no_such_name\n", "python")
        problems = run_runnable(broken, tmp_path)
        assert problems and "exited 1" in problems[0]

    @NEEDS_BASH
    def test_a_python_block_that_runs_passes(self, tmp_path: Path) -> None:
        ok = _block("import threatcode\nassert threatcode.__version__\n", "python")
        assert run_runnable(ok, tmp_path) == []

    @NEEDS_BASH
    def test_the_old_register_parser_signature_fails(self, tmp_path: Path) -> None:
        """The example this harness was written for: arguments in the wrong order."""
        broken = _block(
            "from pathlib import Path\n"
            "from threatcode.parsers import register_parser, detect_and_parse\n"
            "def my_parser(path, content, data): return None\n"
            "def detect_my_format(path, content, data): return path.name.endswith('.myfmt')\n"
            "register_parser('my_format', my_parser, detect_my_format, priority=50)\n"
            "Path('x_my_format.myfmt').write_text('x')\n"
            "detect_and_parse('x_my_format.myfmt')\n",
            "python",
        )
        assert run_runnable(broken, tmp_path)

    def test_a_rules_file_that_reuses_a_builtin_id_fails(self, tmp_path: Path) -> None:
        text = (
            "rules:\n"
            "  - id: S3_PUBLIC_ACCESS\n"
            "    title: Duplicate\n"
            "    description: Collides with a built-in rule.\n"
            "    stride_category: information_disclosure\n"
            "    severity: high\n"
            "    resource_type: aws_s3_bucket\n"
            "    condition:\n"
            "      acl: public-read\n"
            "    mitigation: none\n"
        )
        problems = check_rules_file(_block(text, "yaml", "rules-file"), tmp_path)
        assert problems and "Duplicate rule ID" in problems[0]

    def test_a_rules_file_with_a_new_id_loads(self, tmp_path: Path) -> None:
        text = (
            "rules:\n"
            "  - id: EXAMPLE_PUBLIC_BUCKET\n"
            "    title: Example\n"
            "    description: A custom rule with its own id.\n"
            "    stride_category: information_disclosure\n"
            "    severity: high\n"
            "    resource_type: aws_s3_bucket\n"
            "    condition:\n"
            "      acl: public-read\n"
            "    mitigation: Make the bucket private.\n"
        )
        assert check_rules_file(_block(text, "yaml", "rules-file"), tmp_path) == []

    @pytest.mark.parametrize(
        "line",
        [
            "threatcode vuln package-lock.json --min-severity high",
            "threatcode scan infra/ --min-severity urgent",
            "threatcode scan infra/ --no-such-flag",
            "threatcode --no-color scan",
            "threatcode scan infra/ --no-color",
            "threatcode fs .",
            "threatcode scan infra/ -f cyclonedx",
        ],
    )
    def test_a_command_the_cli_would_refuse_is_reported(self, line: str) -> None:
        arguments = command_tokens(line)
        assert arguments is not None
        assert check_command(arguments, "synthetic.md:1")

    @pytest.mark.parametrize(
        "line",
        [
            "threatcode scan infra/",
            "threatcode -q --no-color scan infra/ -f sarif -o out.sarif --fail-on high",
            "terraform show -json tfplan | threatcode scan - --stdin-name plan.json",
            "threatcode diff base.json current.json --fail-on-new high",
            "threatcode scan infra/ -f matrix",
            "CI=1 threatcode scan . --strict && echo clean",
        ],
    )
    def test_a_valid_command_passes(self, line: str) -> None:
        arguments = command_tokens(line)
        assert arguments is not None
        assert check_command(arguments, "synthetic.md:1") == []

    def test_a_line_without_the_command_is_ignored(self) -> None:
        assert command_tokens("pip install threatcode") is None
        assert command_tokens("# threatcode scan infra/") is None

    def test_blocks_are_found_with_their_markers(self) -> None:
        text = (
            "intro\n\n<!-- runnable exit=1 -->\n\n```bash\nthreatcode scan x\n```\n\n"
            "```python\nprint(1)\n```\n"
        )
        blocks = extract_blocks(text, Path("t.md"))
        assert [b.lang for b in blocks] == ["bash", "python"]
        assert blocks[0].marker == "runnable" and blocks[0].expected_exit == 1
        assert blocks[1].marker is None

    def test_a_marker_two_paragraphs_above_does_not_count(self) -> None:
        text = "<!-- runnable -->\n\ntext\n\n```bash\nls\n```\n"
        assert extract_blocks(text, Path("t.md"))[0].marker is None

    def test_a_crowded_line_is_flagged_and_a_clean_one_is_not(self) -> None:
        assert two_sentences("This is one. This is another.")
        assert not two_sentences("This is one sentence, e.g. with an abbreviation.")
        assert not two_sentences("See `a. B` and version 0.9.1 for details.")
