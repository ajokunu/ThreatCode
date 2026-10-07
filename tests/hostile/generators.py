"""Generators for hostile inputs: nothing here is a stored file, everything is built on demand.

A scanner reads files other people wrote, so the inputs that matter are the ones built to hurt it.
Each generator writes one such input into a directory the caller owns, and returns the path to
hand to a scan. Sizes are parameters; the defaults are the smallest that hurt the parsers as
they were written, and every one stays small enough to build in well under a second.

* ``unterminated_helm_chart``: ``{{`` with no ``}}``, which a regex-based template scan answers
  in quadratic time.
* ``symlink_escape_tree``: links inside a scanned directory that point out of it, plus link cycles.
* ``fifo_tree``: a named pipe that blocks any reader that opens it.
* ``huge_line_*``: single lines of megabytes, plain and shaped to trigger regex backtracking.
* ``nested_*``: JSON and YAML nested thousands of levels deep.
* ``yaml_alias_bomb``: aliases that expand exponentially when something walks the document.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

CHART_YAML = "apiVersion: v2\nname: hostile\nversion: 0.1.0\n"

# ``name`` and ``bucket`` values that identify a resource unambiguously in scan output
INSIDE_RESOURCE = "inside_bucket"
OUTSIDE_RESOURCE = "leaked_outside_bucket"


def _tf(resource_name: str) -> str:
    return f'resource "aws_s3_bucket" "{resource_name}" {{\n  bucket = "{resource_name}"\n}}\n'


# ---------------------------------------------------------------------------------------
# Helm
# ---------------------------------------------------------------------------------------

HELM_SHAPES = ("braces", "if_blocks", "dash_whitespace")
# Units per shape that cost a regex-based template scan well over ten seconds. ``dash_whitespace``
# is the control: long, unterminated and cheap, because no pattern backtracks over it.
HELM_DEFAULT_UNITS = {"braces": 40_000, "if_blocks": 15_000, "dash_whitespace": 400_000}


def helm_template_body(shape: str, units: int) -> str:
    """Template text of ``units`` repetitions that opens an action and never closes it."""
    if shape == "braces":
        return "{{" * units
    if shape == "if_blocks":
        return "{{ if .Values.enabled " * units
    if shape == "dash_whitespace":
        return "{{-" + " " * units
    raise ValueError(f"unknown Helm shape {shape!r}; expected one of {HELM_SHAPES}")


def unterminated_helm_chart(root: Path, shape: str = "braces", units: int | None = None) -> Path:
    """A chart whose only template carries an unterminated action; returns its Chart.yaml."""
    if shape not in HELM_DEFAULT_UNITS:
        raise ValueError(f"unknown Helm shape {shape!r}; expected one of {HELM_SHAPES}")
    chart = root / f"chart-{shape}"
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text(CHART_YAML, encoding="utf-8")
    (chart / "values.yaml").write_text("enabled: true\n", encoding="utf-8")
    body = helm_template_body(shape, HELM_DEFAULT_UNITS[shape] if units is None else units)
    template = (
        f'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: hostile\ndata:\n  v: "{body}"\n'
    )
    (chart / "templates" / "configmap.yaml").write_text(template, encoding="utf-8")
    return chart / "Chart.yaml"


# ---------------------------------------------------------------------------------------
# Symlinks and FIFOs
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SymlinkTree:
    scan_root: Path  # the directory a scan is pointed at
    outside_dir: Path  # a sibling directory the links point into
    links: tuple[Path, ...]  # every symlink created inside scan_root


def symlink_escape_tree(root: Path) -> SymlinkTree:
    """A scan root holding one real file and links that lead out of it or round in circles.

    ``scan/main.tf`` declares ``inside_bucket``. ``outside/secret.tf`` declares
    ``leaked_outside_bucket`` and must never appear in a scan of ``scan/``. The links are a file
    link and a directory link to the outside, a link to the scan root itself and a two-link cycle.
    """
    scan_root = root / "scan"
    outside = root / "outside"
    scan_root.mkdir(parents=True)
    outside.mkdir()
    (scan_root / "main.tf").write_text(_tf(INSIDE_RESOURCE), encoding="utf-8")
    (outside / "secret.tf").write_text(_tf(OUTSIDE_RESOURCE), encoding="utf-8")
    links = [
        (scan_root / "escape-file.tf", Path("..") / "outside" / "secret.tf"),
        (scan_root / "escape-dir", Path("..") / "outside"),
        (scan_root / "loop-to-root", Path(".")),
        (scan_root / "cycle-a", Path("cycle-b")),
        (scan_root / "cycle-b", Path("cycle-a")),
    ]
    for link, target in links:
        link.symlink_to(target)
    return SymlinkTree(scan_root, outside, tuple(link for link, _ in links))


def fifo_tree(root: Path) -> Path:
    """A scan root with one real file and a named pipe with a Terraform name; returns the root.

    Opening the pipe for reading blocks until a writer appears, so a scanner that opens every
    file whose name matches hangs. Callers run the scan in a subprocess with a timeout.
    """
    if not hasattr(os, "mkfifo"):
        raise OSError("this platform has no os.mkfifo")
    scan_root = root / "fifo-scan"
    scan_root.mkdir(parents=True)
    (scan_root / "main.tf").write_text(_tf(INSIDE_RESOURCE), encoding="utf-8")
    os.mkfifo(scan_root / "pipe.tf")
    return scan_root


def is_fifo(path: Path) -> bool:
    return stat.S_ISFIFO(os.lstat(path).st_mode)


# ---------------------------------------------------------------------------------------
# Huge single lines
# ---------------------------------------------------------------------------------------


def huge_line_dockerfile(root: Path, size: int = 5_000_000) -> Path:
    """A Dockerfile whose RUN instruction is one line of ``size`` bytes."""
    path = root / "huge-line.Dockerfile"
    path.write_text("FROM debian:12-slim\nRUN " + "a" * size + "\n", encoding="utf-8")
    return path


def backtracking_dockerfile(root: Path, repeats: int = 200_000) -> Path:
    """A RUN line of ``curl x`` repeated, which a ``curl .* | sh`` regex retries from every start.

    The line has no pipe at all, so a correct scan finds nothing; a backtracking one compares every
    ``curl`` against the rest of the line.
    """
    path = root / "backtracking.Dockerfile"
    path.write_text("FROM debian:12-slim\nRUN " + "curl x " * repeats + "\n", encoding="utf-8")
    return path


def huge_line_terraform(root: Path, size: int = 3_000_000) -> Path:
    path = root / "huge-line.tf"
    path.write_text(
        f'resource "aws_s3_bucket" "b" {{\n  bucket = "{"x" * size}"\n}}\n', encoding="utf-8"
    )
    return path


def huge_line_mcp(root: Path, size: int = 5_000_000) -> Path:
    path = root / ".mcp.json"
    path.write_text(
        '{"mcpServers":{"a":{"command":"npx","args":["-y","' + "x" * size + '"]}}}',
        encoding="utf-8",
    )
    return path


def huge_line_kubernetes(root: Path, size: int = 5_000_000) -> Path:
    path = root / "huge-line.yaml"
    path.write_text(
        f'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\ndata:\n  k: "{"x" * size}"\n',
        encoding="utf-8",
    )
    return path


# ---------------------------------------------------------------------------------------
# Deep nesting and alias bombs
# ---------------------------------------------------------------------------------------


def nested_json(root: Path, depth: int = 100_000) -> Path:
    path = root / "nested.json"
    path.write_text("[" * depth + "]" * depth, encoding="utf-8")
    return path


def nested_yaml_flow(root: Path, depth: int = 100_000) -> Path:
    path = root / "nested-flow.yaml"
    path.write_text("[" * depth + "]" * depth, encoding="utf-8")
    return path


def nested_yaml_block(root: Path, depth: int = 3_000) -> Path:
    """Block mappings indented one more space per line, ``depth`` levels deep."""
    path = root / "nested-block.yaml"
    path.write_text("\n".join(" " * i + "a:" for i in range(depth)) + "\n", encoding="utf-8")
    return path


def yaml_alias_bomb(levels: int = 9, fanout: int = 9) -> str:
    """A Kubernetes ConfigMap whose ``data`` aliases expand to ``fanout ** levels`` leaves.

    Loading the document is cheap because aliases share one object; anything that copies or
    serialises the properties expands it. The default expands to 387 million strings.
    """
    lines = [
        "apiVersion: v1",
        "kind: ConfigMap",
        "metadata:",
        "  name: bomb",
        "data:",
        "  l0: &l0 [" + ",".join(['"lol"'] * fanout) + "]",
    ]
    for level in range(1, levels + 1):
        lines.append(f"  l{level}: &l{level} [" + ",".join([f"*l{level - 1}"] * fanout) + "]")
    return "\n".join(lines) + "\n"


def alias_bomb_expansion(levels: int = 9, fanout: int = 9) -> int:
    """How many leaf strings the bomb expands to."""
    return fanout ** (levels + 1)


def write_alias_bomb(root: Path, levels: int = 9, fanout: int = 9) -> Path:
    path = root / "alias-bomb.yaml"
    path.write_text(yaml_alias_bomb(levels, fanout), encoding="utf-8")
    return path


def json_depth(text: str) -> int:
    """Deepest nesting of ``[`` and ``{`` in a JSON document, ignoring brackets inside strings."""
    depth = deepest = 0
    in_string = escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif ch in "]}":
            depth -= 1
    return deepest
