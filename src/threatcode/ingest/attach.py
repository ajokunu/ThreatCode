"""Joining a scanner finding to the nodes of the graph.

A finding is placed by the first of these keys that matches; every key is documented here and a
finding no key places is kept unattached, never dropped.

1. **Image reference** (findings of image scope).
   The finding's image references (name, tag, digest) are compared with ``same_image`` of
   ``threatcode.parsers.image_ref``: registry, repository, tag and digest are normalized, Docker Hub
   names are expanded (``nginx`` is ``docker.io/library/nginx:latest``), and a digest, when both
   sides have one, decides.
   The references a node holds are:

   * Kubernetes workloads: ``properties['images']``, every container of the pod template (a Helm
     chart is rendered into workloads first, so its values images arrive the same way);
   * ECS task definitions: the ``image`` of each entry of ``container_definitions`` (a JSON string);
   * Lambda functions and App Runner services: ``image_uri`` and ``image_identifier``;
   * any other node: the ``image`` and ``container_image`` properties wherever they sit, and image
     references written inside the script-like text of ``user_data``, ``custom_data``, ``command``,
     ``args``, ``entrypoint`` and ``script`` properties (base64 ``user_data`` and ``custom_data``
     are decoded first); a token counts as a reference only when it contains ``/``, ``:`` or ``@``,
     so a bare word is never mistaken for an image;
   * Dockerfile stages: ``base_image``, so a CVE in a base image attaches to the
     ``dockerfile_stage`` node and not to the ``FROM`` instruction or the image summary.

   References that hold a variable (``${TAG}``) match nothing, because the image is unknown.
   Every node that holds the image gets its own finding.

2. **File and line** (findings of path scope that name a file and a line).
   The file is made root-relative (see ``resolve_file``) and the node whose source span contains the
   line is the target, in any format.
   When several spans contain the line the narrowest wins (a Dockerfile instruction over its stage).
   A node with no end line spans from its start line up to the line before the next node of the
   same file.

3. **Manifest directory** (package vulnerabilities of path scope that name a lockfile or manifest).
   The finding joins the workloads of the unit in the same directory as the file: the final stage
   of each Dockerfile there (the stage that ships) and the Kubernetes workloads.
   The directory is matched exactly; for a path from another machine (``/home/ci/repo/api/go.sum``)
   the longest directory of the graph that ends the path wins, and a lone file name means the scan
   root.

A finding that matches none of these has no node.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import posixpath
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from threatcode.ingest.model import ExternalFinding
from threatcode.parsers.image_ref import ImageRef, parse_image_ref, same_image

if TYPE_CHECKING:
    from threatcode.ir.graph import InfraGraph
    from threatcode.ir.nodes import InfraNode

__all__ = ["NodeIndex", "Placement", "node_image_refs"]

# Properties whose string value is an image reference as a whole.
_IMAGE_KEYS = frozenset(
    {"image", "images", "image_uri", "image_identifier", "container_image", "docker_image"}
)
# Properties that hold JSON text with container definitions.
_JSON_KEYS = frozenset({"container_definitions"})
_ENCODED_TEXT_KEYS = ("user_data", "userdata", "custom_data")
# Properties whose text may run a container: only these are searched for image references written
# in free text, so an ARN or an API version is never read as one.
_SCRIPT_KEYS = (*_ENCODED_TEXT_KEYS, "script", "command", "args", "entrypoint", "cloud_init")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\-/:@+]*")
_PORTS = re.compile(r"\d+(?::\d+)+")
_MAX_TEXT = 64 * 1024
_MAX_VALUES = 5000
_MAX_DEPTH = 10
_K8S_WORKLOADS = frozenset(
    {
        "kubernetes_deployment",
        "kubernetes_deployment_v1",
        "kubernetes_stateful_set",
        "kubernetes_stateful_set_v1",
        "kubernetes_daemon_set",
        "kubernetes_daemonset_v1",
        "kubernetes_job",
        "kubernetes_job_v1",
        "kubernetes_cron_job",
        "kubernetes_cron_job_v1",
        "kubernetes_cronjob_v1",
        "kubernetes_pod",
        "kubernetes_pod_v1",
        "kubernetes_replica_set",
        "kubernetes_replication_controller",
        "kubernetes_replication_controller_v1",
    }
)


@dataclass
class Placement:
    """Where a finding landed: the nodes it joined, by which key, and the location to report."""

    join: str
    nodes: list[InfraNode] = field(default_factory=list)
    location_file: str = ""
    line: int | None = None
    end_line: int | None = None


def _norm(path: str) -> str:
    text = path.replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    return text


def _is_absolute(path: str) -> bool:
    return path.startswith("/") or bool(re.match(r"^[A-Za-z]:/", path))


def _tokens(text: str) -> list[ImageRef]:
    refs: list[ImageRef] = []
    for match in _TOKEN.finditer(text):
        # A path (/bin/bash) and a port mapping (8080:8080) are not image references.
        if match.start() > 0 and text[match.start() - 1] == "/":
            continue
        token = match.group(0).rstrip(".:-/+")
        if not any(c in token for c in "/:@") or _PORTS.fullmatch(token):
            continue
        ref = parse_image_ref(token)
        if ref.kind == "registry" and ref.repository:
            refs.append(ref)
    return refs


def _decoded(text: str) -> str:
    """The text a base64 string stands for when that is printable text, else ``''``."""
    compact = "".join(text.split())
    if len(compact) < 8 or len(compact) % 4 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        return ""
    try:
        raw = base64.b64decode(compact, validate=True)
        decoded = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return ""
    return decoded if decoded.isprintable() or "\n" in decoded else ""


def node_image_refs(node: InfraNode) -> list[ImageRef]:
    """The container image references a node holds (see the module docstring for the sources)."""
    if node.mode == "data":
        return []
    if node.resource_type.startswith("dockerfile_"):
        if node.resource_type != "dockerfile_stage":
            return []
        base = node.properties.get("base_image")
        ref = parse_image_ref(base) if isinstance(base, str) else None
        return [ref] if ref is not None and ref.kind == "registry" and ref.repository else []
    found: list[ImageRef] = []
    budget = [_MAX_VALUES]
    _collect(node.properties, "", found, 0, budget)
    unique: dict[str, ImageRef] = {}
    for ref in found:
        unique.setdefault(ref.raw, ref)
    return list(unique.values())


def _collect(value: Any, key: str, out: list[ImageRef], depth: int, budget: list[int]) -> None:
    budget[0] -= 1
    if budget[0] < 0 or depth > _MAX_DEPTH:
        return
    if isinstance(value, dict):
        for child_key, child in value.items():
            _collect(child, str(child_key).lower(), out, depth + 1, budget)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _collect(child, key, out, depth + 1, budget)
    elif isinstance(value, str) and value and len(value) <= _MAX_TEXT:
        if key in _IMAGE_KEYS:
            ref = parse_image_ref(value)
            if ref.kind == "registry" and ref.repository:
                out.append(ref)
            return
        if key in _JSON_KEYS:
            try:
                parsed = json.loads(value)
            except ValueError:
                parsed = None
            if parsed is not None:
                _collect(parsed, "", out, depth + 1, budget)
                return
        if not any(marker in key for marker in _SCRIPT_KEYS):
            return
        out.extend(_tokens(value))
        if any(marker in key for marker in _ENCODED_TEXT_KEYS):
            decoded = _decoded(value)
            if decoded:
                out.extend(_tokens(decoded))


def _is_workload(node: InfraNode) -> bool:
    if node.mode == "data" or not node.source_file:
        return False
    return node.resource_type == "dockerfile_stage" or node.resource_type in _K8S_WORKLOADS


class NodeIndex:
    """Lookup tables over a graph for the three join keys, built once per ingestion."""

    def __init__(self, graph: InfraGraph, root: Path) -> None:
        self.root = root
        self._by_name: dict[str, list[tuple[ImageRef, InfraNode]]] = defaultdict(list)
        self._by_digest: dict[str, list[tuple[ImageRef, InfraNode]]] = defaultdict(list)
        self._spans: dict[str, list[tuple[int, float, InfraNode]]] = defaultdict(list)
        self._dirs: dict[str, list[InfraNode]] = defaultdict(list)
        self._image_cache: dict[tuple[str, ...], list[InfraNode]] = {}
        nodes = sorted(graph.nodes.values(), key=lambda n: n.id)
        for node in nodes:
            for ref in node_image_refs(node):
                self._by_name[ref.name].append((ref, node))
                if ref.digest:
                    self._by_digest[ref.digest].append((ref, node))
        self._index_spans(nodes)
        self._index_dirs(nodes)
        self.files = frozenset(self._spans)

    # -- construction ------------------------------------------------------

    def _index_spans(self, nodes: list[InfraNode]) -> None:
        starts: dict[str, list[int]] = defaultdict(list)
        for node in nodes:
            if node.mode != "data" and node.source_file and node.start_line is not None:
                starts[node.source_file].append(node.start_line)
        for node in nodes:
            if node.mode == "data" or not node.source_file or node.start_line is None:
                continue
            if node.end_line is not None:
                end: float = node.end_line
            else:
                later = [s for s in starts[node.source_file] if s > node.start_line]
                end = (min(later) - 1) if later else float("inf")
            self._spans[node.source_file].append((node.start_line, end, node))

    def _index_dirs(self, nodes: list[InfraNode]) -> None:
        last_stage: dict[str, InfraNode] = {}
        for node in nodes:
            if not _is_workload(node):
                continue
            if node.resource_type == "dockerfile_stage":
                kept = last_stage.get(node.source_file)
                if kept is None or (node.start_line or 0) > (kept.start_line or 0):
                    last_stage[node.source_file] = node
                continue
            self._dirs[posixpath.dirname(node.source_file)].append(node)
        for node in last_stage.values():
            self._dirs[posixpath.dirname(node.source_file)].append(node)
        for members in self._dirs.values():
            members.sort(key=lambda n: n.id)

    # -- image reference ---------------------------------------------------

    def nodes_for_images(self, refs: tuple[str, ...]) -> list[InfraNode]:
        """Every node that holds one of the image references ``refs``, in node id order."""
        matched: dict[str, InfraNode] = {}
        for text in refs:
            wanted = parse_image_ref(text)
            if wanted.kind != "registry" or not wanted.repository:
                continue
            candidates = list(self._by_name.get(wanted.name, ()))
            if wanted.digest:
                candidates.extend(self._by_digest.get(wanted.digest, ()))
            for ref, node in candidates:
                if same_image(wanted, ref):
                    matched[node.id] = node
        return [matched[key] for key in sorted(matched)]

    # -- file and line -----------------------------------------------------

    def resolve_file(self, path: str) -> str:
        """The source file of the graph that a scanner path names, or ``''``.

        Tried in order: the path as written, the path relative to the scan root when it is absolute
        and inside it, the longest graph file that ends the path (the scanner ran elsewhere), and
        the one graph file that the path ends (the scanner ran in a subdirectory).
        """
        text = _norm(path)
        if not text:
            return ""
        if text in self.files:
            return text
        relative = self._under_root(text)
        if relative is not None:
            return relative if relative in self.files else ""
        suffixed = [f for f in self.files if text.endswith("/" + f)]
        if suffixed:
            return max(suffixed, key=lambda f: (len(f), f))
        if not _is_absolute(text):
            contained = [f for f in self.files if f.endswith("/" + text)]
            if len(contained) == 1:
                return contained[0]
        return ""

    def node_at(self, file: str, line: int) -> InfraNode | None:
        """The node of ``file`` with the narrowest source span that contains ``line``."""
        best: InfraNode | None = None
        best_rank: tuple[float, int, str] | None = None
        for start, end, node in self._spans.get(file, ()):
            if start <= line <= end:
                rank = (end - start, -start, node.id)
                if best_rank is None or rank < best_rank:
                    best, best_rank = node, rank
        return best

    # -- manifest directory ------------------------------------------------

    def resolve_dir(self, path: str) -> str | None:
        """The directory of the graph that holds the file ``path``, or ``None`` when none does.

        ``''`` is the scan root.
        """
        text = _norm(path)
        if not text:
            return None
        relative = self._under_root(text)
        if relative is not None:
            directory = posixpath.dirname(relative)
            return directory if directory in self._dirs else None
        directory = posixpath.dirname(text)
        if not _is_absolute(text):
            if directory in self._dirs:
                return directory
            contained = [d for d in self._dirs if d and d.endswith("/" + directory) and directory]
            return contained[0] if len(contained) == 1 else None
        suffixed = [d for d in self._dirs if d and (directory + "/").endswith("/" + d + "/")]
        if suffixed:
            return max(suffixed, key=lambda d: (len(d), d))
        return "" if "" in self._dirs and directory in ("", "/") else None

    def nodes_in_dir(self, directory: str) -> list[InfraNode]:
        return list(self._dirs.get(directory, ()))

    # -- paths -------------------------------------------------------------

    def _under_root(self, text: str) -> str | None:
        """``text`` relative to the scan root when it is an absolute path inside it, else None."""
        if not _is_absolute(text):
            return None
        try:
            relative = os.path.relpath(text, self.root)
        except ValueError:
            return None
        if relative == ".." or relative.startswith(".." + os.sep) or os.path.isabs(relative):
            return None
        return Path(relative).as_posix()

    def display_path(self, path: str) -> str:
        """A path for the report: root-relative when it can be, else the file name alone."""
        text = _norm(path)
        if not text:
            return ""
        relative = self._under_root(text)
        if relative is not None:
            return relative
        if _is_absolute(text):
            return posixpath.basename(text)
        return text

    # -- placement ---------------------------------------------------------

    def place(self, finding: ExternalFinding) -> Placement:
        """Place one finding by the first matching key (see the module docstring)."""
        if finding.scope == "image":
            refs = finding.image_refs
            if refs not in self._image_cache:
                self._image_cache[refs] = self.nodes_for_images(refs)
            nodes = self._image_cache[refs]
            return Placement("image" if nodes else "unattached", list(nodes))
        file = self.resolve_file(finding.file) if finding.file else ""
        if file and finding.line is not None:
            node = self.node_at(file, finding.line)
            if node is not None:
                return Placement("file_line", [node], file, finding.line, finding.end_line)
        if finding.kind == "vulnerability" and finding.file:
            directory = self.resolve_dir(finding.file)
            if directory is not None:
                nodes = self.nodes_in_dir(directory)
                if nodes:
                    located = posixpath.join(directory, posixpath.basename(_norm(finding.file)))
                    return Placement("directory", nodes, located)
        return Placement("unattached", [], file or self.display_path(finding.file))
