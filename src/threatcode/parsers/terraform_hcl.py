"""Terraform HCL parser: a directory of .tf, .tofu and .tf.json files is one module.

``parse_directory`` reads every Terraform file directly inside a directory as one module, so a
reference from ``main.tf`` to a subnet in ``network.tf`` resolves.
``parse_file`` and ``parse_text`` read one file with only that file's variables and locals.

What the parser does with a module

- Variables come from ``terraform.tfvars`` and ``*.auto.tfvars`` first, then the variable's
  default, then (inside a followed module) the input the calling ``module`` block passes.
  A variable with none of these is unknown, never absent, and never a guess.
- Locals, simple interpolations and ternaries are evaluated when everything they use is known;
  see ``_hcl_eval`` for what evaluates.
  Every value that cannot be known is a :class:`~threatcode.values.Unknown`, including every
  attribute of another resource, so a rule never reads ``${var.x}`` as text.
- References become ``ParsedResource.references`` (attribute path to reference strings) and
  ``depends_on`` becomes ``dependencies``.
  Indexes and splats are dropped so a reference names every instance of a counted resource.
- ``count``, ``for_each``, ``depends_on``, ``lifecycle`` and ``provider`` move to
  ``ParsedResource.meta`` and are never rule-visible properties.
  A literal ``count = 0`` resource creates nothing and is dropped; a ``count`` that is
  not literal keeps one node flagged in ``meta``.
- A ``dynamic`` block becomes the repeated block it generates.
- ``module`` blocks with a local source (``./`` or ``../``) are followed with their inputs, and
  their resources are addressed ``module.<name>.<type>.<name>``.
  A remote module is not read: it is reported as ``hcl.module_call_skipped`` and the output is
  marked ``metadata["incomplete"]``, so an unanalysed root never reads as clean.
- ``data`` blocks become ``mode="data"`` nodes. A ``data.aws_iam_policy_document`` with literal
  statements renders to policy JSON for the references to its ``.json``.
- One unparseable file in a directory is a ``parse.failed`` error diagnostic and the other files
  still parse. A single file that cannot be parsed raises ``ParseError``.
- Limits keep an untrusted file cheap: values that evaluation builds are limited in size (see
  ``_hcl_eval``), locals, module inputs and outputs and policy documents may refer to each other
  ``MAX_NESTED_RESOLUTIONS`` levels deep, and each of them is worked out once. A value past a
  limit is ``Unknown`` and one ``hcl.evaluation_limit`` warning says so.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from threatcode.constants import is_terraform_json_name, is_terraform_name
from threatcode.diagnostics import Diagnostic, Level, register_code
from threatcode.exceptions import ParseError
from threatcode.ir.addressing import strip_attribute_suffix
from threatcode.parsers import _hcl_adapter
from threatcode.parsers._hcl_adapter import HclBlock, HclDocument
from threatcode.parsers._hcl_eval import (
    MAX_COLLECTION_SIZE,
    MAX_EVALUATION_WORK,
    MAX_VALUE_LENGTH,
    NOT_BOUND,
    Context,
    IteratorContext,
    evaluate_value,
    has_unknown,
    string_references,
)
from threatcode.parsers._hcl_values import canonical_json
from threatcode.parsers._text import decode_input
from threatcode.parsers.base import BaseParser, ParsedOutput, ParsedResource
from threatcode.values import Unknown, is_unknown

logger = logging.getLogger(__name__)

register_code(
    "hcl.evaluation_limit",
    "A Terraform value was treated as unknown because evaluating it reached a size or depth limit",
)

# Followed modules: nesting depth and the total number of module instances read
MAX_MODULE_DEPTH = 8
MAX_MODULE_INSTANCES = 200
# A dynamic block with a known collection is expanded up to this many blocks
MAX_DYNAMIC_EXPANSION = 32
# All the blocks that the dynamic blocks of one resource expand to, nested ones included. Without
# a total, `dynamic` blocks nested N deep over 30 elements each build 30**N blocks.
MAX_DYNAMIC_BLOCKS = 256
# Keys of a known for_each recorded in resource meta
MAX_RECORDED_KEYS = 50
# Resolutions that may be open at once: a local, a module output, a data document or a module
# input being worked out, or the references inside one. A chain of locals that each name the
# previous one nests this deep, and every level costs about a dozen Python frames, so a longer
# chain is cut with Unknown instead of overflowing the stack.
MAX_NESTED_RESOLUTIONS = 24

_META_ARGUMENTS = ("count", "for_each", "depends_on", "lifecycle", "provider")
_MISSING = object()
_POLICY_DOCUMENT = "aws_iam_policy_document"
_POLICY_VERSION = "2012-10-17"
_TFVARS_NAMES = ("terraform.tfvars", "terraform.tfvars.json")
_AUTO_TFVARS_SUFFIXES = (".auto.tfvars", ".auto.tfvars.json")


# --- per-run state -----------------------------------------------------------------------


@dataclass
class _Miss:
    """A variable or local that had no value while an attribute was evaluated."""

    scope: str
    kind: str  # "var" or "local"
    name: str
    status: str  # "no_value" (declared, nothing supplied) or "undeclared"


@dataclass
class _Session:
    """What one parse run shares: diagnostics, the module budget and evaluation counters."""

    diagnostics: list[Diagnostic] = field(default_factory=list)
    skipped_modules: list[dict[str, str]] = field(default_factory=list)
    followed_modules: list[str] = field(default_factory=list)
    instances: int = 0
    documents: dict[str, list[tuple[str, HclDocument]]] = field(default_factory=dict)
    # Counters reset around each attribute by begin() and read back by end()
    misses: list[_Miss] = field(default_factory=list)
    defaults: set[str] = field(default_factory=set)
    lookups: int = 0
    # Limits: resolutions open right now, how many were cut short by the nesting limit so far
    # (see _Scope._memoized), the work left for size checks, and the limits that were reached
    nesting: int = 0
    cut: int = 0
    work_left: int = field(default_factory=lambda: MAX_EVALUATION_WORK)
    limits: dict[str, int] = field(default_factory=dict)

    def begin(self) -> None:
        self.misses = []
        self.defaults = set()
        self.lookups = 0

    def diagnose(
        self, level: Level, code: str, message: str, file: str = "", line: int | None = None
    ) -> None:
        self.diagnostics.append(Diagnostic(level, code, message, file, line))


@dataclass
class _Memo:
    """A resolved value with the misses and defaults it was worked out from."""

    value: Any
    misses: list[_Miss]
    defaults: set[str]
    # The nesting depth a limit cut this value short at; None when nothing was cut. A cut value
    # is worked out again when it is asked for from a shallower depth, which has more room.
    cut_at: int | None = None


@dataclass
class _Variable:
    default: Any = None
    has_default: bool = False


class _Scope(Context):
    """One module: its variables, locals, resources and the way values are looked up in it."""

    def __init__(
        self,
        session: _Session,
        path: str = "",
        directory: Path | None = None,
        parent: _Scope | None = None,
        inputs: dict[str, Any] | None = None,
        tfvars: dict[str, Any] | None = None,
        directory_mode: bool = False,
    ) -> None:
        self.session = session
        self.path = path
        self.directory = directory
        self.parent = parent
        self.inputs: dict[str, Any] = inputs or {}
        self.tfvars: dict[str, Any] = tfvars or {}
        self.directory_mode = directory_mode
        self.variables: dict[str, _Variable] = {}
        self.locals_raw: dict[str, Any] = {}
        self.outputs: dict[str, Any] = {}
        self.blocks: list[tuple[str, HclBlock]] = []  # resources and data, with their file
        self.calls: list[tuple[str, HclBlock]] = []
        self.children: dict[str, _Scope] = {}
        self.declared: set[tuple[str, str]] = set()
        self.data_blocks: dict[tuple[str, str], HclBlock] = {}
        self.module_instances_unknown = False
        self._variable_cache: dict[str, tuple[Any, str, list[_Miss], set[str]]] = {}
        # Everything resolved through _memoized: locals, module inputs, outputs, data
        # documents and the references inside them, keyed by kind and name
        self._memos: dict[tuple[str, str], _Memo] = {}
        self._active: set[tuple[str, str]] = set()

    # -- building -------------------------------------------------------------------------

    def add_document(self, label: str, document: HclDocument) -> None:
        for block in document.blocks:
            if block.kind in ("resource", "data"):
                self.blocks.append((label, block))
                if block.kind == "resource":
                    self.declared.add((block.labels[0], block.labels[1]))
                else:
                    self.data_blocks[(block.labels[0], block.labels[1])] = block
            elif block.kind == "module":
                self.calls.append((label, block))
            elif block.kind == "variable":
                body = block.body
                self.variables[block.labels[0]] = _Variable(body.get("default"), "default" in body)
            elif block.kind == "locals":
                self.locals_raw.update(block.body)
            elif block.kind == "output":
                if "value" in block.body:
                    self.outputs[block.labels[0]] = block.body["value"]

    # -- Context --------------------------------------------------------------------------

    def reference(self, chain: str) -> str:
        return f"{self.path}.{chain}" if self.path else chain

    def declares(self, root: str, name: str) -> bool:
        return (root, name) in self.declared

    def declares_data(self, kind: str, name: str) -> bool:
        return (kind, name) in self.data_blocks

    def isolated(self, compute: Callable[[], Any]) -> tuple[Any, list[_Miss], set[str]]:
        """Run ``compute`` and return its value with the misses and defaults it used.

        The counters of the attribute being evaluated are put back afterwards, so a cached
        value can report what it depended on every time it is used, not only the first time.
        """
        session = self.session
        outer = (session.misses, session.defaults)
        session.misses, session.defaults = [], set()
        try:
            return compute(), session.misses, session.defaults
        finally:
            session.misses, session.defaults = outer

    def replay(self, misses: list[_Miss], defaults: set[str]) -> None:
        self.session.misses.extend(misses)
        self.session.defaults.update(defaults)

    def charge(self, units: int) -> bool:
        session = self.session
        session.work_left -= units
        return session.work_left >= 0

    def exceeded(self, limit: str) -> None:
        limits = self.session.limits
        limits[limit] = limits.get(limit, 0) + 1

    def _memoized(self, key: tuple[str, str], compute: Callable[[], Any], refused: Any) -> Any:
        """Work out ``key`` once, keeping nesting bounded and the answer stable.

        A resolution that is already open for ``key`` is a cycle, and one more level than
        ``MAX_NESTED_RESOLUTIONS`` is a chain too long to follow; both give ``refused``.
        So does a Python ``RecursionError`` from the deepest levels, because a few frames
        per level add up when each level is itself a deeply nested expression.
        The answer is kept, so a value used many times is worked out once; a value that a
        limit cut short is worked out again when it is asked for from a shallower depth,
        so what it comes to does not depend on which attribute asked for it first.
        """
        session = self.session
        depth = session.nesting
        memo = self._memos.get(key)
        if memo is not None and (memo.cut_at is None or depth >= memo.cut_at):
            if memo.cut_at is not None:
                session.cut += 1
            self.replay(memo.misses, memo.defaults)
            return memo.value
        if key in self._active:
            return refused
        if depth >= MAX_NESTED_RESOLUTIONS:
            session.cut += 1
            self.exceeded("nesting")
            return refused
        before = session.cut
        self._active.add(key)
        session.nesting += 1
        try:
            value, misses, defaults = self.isolated(compute)
        except RecursionError:
            session.cut += 1
            self.exceeded("recursion")
            value, misses, defaults = refused, [], set()
        finally:
            session.nesting -= 1
            self._active.discard(key)
        cut_at = depth if session.cut != before else None
        self._memos[key] = _Memo(value, misses, defaults, cut_at)
        self.replay(misses, defaults)
        return value

    def variable(self, name: str) -> Any:
        self.session.lookups += 1
        if self.parent is not None and name in self.inputs:
            parent = self.parent
            raw = self.inputs[name]
            return self._memoized(
                ("input", name), lambda: evaluate_value(raw, parent), Unknown(f"var.{name}")
            )
        cached = self._variable_cache.get(name)
        if cached is None:
            cached = self._resolve_variable(name)
            self._variable_cache[name] = cached
        value, status, misses, defaults = cached
        self.replay(misses, defaults)
        if status == "default":
            self.session.defaults.add(name)
        elif status in ("no_value", "undeclared"):
            self.session.misses.append(_Miss(self.path, "var", name, status))
        return value

    def _resolve_variable(self, name: str) -> tuple[Any, str, list[_Miss], set[str]]:
        declared = self.variables.get(name)
        if self.parent is None and name in self.tfvars:
            return evaluate_value(self.tfvars[name]), "supplied", [], set()
        if declared is not None and declared.has_default:
            return evaluate_value(declared.default), "default", [], set()
        status = "no_value" if declared is not None else "undeclared"
        return Unknown(f"var.{name}"), status, [], set()

    def local(self, name: str) -> Any:
        self.session.lookups += 1
        if name not in self.locals_raw:
            self.session.misses.append(_Miss(self.path, "local", name, "undeclared"))
            return Unknown(f"local.{name}")
        raw = self.locals_raw[name]
        return self._memoized(
            ("local", name), lambda: evaluate_value(raw, self), Unknown(f"local.{name}")
        )

    def module_output(self, module: str, output: str) -> Any:
        child = self.children.get(module)
        unknown = Unknown(f"module.{module}.{output}")
        if child is None or output not in child.outputs:
            return unknown
        raw = child.outputs[output]
        return self._memoized(
            ("output", f"{module}.{output}"), lambda: evaluate_value(raw, child), unknown
        )

    def data_value(self, kind: str, name: str, attribute: str) -> Any:
        if kind != _POLICY_DOCUMENT or attribute != "json":
            return NOT_BOUND
        block = self.data_blocks.get((kind, name))
        if block is None:
            return NOT_BOUND
        rendered = self._memoized(
            ("data", f"{kind}.{name}"), lambda: _render_policy_document(block.body, self), None
        )
        return NOT_BOUND if rendered is None else rendered

    def variable_references(self, name: str) -> list[str]:
        if self.parent is None or name not in self.inputs:
            return []
        return self._references(("varref", name), self.inputs[name], self.parent)

    def local_references(self, name: str) -> list[str]:
        if name not in self.locals_raw:
            return []
        return self._references(("localref", name), self.locals_raw[name], self)

    def module_references(self, module: str, output: str) -> list[str]:
        child = self.children.get(module)
        if child is None or output not in child.outputs:
            return []
        return self._references(("outref", f"{module}.{output}"), child.outputs[output], child)

    def _references(self, key: tuple[str, str], raw: Any, scope: Context) -> list[str]:
        """What ``raw`` refers to, worked out once: a local used twice must not be read twice."""
        found: list[str] = self._memoized(key, lambda: raw_references(raw, scope), [])
        return list(found)


def raw_references(raw: Any, scope: Context, depth: int = 0) -> list[str]:
    """Every reference in a raw value, in order and without repeats."""
    found: list[str] = []
    if depth > 64:
        return found
    if isinstance(raw, str):
        found.extend(string_references(raw, scope))
    elif isinstance(raw, dict):
        for value in raw.values():
            found.extend(raw_references(value, scope, depth + 1))
    elif isinstance(raw, list):
        for item in raw:
            found.extend(raw_references(item, scope, depth + 1))
    return list(dict.fromkeys(found))


def _collect_references(
    raw: Any, path: str, scope: Context, out: dict[str, list[str]], depth: int = 0
) -> None:
    """Record references by attribute path: ``.`` for nesting, ``[]`` for a list of blocks."""
    if depth > 64:
        return
    if isinstance(raw, str):
        refs = string_references(raw, scope)
        if refs:
            known = out.setdefault(path, [])
            known.extend(r for r in refs if r not in known)
    elif isinstance(raw, dict):
        for key, value in raw.items():
            _collect_references(value, f"{path}.{key}" if path else str(key), scope, out, depth + 1)
    elif isinstance(raw, list):
        child = f"{path}[]" if any(isinstance(item, dict) for item in raw) else path
        for item in raw:
            _collect_references(item, child, scope, out, depth + 1)


# --- policy documents --------------------------------------------------------------------


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _one_or_many(values: list[Any]) -> Any:
    return values[0] if len(values) == 1 else values


def _blocks(body: dict[str, Any], name: str) -> list[dict[str, Any]]:
    return [b for b in _as_list(body.get(name)) if isinstance(b, dict)]


def _principals(blocks: list[dict[str, Any]]) -> Any:
    grouped: dict[str, list[Any]] = {}
    for block in blocks:
        kind = block.get("type")
        if not isinstance(kind, str) or is_unknown(kind):
            return None
        grouped.setdefault(kind, []).extend(_as_list(block.get("identifiers")))
    if grouped == {"*": ["*"]}:
        return "*"
    return {kind: _one_or_many(ids) for kind, ids in grouped.items()}


def _render_policy_document(body: dict[str, Any], scope: Context) -> Any:
    """The JSON a ``data.aws_iam_policy_document`` produces, or None when it cannot be known.

    A ``dynamic`` statement, ``source_policy_documents`` and ``override_policy_documents`` make
    the document unknowable. Otherwise it is canonical JSON text, except that a value which is
    exactly one unresolved expression (``resources = [aws_s3_bucket.b.arn]``) keeps the document
    a structure with an ``Unknown`` at that leaf, as ``jsonencode`` does.
    """
    if any(
        key in body for key in ("dynamic", "source_policy_documents", "override_policy_documents")
    ):
        return None
    evaluated = evaluate_value(body, scope, lenient=True)
    if not isinstance(evaluated, dict):
        return None
    statements: list[dict[str, Any]] = []
    for statement in _blocks(evaluated, "statement"):
        item: dict[str, Any] = {}
        sid = statement.get("sid")
        if isinstance(sid, str) and sid:
            item["Sid"] = sid
        item["Effect"] = statement.get("effect") or "Allow"
        for key, rendered in (
            ("actions", "Action"),
            ("not_actions", "NotAction"),
            ("resources", "Resource"),
            ("not_resources", "NotResource"),
        ):
            values = _as_list(statement.get(key))
            if values:
                item[rendered] = _one_or_many(values)
        for key, rendered in (("principals", "Principal"), ("not_principals", "NotPrincipal")):
            blocks = _blocks(statement, key)
            if blocks:
                principal = _principals(blocks)
                if principal is None:
                    return None
                item[rendered] = principal
        conditions: dict[str, dict[str, Any]] = {}
        for condition in _blocks(statement, "condition"):
            test, variable = condition.get("test"), condition.get("variable")
            if not isinstance(test, str) or not isinstance(variable, str):
                return None
            conditions.setdefault(test, {})[variable] = _one_or_many(
                _as_list(condition.get("values"))
            )
        if conditions:
            item["Condition"] = conditions
        statements.append(item)
    document: dict[str, Any] = {"Version": evaluated.get("version") or _POLICY_VERSION}
    if isinstance(evaluated.get("policy_id"), str) and evaluated["policy_id"]:
        document["Id"] = evaluated["policy_id"]
    document["Statement"] = statements
    return document if has_unknown(document) else canonical_json(document)


# --- the parser --------------------------------------------------------------------------


class TerraformHCLParser(BaseParser):
    """Parse raw Terraform files via python-hcl2 (fallback when plan JSON is unavailable).

    A single file is one unit and a directory is one module: every ``.tf``, ``.tofu`` and
    ``.tf.json`` file directly inside it is read once and the resources are concatenated.
    See the module docstring for how variables, references and modules are handled.
    """

    def parse(self, data: Any, source_path: str = "") -> ParsedOutput:
        """Parse a dictionary read from Terraform's JSON syntax."""
        if not isinstance(data, dict):
            raise ParseError("HCL parse result must be a dict")
        document = _hcl_adapter.load_json_syntax(data, None, Path(source_path).name or "<input>")
        return self._parse_single(document, source_path)

    def parse_text(self, text: str, source_path: str = "") -> ParsedOutput:
        """Parse text that was already decoded, so the file is read from disk once."""
        document = self._load_text(text, Path(source_path).name or "<input>")
        return self._parse_single(document, source_path)

    def parse_file(self, path: Path) -> ParsedOutput:
        return self.parse_text(decode_input(path), str(path))

    def parse_directory(self, path: Path) -> ParsedOutput:
        """Parse the Terraform files directly inside ``path`` as one module.

        Files are read in name order. Symlinks are skipped and empty files are ignored,
        because an empty ``outputs.tf`` is normal in a module. ``terraform.tfvars`` and
        ``*.auto.tfvars`` supply variable values. A file that cannot be parsed is reported
        as a ``parse.failed`` error and the others are still read; when none can be parsed
        the error is raised.
        """
        session = _Session()
        files = _terraform_files(path)
        if not files:
            raise ParseError(f"No Terraform files (.tf, .tofu, .tf.json) in {path.name}")
        documents, failures = _read_documents(files, session)
        if failures and not documents:
            raise ParseError(failures[0])
        tfvars, tfvars_files = _read_tfvars(path, session)
        scope = _Scope(session, "", path, None, None, tfvars, directory_mode=True)
        return self._finish(
            scope,
            documents,
            session,
            str(path),
            {"files": [Path(label).name for label, _ in documents]},
            tfvars_files,
        )

    # -- internals ------------------------------------------------------------------------

    @staticmethod
    def _load_text(text: str, name: str) -> HclDocument:
        if is_terraform_json_name(name):
            return _hcl_adapter.load_json_syntax(_load_json_syntax(text, name), text, name)
        return _hcl_adapter.load(text, name)

    def _parse_single(self, document: HclDocument, source_path: str) -> ParsedOutput:
        session = _Session()
        file_path = Path(source_path) if source_path else None
        directory = file_path.parent if file_path is not None and file_path.is_file() else None
        scope = _Scope(session, "", directory, None, None, None, directory_mode=False)
        label = source_path
        return self._finish(scope, [(label, document)], session, source_path, {}, [])

    def _finish(
        self,
        scope: _Scope,
        documents: list[tuple[str, HclDocument]],
        session: _Session,
        source_path: str,
        metadata: dict[str, Any],
        tfvars_files: list[str],
    ) -> ParsedOutput:
        for label, document in documents:
            scope.add_document(label, document)
        _attach_modules(
            scope, session, [os.path.realpath(scope.directory)] if scope.directory else []
        )
        resources: list[ParsedResource] = []
        _emit(scope, resources, session)
        _drop_shadowed_references(resources, session)
        _report_limits(session)
        if tfvars_files:
            metadata["tfvars"] = tfvars_files
        if session.followed_modules:
            metadata["modules"] = list(session.followed_modules)
        if session.skipped_modules:
            metadata["incomplete"] = True
            metadata["skipped_modules"] = list(session.skipped_modules)
        return ParsedOutput(
            resources=resources,
            source_path=source_path,
            format_type="terraform_hcl",
            metadata=metadata,
            diagnostics=session.diagnostics,
        )


_LIMIT_REASONS = {
    "value size": (
        f"a value grew past {MAX_VALUE_LENGTH:,} characters or {MAX_COLLECTION_SIZE:,} elements, "
        "or the files used up the work allowed for size checks"
    ),
    "nesting": f"locals, module inputs or outputs refer to each other more than "
    f"{MAX_NESTED_RESOLUTIONS} levels deep",
    "recursion": "an expression was nested too deeply to evaluate",
    "dynamic blocks": (
        f"the dynamic blocks of a resource would generate more than {MAX_DYNAMIC_BLOCKS} blocks, "
        "so the ones past that are one block each with unknown iterator values"
    ),
}


def _report_limits(session: _Session) -> None:
    """One warning when evaluation gave up on a value, so an Unknown is never unexplained."""
    if not session.limits:
        return
    reasons = "; ".join(_LIMIT_REASONS.get(kind, kind) for kind in sorted(session.limits))
    session.diagnose(
        "warning",
        "hcl.evaluation_limit",
        f"some values are treated as unknown because evaluating them reached a limit: {reasons}",
    )


def _load_json_syntax(text: str, name: str) -> dict[str, Any]:
    """Load Terraform's JSON syntax (CDK for Terraform writes ``cdk.tf.json``)."""
    import json

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ParseError(f"Invalid JSON in {name}, line {e.lineno}: {e.msg}") from e
    except RecursionError as e:
        raise ParseError(f"Invalid JSON in {name}: nested too deeply to read") from e
    if not isinstance(data, dict):
        raise ParseError(f"{name}: a Terraform JSON file must hold an object")
    return data


def _terraform_files(path: Path) -> list[Path]:
    try:
        return sorted(
            (
                entry
                for entry in path.iterdir()
                if is_terraform_name(entry.name) and entry.is_file() and not entry.is_symlink()
            ),
            key=lambda entry: entry.name,
        )
    except OSError as exc:
        raise ParseError(f"Cannot read directory {path.name}: {exc.strerror or exc}") from exc


def _read_documents(
    files: list[Path], session: _Session
) -> tuple[list[tuple[str, HclDocument]], list[str]]:
    """Parse each file; a failure is a diagnostic and the other files still load."""
    documents: list[tuple[str, HclDocument]] = []
    failures: list[str] = []
    for file in files:
        label = str(file)
        try:
            text = decode_input(file, allow_empty=True)
            if not text.strip():
                continue
            documents.append((label, TerraformHCLParser._load_text(text, file.name)))
        except ParseError as exc:
            failures.append(str(exc))
            session.diagnose("error", "parse.failed", str(exc), label)
    return documents, failures


def _read_tfvars(path: Path, session: _Session) -> tuple[dict[str, Any], list[str]]:
    """Variable values from terraform.tfvars and *.auto.tfvars, later files winning."""
    try:
        entries = [e for e in path.iterdir() if e.is_file() and not e.is_symlink()]
    except OSError:
        return {}, []
    chosen = [e for name in _TFVARS_NAMES for e in entries if e.name == name]
    chosen += sorted(
        (e for e in entries if e.name.endswith(_AUTO_TFVARS_SUFFIXES)), key=lambda e: e.name
    )
    values: dict[str, Any] = {}
    used: list[str] = []
    for file in chosen:
        try:
            text = decode_input(file, allow_empty=True)
            if not text.strip():
                continue
            if file.name.endswith(".json"):
                values.update(_load_json_syntax(text, file.name))
            else:
                values.update(_hcl_adapter.load_attributes(text, file.name))
            used.append(file.name)
        except ParseError as exc:
            session.diagnose("warning", "parse.failed", str(exc), str(file))
    return values, used


# --- modules -----------------------------------------------------------------------------


def _is_local_source(source: Any) -> bool:
    return isinstance(source, str) and (source.startswith(("./", "../")) or source in (".", ".."))


def _child_directory(base: Path, source: str) -> Path | None:
    """The directory a local ``source`` names, or None for a symlink or a missing path."""
    current = base
    for part in Path(source).parts:
        if part == "..":
            current = current.parent
        elif part != ".":
            current = current / part
            if current.is_symlink():
                return None
    target = Path(os.path.normpath(base / source))
    return target if target.is_dir() else None


def _module_source(raw: Any) -> Any:
    """The text of a module's ``source``; ``${path.module}`` is the module's own directory."""
    if isinstance(raw, str):
        raw = raw.replace("${path.module}", ".")
    return evaluate_value(raw)


def _attach_modules(scope: _Scope, session: _Session, stack: list[str]) -> None:
    """Follow the local module calls of ``scope`` and report the ones that cannot be read."""
    for label, block in scope.calls:
        name = block.labels[0]
        body = block.body
        address = f"{scope.path}.module.{name}" if scope.path else f"module.{name}"
        source = _module_source(body.get("source"))
        shown = source if isinstance(source, str) and not is_unknown(source) else "(unknown)"
        reason = _module_blocker(scope, source, stack)
        child_dir = None
        if reason is None and scope.directory is not None:
            child_dir = _child_directory(scope.directory, source)
            if child_dir is None:
                reason = "the directory is missing or is reached through a symlink"
            elif os.path.realpath(child_dir) in stack:
                reason = "the module calls itself"
        if reason is not None or child_dir is None:
            _skip_module(session, address, shown, reason or "unreadable", label, block.start_line)
            continue
        instances = _instances(scope, body)
        if instances.drop:
            session.diagnose(
                "info",
                "hcl.count_zero",
                f"{address} has {instances.reason}; it creates nothing and is not analysed",
                label,
                block.start_line,
            )
            continue
        real = os.path.realpath(child_dir)
        session.instances += 1
        inputs = {
            key: value
            for key, value in body.items()
            if key not in ("source", "version", "providers", "count", "for_each", "depends_on")
        }
        child = _Scope(session, address, child_dir, scope, inputs, None, scope.directory_mode)
        if real not in session.documents:
            session.documents[real], _ = _read_documents(_terraform_files(child_dir), session)
        for file_label, document in session.documents[real]:
            child.add_document(file_label, document)
        child.module_instances_unknown = "count" in body or "for_each" in body
        scope.children[name] = child
        session.followed_modules.append(address)
        _attach_modules(child, session, [*stack, real])


def _module_blocker(scope: _Scope, source: Any, stack: list[str]) -> str | None:
    if not isinstance(source, str) or is_unknown(source):
        return "its source is not a known text"
    if not _is_local_source(source):
        return "it is not a local module, so it is not read"
    if scope.directory is None:
        return "the input has no directory to resolve a local source from"
    if len(stack) >= MAX_MODULE_DEPTH:
        return f"modules are nested more than {MAX_MODULE_DEPTH} levels deep"
    if scope.session.instances >= MAX_MODULE_INSTANCES:
        return f"more than {MAX_MODULE_INSTANCES} module calls were followed"
    return None


def _skip_module(
    session: _Session, address: str, source: str, reason: str, file: str, line: int | None
) -> None:
    session.diagnose(
        "warning",
        "hcl.module_call_skipped",
        f"{address} (source {source}) is not analysed: {reason}. "
        "Scan `terraform show -json` output for full coverage",
        file,
        line,
    )
    session.skipped_modules.append({"module": address, "source": source, "reason": reason})


def _drop_shadowed_references(resources: list[ParsedResource], session: _Session) -> None:
    """Remove a reference the graph would bind to the wrong resource.

    The graph resolves a reference written inside a module against that module first.
    A module input such as ``vpc_id = aws_vpc.main.id`` names the caller's VPC, and written
    that way it would find a ``module.net.aws_vpc.main`` of the module's own instead.
    Such a reference is dropped with a diagnostic rather than left to add an edge to the
    wrong node. References inside a module are already qualified and never collide.
    """
    declared = {resource.address for resource in resources}
    for resource in resources:
        if not resource.module:
            continue
        for attribute, refs in resource.references.items():
            kept: list[str] = []
            for ref in refs:
                intended = strip_attribute_suffix(ref, declared)
                shadow = strip_attribute_suffix(f"{resource.module}.{ref}", declared)
                if shadow in declared and shadow != intended:
                    session.diagnose(
                        "info",
                        "hcl.unresolved_reference",
                        f"{resource.address}: '{attribute}' refers to {intended} of the calling "
                        f"module, which {shadow} shadows inside {resource.module}; "
                        "no edge was added",
                        resource.source_location,
                        resource.start_line,
                    )
                else:
                    kept.append(ref)
            # An attribute whose references were all dropped keeps an empty entry, so the graph
            # does not fall back to guessing an edge from the placeholder value
            resource.references[attribute] = kept


# --- instances: count and for_each ---------------------------------------------------------


@dataclass
class _Instances:
    drop: bool = False
    reason: str = ""
    note: str = ""
    meta: dict[str, Any] = field(default_factory=dict)


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool) or is_unknown(value):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value)
    return None


def _keys_of(value: Any) -> list[str] | None:
    """The instance keys a ``for_each`` value produces, or None when they are not known."""
    if isinstance(value, dict):
        return [str(key) for key in value]
    if isinstance(value, (list, tuple)):
        if any(is_unknown(item) or isinstance(item, (dict, list)) for item in value):
            return None
        return [str(item) for item in value]
    return None


def _instances(scope: _Scope, body: dict[str, Any]) -> _Instances:
    """What ``count`` and ``for_each`` say about how many instances a block creates.

    A count of zero that comes from literals, locals or ``tfvars`` creates nothing and drops
    the block. A zero that only a variable default produces keeps the block, because a value
    supplied outside the repository may enable it. A count that is not known keeps one node,
    flagged ``instances_unknown`` in ``meta``.
    """
    result = _Instances()
    session = scope.session
    for key in ("count", "for_each"):
        if key not in body:
            continue
        session.begin()
        value = evaluate_value(body[key], scope)
        by_default = bool(session.defaults)
        if key == "count":
            number = _as_int(value)
            empty = number == 0
            known: Any = number
        else:
            keys = _keys_of(value)
            empty = keys is not None and not keys
            known = None if keys is None else keys[:MAX_RECORDED_KEYS]
        if known is None:
            result.meta["instances_unknown"] = True
        elif empty and not by_default:
            result.drop = True
            result.reason = "count 0" if key == "count" else "an empty for_each"
        else:
            result.meta[key] = known
            if by_default:
                result.meta[f"{key}_from_default"] = True
                if empty:
                    shown = "0" if key == "count" else "empty"
                    result.note = (
                        f"{key} is {shown} with the variable default, so the block is kept: "
                        "a value supplied outside the repository may enable it"
                    )
        break
    return result


# --- resources ---------------------------------------------------------------------------


def _emit(scope: _Scope, out: list[ParsedResource], session: _Session) -> None:
    for label, block in scope.blocks:
        resource = _make_resource(scope, label, block, session)
        if resource is not None:
            out.append(resource)
    for child in scope.children.values():
        _emit(child, out, session)


def _plain(value: Any) -> Any:
    """``${aws_s3_bucket.data}`` as ``aws_s3_bucket.data``; other values unchanged."""
    if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
        inner = value[2:-1].strip()
        if "${" not in inner:
            return inner
    if isinstance(value, list):
        return [_plain(item) for item in value]
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    return value


def _first_dict(value: Any) -> dict[str, Any] | None:
    if isinstance(value, list) and value:
        value = value[0]
    return value if isinstance(value, dict) else None


def _iteration(collection: Any) -> list[tuple[Any, Any]] | None:
    """The (key, value) pairs a ``dynamic`` block iterates, or None when not known."""
    if isinstance(collection, dict):
        return list(collection.items())
    if isinstance(collection, (list, tuple)):
        return list(enumerate(collection))
    return None


def _iterator_name(raw: Any, block_name: str) -> str:
    name = _plain(raw)
    return name if isinstance(name, str) and name and not is_unknown(name) else block_name


@dataclass
class _Notes:
    """The unresolved variables seen per attribute, and the dynamic blocks expanded."""

    unresolved: dict[str, list[_Miss]] = field(default_factory=dict)
    dynamic: list[str] = field(default_factory=list)
    # Blocks generated so far by the dynamic blocks of this resource, charged against
    # MAX_DYNAMIC_BLOCKS
    generated: int = 0


def _has_dynamic(raw: Any, depth: int = 0) -> bool:
    """Whether a raw value holds a ``dynamic`` block anywhere inside it."""
    if depth > 64:
        return False
    if isinstance(raw, dict):
        return "dynamic" in raw or any(_has_dynamic(v, depth + 1) for v in raw.values())
    if isinstance(raw, list):
        return any(_has_dynamic(item, depth + 1) for item in raw)
    return False


def _evaluate_body(
    body: dict[str, Any],
    ctx: Context,
    scope: _Scope,
    path: str,
    references: dict[str, list[str]],
    notes: _Notes,
    top_level: bool,
) -> dict[str, Any]:
    """Evaluate a block body: attributes and nested blocks, with ``dynamic`` blocks expanded."""
    session = scope.session
    result: dict[str, Any] = {}
    for key, raw in body.items():
        if key == "dynamic":
            continue
        if top_level:
            session.begin()
        attribute_path = f"{path}.{key}" if path else key
        if _has_dynamic(raw):
            result[key] = _evaluate_nested(raw, ctx, scope, attribute_path, references, notes)
        else:
            result[key] = evaluate_value(raw, ctx)
            _collect_references(raw, attribute_path, scope, references)
        if top_level and session.misses:
            notes.unresolved[key] = list(session.misses)
    for entry in _as_list(body.get("dynamic")):
        if not isinstance(entry, dict):
            continue
        for block_name, spec_raw in entry.items():
            spec = _first_dict(spec_raw)
            content = _first_dict(spec.get("content")) if spec is not None else None
            if spec is None or content is None:
                continue
            _expand_dynamic(block_name, spec, content, ctx, scope, path, references, notes, result)
    return result


def _evaluate_nested(
    raw: Any,
    ctx: Context,
    scope: _Scope,
    path: str,
    references: dict[str, list[str]],
    notes: _Notes,
) -> Any:
    """Evaluate a nested block that holds a ``dynamic`` block somewhere inside it."""
    if isinstance(raw, list):
        child = f"{path}[]" if any(isinstance(item, dict) for item in raw) else path
        return [_evaluate_nested(item, ctx, scope, child, references, notes) for item in raw]
    if isinstance(raw, dict):
        return _evaluate_body(raw, ctx, scope, path, references, notes, False)
    _collect_references(raw, path, scope, references)
    return evaluate_value(raw, ctx)


def _expand_dynamic(
    name: str,
    spec: dict[str, Any],
    content: dict[str, Any],
    ctx: Context,
    scope: _Scope,
    path: str,
    references: dict[str, list[str]],
    notes: _Notes,
    result: dict[str, Any],
) -> None:
    iterator = _iterator_name(spec.get("iterator"), name)
    # The collection is an input of the attribute that holds the block: what it used is
    # reported with that attribute, and a default it used decides how an empty one is read
    collection, misses, defaults = scope.isolated(lambda: evaluate_value(spec.get("for_each"), ctx))
    scope.replay(misses, defaults)
    by_default = bool(defaults)
    items = _iteration(collection)
    block_path = f"{path}.{name}[]" if path else f"{name}[]"
    expanded: list[dict[str, Any]]
    within_total = items is not None and notes.generated + len(items) <= MAX_DYNAMIC_BLOCKS
    if items is not None and items and len(items) <= MAX_DYNAMIC_EXPANSION and within_total:
        notes.generated += len(items)
        expanded = [
            _evaluate_body(
                content,
                IteratorContext(ctx, iterator, key, value),
                scope,
                block_path,
                references,
                notes,
                False,
            )
            for key, value in items
        ]
        notes.dynamic.append(f"dynamic block '{name}' became {len(expanded)} block(s)")
    elif items is not None and not items and not by_default:
        expanded = []
        notes.dynamic.append(f"dynamic block '{name}' has an empty for_each and creates no block")
    else:
        unknown_ctx = IteratorContext(
            ctx, iterator, Unknown(f"{iterator}.key"), Unknown(f"{iterator}.value")
        )
        expanded = [
            _evaluate_body(content, unknown_ctx, scope, block_path, references, notes, False)
        ]
        if items is not None and items and len(items) <= MAX_DYNAMIC_EXPANSION:
            # a known, small collection that the resource's total left no room for
            scope.exceeded("dynamic blocks")
            notes.dynamic.append(
                f"dynamic block '{name}' became one block; this resource's dynamic blocks "
                f"would generate more than {MAX_DYNAMIC_BLOCKS} blocks"
            )
        else:
            notes.dynamic.append(
                f"dynamic block '{name}' became one block; its for_each is not known here"
            )
    _collect_references(spec.get("for_each"), block_path, scope, references)
    if expanded:
        existing = result.get(name)
        blocks = list(existing) if isinstance(existing, list) else ([existing] if existing else [])
        result[name] = [*blocks, *expanded]


def _make_resource(
    scope: _Scope, label: str, block: HclBlock, session: _Session
) -> ParsedResource | None:
    rtype, name = block.labels
    is_data = block.kind == "data"
    prefix = f"{scope.path}." if scope.path else ""
    address = f"{prefix}{'data.' if is_data else ''}{rtype}.{name}"
    body = dict(block.body)

    instances = _instances(scope, body)
    if instances.drop:
        session.diagnose(
            "info",
            "hcl.count_zero",
            f"{address} has {instances.reason}; it creates no instances and is not modelled",
            label,
            block.start_line,
        )
        return None
    if instances.note:
        session.diagnose(
            "info", "hcl.count_zero", f"{address}: {instances.note}", label, block.start_line
        )
    meta: dict[str, Any] = dict(instances.meta)
    if scope.module_instances_unknown:
        meta["module_instances"] = "unknown"

    arguments = {key: body.pop(key) for key in _META_ARGUMENTS if key in body}
    dependencies: list[str] = []
    if "depends_on" in arguments:
        dependencies = raw_references(arguments["depends_on"], scope)
        meta["depends_on"] = [_plain(item) for item in _as_list(arguments["depends_on"])]
    if "lifecycle" in arguments:
        lifecycle = _first_dict(arguments["lifecycle"])
        if lifecycle is not None:
            meta["lifecycle"] = _plain(lifecycle)
    if "provider" in arguments:
        meta["provider"] = _plain(arguments["provider"])

    references: dict[str, list[str]] = {}
    notes = _Notes()
    properties = _evaluate_body(body, scope, scope, "", references, notes, True)

    if notes.unresolved:
        misses = [
            miss for attribute_misses in notes.unresolved.values() for miss in attribute_misses
        ]
        names = list(
            dict.fromkeys(
                (f"{m.scope}: " if m.scope != scope.path else "") + f"{m.kind}.{m.name}"
                for m in misses
            )
        )
        undeclared = any(m.status == "undeclared" for m in misses)
        session.diagnose(
            "warning" if undeclared and scope.directory_mode else "info",
            "hcl.unresolved_reference",
            f"{address}: no value for {', '.join(names)} in this input, so "
            f"{', '.join(repr(a) for a in notes.unresolved)} "
            f"{'is' if len(notes.unresolved) == 1 else 'are'} treated as unknown",
            label,
            block.start_line,
        )
    for message in notes.dynamic:
        session.diagnose(
            "info", "hcl.dynamic_block", f"{address}: {message}", label, block.start_line
        )

    return ParsedResource(
        resource_type=rtype,
        address=address,
        name=name,
        provider=_infer_provider(rtype),
        properties=properties,
        dependencies=dependencies,
        module=scope.path,
        source_location=label,
        references=references,
        start_line=block.start_line,
        end_line=block.end_line,
        mode="data" if is_data else "managed",
        meta=meta,
    )


def _infer_provider(resource_type: str) -> str:
    prefix = resource_type.split("_")[0]
    return {
        "aws": "hashicorp/aws",
        "azurerm": "hashicorp/azurerm",
        "google": "hashicorp/google",
    }.get(prefix, prefix)
