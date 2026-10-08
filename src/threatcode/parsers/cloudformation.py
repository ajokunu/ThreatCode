"""AWS CloudFormation template parser.

The parser turns a template into `ParsedResource` objects the rules and the graph can read:

- the resource type is named after the Terraform type that models it (`_cfn_types`),
- the properties are translated to the attributes those rules read, with intrinsics
  resolved where the template decides them and `values.Unknown` where it does not
  (`_cfn_properties`),
- every `Ref`, `Fn::GetAtt` and `Fn::Sub` that names another resource is recorded as a
  reference under the attribute that holds it, and with `DependsOn` as a dependency
  (`_cfn_refs`),
- an AWS SAM template is first written out as plain CloudFormation (`_sam`), and
- every resource carries the lines of the template it comes from.

Anything the parser cannot model is a diagnostic, never a silent skip: an entry that is not a
resource, a type with no mapping, a nested stack, intrinsics that stayed unresolved.
"""

from __future__ import annotations

import json
from bisect import bisect_right
from collections.abc import Callable, Mapping
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

from threatcode.diagnostics import Diagnostic
from threatcode.exceptions import ParseError
from threatcode.parsers import _sam
from threatcode.parsers._cfn_properties import (
    RAW_KEY,
    TemplateContext,
    evaluate_condition,
    translate,
)
from threatcode.parsers._cfn_refs import WorkBudget, scan_refs
from threatcode.parsers._cfn_types import resolve_type
from threatcode.parsers._json_lines import json_line_index
from threatcode.parsers._text import decode_input
from threatcode.parsers._yaml import load_yaml_documents
from threatcode.parsers.base import BaseParser, ParsedEdge, ParsedOutput, ParsedResource

NESTED_STACK_TYPE = "AWS::CloudFormation::Stack"

# How a flow a SAM event declares is drawn in the graph
_SAM_EDGE_TYPES = {"invokes": "network_flow", "triggers": "data_flow"}


def _kind(value: Any) -> str:
    return type(value).__name__ if value is not None else "null"


def _scalar_text(value: Any) -> str:
    """A template header value as text: a date such as 2010-09-09 stays the text written."""
    if value is None or isinstance(value, Mapping | list):
        return ""
    return str(value)


def _looks_like_json(text: str) -> bool:
    return text.lstrip("\ufeff \t\r\n").startswith(("{", "["))


def _pointer_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


class LineIndex:
    """The first and last line of each resource, read from the template text.

    The registry hands a parser the loaded template, not its text, so the index re-reads the
    file; it is None when the text is not available or does not load again.
    """

    def __init__(self, text: str, index: Mapping[str, int], is_json: bool) -> None:
        self._text = text
        self._lines = text.split("\n")
        self._index = index
        self._json = is_json
        self._offsets: list[int] = []
        offset = 0
        for line in self._lines:
            self._offsets.append(offset)
            offset += len(line) + 1
        # Lines where a resource or a top-level section starts: where the previous one ends
        self._boundaries = sorted(
            {line for pointer, line in index.items() if pointer and pointer.count("/") <= 2}
        )

    @classmethod
    def load(cls, text: str | None, source_path: str) -> LineIndex | None:
        name = Path(source_path).name if source_path else "<input>"
        if text is None:
            path = Path(source_path) if source_path else None
            if path is None or not path.is_file():
                return None
            try:
                text = decode_input(path)
            except (OSError, ParseError):
                return None
        try:
            if _looks_like_json(text):
                index = json_line_index(text)
            else:
                documents, indexes = load_yaml_documents(text, with_lines=True, source=name)
                position = next(
                    (
                        i
                        for i, document in enumerate(documents)
                        if isinstance(document, Mapping) and "Resources" in document
                    ),
                    None,
                )
                if position is None:
                    return None
                index = indexes[position]
        except (ParseError, ValueError, RecursionError):
            return None
        return cls(text, index, _looks_like_json(text))

    def span(self, logical_id: str) -> tuple[int | None, int | None]:
        """The 1-based first and last line of a resource, or (None, None) when unknown."""
        start = self._index.get(f"/Resources/{_pointer_token(logical_id)}")
        if start is None:
            return None, None
        end = self._json_end(logical_id, start) if self._json else self._yaml_end(start)
        return start, max(end, start)

    def _yaml_end(self, start: int) -> int:
        """One line before the next resource or section, without the blank and comment lines."""
        position = bisect_right(self._boundaries, start)
        following = self._boundaries[position] if position < len(self._boundaries) else None
        end = min(following - 1 if following is not None else len(self._lines), len(self._lines))
        while end > start:
            text = self._lines[end - 1].strip()
            if text and not text.startswith("#"):
                break
            end -= 1
        return end

    def _json_end(self, logical_id: str, start: int) -> int:
        """The line of the bracket that closes the resource's value."""
        if start > len(self._lines):
            return start
        needle = json.dumps(logical_id)
        column = self._lines[start - 1].find(needle)
        if column < 0:
            return start
        text, i = self._text, self._offsets[start - 1] + column + len(needle)
        while i < len(text) and text[i] in " \t\r\n:":
            i += 1
        if i >= len(text) or text[i] not in "{[":
            return start
        depth, in_string, escaped = 0, False, False
        while i < len(text):
            char = text[i]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
            elif char == '"':
                in_string = True
            elif char in "{[":
                depth += 1
            elif char in "}]":
                depth -= 1
                if depth == 0:
                    return bisect_right(self._offsets, i)
            i += 1
        return start


# Every property the parser synthesizes, by resource type, for the provenance gate
# (tests/test_engine/test_rule_property_provenance.py).
# The properties of a resource are the template's, renamed to the Terraform attribute names the
# rules use (see _cfn_properties); the one property of its own is the raw Properties mapping.
PRODUCED: Mapping[str, frozenset[str]] = MappingProxyType({"*": frozenset({RAW_KEY})})


class CloudFormationParser(BaseParser):
    """Parse CloudFormation YAML or JSON templates, including AWS SAM templates."""

    def parse(self, data: Any, source_path: str = "") -> ParsedOutput:
        return self._parse(data, source_path, None)

    def parse_text(self, text: str, source_path: str = "") -> ParsedOutput:
        """Parse template text, as YAML (with short-form intrinsics) or JSON."""
        name = Path(source_path).name if source_path else "<input>"
        if text.lstrip("﻿ \t\r\n").startswith(("{", "[")):
            import json

            try:
                data = json.loads(text)
            except (json.JSONDecodeError, RecursionError) as exc:
                raise ParseError(f"Invalid JSON in {name}: {exc}") from exc
        else:
            documents = load_yaml_documents(text, source=name)
            if len(documents) != 1:
                raise ParseError(
                    f"{name} holds {len(documents)} YAML documents; "
                    "a CloudFormation template is one document"
                )
            data = documents[0]
        return self._parse(data, source_path, text)

    def parse_file(self, path: Path) -> ParsedOutput:
        return self.parse_text(decode_input(path), str(path))

    # -- the work --------------------------------------------------------------------

    def _parse(self, data: Any, source_path: str, text: str | None) -> ParsedOutput:
        if not isinstance(data, Mapping):
            raise ParseError("CloudFormation template must be an object")
        block = data.get("Resources")
        if block is None or (isinstance(block, Mapping) and not block):
            raise ParseError("CloudFormation template has no Resources block")
        if not isinstance(block, Mapping):
            raise ParseError(
                "CloudFormation Resources must be a mapping of logical ids to resources, "
                f"not a {_kind(block)}"
            )

        run = _Run(data, source_path, LineIndex.load(text, source_path))
        expansion = _sam.expand(block, data.get("Globals"))
        run.adopt(expansion)
        for logical_id, definition in expansion.resources.items():
            run.add_resource(str(logical_id), definition)
        return run.output()


class _Run:
    """The state of parsing one template."""

    def __init__(self, template: Mapping[str, Any], source_path: str, lines: LineIndex | None):
        self.template = template
        self.source = source_path
        self.lines = lines
        self.budget = WorkBudget()
        self.context = TemplateContext.from_template(template, self.budget)
        self.resources: list[ParsedResource] = []
        self.diagnostics: list[Diagnostic] = []
        self.edges: list[ParsedEdge] = []
        self.expansion = _sam.SamExpansion()
        self.logical_ids: set[str] = set()
        # logical id -> the type the resource is named, for every resource that can be modelled
        self.types: dict[str, str] = {}
        self.unresolved = 0
        self.imports: list[str] = []
        self.unmapped: dict[str, list[str]] = {}
        self.nested: list[tuple[str, str, int | None]] = []
        self.skipped = 0
        self.rain_modules = 0

    # -- diagnostics -----------------------------------------------------------------

    def diagnose(
        self, level: Any, code: str, message: str, logical_id: str = "", line: int | None = None
    ) -> None:
        if line is None and logical_id and self.lines is not None:
            line = self.lines.span(logical_id)[0]
        self.diagnostics.append(Diagnostic(level, code, message, self.source, line))

    def adopt(self, expansion: _sam.SamExpansion) -> None:
        """Take the expanded resources' ids, SAM notes and flows."""
        self.expansion = expansion
        self.logical_ids = {str(key) for key in expansion.resources}
        for key, definition in expansion.resources.items():
            if _validate(definition) is None:
                properties = definition.get("Properties") or {}
                self.types[str(key)] = resolve_type(definition["Type"], properties).resource_type
        for note in expansion.notes:
            origin = note.logical_id
            self.diagnose(note.level, note.code, note.message, origin)

    # -- one resource ----------------------------------------------------------------

    def add_resource(self, logical_id: str, definition: Any) -> None:
        origin = self.expansion.origins.get(logical_id)
        span_id = origin.logical_id if origin is not None else logical_id
        problem = _for_each_problem(logical_id) or _validate(definition)
        if problem is not None:
            self.skipped += 1
            if _rain_module(definition) is not None:
                self.rain_modules += 1
            self.diagnose(
                "warning",
                "cfn.skipped_resource",
                f"Resource '{logical_id}' was skipped: {problem}",
                span_id,
            )
            return
        cfn_type: str = definition["Type"]
        properties: Mapping[str, Any] = definition.get("Properties") or {}

        resolved = resolve_type(cfn_type, properties)
        if not resolved.mapped:
            self.unmapped.setdefault(cfn_type, []).append(logical_id)
        translation = translate(cfn_type, properties, self.context)
        self.unresolved += translation.unresolved

        scan = scan_refs(properties, self.logical_ids, budget=self.budget)
        references: dict[str, list[str]] = {}
        for hit in scan.hits:
            bucket = references.setdefault(translation.paths.map(hit.path), [])
            if hit.logical_id not in bucket:
                bucket.append(hit.logical_id)
        for name in scan.imports:
            if name not in self.imports:
                self.imports.append(name)

        covered = self._typed_targets(references)
        dependencies = list(
            dict.fromkeys(
                [*_depends_on(definition), *(i for i in scan.logical_ids if i not in covered)]
            )
        )
        meta = self._meta(cfn_type, definition, origin, scan.imports)
        start, end = self.lines.span(span_id) if self.lines is not None else (None, None)
        if cfn_type == NESTED_STACK_TYPE:
            url = properties.get("TemplateURL")
            self.nested.append((logical_id, url if isinstance(url, str) else "", start))

        self.resources.append(
            ParsedResource(
                resource_type=resolved.resource_type,
                address=logical_id,
                name=logical_id,
                provider=resolved.provider,
                properties=translation.properties,
                dependencies=dependencies,
                source_location=self.source,
                references=references,
                start_line=start,
                end_line=end,
                meta=meta,
            )
        )

    def _typed_targets(self, references: Mapping[str, list[str]]) -> set[str]:
        """The referenced ids the graph already turns into a typed edge.

        A reference in `vpc_id`, `role`, `subnet_ids` and the like becomes a containment,
        iam_binding or security-group edge to a node of the right type.
        Listing the same target as a dependency as well would add a second, untyped edge
        between the pair, which doubles every boundary threat on it, so those targets are
        left out of `dependencies`.
        A reference the typed rule rejects, such as a nested stack in `subnet_id`, still
        needs the dependency.
        """
        rules = _attachment_rules()
        covered: set[str] = set()
        for attribute, targets in references.items():
            matches = rules.get(attribute)
            if matches is None:
                continue
            covered.update(t for t in targets if matches(self.types.get(t, "")))
        return covered

    def _meta(
        self,
        cfn_type: str,
        definition: Mapping[str, Any],
        origin: _sam.SamOrigin | None,
        imports: list[str],
    ) -> dict[str, Any]:
        meta: dict[str, Any] = {"cfn_type": cfn_type}
        condition = definition.get("Condition")
        if isinstance(condition, str):
            meta["condition"] = condition
            meta["condition_holds"] = evaluate_condition(condition, self.context)
        for key, name in (
            ("DeletionPolicy", "deletion_policy"),
            ("UpdateReplacePolicy", "update_replace_policy"),
        ):
            value = definition.get(key)
            if isinstance(value, str):
                meta[name] = value
        if imports:
            meta["import_values"] = list(imports)
        if origin is not None:
            meta["sam_origin"] = origin.logical_id
            meta["sam_type"] = origin.cfn_type
        return meta

    # -- the result ------------------------------------------------------------------

    def output(self) -> ParsedOutput:
        self._summarize()
        transforms = _sam.transform_names(self.template.get("Transform"))
        metadata: dict[str, Any] = {
            "template_version": _scalar_text(self.template.get("AWSTemplateFormatVersion")),
            "description": _scalar_text(self.template.get("Description")),
        }
        if transforms:
            metadata["transform"] = transforms
        if self.expansion.expanded:
            metadata["sam"] = True
        if self.imports:
            metadata["imports"] = sorted(self.imports)
        if self.nested or self.rain_modules:
            metadata["incomplete"] = True
        if self.unresolved:
            metadata["unresolved_intrinsics"] = self.unresolved
        addresses = {resource.address for resource in self.resources}
        for edge in self.expansion.edges:
            if edge.source in addresses and edge.target in addresses and edge.source != edge.target:
                self.edges.append(
                    ParsedEdge(
                        source=edge.source,
                        target=edge.target,
                        edge_type=_SAM_EDGE_TYPES.get(edge.relation, "network_flow"),
                        metadata={"relation": edge.relation, "via": "sam_events"},
                        declared=False,
                    )
                )
        return ParsedOutput(
            resources=self.resources,
            source_path=self.source,
            format_type="cloudformation",
            metadata=metadata,
            edges=self.edges,
            diagnostics=self.diagnostics,
        )

    def _summarize(self) -> None:
        for cfn_type, ids in self.unmapped.items():
            shown = ", ".join(ids[:3]) + (", ..." if len(ids) > 3 else "")
            self.diagnose(
                "info",
                "cfn.unmapped_type",
                f"{cfn_type} has no Terraform mapping, so it keeps that name and no rule reads it "
                f"({len(ids)} resource{'s' if len(ids) != 1 else ''}: {shown})",
                ids[0],
            )
        for logical_id, url, line in self.nested:
            target = f" ({url})" if url else ""
            self.diagnose(
                "warning",
                "cfn.nested_stack",
                f"Nested stack '{logical_id}'{target} is not followed; "
                "the resources it creates are not analysed",
                logical_id,
                line,
            )
        if self.unresolved:
            self.diagnose(
                "info",
                "cfn.unresolved_intrinsic",
                f"{self.unresolved} intrinsic function value{'s' if self.unresolved != 1 else ''} "
                "could not be resolved from the template alone; rules treat them as unknown",
            )
        transforms = [
            name
            for name in _sam.transform_names(self.template.get("Transform"))
            if not name.startswith("AWS::Serverless")
        ]
        if transforms:
            self.diagnose(
                "info",
                "cfn.unresolved_intrinsic",
                f"Transform {', '.join(transforms)} is not expanded; "
                "resources it adds or changes are not analysed",
            )
        if not self.resources:
            self.diagnose(
                "warning",
                "parse.zero_resources",
                f"The template has {self.skipped} resource entr"
                f"{'y' if self.skipped == 1 else 'ies'} and none could be modelled",
            )


@lru_cache(maxsize=1)
def _attachment_rules() -> Mapping[str, Callable[[str], bool]]:
    """Attribute -> does the graph type an edge to a node of this resource type.

    Read from the graph's own attachment table so the two cannot disagree.
    Without the table (a graph that names it differently) nothing is left out of
    `dependencies`, which only costs a redundant edge.
    """
    try:
        from threatcode.ir.graph import ATTACHMENT_RULES

        table = {
            attribute: (rule.target or (lambda _type: True))
            for rule in ATTACHMENT_RULES
            for attribute in rule.attributes
        }
    except (ImportError, AttributeError):  # pragma: no cover - a graph without the table
        return {}
    return table


def _for_each_problem(logical_id: str) -> str | None:
    """A Fn::ForEach loop of AWS::LanguageExtensions sits among the resources as one entry."""
    if logical_id.startswith("Fn::ForEach::"):
        return (
            "it is an Fn::ForEach loop (AWS::LanguageExtensions), which is not expanded, "
            "so the resources it creates are not analysed"
        )
    return None


_RAIN_MODULE_KEY = "Fn::Rain::Module"


def _rain_module(definition: Any) -> str | None:
    """The module path of a ``Type: !Rain::Module <path>`` entry; None for anything else.

    Rain (``rain pkg``) packages a module into the template.
    The template as written holds the tag where a resource type goes, and the YAML loader keeps it
    as ``{"Fn::Rain::Module": path}``.
    """
    if not isinstance(definition, Mapping):
        return None
    cfn_type = definition.get("Type")
    if isinstance(cfn_type, Mapping) and _RAIN_MODULE_KEY in cfn_type:
        path = cfn_type[_RAIN_MODULE_KEY]
        return path if isinstance(path, str) else str(path)
    return None


def _validate(definition: Any) -> str | None:
    """Why a Resources entry cannot be modelled, or None when it can."""
    if not isinstance(definition, Mapping):
        return f"the entry is a {_kind(definition)}, not a mapping with a Type"
    module = _rain_module(definition)
    if module is not None:
        return (
            f"Rain module not expanded (Type is !Rain::Module {module}; run rain pkg to expand "
            "it), so the resources it creates are not analysed"
        )
    cfn_type = definition.get("Type")
    if not isinstance(cfn_type, str) or not cfn_type.strip():
        return f"Type must be a string, not a {_kind(cfn_type)}"
    properties = definition.get("Properties")
    if properties is not None and not isinstance(properties, Mapping):
        return f"Properties must be a mapping, not a {_kind(properties)}"
    return None


def _depends_on(definition: Mapping[str, Any]) -> list[str]:
    value = definition.get("DependsOn", [])
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []
