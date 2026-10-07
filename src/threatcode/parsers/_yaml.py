"""YAML loading shared by the parsers.

``CfnSafeLoader`` is a safe loader: it never constructs Python objects, so a
``!!python/object`` tag is rejected like it is by ``yaml.safe_load``. On top of that it
reads the CloudFormation short-form intrinsics (``!Ref``, ``!GetAtt``, ``!Sub`` and the
rest) and returns the long form a JSON template spells out, so every later stage sees one
shape. The extra tags are harmless for other YAML because they only apply to local tags,
which plain Kubernetes manifests do not use.

``load_yaml_documents`` can also return, for every document, an index from JSON pointer to
the line where that mapping key or sequence item starts, for source locations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, overload

import yaml
from yaml.constructor import ConstructorError

from threatcode.exceptions import ParseError

if TYPE_CHECKING:
    _LoaderBase = yaml.SafeLoader
else:
    # libyaml is several times faster than the pure Python loader when it is installed.
    _LoaderBase = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def _long_form_key(tag_suffix: str) -> str:
    """Return the long-form key for a short-form tag name (``Ref`` stays ``Ref``)."""
    if tag_suffix in ("Ref", "Condition"):
        return tag_suffix
    return f"Fn::{tag_suffix}"


def _construct_by_kind(loader: Any, node: yaml.Node) -> Any:
    """Construct a tagged node's value from its kind, building nested tags as well."""
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    kind = type(node).__name__
    raise ConstructorError(None, None, f"unexpected YAML node {kind}", node.start_mark)


def _construct_cfn_tag(loader: Any, tag_suffix: str, node: yaml.Node) -> Any:
    """Turn ``!Name value`` into ``{"Fn::Name": value}`` (``!Ref`` and ``!Condition`` bare)."""
    value = _construct_by_kind(loader, node)
    if tag_suffix == "GetAtt" and isinstance(value, str):
        # '!GetAtt Resource.Attribute' splits on the first dot only: the attribute itself
        # may contain dots (Endpoint.Address), the logical id cannot.
        value = value.split(".", 1)
    return {_long_form_key(tag_suffix): value}


def _construct_timestamp_as_str(loader: Any, node: yaml.ScalarNode) -> str:
    """Keep YAML 1.1 timestamps as the text that was written.

    ``AWSTemplateFormatVersion: 2010-09-09`` and an unquoted IAM ``Version: 2012-10-17``
    would otherwise load as ``datetime.date``, which JSON output cannot serialize and no
    rule can compare with a string.
    """
    return str(loader.construct_scalar(node))


class CfnSafeLoader(_LoaderBase):
    """Safe YAML loader that understands CloudFormation short-form intrinsics."""


CfnSafeLoader.add_multi_constructor("!", _construct_cfn_tag)
CfnSafeLoader.add_constructor("tag:yaml.org,2002:timestamp", _construct_timestamp_as_str)


def _describe_yaml_error(exc: yaml.YAMLError, source: str) -> str:
    """Build a one-line message with the file, the line and the problem."""
    mark = getattr(exc, "problem_mark", None)
    problem = getattr(exc, "problem", None) or str(exc)
    problem = str(problem).strip().splitlines()[0] if str(problem).strip() else "syntax error"
    if mark is not None:
        return f"Invalid YAML in {source}, line {mark.line + 1}: {problem}"
    return f"Invalid YAML in {source}: {problem}"


def _pointer_token(token: str) -> str:
    """Escape a key for a JSON pointer (RFC 6901)."""
    return token.replace("~", "~0").replace("/", "~1")


def _wrapper_key(tag: str) -> str | None:
    """Return the long-form key a short-form tagged collection was wrapped under."""
    if tag.startswith("!") and not tag.startswith("!!") and len(tag) > 1:
        return _long_form_key(tag[1:])
    return None


def _build_line_index(root: yaml.Node) -> dict[str, int]:
    """Map JSON pointers to 1-based line numbers for every key and item under ``root``.

    The pointers follow the constructed value, so a short-form tagged collection such as
    ``!Join [",", [a, b]]`` is indexed under ``/Fn::Join/0``. A node reached through an
    alias keeps the line of its first occurrence, which also bounds the walk.
    """
    index: dict[str, int] = {"": root.start_mark.line + 1}
    seen: set[int] = set()
    stack: list[tuple[yaml.Node, str]] = [(root, "")]
    while stack:
        node, pointer = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, yaml.ScalarNode):
            continue
        wrapper = _wrapper_key(node.tag)
        if wrapper is not None:
            pointer = f"{pointer}/{_pointer_token(wrapper)}"
            index.setdefault(pointer, node.start_mark.line + 1)
        children: list[tuple[yaml.Node, str]] = []
        if isinstance(node, yaml.SequenceNode):
            for position, item in enumerate(node.value):
                child_pointer = f"{pointer}/{position}"
                index.setdefault(child_pointer, item.start_mark.line + 1)
                children.append((item, child_pointer))
        elif isinstance(node, yaml.MappingNode):
            for key_node, value_node in node.value:
                if not isinstance(key_node, yaml.ScalarNode):
                    continue
                child_pointer = f"{pointer}/{_pointer_token(str(key_node.value))}"
                index[child_pointer] = key_node.start_mark.line + 1
                children.append((value_node, child_pointer))
        # Push in reverse so nodes are visited in document order and the first
        # occurrence of an aliased node is the one that is recorded.
        stack.extend(reversed(children))
    return index


@overload
def load_yaml_documents(
    text: str, with_lines: Literal[False] = False, *, source: str = ...
) -> list[Any]: ...


@overload
def load_yaml_documents(
    text: str, with_lines: Literal[True], *, source: str = ...
) -> tuple[list[Any], list[dict[str, int]]]: ...


# libyaml composes flow collections recursively in C, so a document like "[[[[...]]]]"
# a few thousand levels deep overflows the native stack and kills the process before Python
# can raise RecursionError. Real manifests and templates nest flow collections a handful of
# levels, so anything past this depth is rejected before the text reaches the loader.
MAX_FLOW_DEPTH = 256


def _check_flow_depth(text: str, source: str) -> None:
    """Raise ParseError when brackets nest deeper than ``MAX_FLOW_DEPTH``.

    Every bracket counts, including those inside quoted scalars and comments. Skipping quoted
    text would let a stray apostrophe in a plain scalar hide the nesting that follows it, and
    no real document puts hundreds of unclosed brackets inside a string.
    """
    if text.count("[") + text.count("{") <= MAX_FLOW_DEPTH:
        return
    depth = 0
    for ch in text:
        if ch in "[{":
            depth += 1
            if depth > MAX_FLOW_DEPTH:
                raise ParseError(
                    f"Invalid YAML in {source}: flow collections nest deeper than "
                    f"{MAX_FLOW_DEPTH} levels"
                )
        elif ch in "]}" and depth:
            depth -= 1


def load_yaml_documents(
    text: str, with_lines: bool = False, *, source: str = "<input>"
) -> list[Any] | tuple[list[Any], list[dict[str, int]]]:
    """Load every non-empty YAML document in ``text``.

    Args:
        text: YAML text, possibly with several ``---`` separated documents.
        with_lines: Also return one ``{json-pointer: start line}`` index per document,
            covering every mapping key and sequence item.
        source: File name to put in error messages.

    Returns:
        The documents, or ``(documents, line_indexes)`` when ``with_lines`` is set. An
        empty document (``---`` followed by nothing) is dropped from both lists.

    Raises:
        ParseError: The text is not valid YAML or uses a tag that is not allowed. The
            message names the source, the line and the problem.
    """
    _check_flow_depth(text, source)
    documents: list[Any] = []
    indexes: list[dict[str, int]] = []
    loader = CfnSafeLoader(text)
    try:
        while loader.check_node():
            node = loader.get_node()
            if node is None:
                break
            document = loader.construct_document(node)
            if document is None:
                continue
            documents.append(document)
            if with_lines:
                indexes.append(_build_line_index(node))
    except yaml.YAMLError as exc:
        raise ParseError(_describe_yaml_error(exc, source)) from exc
    except RecursionError as exc:
        raise ParseError(f"Invalid YAML in {source}: nesting is too deep") from exc
    finally:
        loader.dispose()
    if with_lines:
        return documents, indexes
    return documents
