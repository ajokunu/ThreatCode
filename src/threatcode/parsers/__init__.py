"""Parser auto-detection and dispatch via pluggable registry.

``detect_and_parse`` reads a file once (BOM sniffing, strict UTF-8, size cap), loads it as
JSON or YAML when the extension says so, and hands it to the first registered parser whose
detector claims it. Once a detector has claimed a file, a parser failure is never reported
as "unsupported format": it surfaces as a ``ParseError`` that names the parser and the file.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from threatcode.constants import is_dockerfile_name, is_terraform_json_name, is_terraform_name
from threatcode.exceptions import ParseError, ThreatCodeError, UnsupportedFormatError
from threatcode.parsers._text import MAX_INPUT_SIZE_BYTES, decode_input
from threatcode.parsers._yaml import load_yaml_documents

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from threatcode.parsers.base import BaseParser, ParsedOutput

__all__ = [
    "MAX_INPUT_SIZE_BYTES",
    "DuplicateParserError",
    "ParseFileParser",
    "ParserEntry",
    "ParserPriority",
    "detect_and_parse",
    "is_dockerfile_name",
    "register_parser",
]


class ParserPriority(IntEnum):
    """Order in which detectors run; a lower number is checked first."""

    HELM = 8
    TERRAFORM_PLAN = 10
    MCP_CONFIG = 15
    CLOUDFORMATION = 20
    KUBERNETES = 22
    DOCKERFILE = 25
    TERRAFORM_HCL = 30
    DEFAULT = 100


class DuplicateParserError(ThreatCodeError, ValueError):
    """Raised when a parser name is registered twice."""


@runtime_checkable
class ParseFileParser(Protocol):
    """A parser that reads source text itself instead of a pre-parsed JSON or YAML value.

    ``parse_text`` receives text the registry already decoded, so a file is read once.
    ``parse_file`` is the same operation starting from a path, for direct callers.
    """

    def parse_file(self, path: Path) -> ParsedOutput: ...

    def parse_text(self, text: str, source_path: str = "") -> ParsedOutput: ...


@dataclass
class ParserEntry:
    """Registry entry for a parser."""

    name: str
    detector: Callable[[Path, str, Any | None], bool]
    factory: Callable[[], BaseParser]
    extensions: frozenset[str] = field(default_factory=frozenset)
    priority: int = ParserPriority.DEFAULT


_REGISTRY: list[ParserEntry] = []


def register_parser(
    name: str,
    detector: Callable[[Path, str, Any | None], bool],
    factory: Callable[[], BaseParser],
    extensions: frozenset[str] | set[str] | None = None,
    priority: int = ParserPriority.DEFAULT,
) -> None:
    """Register a custom parser.

    Args:
        name: Human-readable parser name, unique in the registry.
        detector: Function(path, content, parsed_data) -> bool. Called to check if this
            parser handles the given file. `parsed_data` is the JSON/YAML-parsed value
            if available, else None.
        factory: Callable that returns a BaseParser instance.
        extensions: File extensions this parser handles (e.g., {".yaml", ".yml"}),
            compared case-insensitively.
        priority: Lower number = checked first. Built-in parsers use ParserPriority.

    Raises:
        DuplicateParserError: A parser with this name is already registered.
    """
    if any(entry.name == name for entry in _REGISTRY):
        raise DuplicateParserError(f"A parser named '{name}' is already registered")
    entry = ParserEntry(
        name=name,
        detector=detector,
        factory=factory,
        extensions=frozenset(ext.lower() for ext in (extensions or set())),
        priority=priority,
    )
    _REGISTRY.append(entry)
    _REGISTRY.sort(key=lambda e: e.priority)


_SUPPORTED_INPUTS = (
    "Terraform plan JSON (terraform show -json PLANFILE)",
    "Terraform files: .tf, .tofu, .tf.json, or a directory of them",
    "CloudFormation templates: YAML, JSON, .template",
    "Kubernetes manifests: YAML or JSON",
    "Helm charts (Chart.yaml)",
    "Dockerfile and Containerfile",
    "MCP client configs (.mcp.json, .vscode/mcp.json, claude_desktop_config.json)",
)

# Extensions that hold JSON or YAML, told apart by the first character.
_AMBIGUOUS_SUFFIXES = frozenset({".template", ".cfn"})


def detect_and_parse(path: str | Path) -> ParsedOutput:
    """Auto-detect the input format and parse it.

    A file goes to the first parser whose detector claims it. A directory is read as one
    Terraform module when it holds .tf, .tofu or .tf.json files.

    Raises:
        FileNotFoundError: The path does not exist.
        UnsupportedFormatError: No parser claims the input, or the JSON or YAML is invalid.
        ParseError: The input is empty, not valid text, too large, or a parser that claimed
            it failed.
    """
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    if path.is_dir():
        return _parse_directory(path)

    text = decode_input(path)
    data = _preparse(path, text)
    suffix = path.suffix.lower()

    for entry in _REGISTRY:
        if entry.extensions and suffix not in entry.extensions:
            continue
        try:
            claimed = entry.detector(path, text, data)
        except ParseError:
            # A detector may raise a ParseError to explain exactly why it rejects a file.
            raise
        except Exception as exc:
            logger.debug("Detector '%s' failed for %s: %s", entry.name, path.name, exc)
            continue
        if claimed:
            return _run_parser(entry, path, text, data)

    raise _unsupported(path, data)


def _call_parser(name: str, path: Path, call: Callable[[], ParsedOutput]) -> ParsedOutput:
    """Run a parser that claimed ``path``; any failure other than ParseError is wrapped."""
    try:
        return call()
    except ParseError:
        raise
    except Exception as exc:
        raise ParseError(
            f"{name} parser failed on {path.name}: {type(exc).__name__}: {exc}"
        ) from exc


def _run_parser(entry: ParserEntry, path: Path, text: str, data: Any) -> ParsedOutput:
    def call() -> ParsedOutput:
        parser = entry.factory()
        if data is None and isinstance(parser, ParseFileParser):
            return parser.parse_text(text, source_path=str(path))
        return parser.parse(data if data is not None else text, source_path=str(path))

    return _call_parser(entry.name, path, call)


def _parse_directory(path: Path) -> ParsedOutput:
    """Parse a directory of Terraform files as one module."""
    from threatcode.parsers.terraform_hcl import TerraformHCLParser

    try:
        has_terraform = any(
            is_terraform_name(entry.name) and entry.is_file() and not entry.is_symlink()
            for entry in path.iterdir()
        )
    except OSError as exc:
        raise ParseError(f"Cannot read directory {path.name}: {exc.strerror or exc}") from exc
    if not has_terraform:
        raise UnsupportedFormatError(
            f"Cannot detect format for {path.name}: it is a directory with no Terraform files.\n"
            "A directory is read as one module when it holds .tf, .tofu or .tf.json files."
        )
    return _call_parser("terraform_hcl", path, lambda: TerraformHCLParser().parse_directory(path))


# ── Pre-parsing ───────────────────────────────────────────────────────


def _preparse(path: Path, text: str) -> Any:
    """Load JSON or YAML according to the extension; None for everything else.

    One YAML document is returned as is, several as a list, none as None.
    """
    suffix = path.suffix.lower()
    if suffix == ".json":
        return _load_json(path, text)
    if suffix in (".yml", ".yaml"):
        return _load_yaml(path, text)
    if suffix in _AMBIGUOUS_SUFFIXES:
        if text.lstrip().startswith(("{", "[")):
            return _load_json(path, text)
        return _load_yaml(path, text)
    return None


def _load_json(path: Path, text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        data = _parse_jsonc_mcp_config(path, text)
        if data is None:
            raise UnsupportedFormatError(
                f"Invalid JSON in {path.name}, line {e.lineno}: {e.msg}"
            ) from e
        return data
    except RecursionError as e:
        raise UnsupportedFormatError(f"Invalid JSON in {path.name}: nesting is too deep") from e


def _load_yaml(path: Path, text: str) -> Any:
    try:
        # Kubernetes manifests routinely hold several documents separated by ---.
        # One document stays a plain value; several become a list of documents.
        docs = load_yaml_documents(text, source=path.name)
    except UnsupportedFormatError:
        raise
    except ParseError as e:
        raise UnsupportedFormatError(str(e)) from e
    return docs[0] if len(docs) == 1 else (docs or None)


def _parse_jsonc_mcp_config(path: Path, content: str) -> Any:
    """Parse an MCP config file that uses JSONC comments, as VS Code's mcp.json may.

    Returns None when the file is not a known MCP config name or still fails to parse.
    """
    from threatcode.parsers.mcp_config import MCP_CONFIG_FILENAMES, strip_jsonc

    if path.name not in MCP_CONFIG_FILENAMES:
        return None
    try:
        return json.loads(strip_jsonc(content))
    except json.JSONDecodeError:
        return None


def _unsupported(path: Path, data: Any) -> UnsupportedFormatError:
    lines = [f"Cannot detect format for {path.name}.", "Supported inputs:"]
    lines.extend(f"  - {item}" for item in _SUPPORTED_INPUTS)
    if isinstance(data, dict):
        if "format_version" in data:
            lines.append("Hint: no planned_values or resource_changes, so this is not a plan.")
        else:
            lines.append("Hint: needs apiVersion and kind, or Resources with AWS:: types.")
    return UnsupportedFormatError("\n".join(lines))


# ── Built-in parser registration ──────────────────────────────────────

TERRAFORM_STATE_MESSAGE = (
    "This is Terraform state, not a plan. "
    "Run: terraform plan -out tfplan && terraform show -json tfplan"
)
TERRAFORM_DESTROY_MESSAGE = "this plan destroys every resource; there is nothing to model"


def _planned_resource_count(planned: Any) -> int:
    """Count the resources in a plan's planned_values, child modules included."""
    if not isinstance(planned, dict):
        return 0
    count = 0
    pending = [planned.get("root_module")]
    while pending:
        module = pending.pop()
        if not isinstance(module, dict):
            continue
        resources = module.get("resources")
        if isinstance(resources, list):
            count += len(resources)
        children = module.get("child_modules")
        if isinstance(children, list):
            pending.extend(children)
    return count


def _is_delete(change: Any) -> bool:
    detail = change.get("change") if isinstance(change, dict) else None
    return isinstance(detail, dict) and detail.get("actions") == ["delete"]


def _destroys_everything(data: dict[str, Any]) -> bool:
    """True when the plan deletes resources and plans none to exist afterwards."""
    changes = data.get("resource_changes")
    if not isinstance(changes, list):
        return False
    managed = [c for c in changes if not (isinstance(c, dict) and c.get("mode") == "data")]
    if not managed or not all(_is_delete(c) for c in managed):
        return False
    return _planned_resource_count(data.get("planned_values")) == 0


def _detect_terraform_plan(path: Path, content: str, data: Any) -> bool:
    """Claim the JSON of `terraform show -json PLANFILE`.

    A plan has format_version and planned_values or resource_changes. The same command on
    state prints format_version and values with no planned_values; that and a plan that
    only destroys are rejected with a message that names the right command.
    """
    if not isinstance(data, dict) or is_terraform_json_name(path.name):
        return False
    if "format_version" not in data:
        return False
    if "planned_values" not in data:
        if "values" in data:
            raise ParseError(TERRAFORM_STATE_MESSAGE)
        if "resource_changes" not in data:
            return False
    if _destroys_everything(data):
        raise ParseError(TERRAFORM_DESTROY_MESSAGE)
    return True


_CFN_TYPE_PREFIXES = ("AWS::", "Custom::", "Alexa::")
_CFN_SECTION_KEYS = ("Description", "Parameters", "Outputs", "Mappings", "Conditions")


def _is_cfn_resource(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    cfn_type = value.get("Type")
    return isinstance(cfn_type, str) and cfn_type.startswith(_CFN_TYPE_PREFIXES)


def _detect_cloudformation(path: Path, content: str, data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    # A version marker or a Transform (SAM, macros) is enough on its own.
    if "AWSTemplateFormatVersion" in data or "Transform" in data:
        return True
    resources = data.get("Resources")
    if not isinstance(resources, dict):
        return False
    # A template without a version still has resources typed AWS::, Custom:: or Alexa::.
    if any(_is_cfn_resource(value) for value in resources.values()):
        return True
    # Older heuristic: Resources next to another CloudFormation-only section.
    return any(key in data for key in _CFN_SECTION_KEYS)


def _detect_terraform_hcl(path: Path, content: str, data: Any) -> bool:
    return is_terraform_name(path.name)


def _factory_terraform_plan() -> BaseParser:
    from threatcode.parsers.terraform_plan import TerraformPlanParser

    return TerraformPlanParser()


def _factory_cloudformation() -> BaseParser:
    from threatcode.parsers.cloudformation import CloudFormationParser

    return CloudFormationParser()


def _factory_terraform_hcl() -> BaseParser:
    from threatcode.parsers.terraform_hcl import TerraformHCLParser

    return TerraformHCLParser()


register_parser(
    name="terraform_plan",
    detector=_detect_terraform_plan,
    factory=_factory_terraform_plan,
    extensions=frozenset({".json"}),
    priority=ParserPriority.TERRAFORM_PLAN,
)

register_parser(
    name="cloudformation",
    detector=_detect_cloudformation,
    factory=_factory_cloudformation,
    extensions=frozenset({".json", ".yml", ".yaml", ".template", ".cfn"}),
    priority=ParserPriority.CLOUDFORMATION,
)

register_parser(
    name="terraform_hcl",
    detector=_detect_terraform_hcl,
    factory=_factory_terraform_hcl,
    extensions=frozenset({".tf", ".tofu", ".json"}),
    priority=ParserPriority.TERRAFORM_HCL,
)


def _detect_dockerfile(path: Path, content: str, data: Any) -> bool:
    return is_dockerfile_name(path.name)


def _factory_dockerfile() -> BaseParser:
    from threatcode.parsers.dockerfile import DockerfileParser

    return DockerfileParser()


register_parser(
    name="dockerfile",
    detector=_detect_dockerfile,
    factory=_factory_dockerfile,
    extensions=frozenset(),  # No extension filter: detection uses the file name
    priority=ParserPriority.DOCKERFILE,
)


def _is_kubernetes_doc(doc: Any) -> bool:
    # Must have apiVersion and kind, and NOT be a CloudFormation template
    return (
        isinstance(doc, dict)
        and "apiVersion" in doc
        and "kind" in doc
        and "AWSTemplateFormatVersion" not in doc
        and "Resources" not in doc
    )


def _is_kubernetes_list(doc: Any) -> bool:
    # kubectl wraps several objects in a List or <Kind>List with the objects under items
    if not isinstance(doc, dict):
        return False
    kind = doc.get("kind")
    return (
        isinstance(kind, str)
        and (kind == "List" or kind.endswith("List"))
        and isinstance(doc.get("items"), list)
    )


def _detect_kubernetes(path: Path, content: str, data: Any) -> bool:
    if isinstance(data, list):
        # A multi-document file: it is claimed when any document is a Kubernetes object,
        # because manifests are often mixed with other YAML.
        return any(_is_kubernetes_doc(doc) or _is_kubernetes_list(doc) for doc in data)
    return _is_kubernetes_doc(data) or _is_kubernetes_list(data)


def _factory_kubernetes() -> BaseParser:
    from threatcode.parsers.kubernetes import KubernetesParser

    return KubernetesParser()


register_parser(
    name="kubernetes",
    detector=_detect_kubernetes,
    factory=_factory_kubernetes,
    extensions=frozenset({".yml", ".yaml", ".json"}),
    priority=ParserPriority.KUBERNETES,
)


def _detect_helm_chart(path: Path, content: str, data: Any) -> bool:
    if path.name == "Chart.yaml" and isinstance(data, dict):
        return "apiVersion" in data and ("name" in data or "version" in data)
    return False


def _factory_helm() -> BaseParser:
    from threatcode.parsers.helm import HelmParser

    return HelmParser()


register_parser(
    name="helm",
    detector=_detect_helm_chart,
    factory=_factory_helm,
    extensions=frozenset({".yaml", ".yml"}),
    priority=ParserPriority.HELM,
)


def _detect_mcp_config(path: Path, content: str, data: Any) -> bool:
    from threatcode.parsers.mcp_config import is_mcp_config

    return is_mcp_config(path, data)


def _factory_mcp_config() -> BaseParser:
    from threatcode.parsers.mcp_config import MCPConfigParser

    return MCPConfigParser()


register_parser(
    name="mcp_config",
    detector=_detect_mcp_config,
    factory=_factory_mcp_config,
    extensions=frozenset({".json"}),
    priority=ParserPriority.MCP_CONFIG,
)
