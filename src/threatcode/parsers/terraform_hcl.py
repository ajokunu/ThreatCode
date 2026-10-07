"""Terraform HCL parser for raw .tf, .tofu and .tf.json files and module directories."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from threatcode.constants import is_terraform_json_name, is_terraform_name
from threatcode.exceptions import ParseError
from threatcode.parsers._text import decode_input
from threatcode.parsers.base import BaseParser, ParsedOutput, ParsedResource


class TerraformHCLParser(BaseParser):
    """Parse raw Terraform files via python-hcl2 (fallback when plan JSON is unavailable).

    A single file is one unit and a directory is one module: every ``.tf``, ``.tofu`` and
    ``.tf.json`` file directly inside it is read once and the resources are concatenated.
    References between resources and expression evaluation are not resolved here.
    """

    def parse(self, data: Any, source_path: str = "") -> ParsedOutput:
        if not isinstance(data, dict):
            raise ParseError("HCL parse result must be a dict")
        return self._extract_resources(data, source_path)

    def parse_text(self, text: str, source_path: str = "") -> ParsedOutput:
        """Parse text that was already decoded, so the file is read from disk once."""
        data = self._load_text(text, Path(source_path).name or "<input>")
        return self._extract_resources(data, source_path)

    def parse_file(self, path: Path) -> ParsedOutput:
        return self.parse_text(decode_input(path), str(path))

    def parse_directory(self, path: Path) -> ParsedOutput:
        """Parse the Terraform files directly inside ``path`` as one module.

        Files are read in name order. Symlinks are skipped and empty files are ignored,
        because an empty ``outputs.tf`` is normal in a module.
        """
        try:
            files = sorted(
                (
                    entry
                    for entry in path.iterdir()
                    if is_terraform_name(entry.name) and entry.is_file() and not entry.is_symlink()
                ),
                key=lambda entry: entry.name,
            )
        except OSError as exc:
            raise ParseError(f"Cannot read directory {path.name}: {exc.strerror or exc}") from exc
        if not files:
            raise ParseError(f"No Terraform files (.tf, .tofu, .tf.json) in {path.name}")

        resources: list[ParsedResource] = []
        parsed_files: list[str] = []
        for file in files:
            text = decode_input(file, allow_empty=True)
            if not text.strip():
                continue
            data = self._load_text(text, file.name)
            resources.extend(self._extract_resources(data, str(file)).resources)
            parsed_files.append(file.name)

        return ParsedOutput(
            resources=resources,
            source_path=str(path),
            format_type="terraform_hcl",
            metadata={"files": parsed_files},
        )

    def _load_text(self, text: str, name: str) -> dict[str, Any]:
        if is_terraform_json_name(name):
            return self._load_json_syntax(text, name)
        try:
            from hcl2.api import loads as hcl2_loads
        except ImportError as e:
            raise ParseError("python-hcl2 required: pip install python-hcl2") from e

        try:
            data = hcl2_loads(text)
        except Exception as e:
            raise ParseError(_describe_hcl_error(e, name)) from e
        return dict(data)

    @staticmethod
    def _load_json_syntax(text: str, name: str) -> dict[str, Any]:
        """Load Terraform's JSON syntax (CDK for Terraform writes ``cdk.tf.json``)."""
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise ParseError(f"Invalid JSON in {name}, line {e.lineno}: {e.msg}") from e
        if not isinstance(data, dict):
            raise ParseError(f"{name}: a Terraform JSON file must hold an object")
        return data

    def _extract_resources(self, data: dict[str, Any], source_path: str) -> ParsedOutput:
        resources: list[ParsedResource] = []

        blocks = data.get("resource", [])
        if isinstance(blocks, dict):
            # JSON syntax writes one object, {"aws_s3_bucket": {"name": {...}}}; HCL parses
            # to a list of such objects.
            blocks = [blocks]
        for block in blocks:
            if not isinstance(block, dict):
                continue
            for rtype, instances in block.items():
                if not isinstance(instances, dict):
                    continue
                for name, config in instances.items():
                    if isinstance(config, list) and config and isinstance(config[0], dict):
                        config = config[0]  # JSON syntax allows a one-element array
                    props = config if isinstance(config, dict) else {}
                    resources.append(
                        ParsedResource(
                            resource_type=rtype,
                            address=f"{rtype}.{name}",
                            name=name,
                            provider=_infer_provider(rtype),
                            properties=props,
                            source_location=source_path,
                        )
                    )

        return ParsedOutput(
            resources=resources,
            source_path=source_path,
            format_type="terraform_hcl",
        )


def _describe_hcl_error(exc: Exception, name: str) -> str:
    """One-line message with the file and line, without the parser's token dump."""
    line = getattr(exc, "line", None)
    column = getattr(exc, "column", None)
    if isinstance(line, int) and line > 0:
        where = f"line {line}"
        if isinstance(column, int) and column > 0:
            where += f", column {column}"
        return f"Invalid HCL in {name}, {where}: syntax error"
    detail = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
    if "Token(" in detail or "Expected one of" in detail:
        detail = "syntax error"  # the parser's token dump helps nobody
    return f"Invalid HCL in {name}: {detail}"


def _infer_provider(resource_type: str) -> str:
    prefix = resource_type.split("_")[0]
    return {
        "aws": "hashicorp/aws",
        "azurerm": "hashicorp/azurerm",
        "google": "hashicorp/google",
    }.get(prefix, prefix)
