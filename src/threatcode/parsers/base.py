"""Base parser types and abstract class."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ParsedResource:
    resource_type: str
    address: str
    name: str
    provider: str
    properties: dict[str, Any] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    module: str = ""
    source_location: str = ""

    @property
    def provider_short(self) -> str:
        """Extract short provider name (e.g., 'aws' from 'registry.terraform.io/hashicorp/aws')."""
        if "/" in self.provider:
            return self.provider.rsplit("/", 1)[-1]
        return self.provider

    @property
    def service(self) -> str:
        """Extract service from resource type (e.g., 's3' from 'aws_s3_bucket')."""
        parts = self.resource_type.split("_", 2)
        return parts[1] if len(parts) >= 2 else self.resource_type


@dataclass
class ParsedOutput:
    resources: list[ParsedResource] = field(default_factory=list)
    source_path: str = ""
    format_type: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseParser(ABC):
    @abstractmethod
    def parse(self, data: Any, source_path: str = "") -> ParsedOutput: ...
