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


@dataclass
class ParsedOutput:
    resources: list[ParsedResource] = field(default_factory=list)
    source_path: str = ""
    format_type: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseParser(ABC):
    @abstractmethod
    def parse(self, data: Any, source_path: str = "") -> ParsedOutput: ...
