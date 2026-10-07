"""The enums every catalog family module is written in.

They live here, below both `ir.nodes` and the family modules, so neither has to
import the other. `ir.nodes` re-exports them, and `from threatcode.ir.nodes
import NodeCategory, TrustZone` is the import to use everywhere else.
"""

from __future__ import annotations

from enum import Enum


class NodeCategory(str, Enum):
    COMPUTE = "compute"
    STORAGE = "storage"
    NETWORK = "network"
    DATABASE = "database"
    IAM = "iam"
    SERVERLESS = "serverless"
    CDN = "cdn"
    DNS = "dns"
    MONITORING = "monitoring"
    MESSAGING = "messaging"
    CONTAINER = "container"
    UNKNOWN = "unknown"

    @property
    def stride_element(self) -> str:
        """Map to STRIDE element type."""
        return _CATEGORY_TO_STRIDE.get(self, "process")


class TrustZone(str, Enum):
    INTERNET = "internet"
    DMZ = "dmz"
    PRIVATE = "private"
    DATA = "data"
    MANAGEMENT = "management"


_CATEGORY_TO_STRIDE: dict[NodeCategory, str] = {
    NodeCategory.COMPUTE: "process",
    NodeCategory.STORAGE: "data_store",
    NodeCategory.NETWORK: "data_flow",
    NodeCategory.DATABASE: "data_store",
    NodeCategory.IAM: "external_entity",
    NodeCategory.SERVERLESS: "process",
    NodeCategory.CDN: "data_flow",
    NodeCategory.DNS: "data_flow",
    NodeCategory.MONITORING: "process",
    NodeCategory.MESSAGING: "data_flow",
    NodeCategory.CONTAINER: "process",
    NodeCategory.UNKNOWN: "process",
}
