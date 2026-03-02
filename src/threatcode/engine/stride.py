"""STRIDE threat classification."""

from __future__ import annotations

from enum import Enum


class StrideCategory(str, Enum):
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"

    @property
    def label(self) -> str:
        return self.value.replace("_", " ").title()

    @property
    def description(self) -> str:
        return _DESCRIPTIONS[self]


_DESCRIPTIONS: dict[StrideCategory, str] = {
    StrideCategory.SPOOFING: (
        "Pretending to be something or someone other than yourself. Threatens authentication."
    ),
    StrideCategory.TAMPERING: (
        "Modifying data or code without authorization. Threatens integrity."
    ),
    StrideCategory.REPUDIATION: (
        "Claiming to have not performed an action. Threatens non-repudiation and audit trails."
    ),
    StrideCategory.INFORMATION_DISCLOSURE: (
        "Exposing information to unauthorized parties. Threatens confidentiality."
    ),
    StrideCategory.DENIAL_OF_SERVICE: (
        "Denying or degrading service to users. Threatens availability."
    ),
    StrideCategory.ELEVATION_OF_PRIVILEGE: (
        "Gaining capabilities without proper authorization. Threatens authorization boundaries."
    ),
}

# STRIDE-per-element: which categories apply to each element type
STRIDE_ELEMENT_MAP: dict[str, list[StrideCategory]] = {
    "external_entity": [
        StrideCategory.SPOOFING,
        StrideCategory.REPUDIATION,
    ],
    "process": [
        StrideCategory.SPOOFING,
        StrideCategory.TAMPERING,
        StrideCategory.REPUDIATION,
        StrideCategory.INFORMATION_DISCLOSURE,
        StrideCategory.DENIAL_OF_SERVICE,
        StrideCategory.ELEVATION_OF_PRIVILEGE,
    ],
    "data_store": [
        StrideCategory.TAMPERING,
        StrideCategory.REPUDIATION,
        StrideCategory.INFORMATION_DISCLOSURE,
        StrideCategory.DENIAL_OF_SERVICE,
    ],
    "data_flow": [
        StrideCategory.TAMPERING,
        StrideCategory.INFORMATION_DISCLOSURE,
        StrideCategory.DENIAL_OF_SERVICE,
    ],
}
