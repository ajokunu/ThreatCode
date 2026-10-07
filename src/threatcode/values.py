"""Values a static scan cannot know.

A Terraform plan leaves a property out of ``values`` when it is only known after apply,
an HCL expression can name a variable nobody set, and a CloudFormation intrinsic can
refer to a stack parameter.
Parsers put an :class:`Unknown` at the property path in those cases instead of leaving
a hole, so a rule can tell "not configured" from "configured, value not known here".

``Unknown`` is a ``str``, so it survives JSON serialization and every formatter without
special handling, and it is immutable.
The rule matcher turns any check that touches one into the third truth value, so an
unresolved property never produces a finding and never counts as a pass.
"""

from __future__ import annotations

from typing import Any, TypeGuard

UNKNOWN_TEXT = "(known after apply)"


class Unknown(str):
    """A property whose value exists but cannot be resolved by this scan.

    ``reference`` is the expression or reference that could not be resolved, such as
    ``aws_kms_key.logs.arn`` or ``var.encrypted``; it is empty when nothing is known.
    Every ``Unknown`` has the text ``(known after apply)``, so two of them compare equal
    as strings; use :func:`is_unknown`, not ``==``, to recognize one.
    """

    reference: str

    def __new__(cls, reference: str = "") -> Unknown:
        instance = super().__new__(cls, UNKNOWN_TEXT)
        instance.reference = reference
        return instance

    def __repr__(self) -> str:
        return f"Unknown({self.reference!r})"

    def __reduce__(self) -> tuple[type[Unknown], tuple[str]]:
        return (Unknown, (self.reference,))

    def __copy__(self) -> Unknown:
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> Unknown:
        return self


UNKNOWN = Unknown()
"""The Unknown that carries no reference."""


def is_unknown(value: object) -> TypeGuard[Unknown]:
    """True for an :class:`Unknown`, and for nothing else, including the same text."""
    return isinstance(value, Unknown)
