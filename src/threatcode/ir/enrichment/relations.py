"""Facts a compute resource inherits from the role it runs as.

Lambda functions, ECS task definitions, EC2 instances (through their instance profile),
SageMaker notebook instances and EKS node groups reference an IAM role.
The role's own facts (``attached_policy_arns``, ``inline_policy_statements`` and
``attached_policy_statements``, computed by the ``companions`` module) are copied onto the compute
node as:

``derived.role_attached_policy_arns``
    The managed policy ARNs attached to the role(s).
``derived.role_policy_statements``
    The normalized statements of the role's inline policies and of the customer managed policies
    attached to it that the scan can see.
``derived.role_ids``
    The graph ids of the role nodes the link resolved to.

A compute node with no role attribute at all gets none of these keys, except where the attribute is
mandatory (a function's ``role``, a notebook's ``role_arn``, a node group's ``node_role_arn``): a
plan omits those when they are computed, so their absence makes the keys Unknown.
A role the scan cannot find (a variable, a module output, an ARN of a role outside the inputs) makes
all three keys Unknown, never empty.
An ECS task definition names two roles; the keys hold the union of the task role and the execution
role.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from threatcode.ir.enrich import (
    EnrichContext,
    Produced,
    RelationSpec,
    merge_value,
    produced_by_relations,
)
from threatcode.ir.nodes import InfraNode

_ABSENT: dict[str, Any] = {
    "role_attached_policy_arns": [],
    "role_policy_statements": [],
    "role_ids": [],
}


def _role_facts(roles: Sequence[InfraNode], ctx: EnrichContext) -> dict[str, Any]:
    arns: Any = []
    statements: Any = []
    for role in roles:
        derived = ctx.derived(role)
        arns = merge_value(arns, derived.get("attached_policy_arns", []))
        own = merge_value(
            derived.get("inline_policy_statements", []),
            derived.get("attached_policy_statements", []),
        )
        statements = merge_value(statements, own)
    return {
        "role_attached_policy_arns": arns,
        "role_policy_statements": statements,
        "role_ids": [role.id for role in roles],
    }


RELATIONS: tuple[RelationSpec, ...] = (
    RelationSpec(
        source_types=("aws_lambda_function",),
        link_attrs=("role",),
        required=True,
        target_type="aws_iam_role",
        derive=_role_facts,
        absent=_ABSENT,
    ),
    RelationSpec(
        source_types=("aws_ecs_task_definition",),
        link_attrs=("task_role_arn", "execution_role_arn"),
        target_type="aws_iam_role",
        derive=_role_facts,
        absent=_ABSENT,
    ),
    RelationSpec(
        source_types=("aws_instance",),
        link_attrs=("iam_instance_profile",),
        target_type="aws_iam_instance_profile",
        hop_attrs=("role", "roles"),
        hop_type="aws_iam_role",
        derive=_role_facts,
        absent=_ABSENT,
    ),
    RelationSpec(
        source_types=("aws_sagemaker_notebook_instance",),
        link_attrs=("role_arn",),
        required=True,
        target_type="aws_iam_role",
        derive=_role_facts,
        absent=_ABSENT,
    ),
    RelationSpec(
        source_types=("aws_eks_node_group",),
        link_attrs=("node_role_arn",),
        required=True,
        target_type="aws_iam_role",
        derive=_role_facts,
        absent=_ABSENT,
    ),
)

# Every derived fact this module can write, by resource type, for the provenance gate
# (tests/test_engine/test_rule_property_provenance.py): a rule may read ``derived.<fact>`` of a
# type only if some module declares it, and a module may write only what it declares.
PRODUCED: Produced = produced_by_relations(RELATIONS)
