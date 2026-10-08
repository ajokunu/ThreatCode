"""The words the SVG diagram, the Mermaid flowcharts and the Markdown report share.

The engine records an attack path in machine tokens: edge types such as ``network_flow``,
relations such as ``instance_profile``, resource types such as ``aws_lb_target_group``.
Each format used to print those tokens as they were, so a reader met ``iam_binding invokes`` and
``network_flow 8080``.
This module says the same things in plain words, from one table, so the three formats never
disagree and no raw token reaches a reader.

It also holds the label rules the diagram and the charts need: a short type prefix that tells
apart resources whose names are the same (``role.app`` and ``profile.app``), a shortening that
keeps both ends of a long address, and the list of findings that enable each hop.
Nothing here draws anything; the functions take plain strings and the report's own objects.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from threatcode.models.report import threat_severity

if TYPE_CHECKING:
    from threatcode.models.attack_path import AttackPath
    from threatcode.models.threat import Severity, Threat

__all__ = [
    "GENERIC_EDGE_LABELS",
    "Enabler",
    "edge_label",
    "edge_phrase",
    "first_sentence",
    "friendly_noun",
    "hop_enablers",
    "humanize_tokens",
    "node_labels",
    "port_phrase",
    "short_type",
    "shorten_address",
    "shorten_middle",
]

ELLIPSIS = "..."

# -- Ports and edges ----------------------------------------------------------

# Ports whose service everyone knows; any other port is shown as ``tcp/8080``
_PORT_NAMES: dict[str, str] = {
    "22": "SSH",
    "80": "HTTP",
    "443": "HTTPS",
    "1433": "SQL Server",
    "3306": "MySQL",
    "3389": "RDP",
    "5432": "PostgreSQL",
    "6379": "Redis",
    "27017": "MongoDB",
}
_PORTS_SHOWN = 3
_APPLICATION_PROTOCOLS = frozenset({"http", "https", "ssh"})

# relation -> (short label for an arrow, predicate that follows "then"). ``{noun}`` is what the
# next resource is, in a word or two.
_RELATIONS: dict[str, tuple[str, str]] = {
    "assumes": ("assumes", "assumes the {noun}"),
    "instance_profile": ("uses profile", "runs with the {noun}"),
    "attaches": ("attaches", "attaches the {noun}"),
    "has_policy": ("has policy", "holds the {noun}"),
    "can_assume": ("can assume", "can assume the {noun}"),
    "resource_policy": ("resource policy", "is covered by a resource policy"),
    "runs": ("runs as", "runs as the {noun}"),
    "runs_as": ("runs as", "runs as the {noun}"),
    "bound_role": ("bound to", "is bound to the {noun}"),
    "reads_secret": ("reads", "reads the {noun}"),
    "invokes": ("invokes", "invokes the {noun}"),
    "returns_content": ("returns content", "returns content to the {noun}"),
    "untrusted_content": ("untrusted data", "feeds untrusted content to the {noun}"),
    "remote_server": ("remote server", "reaches the {noun}"),
    "security_group": ("security group", "is guarded by the {noun}"),
    "selects": ("selects", "selects the {noun}"),
    "backend": ("routes to", "routes requests to the {noun}"),
}
# edge type -> (short label, predicate) when the edge names no relation
_EDGE_TYPES: dict[str, tuple[str, str]] = {
    "network_flow": ("traffic", "sends traffic to the {noun}"),
    "data_flow": ("data flow", "passes data to the {noun}"),
    "iam_binding": ("permissions", "acts through the {noun}"),
    "dependency": ("depends on", "references the {noun}"),
    "containment": ("inside", "is placed in the {noun}"),
}
# What an arrow says when the edge names nothing more than its type
GENERIC_EDGE_LABELS: frozenset[str] = frozenset(short for short, _ in _EDGE_TYPES.values())
_ACCESS_WORDS = {"read": "can read", "write": "can write", "admin": "has full access to"}
_ACCESS_SHORT = {"read": "can read", "write": "can write", "admin": "full access"}

_INTERNAL_TOKENS: dict[str, str] = {
    "network_flow": "network traffic",
    "data_flow": "data flow",
    "iam_binding": "IAM binding",
}
_INTERNAL_TOKEN = re.compile(r"\b(" + "|".join(_INTERNAL_TOKENS) + r")\b")


def _ports(via: Mapping[str, Any]) -> list[str]:
    raw = via.get("ports", via.get("port"))
    if isinstance(raw, (list, tuple)):
        return [str(p) for p in raw if str(p)]
    if isinstance(raw, (str, int)) and not isinstance(raw, bool) and str(raw):
        return [str(raw)]
    return []


def port_phrase(via: Mapping[str, Any]) -> str:
    """The ports an edge carries in words: ``HTTPS 443``, ``tcp/8080`` or ``tcp/80,443``.

    ``""`` when the edge names no port.
    """
    ports = _ports(via)
    if not ports:
        return ""
    protocol = str(via.get("protocol") or "tcp").lower()
    if len(ports) == 1:
        port = ports[0]
        if protocol in _APPLICATION_PROTOCOLS:
            return f"{protocol.upper()} {port}"
        name = _PORT_NAMES.get(port) if protocol == "tcp" else None
        return f"{name} {port}" if name else f"{protocol}/{port}"
    shown = ",".join(ports[:_PORTS_SHOWN]) + (f",{ELLIPSIS}" if len(ports) > _PORTS_SHOWN else "")
    return f"{protocol}/{shown}"


def _words(edge_type: str, relation: str, via: Mapping[str, Any], *, short: bool) -> str:
    """The short label or the predicate for an edge; the ``{noun}`` stays in the predicate."""
    index = 0 if short else 1
    if edge_type == "network_flow":
        ports = port_phrase(via)
        if short:
            return ports or _RELATIONS.get(relation, _EDGE_TYPES["network_flow"])[0]
        if relation in ("backend", "selects"):
            return _RELATIONS[relation][1] + (f" on {ports}" if ports else "")
        return f"sends traffic on {ports}" if ports else "sends traffic to the {noun}"
    if edge_type == "iam_binding" and relation == "permission":
        access = str(via.get("access") or "")
        if short:
            return _ACCESS_SHORT.get(access, "permission")
        verb = _ACCESS_WORDS.get(access, "has access to")
        actions = via.get("actions")
        listed = ""
        if isinstance(actions, (list, tuple)) and actions:
            shown = ", ".join(str(a) for a in actions[:2])
            listed = f" ({shown}{', ' + ELLIPSIS if len(actions) > 2 else ''})"
        return f"{verb} the {{noun}}{listed}"
    if relation in _RELATIONS:
        text = _RELATIONS[relation][index]
    elif relation:
        words = relation.replace("_", " ")
        text = words if short else f"is linked to the {{noun}} ({words})"
    else:
        text = _EDGE_TYPES.get(edge_type, (edge_type.replace("_", " "), "links to the {noun}"))[
            index
        ]
    protocol = str(via.get("protocol") or "")
    if not short and protocol and edge_type != "network_flow":
        text += f" over {protocol}"
    return text


def edge_label(
    edge_type: str | None, relation: str = "", via: Mapping[str, Any] | None = None
) -> str:
    """What an arrow between two resources says, in a few words: ``HTTPS 443`` or ``assumes``.

    ``relation`` and the ports come from the edge, or from a hop's ``via``, which carries both.
    """
    if not edge_type:
        return ""
    details = via or {}
    return _words(edge_type, relation or str(details.get("relation") or ""), details, short=True)


def edge_phrase(
    edge_type: str | None,
    relation: str = "",
    via: Mapping[str, Any] | None = None,
    target_type: str = "",
) -> str:
    """What a hop does to the next one, as a predicate: ``sends traffic on HTTPS 443``.

    ``target_type`` is the resource type of the next hop, which names it in the sentence
    (``assumes the instance profile``).
    """
    if not edge_type:
        return ""
    details = via or {}
    text = _words(edge_type, relation or str(details.get("relation") or ""), details, short=False)
    return text.replace("{noun}", friendly_noun(target_type))


def humanize_tokens(text: str) -> str:
    """``text`` with the engine's edge type tokens in plain words.

    ``crosses a trust boundary (network_flow)`` reads ``... (network traffic)``.
    """
    return _INTERNAL_TOKEN.sub(lambda m: _INTERNAL_TOKENS[m.group(1)], text)


# -- Resource types and names --------------------------------------------------

_SHORT_TYPES: dict[str, str] = {
    "aws_alb": "lb",
    "aws_db_instance": "db",
    "aws_db_subnet_group": "db_subnet_group",
    "aws_iam_instance_profile": "profile",
    "aws_iam_policy": "policy",
    "aws_iam_role": "role",
    "aws_iam_role_policy": "role_policy",
    "aws_iam_user": "user",
    "aws_instance": "instance",
    "aws_internet_gateway": "igw",
    "aws_kms_key": "kms_key",
    "aws_lambda_function": "lambda",
    "aws_lb": "lb",
    "aws_lb_listener": "listener",
    "aws_lb_target_group": "target_group",
    "aws_lb_target_group_attachment": "tg_attachment",
    "aws_route_table": "route_table",
    "aws_s3_bucket": "bucket",
    "aws_secretsmanager_secret": "secret",
    "aws_security_group": "sg",
    "aws_subnet": "subnet",
    "aws_vpc": "vpc",
}
_NOUNS: dict[str, str] = {
    "aws_db_instance": "database",
    "aws_iam_instance_profile": "instance profile",
    "aws_iam_role": "role",
    "aws_iam_role_policy": "role policy",
    "aws_instance": "instance",
    "aws_lb": "load balancer",
    "aws_rds_cluster": "database",
    "aws_s3_bucket": "bucket",
    "aws_secretsmanager_secret": "secret",
    "kubernetes_cluster_role": "cluster role",
    "kubernetes_deployment": "deployment",
    "kubernetes_ingress": "ingress",
    "kubernetes_role": "role",
    "kubernetes_secret": "secret",
    "kubernetes_service": "service",
    "kubernetes_service_account": "service account",
    "mcp_agent": "agent",
    "mcp_server": "MCP server",
}
# Written with a slash, as ``kubectl`` writes them: ``deployment/storefront``
_SLASH_PROVIDERS = ("kubernetes_",)
_PROVIDER_PREFIX = re.compile(r"^[a-z0-9]+_")


def short_type(resource_type: str) -> str:
    """A short name for a resource type: ``aws_iam_role`` is ``role``, ``kubernetes_ingress`` is
    ``ingress``.

    Common types have a fixed short form; for the rest the provider prefix goes and at most the
    last two words stay.
    """
    if resource_type in _SHORT_TYPES:
        return _SHORT_TYPES[resource_type]
    stripped = _PROVIDER_PREFIX.sub("", resource_type, count=1) if "_" in resource_type else ""
    stripped = stripped or resource_type
    words = stripped.split("_")
    return "_".join(words[-2:]) if len(words) > 2 else stripped


def friendly_noun(resource_type: str) -> str:
    """What a resource of this type is called in a sentence: ``instance profile``, ``bucket``."""
    if resource_type in _NOUNS:
        return _NOUNS[resource_type]
    if not resource_type:
        return "next hop"
    return short_type(resource_type).replace("_", " ")


def _last_segment(address: str) -> str:
    """The last dot-separated part of an address, ignoring dots inside ``[...]``."""
    depth = 0
    for index in range(len(address) - 1, -1, -1):
        char = address[index]
        if char == "]":
            depth += 1
        elif char == "[":
            depth = max(depth - 1, 0)
        elif char == "." and depth == 0:
            return address[index + 1 :]
    return address


def base_name(node_id: str, resource_type: str = "") -> str:
    """The name a resource goes by inside its type: the last part of its address.

    ``aws_instance.app[0]`` is ``app[0]``, ``template.yaml::HelloFunction`` is ``HelloFunction``
    and a Dockerfile instruction ``dockerfile.run.3`` is ``run.3``.
    """
    tail = node_id.rsplit("::", 1)[-1] if "::" in node_id else node_id
    if "." not in tail:
        return tail
    short = _last_segment(tail)
    if resource_type.startswith("dockerfile_") and short.isdigit():
        return ".".join(tail.rsplit(".", 2)[-2:])
    return short


def _prefixed(resource_type: str, name: str) -> str:
    separator = "/" if resource_type.startswith(_SLASH_PROVIDERS) else "."
    return f"{short_type(resource_type)}{separator}{name}"


def node_labels(nodes: Iterable[tuple[str, str]], *, limit: int = 26) -> dict[str, str]:
    """A visible name for each ``(node id, resource type)`` that tells every resource apart.

    A resource goes by its name (``app``).
    Where two drawn resources share a name the type is put in front (``role.app``,
    ``profile.app``, ``ingress/storefront``), and where they still share one (two namespaces) the
    whole rest of the address is used.
    A name longer than ``limit`` characters keeps both of its ends.
    """
    pairs = list(dict.fromkeys(nodes))
    base = {node_id: base_name(node_id, rtype) for node_id, rtype in pairs}
    types = dict(pairs)

    def collisions(labels: Mapping[str, str]) -> set[str]:
        seen: dict[str, int] = {}
        for label in labels.values():
            seen[label] = seen.get(label, 0) + 1
        return {label for label, count in seen.items() if count > 1}

    labels = dict(base)
    clash = collisions(labels)
    for node_id in labels:
        if labels[node_id] in clash:
            labels[node_id] = _prefixed(types[node_id], base[node_id])
    clash = collisions(labels)
    for node_id in labels:
        if labels[node_id] in clash:
            rtype = types[node_id]
            rest = node_id[len(rtype) + 1 :] if node_id.startswith(rtype + ".") else node_id
            labels[node_id] = _prefixed(rtype, rest)
    return {node_id: shorten_middle(label, limit) for node_id, label in labels.items()}


# -- Shortening ---------------------------------------------------------------


def shorten_middle(text: str, limit: int) -> str:
    """``text`` cut in the middle to at most ``limit`` characters, so its end survives.

    The end of an address (the resource name) says more than its middle, so it keeps the larger
    share.
    """
    if len(text) <= limit or limit <= len(ELLIPSIS) + 2:
        return text if len(text) <= limit else text[:limit]
    tail = (limit - len(ELLIPSIS)) * 3 // 5
    head = limit - len(ELLIPSIS) - tail
    return f"{text[:head].rstrip()}{ELLIPSIS}{text[len(text) - tail :].lstrip()}"


def shorten_address(text: str, limit: int) -> str:
    """``text`` shortened to ``limit`` characters, dropping whole middle path segments first.

    ``python3.10/step-func/{{x}}/template.yaml::Fn`` keeps its first and last segments and as
    many of the ones after the first as fit, with ``...`` where the rest was.
    An address with no ``/`` (or one that is still too long) is cut in the middle.
    """
    if len(text) <= limit:
        return text
    segments = text.split("/")
    if len(segments) > 2:
        head, middle, tail = segments[0], segments[1:-1], segments[-1]
        for keep in range(len(middle) - 1, -1, -1):
            candidate = "/".join([head, *middle[:keep], ELLIPSIS, tail])
            if len(candidate) <= limit:
                return candidate
    return shorten_middle(text, limit)


def first_sentence(text: str) -> str:
    """The first sentence of ``text``, or all of it when it is one sentence.

    A full stop followed by a capital letter ends a sentence; ``e.g.``, ``i.e.``, ``vs.`` and a
    dot inside a version number do not.
    """
    flat = " ".join(text.split())
    for match in re.finditer(r"[.!?](?=\s+[A-Z0-9`(])", flat):
        end = match.end()
        before = flat[:end].lower()
        if before.endswith(("e.g.", "i.e.", "vs.", "etc.")):
            continue
        return flat[:end]
    return flat


# -- Findings that enable a hop -----------------------------------------------


@dataclass(frozen=True)
class Enabler:
    """A finding that makes a hop possible, as a reader sees it."""

    threat_id: str
    label: str
    title: str
    severity: Severity | None
    known: bool


def _enabler(threat_id: str, by_id: Mapping[str, Threat]) -> Enabler:
    threat = by_id.get(threat_id)
    if threat is None:
        return Enabler(threat_id, threat_id, "", None, False)
    return Enabler(
        threat_id,
        threat.rule_id or threat.source.value,
        threat.title,
        threat_severity(threat),
        True,
    )


def hop_enablers(path: AttackPath, by_id: Mapping[str, Threat]) -> list[list[Enabler]]:
    """The findings that enable each hop of ``path``, worst first.

    A finding that enables a hop and the hop before it is listed once, on the first of the two:
    a security group that admits the traffic into a load balancer is the same finding on both
    sides of it.
    """
    result: list[list[Enabler]] = []
    previous: set[str] = set()
    for hop in path.hops:
        ids = list(dict.fromkeys(hop.enabled_by))
        found = [_enabler(threat_id, by_id) for threat_id in ids if threat_id not in previous]
        found.sort(key=lambda e: (-(e.severity.rank if e.severity else -1), e.label, e.threat_id))
        result.append(found)
        previous = set(ids)
    return result


def shared_prefix_length(path: AttackPath, earlier: Sequence[AttackPath]) -> tuple[int, int]:
    """How many leading hops ``path`` shares with the best of ``earlier``, and which one.

    A hop is shared when it is the same resource and the next step out of it is the same.
    Returns ``(0, -1)`` when no earlier path shares even the first hop.
    """
    best = (0, -1)
    for index, other in enumerate(earlier):
        length = 0
        for mine, theirs in zip(path.hops, other.hops, strict=False):
            if (
                mine.node_id != theirs.node_id
                or mine.edge_type_to_next != theirs.edge_type_to_next
                or edge_phrase(mine.edge_type_to_next, via=mine.via)
                != edge_phrase(theirs.edge_type_to_next, via=theirs.via)
            ):
                break
            length += 1
        if length > best[0]:
            best = (length, index)
    return best
