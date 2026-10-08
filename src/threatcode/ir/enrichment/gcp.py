"""Google Cloud facts the GCP rules read.

The matcher reads a mapping's ports from the keys AWS and Azure use (``from_port``,
``port_range``), not from the ``ports`` list a ``google_compute_firewall`` allow block carries,
and a Compute Engine firewall has defaults that no single attribute shows: a rule without a
direction is an ingress rule, a rule with no source at all admits every address, and an allow
block without ports admits every port of its protocol.
The deriver below reads those once, so the three firewall rules compare facts instead of
re-deriving them.

Documented derived keys, by resource type:

``google_compute_firewall``
    ``ingress_allow``: the allow blocks that admit inbound traffic, as a list of
    ``{protocol, port_range, all_ports}``.
    It is empty for an egress rule, a disabled rule and a rule that has only ``deny`` blocks,
    and an Unknown when the direction, the disabled flag or the blocks cannot be read.
    ``protocol`` is lower case with IP protocol numbers translated (``6`` is ``tcp``).
    ``port_range`` is the list of ports and ``lo-hi`` ranges the block opens: the ports as
    written, or ``0-65535`` for ``tcp``, ``udp`` and ``sctp`` without ports.
    It is left out for ``all`` (which the port predicate treats as every port) and for protocols
    that have no ports.
    ``all_ports`` is true for ``all`` and for a port protocol whose ports cover 0-65535.
    ``world_source``: true when the rule admits the whole internet, because ``source_ranges``
    holds ``0.0.0.0/0`` or ``::/0`` or because the rule names no source (no ranges, no tags, no
    service accounts), which Compute Engine reads as any address.
    False for an egress rule, which has no source.
    Unknown when a source cannot be read and no known range already settles it.

No ``DEFAULTS`` table: the GCP rules state provider defaults as negations (a Cloud SQL instance
has a public address unless ``ipv4_enabled`` is false), which also covers an omitted parent
block that a nested default cannot fill.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from typing import Any

from threatcode.ir.enrich import Deriver, EnrichContext, as_list, tri_bool
from threatcode.ir.nodes import InfraNode
from threatcode.values import Unknown, is_unknown
from threatcode.vocab import is_world_source

Facts = Mapping[str, Any]

_FIREWALL = "google_compute_firewall"
_PORT_PROTOCOLS = frozenset({"tcp", "udp", "sctp"})
_PROTOCOL_NUMBERS: Mapping[str, str] = {"6": "tcp", "17": "udp", "132": "sctp", "1": "icmp"}
_ALL_PORTS = (0, 65535)
_PORT_RE = re.compile(r"\s*(\d{1,5})\s*(?:-\s*(\d{1,5})\s*)?")


def _is_world(value: Any) -> bool:
    if not isinstance(value, str) or is_unknown(value):
        return False
    if is_world_source(value):
        return True
    try:
        return ipaddress.ip_network(value.strip(), strict=False).prefixlen == 0
    except ValueError:
        return False


def _port_interval(value: Any) -> tuple[int, int] | None:
    """The inclusive range a port or ``lo-hi`` string names, or None when it names none."""
    if isinstance(value, bool) or not isinstance(value, str | int):
        return None
    found = _PORT_RE.fullmatch(str(value))
    if found is None:
        return None
    low = int(found.group(1))
    high = int(found.group(2)) if found.group(2) is not None else low
    if low > high or high > _ALL_PORTS[1]:
        return None
    return (low, high)


def _covers_every_port(intervals: list[tuple[int, int]]) -> bool:
    reach = -1
    for low, high in sorted(intervals):
        if low > reach + 1:
            return False
        reach = max(reach, high)
    return reach >= _ALL_PORTS[1]


def _allow_block(block: Mapping[str, Any]) -> dict[str, Any]:
    raw = block.get("protocol")
    if is_unknown(raw):
        return {"protocol": raw, "all_ports": Unknown(raw.reference), "port_range": raw}
    protocol = str(raw).strip().lower() if raw is not None else ""
    protocol = _PROTOCOL_NUMBERS.get(protocol, protocol)
    entry: dict[str, Any] = {"protocol": protocol}
    if protocol == "all":
        entry["all_ports"] = True
        return entry
    if protocol not in _PORT_PROTOCOLS:
        entry["all_ports"] = False
        return entry
    ports = block.get("ports")
    if is_unknown(ports):
        entry["port_range"] = ports
        entry["all_ports"] = Unknown(ports.reference)
        return entry
    items = [item for item in as_list(ports) if item is not None]
    if not items:
        entry["port_range"] = ["0-65535"]
        entry["all_ports"] = True
        return entry
    unknown = next((item for item in items if is_unknown(item)), None)
    intervals = [i for i in map(_port_interval, items) if i is not None]
    entry["port_range"] = [str(item) if is_unknown(item) else str(item).strip() for item in items]
    if _covers_every_port(intervals):
        entry["all_ports"] = True
    elif unknown is not None:
        entry["all_ports"] = Unknown(unknown.reference)
    else:
        entry["all_ports"] = False
    return entry


def _ingress_allow(props: Mapping[str, Any]) -> Any:
    direction = props.get("direction")
    if is_unknown(direction):
        return Unknown(direction.reference)
    if isinstance(direction, str) and direction.strip().upper() == "EGRESS":
        return []
    disabled = tri_bool(props.get("disabled"))
    if is_unknown(disabled):
        return Unknown(disabled.reference)
    if disabled is True:
        return []
    allow = props.get("allow")
    if is_unknown(allow):
        return Unknown(allow.reference)
    entries: list[Any] = []
    for item in as_list(allow):
        if is_unknown(item):
            entries.append(item)
        elif isinstance(item, Mapping):
            entries.append(_allow_block(item))
    return entries


def _world_source(props: Mapping[str, Any]) -> Any:
    direction = props.get("direction")
    if isinstance(direction, str) and direction.strip().upper() == "EGRESS":
        return False
    ranges = props.get("source_ranges")
    sources = [ranges, props.get("source_tags"), props.get("source_service_accounts")]
    unreadable: Unknown | None = None
    for source in sources:
        for item in [source] if is_unknown(source) else as_list(source):
            if is_unknown(item) and unreadable is None:
                unreadable = item
    if not is_unknown(ranges) and any(_is_world(item) for item in as_list(ranges)):
        return True
    if unreadable is not None:
        return Unknown(unreadable.reference)
    # No ranges, no tags and no service accounts: Compute Engine admits every source address
    return not any(as_list(source) for source in sources)


def _firewall_facts(node: InfraNode, ctx: EnrichContext) -> Facts:
    return {
        "ingress_allow": _ingress_allow(node.properties),
        "world_source": _world_source(node.properties),
    }


DERIVERS: tuple[Deriver, ...] = (Deriver((_FIREWALL,), _firewall_facts),)
