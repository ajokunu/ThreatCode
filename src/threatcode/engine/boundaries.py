"""Trust boundary crossing threats.

A trust boundary is a risk where something flows across it, so a boundary threat comes from a
flow edge (`network_flow` or `data_flow`, including the flows a design declares) between two nodes
that can exchange traffic, and from nothing else.
A containment, dependency or IAM edge between nodes in different zones says how things are wired
together, not that traffic crosses, so it produces no threat: a subnet inside its VPC, an internet
gateway attached to a VPC and a function bound to its role are not trust boundary crossings.
A security group, a network ACL, a route table, an IAM policy and a network or namespace
container cannot send or receive traffic either (`InfraNode.can_exchange_traffic`).

The flow edges include the ones the reachability pass adds (`threatcode.ir.reachability`): the
internet to an exposed load balancer on 443/tcp, the load balancer to its targets on 8080/tcp, an
application tier to a database on 5432/tcp.
The port and protocol of such an edge are in the description.
The pass also adds edges that model what an attacker controls rather than traffic (an MCP server
that fetches untrusted content, `source` `agent`); those produce no boundary threat, because the
MCP rules already report the exposure.

One threat is produced per ordered (source, target) pair, merging every flow edge between them.
Its id hashes the pair and the sorted edge types, so ids are stable and never repeat.
A crossing that starts at the synthetic internet node belongs to the node it enters: it has no
file and line of its own, so `resource_address` is the exposed resource and the flow's source is
in the title, the description and the `flow` metadata.

What the threat says follows what the flow is known to be:

- The zone pair gives the ATT&CK technique of the crossing: from the internet into the DMZ
  T1190, into the data zone T1530, into the management zone T1078.
- A flow that is declared unauthenticated is a spoofing threat (T1557), one that is declared
  unencrypted an information disclosure threat (T1040), and any other is tampering with a flow
  in transit (T1565.002).
  The attributes are `authenticated` and `encrypted` on the edge, and `encrypted` is also read from
  a `protocol` such as `https`.
- The severity comes from the zone pair, higher when the source faces the internet, and lower by
  one level when every merged edge declares the flow both encrypted and authenticated.
- A flow about which nothing is known says so, and its confidence is lower.
- The connection of an agent to an MCP server is the one flow whose authentication the input
  usually cannot show.
  The MCP parser sets `authenticated` on its edges only when the configuration carries a
  credential, because a client that follows the MCP authorization spec discovers OAuth when it
  connects, so a configuration without a credential does not say the server accepts anonymous
  calls.
  This module reads the flag as the edge states it: absent is unknown, never false.
  When authentication is the only open question about a flow that ends at an MCP server, the
  finding carries the low confidence of an absence and its severity is at most that of
  `MCP_REMOTE_NO_AUTH`, which reports the same missing credential.
  A server over plain http is still a definite finding, as `MCP_PLAINTEXT_TRANSPORT` is.

A threat leads its title with what tells it from the others of the same resource: the zones and
the other end of the flow (`dmz > private: to aws_instance.app[0] (tcp/8080)`).
The RESOURCE column of a report already shows the resource the threat sits on.

`metadata['boundary_rule']` says which kind of crossing a threat is, so a report can group them:
`BOUNDARY_UNAUTHENTICATED_FLOW` (spoofing), `BOUNDARY_UNENCRYPTED_FLOW` (information disclosure),
`BOUNDARY_UNVALIDATED_FLOW` (a flow declared `validated: false`) and `BOUNDARY_GENERIC_FLOW`
(tampering with a flow in transit).
It is not `Threat.rule_id`: that field names the rules of the rule engine, and the tests and
tools that list the rules which fired would count a boundary threat as one; the planted-issue
benchmark does, and would report a crossing on a hardened resource as a rule that fired there.
The text report prints the kind in its RULE column and an ignore file accepts it.
The fingerprint names both ends of the flow, so a baseline that accepts the flow from a load
balancer to one instance does not accept its flow to another.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from threatcode.engine.mitre import tactics_for_techniques
from threatcode.engine.stride import StrideCategory
from threatcode.ir.edges import AGENT, FLOW_EDGE_TYPES, InfraEdge
from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import InfraNode
from threatcode.models.threat import Severity, Threat, ThreatSource, hash_id

# Protocols that carry their traffic encrypted, and protocols that carry it in the clear
ENCRYPTED_PROTOCOLS: frozenset[str] = frozenset(
    {"https", "tls", "ssl", "mtls", "wss", "ssh", "sftp", "grpcs", "amqps", "mqtts", "smtps"}
)
PLAINTEXT_PROTOCOLS: frozenset[str] = frozenset(
    {"http", "ws", "ftp", "telnet", "mqtt", "amqp", "smtp"}
)

_HIGH_RISK_PAIRS = {
    ("internet", "private"),
    ("internet", "data"),
    ("dmz", "data"),
    ("internet", "management"),
}
_LOWER = {Severity.HIGH: Severity.MEDIUM, Severity.MEDIUM: Severity.LOW}
_LOW_CONFIDENCE = 0.5
# The severity of MCP_REMOTE_NO_AUTH, the rule that reports a remote server with no credential
_UNKNOWN_AUTH_SEVERITY = Severity.LOW


@dataclass
class _Flow:
    """Everything the edges between one (source, target) pair say about the flow."""

    edges: list[InfraEdge] = field(default_factory=list)
    # True when the flow ends at an MCP server, whose sign-in the input usually cannot show
    ends_at_mcp_server: bool = False

    @property
    def edge_types(self) -> list[str]:
        return sorted({e.edge_type.value for e in self.edges})

    @property
    def declared(self) -> bool:
        return any(e.declared for e in self.edges)

    @property
    def relations(self) -> list[str]:
        return sorted({e.relation for e in self.edges if e.relation})

    def _states(self, key: str) -> list[bool | None]:
        return [_flag(e, key) for e in self.edges]

    def _all(self, key: str) -> bool | None:
        """False if any edge says no, True if every edge says yes, else unknown."""
        states = self._states(key)
        if any(state is False for state in states):
            return False
        if states and all(state is True for state in states):
            return True
        return None

    @property
    def authenticated(self) -> bool | None:
        return self._all("authenticated")

    @property
    def only_authentication_is_open(self) -> bool:
        """Whether the one thing the input does not show is who the other end is.

        True for a flow that ends at an MCP server and neither states its authentication nor
        shows a plaintext transport.
        """
        return (
            self.ends_at_mcp_server and self.authenticated is None and self.encrypted is not False
        )

    @property
    def validated(self) -> bool | None:
        return self._all("validated")

    @property
    def encrypted(self) -> bool | None:
        states = [_encrypted(e) for e in self.edges]
        if any(state is False for state in states):
            return False
        if states and all(state is True for state in states):
            return True
        return None

    @property
    def protocols(self) -> list[str]:
        found: set[str] = set()
        for edge in self.edges:
            listed = _attribute(edge, "protocols")
            for value in (
                listed if isinstance(listed, (list, tuple)) else [_attribute(edge, "protocol")]
            ):
                if isinstance(value, str) and value.strip():
                    found.add(value.strip().lower())
        return sorted(found)

    @property
    def ports(self) -> list[str]:
        found: set[str] = set()
        for edge in self.edges:
            for key in ("port", "ports"):
                value = _attribute(edge, key)
                for item in value if isinstance(value, (list, tuple)) else [value]:
                    if item not in (None, "") and not isinstance(item, bool):
                        found.add(str(item))
        return sorted(found, key=lambda p: (not p.isdigit(), int(p) if p.isdigit() else 0, p))


def _attribute(edge: InfraEdge, key: str) -> Any:
    """A parser-supplied attribute of an edge, from `attributes` or else `metadata`."""
    if key in edge.attributes:
        return edge.attributes[key]
    return edge.metadata.get(key)


def _flag(edge: InfraEdge, key: str) -> bool | None:
    value = _attribute(edge, key)
    return value if isinstance(value, bool) else None


def _encrypted(edge: InfraEdge) -> bool | None:
    """Whether the edge declares the flow encrypted: the flag, else what its protocol implies."""
    declared = _flag(edge, "encrypted")
    if declared is not None:
        return declared
    protocol = _attribute(edge, "protocol")
    if isinstance(protocol, str):
        name = protocol.strip().lower()
        if name in ENCRYPTED_PROTOCOLS:
            return True
        if name in PLAINTEXT_PROTOCOLS:
            return False
    return None


def analyze(graph: InfraGraph) -> list[Threat]:
    """Generate threats for the traffic that crosses a trust boundary."""
    flows: dict[tuple[str, str], _Flow] = {}
    for edge in graph.get_boundary_crossing_edges():
        if edge.edge_type not in FLOW_EDGE_TYPES or _is_modelled_exposure(graph, edge):
            continue
        src = graph.get_node(edge.source)
        tgt = graph.get_node(edge.target)
        if src is None or tgt is None:
            continue
        if not (src.can_exchange_traffic and tgt.can_exchange_traffic):
            continue
        flow = flows.setdefault((edge.source, edge.target), _Flow())
        flow.edges.append(edge)
        flow.ends_at_mcp_server = "mcp_server" in (src.resource_type, tgt.resource_type)
    threats: list[Threat] = []
    for (source_id, target_id), flow in flows.items():
        src = graph.get_node(source_id)
        tgt = graph.get_node(target_id)
        if src is not None and tgt is not None:
            threats.append(_threat(src, tgt, flow))
    return threats


def _is_modelled_exposure(graph: InfraGraph, edge: InfraEdge) -> bool:
    """Whether the edge is the pass's model of untrusted content reaching an agent's server.

    It says what an attacker controls, not that traffic crosses, and the MCP rules report it.
    """
    source = graph.get_node(edge.source)
    return source is not None and source.is_internet and edge.source_kind == AGENT


def _zone(node: InfraNode) -> str:
    return node.trust_zone.value


def _threat(src: InfraNode, tgt: InfraNode, flow: _Flow) -> Threat:
    src_zone, tgt_zone = _zone(src), _zone(tgt)
    stride = _stride(flow)
    techniques = _techniques(src_zone, tgt_zone, stride)
    severity = _boundary_severity("internet" if src.exposure == "internet" else src_zone, tgt_zone)
    if flow.encrypted is True and flow.authenticated is True:
        severity = _LOWER.get(severity, severity)
    if flow.only_authentication_is_open:
        severity = min(severity, _UNKNOWN_AUTH_SEVERITY)
    known = (flow.encrypted is not None or flow.authenticated is not None) and not (
        flow.only_authentication_is_open
    )
    rule = _rule_id(stride, flow)
    # The separator keeps ("a_b", "c") apart from ("a", "b_c")
    seed = f"BOUNDARY|{src.id}|{tgt.id}|{'+'.join(flow.edge_types)}"
    # The internet has no file and no line: the finding sits on the resource it enters
    anchor, other = (tgt, "") if src.is_internet else (src, tgt.id)
    return Threat(
        id=hash_id(seed),
        title=_title(src_zone, tgt_zone, tgt, flow),
        description=_description(src, tgt, flow),
        stride_category=stride,
        severity=severity,
        source=ThreatSource.BOUNDARY,
        resource_type=anchor.resource_type,
        resource_address=anchor.id,
        mitigation=_mitigation(stride, flow),
        confidence=1.0 if known else _LOW_CONFIDENCE,
        metadata={
            "boundary_key": f"BOUNDARY_{src_zone}_{tgt_zone}",
            "boundary_rule": rule,
            # Both ends of the flow, so two flows from one resource are two findings
            "fingerprint_hint": f"{src.id} -> {tgt.id}",
            "source_address": src.id,
            "target_address": tgt.id,
            "source_zone": src_zone,
            "target_zone": tgt_zone,
            "flow": {
                "source": src.id,
                "target": tgt.id,
                "edge_types": flow.edge_types,
                "relations": flow.relations,
                "protocols": flow.protocols,
                "ports": flow.ports,
                "authenticated": flow.authenticated,
                "encrypted": flow.encrypted,
            },
        },
        mitre_techniques=techniques,
        mitre_tactics=tactics_for_techniques(techniques),
        target_address=other,
    )


def _rule_id(stride: str, flow: _Flow) -> str:
    if stride == StrideCategory.SPOOFING.value:
        return "BOUNDARY_UNAUTHENTICATED_FLOW"
    if stride == StrideCategory.INFORMATION_DISCLOSURE.value:
        return "BOUNDARY_UNENCRYPTED_FLOW"
    return "BOUNDARY_UNVALIDATED_FLOW" if flow.validated is False else "BOUNDARY_GENERIC_FLOW"


def _title(src_zone: str, tgt_zone: str, tgt: InfraNode, flow: _Flow) -> str:
    """``dmz > private: to aws_instance.app[0] (tcp/8080)``: the part that tells crossings apart."""
    text = f"{src_zone} > {tgt_zone}: to {tgt.id}"
    words = _flow_words(flow)
    if words:
        text += f" ({words})"
    if flow.encrypted is False:
        text += ", unencrypted"
    if flow.authenticated is False:
        text += ", unauthenticated"
    return text


def _flow_words(flow: _Flow) -> str:
    """``tcp/8080``, ``https/443``, ``port 22`` or ``all protocols``: how the traffic travels."""
    protocols, ports = flow.protocols, ",".join(flow.ports)
    if protocols == ["all"]:
        return "all protocols"
    if protocols and ports:
        return f"{'/'.join(protocols)}/{ports}"
    if ports:
        return f"port {ports}"
    return "/".join(protocols)


def _stride(flow: _Flow) -> str:
    if flow.authenticated is False:
        return StrideCategory.SPOOFING.value
    if flow.encrypted is False:
        return StrideCategory.INFORMATION_DISCLOSURE.value
    return StrideCategory.TAMPERING.value


def _techniques(src_zone: str, tgt_zone: str, stride: str) -> list[str]:
    found: list[str] = []
    if src_zone == "internet" and tgt_zone == "dmz":
        found.append("T1190")
    if tgt_zone == "data":
        found.append("T1530")
    elif tgt_zone == "management":
        found.append("T1078")
    found.append(
        {
            StrideCategory.SPOOFING.value: "T1557",
            StrideCategory.INFORMATION_DISCLOSURE.value: "T1040",
        }.get(stride, "T1565.002")
    )
    return list(dict.fromkeys(found))


def _description(src: InfraNode, tgt: InfraNode, flow: _Flow) -> str:
    src_part = f"{src.id} ({_zone(src)} zone)"
    tgt_part = f"{tgt.id} ({_zone(tgt)} zone)"
    kinds = " and a ".join(kind.replace("_", " ") for kind in flow.edge_types)
    where = _where(flow)
    if flow.declared:
        lead = f"The input declares a {kinds} from {src_part} to {tgt_part}{where}"
        lead += ", crossing a trust boundary" if where else ", which crosses a trust boundary"
    elif where:
        lead = f"Traffic from {src_part} to {tgt_part}{where} crosses a trust boundary"
    else:
        lead = f"{src_part} can reach {tgt_part}, crossing a trust boundary"
    return f"{lead}. {_knowledge(flow)}"


def _where(flow: _Flow) -> str:
    protocols, ports = flow.protocols, flow.ports
    if protocols == ["all"]:
        return " over all protocols and ports"
    if protocols and ports:
        return f" over {'/'.join(protocols)}/{','.join(ports)}"
    if protocols:
        return f" over {'/'.join(protocols)}"
    if ports:
        return f" on port {','.join(ports)}"
    return ""


def _knowledge(flow: _Flow) -> str:
    authenticated, encrypted = flow.authenticated, flow.encrypted
    if authenticated is True and encrypted is True:
        return "The flow is declared authenticated and encrypted."
    parts: list[str] = []
    if authenticated is False:
        parts.append("is not authenticated")
    if encrypted is False:
        parts.append("is not encrypted")
    if parts:
        return f"The flow {' and '.join(parts)}."
    if authenticated is True:
        return "The flow is declared authenticated; nothing says whether it is encrypted."
    if encrypted is True:
        return "The flow is declared encrypted; nothing says whether it is authenticated."
    return "Nothing in the input says whether the flow is authenticated or encrypted."


def _mitigation(stride: str, flow: _Flow) -> str:
    if "returns_content" in flow.relations:
        return _returned_content_mitigation(stride)
    if stride == StrideCategory.SPOOFING.value:
        return (
            "Authenticate the caller at the receiving end of this flow (mutual TLS, signed "
            "requests or a token) so a party in the other zone cannot impersonate the source."
        )
    if stride == StrideCategory.INFORMATION_DISCLOSURE.value:
        return "Encrypt this flow in transit (TLS or mutual TLS) so it cannot be read on the path."
    return (
        "Ensure all data crossing trust boundaries is encrypted in transit "
        "(TLS/mTLS), authenticated, and validated at the receiving end."
    )


def _returned_content_mitigation(stride: str) -> str:
    """The advice for what a server sends back to an agent, which is the agent's input.

    The agent starts the call, so "authenticate the caller at the receiving end" would point at
    the wrong side: what needs a check is the server the agent trusts, and what it returns.
    """
    if stride == StrideCategory.INFORMATION_DISCLOSURE.value:
        return (
            "Connect to the server over https or wss, so the requests and the content it returns "
            "cannot be read or changed on the path."
        )
    return (
        "Connect only to servers you trust and confirm the server requires authentication (a "
        "server that follows the MCP authorization spec asks the client to sign in). Treat what "
        "it returns as untrusted input to the agent, and do not give the agent a tool that "
        "can send data out or act on it without confirmation."
    )


def _boundary_severity(src_zone: str, tgt_zone: str) -> Severity:
    """Higher severity for more sensitive boundary crossings."""
    pair = (src_zone, tgt_zone)
    reverse = (tgt_zone, src_zone)
    if pair in _HIGH_RISK_PAIRS or reverse in _HIGH_RISK_PAIRS:
        return Severity.HIGH
    return Severity.MEDIUM
