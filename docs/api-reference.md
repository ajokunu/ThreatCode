# API Reference

## `scan()` -- Primary Public API

The `scan()` function is the main entry point for programmatic use. It accepts any supported IaC file and returns a structured threat report as a dictionary.

```python
from threatcode import scan
```

### Signature

```python
def scan(
    input_path: str | Path,
    *,
    no_llm: bool = True,
    output_format: str = "json",
    min_severity: str = "info",
    config_path: str | Path | None = None,
    extra_rule_paths: list[str | Path] | None = None,
) -> dict[str, Any]:
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `input_path` | `str \| Path` | *required* | Path to a Terraform plan JSON, `.tf` file, or CloudFormation template |
| `no_llm` | `bool` | `True` | If `True`, skip LLM analysis and use rules only |
| `output_format` | `str` | `"json"` | Output format: `json`, `sarif`, `markdown`, `bitbucket`, `matrix` |
| `min_severity` | `str` | `"info"` | Minimum severity to include: `critical`, `high`, `medium`, `low`, `info` |
| `config_path` | `str \| Path \| None` | `None` | Path to a `.threatcode.yml` config file |
| `extra_rule_paths` | `list[str \| Path] \| None` | `None` | Additional YAML rule files to load alongside built-in rules |

### Return Type

Returns a `dict[str, Any]` with this structure:

```python
{
    "version": "0.1.1",               # ThreatCode version
    "timestamp": "2026-02-28T...",     # ISO 8601 UTC timestamp
    "input_file": "tfplan.json",       # Input file path
    "scanned_resources": 7,            # Number of resources in graph
    "total_threats": 12,               # Total threat count
    "summary": {                       # Counts by severity
        "critical": 3,
        "high": 4,
        "medium": 5
    },
    "threats": [                       # List of threat dicts
        {
            "id": "8ec379e733ff",
            "title": "S3 bucket without server-side encryption",
            "description": "...",
            "stride_category": "information_disclosure",
            "severity": "high",
            "source": "rule",
            "resource_type": "aws_s3_bucket",
            "resource_address": "aws_s3_bucket.data",
            "mitigation": "...",
            "rule_id": "S3_NO_ENCRYPTION",
            "confidence": 1.0,
            "metadata": {},
            "mitre_techniques": ["T1530"],
            "mitre_tactics": ["TA0009"]
        }
    ]
}
```

### Threat Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | Deterministic SHA-256 hash (12 chars), stable for the same rule + resource |
| `title` | `str` | Human-readable threat title |
| `description` | `str` | Detailed threat scenario explanation |
| `stride_category` | `str` | STRIDE category: `spoofing`, `tampering`, `repudiation`, `information_disclosure`, `denial_of_service`, `elevation_of_privilege` |
| `severity` | `str` | `critical`, `high`, `medium`, `low`, or `info` |
| `source` | `str` | Origin of the finding: `rule`, `boundary`, or `llm` |
| `resource_type` | `str` | Cloud resource type (e.g., `aws_s3_bucket`) |
| `resource_address` | `str` | Full resource address from the IaC input |
| `mitigation` | `str` | Actionable remediation guidance |
| `rule_id` | `str` | The YAML rule ID (empty for boundary/LLM findings) |
| `confidence` | `float` | Confidence score: `1.0` for rules, `0.0`-`1.0` for LLM |
| `metadata` | `dict` | Additional rule metadata (includes MITRE block for rule findings) |
| `mitre_techniques` | `list[str]` | MITRE ATT&CK technique IDs (e.g., `["T1530"]`) |
| `mitre_tactics` | `list[str]` | MITRE ATT&CK tactic IDs (e.g., `["TA0009"]`) |

---

## Internal APIs

For deeper integration, ThreatCode exposes its component APIs.

### Parser Layer -- `detect_and_parse()`

```python
from threatcode.parsers import detect_and_parse

parsed = detect_and_parse("tfplan.json")
# parsed.resources -> list of ParsedResource
# parsed.source_path -> str
# parsed.format_type -> str
```

Auto-detects the input format based on file extension and content. Supports:

- **Terraform plan JSON** (`.json` with `planned_values` or `format_version`)
- **Terraform HCL** (`.tf` files)
- **CloudFormation** (`.json`, `.yml`, `.yaml` with `AWSTemplateFormatVersion` or `Resources`)

### IR Layer -- `InfraGraph`

```python
from threatcode.ir.graph import InfraGraph

graph = InfraGraph.from_parsed(parsed)
```

The infrastructure graph is a NetworkX-backed directed graph. Key methods:

| Method | Returns | Description |
|--------|---------|-------------|
| `graph.nodes` | `dict[str, InfraNode]` | All nodes keyed by resource address |
| `graph.edges` | `list[InfraEdge]` | All edges in the graph |
| `graph.node_count` | `int` | Total node count |
| `graph.get_node(id)` | `InfraNode \| None` | Look up a node by ID |
| `graph.get_neighbors(id)` | `list[InfraNode]` | Get adjacent nodes |
| `graph.get_boundary_crossing_edges()` | `list[InfraEdge]` | Edges that cross trust zone boundaries |
| `graph.nodes_by_zone()` | `dict[TrustZone, list[InfraNode]]` | Group nodes by trust zone |
| `graph.to_dict()` | `dict` | Serialize the graph to a dictionary |

#### `InfraNode` Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | Resource address (e.g., `aws_s3_bucket.data`) |
| `resource_type` | `str` | Cloud resource type |
| `name` | `str` | Resource name |
| `category` | `NodeCategory` | `compute`, `storage`, `network`, `database`, `iam`, `serverless`, `cdn`, `dns`, `monitoring`, `messaging`, `container`, `unknown` |
| `trust_zone` | `TrustZone` | `internet`, `dmz`, `private`, `data`, `management` |
| `properties` | `dict` | Raw resource properties from IaC |
| `stride_element` | `str` (property) | STRIDE element type: `process`, `data_store`, `data_flow`, or `external_entity` |

#### `InfraEdge` Fields

| Field | Type | Description |
|-------|------|-------------|
| `source` | `str` | Source node ID |
| `target` | `str` | Target node ID |
| `edge_type` | `EdgeType` | `dependency`, `containment`, `network_flow`, `iam_binding`, `data_flow` |
| `crosses_trust_boundary` | `bool` (property) | Whether this edge crosses a trust zone boundary |

### Engine Layer -- `HybridEngine`

```python
from threatcode.engine.hybrid import HybridEngine

engine = HybridEngine(config=config, extra_rule_paths=extra_paths, llm_client=llm_client)
report = engine.analyze(graph, input_file="tfplan.json")
```

The engine runs three analysis phases in sequence:

1. **Rule-based** -- Evaluates all YAML rules against all graph nodes
2. **Trust boundary** -- Generates threats for cross-zone edge crossings
3. **LLM-augmented** -- Sends a redacted graph to an LLM for architectural threat analysis (only if an `llm_client` is provided)

Returns a `ThreatReport` object with a `.to_dict()` method.

### Formatter Layer

```python
from threatcode.formatters.json_out import format_json
from threatcode.formatters.sarif import format_sarif
from threatcode.formatters.markdown import format_markdown
from threatcode.formatters.bitbucket import format_bitbucket
from threatcode.formatters.attack_navigator import format_attack_navigator

output = format_sarif(report)  # returns str (JSON)
```

All formatters accept a `ThreatReport` and return a formatted string.
