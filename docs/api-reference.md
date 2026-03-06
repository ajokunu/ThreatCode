# API Reference

ThreatCode's public Python API is exposed from the top-level `threatcode` module.

```python
import threatcode

# All public functions:
# scan()               — IaC threat modeling
# analyze()            — Threat model + infrastructure graph
# scan_secrets()       — Secret detection
# scan_vulnerabilities() — Lockfile vulnerability scanning
# scan_all()           — Unified multi-scanner
# scan_image()         — Container image scanning
```

---

## `scan()`

Scan an IaC file and return a threat report dict.

```python
from threatcode import scan

report = scan(
    input_path,
    *,
    no_llm=True,
    output_format="json",
    min_severity="info",
    config_path=None,
    extra_rule_paths=None,
)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `input_path` | `str \| Path` | required | Path to Terraform plan JSON, `.tf` file, CloudFormation template, Dockerfile, Kubernetes YAML, or lockfile |
| `no_llm` | `bool` | `True` | Skip LLM analysis, use rules only |
| `output_format` | `str` | `"json"` | Output format: `json`, `sarif`, `markdown`, `bitbucket` |
| `min_severity` | `str` | `"info"` | Minimum severity: `critical`, `high`, `medium`, `low`, `info` |
| `config_path` | `str \| Path \| None` | `None` | Path to `.threatcode.yml` config file |
| `extra_rule_paths` | `list[str \| Path] \| None` | `None` | Additional YAML rule files to load |

**Returns:** `dict[str, Any]` — `ThreatReport.to_dict()`:

```python
{
    "version": "0.7.0",
    "timestamp": "2026-03-05T12:00:00+00:00",
    "input_file": "tfplan.json",
    "scanned_resources": 14,
    "total_threats": 3,
    "summary": {
        "critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0
    },
    "threats": [
        {
            "id": "8ec379e733ff",
            "title": "S3 bucket without server-side encryption",
            "description": "...",
            "stride_category": "information_disclosure",
            "severity": "high",
            "source": "rule",             # "rule", "boundary", "llm"
            "resource_type": "aws_s3_bucket",
            "resource_address": "aws_s3_bucket.data",
            "mitigation": "Enable SSE-S3 or SSE-KMS encryption.",
            "rule_id": "S3_NO_ENCRYPTION",
            "confidence": 1.0,
            "metadata": {},
            "mitre_techniques": ["T1530"],
            "mitre_tactics": ["TA0009"]
        }
    ]
}
```

**Raises:** `ThreatCodeError` | `FileNotFoundError`

---

## `analyze()`

Like `scan()`, but returns the infrastructure graph alongside the threat report — useful for diagram rendering and topology analysis.

```python
from threatcode import analyze

result = analyze(
    input_path,
    *,
    no_llm=True,
    min_severity="info",
    config_path=None,
    extra_rule_paths=None,
)
```

**Returns:** `AnalysisResult`

```python
result.graph   # InfraGraph — NetworkX-backed infrastructure graph
result.report  # ThreatReport

# Working with the graph
for node_id, node in result.graph.nodes.items():
    print(f"{node_id}: {node.category.value} / {node.trust_zone.value}")
    print(f"  Properties: {node.properties}")

for edge in result.graph.get_boundary_crossing_edges():
    print(f"Trust boundary crossing: {edge.source} → {edge.target}")

# Render to SVG
svg = result.to_svg()
```

---

## `scan_secrets()`

Scan files or directories for hardcoded secrets.

```python
from threatcode import scan_secrets

result = scan_secrets(
    path,
    *,
    config_path=None,
)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `path` | `str \| Path` | required | File or directory to scan (recursive) |
| `config_path` | `str \| Path \| None` | `None` | Optional secret scan config |

**Returns:**

```python
{
    "total_secrets": 2,
    "findings": [
        {
            "id": "SECRET-a1b2c3d4",
            "finding_type": "secret",
            "title": "AWS Access Key ID",
            "severity": "critical",
            "file_path": "src/config.py",
            "line_number": 14,
            "secret_type": "aws",
            "match": "AKIA****WXYZ",     # redacted — first/last 4 chars
            "rule_id": "SECRET_AWS_ACCESS_KEY",
            "metadata": {}
        }
    ]
}
```

**Raises:** `ThreatCodeError` | `FileNotFoundError`

---

## `scan_vulnerabilities()`

Scan a lockfile for known vulnerabilities using the offline OSV database. Requires running `threatcode db update` first.

```python
from threatcode import scan_vulnerabilities

result = scan_vulnerabilities(
    input_path,
    *,
    ignore_unfixed=False,
)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `input_path` | `str \| Path` | required | Path to a supported lockfile |
| `ignore_unfixed` | `bool` | `False` | Skip vulnerabilities without a fixed version |

**Supported lockfiles:** `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `go.sum`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`

**Returns:**

```python
{
    "total_vulnerabilities": 2,
    "dependencies_scanned": 47,
    "findings": [
        {
            "id": "VULN-1234abcd",
            "finding_type": "vulnerability",
            "title": "Remote code execution via crafted request",
            "severity": "critical",
            "package_name": "requests",
            "package_version": "2.28.0",
            "ecosystem": "pypi",
            "cve_id": "CVE-2023-12345",
            "fixed_version": "2.31.0",
            "advisory_url": "",
            "cvss_score": 9.8,
            "metadata": {"vuln_id": "GHSA-xxxx", "aliases": ["CVE-2023-12345"]}
        }
    ]
}
```

**Raises:** `ThreatCodeError` (if database not found) | `FileNotFoundError`

---

## `scan_all()`

Run multiple scanner types in one call and return unified results.

```python
from threatcode import scan_all

result = scan_all(
    input_path,
    *,
    scanners=("misconfig",),
    no_llm=True,
    min_severity="info",
    config_path=None,
    extra_rule_paths=None,
    ignore_unfixed=False,
)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `input_path` | `str \| Path` | required | File or directory |
| `scanners` | `tuple[str, ...]` | `("misconfig",)` | Scanner types: `"misconfig"`, `"secret"`, `"vuln"`, `"license"` |
| `no_llm` | `bool` | `True` | Skip LLM analysis in misconfig scanner |
| `min_severity` | `str` | `"info"` | Minimum severity for misconfig results |
| `config_path` | `str \| Path \| None` | `None` | Config file path |
| `extra_rule_paths` | `list \| None` | `None` | Additional rule files for misconfig |
| `ignore_unfixed` | `bool` | `False` | Skip unfixed vulns in vuln scanner |

**Returns:**

```python
{
    "scanners": ["misconfig", "secret", "vuln", "license"],
    "misconfig": {
        # Full ThreatReport.to_dict() — or {"error": "..."} on failure
        "total_threats": 5,
        "threats": [...]
    },
    "secret": {
        "total_secrets": 1,
        "findings": [...]
    },
    "vuln": {
        "total_vulnerabilities": 2,
        "dependencies_scanned": 47,
        "findings": [...]
    },
    "license": {
        "total_issues": 1,
        "dependencies_scanned": 47,
        "findings": [...]
    }
}
```

---

## `scan_image()`

Pull a container image from any OCI registry and scan for vulnerabilities, secrets, and misconfigurations.

```python
from threatcode import scan_image

result = scan_image(
    image_ref,
    *,
    platform="linux/amd64",
    ignore_unfixed=False,
    scan_secrets=False,
    scan_misconfig=True,
)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `image_ref` | `str` | required | Image reference (see formats below) |
| `platform` | `str` | `"linux/amd64"` | Target platform for multi-arch images |
| `ignore_unfixed` | `bool` | `False` | Skip vulnerabilities without a fixed version |
| `scan_secrets` | `bool` | `False` | Also scan the image filesystem for secrets |
| `scan_misconfig` | `bool` | `True` | Check image config for misconfigurations |

**Supported image reference formats:**

| Input | Resolved |
|-------|---------|
| `nginx` | `registry-1.docker.io/library/nginx:latest` |
| `nginx:1.25` | `registry-1.docker.io/library/nginx:1.25` |
| `myuser/myapp:v2` | `registry-1.docker.io/myuser/myapp:v2` |
| `ghcr.io/owner/repo:tag` | `ghcr.io/owner/repo:tag` |
| `gcr.io/project/image:tag` | `gcr.io/project/image:tag` |
| `nginx@sha256:abc...` | digest-pinned reference |

**Returns:**

```python
{
    "image": "nginx:latest",
    "os": {
        "family": "debian",
        "name": "Debian GNU/Linux",
        "version": "12"
    },
    "metadata": {
        "architecture": "amd64",
        "os": "linux",
        "created": "2024-01-15T10:00:00Z",
        "user": "nginx",
        "cmd": ["nginx", "-g", "daemon off;"],
        "entrypoint": ["/docker-entrypoint.sh"],
        "env": ["PATH=/usr/local/sbin:/usr/local/bin"],
        "labels": {"maintainer": "NGINX Docker Maintainers"},
        "exposed_ports": ["80/tcp", "443/tcp"],
        "working_dir": "/"
    },
    "summary": {
        "os_packages": 142,
        "os_vulnerabilities": 12,
        "app_dependencies": 0,
        "app_vulnerabilities": 0,
        "secrets": 0,
        "misconfigs": 1,
        "total_vulnerabilities": 12
    },
    "os_vulnerabilities": [...VulnerabilityFinding dicts...],
    "app_vulnerabilities": [...VulnerabilityFinding dicts...],
    "secrets": [...SecretFinding dicts...],
    "misconfigs": [
        {
            "id": "IMG_ROOT_USER",
            "title": "Container runs as root",
            "severity": "high",
            "description": "..."
        }
    ]
}
```

**Raises:** `ThreatCodeError` (registry errors, extraction failures, invalid references)

---

## Internal APIs

For deeper integration you can use the component APIs directly:

```python
from threatcode.parsers import detect_and_parse, register_parser
from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import NodeCategory, TrustZone
from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.secrets.scanner import SecretScanner
from threatcode.engine.vulns.scanner import VulnerabilityScanner
from threatcode.engine.vulns.db import VulnDB
from threatcode.engine.licenses.scanner import LicenseScanner
from threatcode.image.reference import ImageReference
from threatcode.image.registry import RegistryClient
from threatcode.image.layer import LayerExtractor
from threatcode.image.scanner import ImageScanner
from threatcode.formatters.sarif import format_sarif
from threatcode.formatters.cyclonedx import format_cyclonedx
from threatcode.formatters.diagram import format_diagram
```

### Register a custom parser

```python
from threatcode.parsers import register_parser
from threatcode.parsers.base import ParsedOutput, ParsedResource

def my_parser(content, source_path=""):
    # ... parse content ...
    return ParsedOutput(
        resources=[ParsedResource(
            resource_type="my_resource",
            address="my_resource.main",
            name="main",
            provider="custom",
            properties={"key": "value"},
        )],
        source_path=source_path,
        format_type="my_format",
    )

def detect_my_format(content, path):
    return "my_format" in path

register_parser("my_format", my_parser, detect_my_format, priority=50)
```

### Infrastructure graph

```python
from threatcode.parsers import detect_and_parse
from threatcode.ir.graph import InfraGraph

parsed = detect_and_parse("tfplan.json")
graph = InfraGraph.from_parsed(parsed)

# Node categories: compute, storage, network, database, iam, serverless,
#                  cdn, dns, monitoring, messaging, container, unknown
# Trust zones: internet, dmz, private, data, management

for node_id, node in graph.nodes.items():
    print(f"{node.resource_type} [{node.trust_zone.value}] {node.category.value}")

for edge in graph.get_boundary_crossing_edges():
    print(f"Boundary: {edge.source} → {edge.target}")
```
