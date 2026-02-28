# ThreatCode

**STRIDE threat model generator from Infrastructure-as-Code.**

ThreatCode parses Terraform plans, HCL files, and CloudFormation templates into a cloud-agnostic infrastructure graph, then runs STRIDE threat analysis against it. It bridges a critical gap in the DevSecOps pipeline: tools like Checkov, tfsec, and Trivy catch *misconfigurations* -- ThreatCode performs actual *threat modeling*, identifying how an attacker could exploit your infrastructure's architecture, trust relationships, and data flows.

## Quick Install

```bash
pip install threatcode
```

## Quick Start

```python
from threatcode import scan

report = scan("tfplan.json")

for threat in report["threats"]:
    print(f"[{threat['severity'].upper()}] {threat['title']}")
    print(f"  Resource: {threat['resource_address']}")
    print(f"  STRIDE:   {threat['stride_category']}")
    print(f"  Fix:      {threat['mitigation']}")
```

## Feature Highlights

- **19 built-in rules** across 6 AWS services (S3, IAM, EC2, VPC, RDS, Lambda)
- **MITRE ATT&CK mapping** -- every rule and LLM finding maps to ATT&CK Cloud Matrix technique IDs and tactic IDs
- **Multiple output formats** -- SARIF 2.1.0 (GitHub Code Scanning), JSON, Markdown, Bitbucket Code Insights, and ATT&CK Navigator layers
- **LLM augmentation** -- optional hybrid analysis with Claude, OpenAI-compatible APIs, or local models (Ollama, vLLM) to catch architectural threats rules cannot
- **Trust boundary detection** -- automatically identifies cross-zone data flows (internet, DMZ, private, data, management) and flags missing controls
- **Enterprise-grade redaction** -- strips AWS account IDs, ARNs, IP addresses, and emails before any data reaches an external LLM

!!! tip "New to ThreatCode?"
    Head to the [Getting Started](getting-started.md) guide for a full walkthrough of installation, first scan, and reading output.
