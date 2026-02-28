# Changelog

## [0.1.1] - 2026-02-28

### Changed
- Rewrite README to lead with library API — ThreatCode is a Python library first, CLI second
- Position `scan()` as the primary interface, CLI as included convenience

## [0.1.0] - 2026-02-28

### Added
- Initial project scaffold and Phase 1 implementation
- Terraform plan JSON parser
- Cloud-agnostic IR graph (NetworkX-based)
- STRIDE threat classification engine
- Rule-based threat detection with YAML rule files
- Built-in AWS rules: S3, IAM, EC2, VPC, RDS, Lambda
- SARIF 2.1.0 output formatter
- JSON output formatter
- Markdown output formatter
- Trust boundary crossing detection
- LLM-augmented analysis (Claude API, OpenAI-compatible, dry-run)
- ARN/account/tag/IP redaction for LLM calls
- GitHub composite action with SARIF upload
- Bitbucket Code Insights formatter
- Terraform HCL fallback parser
- CloudFormation YAML/JSON parser
- Threat model diff between runs
- Click CLI with `scan` and `diff` commands
- Pydantic configuration model with `.threatcode.yml` support
