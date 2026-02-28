# Changelog

## [0.2.0] - 2026-02-28

### Added
- MITRE ATT&CK Cloud Matrix integration — all 19 rules mapped to ATT&CK technique IDs
- `mitre_techniques` and `mitre_tactics` fields on all Threat objects
- ATT&CK Navigator layer export via `--format matrix` (loadable in Navigator web app)
- MITRE technique tags in SARIF output (`mitre/T1530`, etc.)
- MITRE technique IDs in Markdown output
- MITRE reference module (`engine/mitre.py`) with full Cloud Matrix lookup data
- LLM prompts now request MITRE ATT&CK technique IDs in structured output
- Boundary crossing threats include default MITRE techniques (T1040, T1557)
- Multi-service insecure test fixture (22 resources, triggers all 19 rules)
- Multi-service secure test fixture (22 resources, triggers zero rules)
- CloudFormation insecure stack test fixture
- End-to-end scan tests validating all 19 rules fire correctly
- MkDocs Material documentation site (9 pages: getting started, API reference, rule writing, MITRE ATT&CK, CI/CD, architecture, configuration, security)
- `docs` optional dependency group for building documentation

### Changed
- SARIF rule tags now include MITRE technique IDs alongside STRIDE and source tags
- Markdown formatter includes MITRE ATT&CK technique IDs per finding
- LLM system prompt includes prompt injection guard instructions
- LLM response parser enforces 512 KB response length limit and 100-threat cap
- LLM clients enforce prompt size limits (256 KB), API timeouts (120s), and token caps (8192)
- Rule loader validates rule schema (severity, stride_category, condition structure)
- Rule loader enforces limits: 100 rules/file, 500 total rules
- Parser rejects input files larger than 50 MB

### Fixed
- EC2_NO_MONITORING rule condition had broken `any_of` nesting — never fired
- EC2_UNENCRYPTED_EBS rule condition had broken `any_of` nesting — never fired
- RDS_NO_ENCRYPTION rule condition had broken `any_of` nesting — never fired

### Removed
- `jinja2` dependency (listed but never imported)

### Security
- Code audit: no eval(), exec(), pickle, marshal, __import__, or compile() in codebase
- All YAML loading uses yaml.safe_load() exclusively
- No string interpolation of user input into shell commands
- LLM responses parsed as JSON only, never executed
- Regex patterns reviewed for ReDoS — all linear, no nested quantifiers
- Prompt injection guard added to LLM system prompt
- Added `pip-audit` to dev dependencies for vulnerability scanning

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
