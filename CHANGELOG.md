# Changelog

## [0.4.3] - 2026-03-02

### Security
- **Action command injection**: Composite action (`action.yml`) now uses environment variables instead of direct `${{ inputs.* }}` interpolation in shell — prevents shell injection via crafted input values
- **Action SHA pinning**: Pinned `setup-python` and `codeql-action/upload-sarif` to SHA hashes in composite action
- **SSRF 0.0.0.0 blocking**: `_validate_base_url()` now checks `is_unspecified` — blocks the unspecified address (`0.0.0.0`)
- **SSRF port fallback**: DNS resolution uses port 80 for `http://` URLs (was incorrectly defaulting to 443)
- **Response size limit**: OpenAI-compatible client caps response body at 10 MB to prevent memory exhaustion
- **Bidi character stripping**: `_sanitize_for_prompt()` removes Unicode bidirectional override characters (U+200E–U+202E, U+2066–U+2069)
- **Redactor prefix collision**: `unredact_string()` replaces longest placeholders first to prevent partial-match corruption
- **Redactor sensitive value recursion**: Nested dicts/lists under sensitive keys now fully redacted (previously only top-level dict values were replaced)

### Fixed
- **LLM failure resilience**: `LLMError` from LLM analysis no longer propagates — rule-based results are preserved with a logged warning
- **Edge dedup ordering**: Edge dedup key is now committed only after confirming the edge passes the limit check
- **Confidence type guard**: `Threat.confidence` validates type before clamping — non-numeric values default to 1.0
- **Severity ValueError in public API**: `scan()`/`analyze()` now convert invalid `min_severity` to `ThreatCodeError` instead of leaking `ValueError`
- **subnet_id merge**: `subnet_id` is now merged into `subnet_ids` list instead of clobbering it
- **Type index cleanup**: Duplicate resource addresses properly remove old entries from `_type_index`
- **LLM field unredaction**: `title`, `description`, and `mitigation` from LLM output are now unredacted alongside `resource_address`
- **AnalysisResult.to_dict()**: Now includes `graph` topology data, not just the threat report
- **CloudFormation detection**: Requires `Resources` plus a second CFN-specific key to avoid false positives on arbitrary YAML with a `Resources` key
- **Bitbucket field limits**: Annotation `summary` capped at 450 chars, `details` at 2000 chars per Bitbucket API limits
- **Multiple operator warning**: Rule matcher warns when a condition contains multiple operator keys (`all_of`, `any_of`, etc.)
- **Rule ID dedup**: Duplicate rule IDs are now checked incrementally during loading (builtins checked before extras)
- **CLI error handling**: `InfraGraph.from_parsed()`, `engine.analyze()`, and `diff` command wrapped in error handlers
- **LLM response truncation log**: Warning now correctly says "chars" instead of "bytes"

## [0.4.2] - 2026-03-02

### Fixed
- **Config explicit path**: `--config` pointing to nonexistent file now raises `ConfigError` instead of silently falling through to auto-discovery
- **CLI unknown provider**: Unknown LLM provider now warns and falls back to rules-only instead of silently returning None
- **Public API DRY**: Extracted shared `_run_pipeline()` helper — `scan()` and `analyze()` no longer duplicate 90% of their code
- **Parser truthiness bug**: `parsed_data or content` replaced with `parsed_data if parsed_data is not None` — empty dicts no longer skipped
- **Swallowed exceptions**: Parser registry now logs `DEBUG` messages when parsers fail instead of silently swallowing
- **SARIF ruleIndex**: Each result now references the correct `ruleIndex` instead of hardcoded `0` — fixes GitHub Code Scanning misattribution
- **Edge deduplication**: Infrastructure graph now deduplicates edges by (source, target, type) tuple
- **Subnet/SG false edges**: Subnet and security group inference now matches by reference ID, not blindly connecting ALL nodes of matching type
- **Redactor iteration safety**: `_redact_string` collects all regex matches before mutating, fixing potential mid-iteration corruption
- **Redactor overflow mapping**: Overflow placeholder now stored in `_reverse` dict for proper unredaction
- **Redactor performance**: `sensitive_keys` set built once at init instead of rebuilt on every `_redact_field` call
- **Severity total ordering**: `__eq__` now uses rank-based comparison consistent with `__lt__`, fixing sort stability
- **Confidence bounds**: `Threat.confidence` clamped to [0.0, 1.0] on construction
- **LLM Severity ValueError**: `hybrid.py` catches `ValueError` from invalid severity strings instead of crashing
- **Matcher type guards**: `all_of`/`any_of`/`none_of`/`not` operators validate input types before evaluation
- **Symlink detection**: Fixed tautological `resolved != path.resolve()` comparison in rule loader
- **Rule field types**: Rule loader now coerces YAML fields to `str` and validates `condition`/`metadata` types
- **Bitbucket severity fallback**: `_to_bb_severity` uses `.get()` with `"MEDIUM"` fallback instead of bare dict indexing
- **SARIF severity fallback**: `_severity_to_sarif_level` uses `.get()` with `"warning"` fallback
- **SARIF PascalCase**: `_to_pascal_case` now handles hyphens and underscores
- **Diff error handling**: `compute_diff` validates file existence and JSON validity with clear error messages
- **DRY `_escape_md`**: Extracted to `formatters/_utils.py` shared by `markdown.py` and `diff.py`
- **Exception chains**: `ValueError` from `ipaddress` now properly chained with `from e`
- **OpenAI client**: Catches `IndexError` and `UnicodeDecodeError` for empty/malformed API responses
- **Graph prompt size**: `build_analysis_prompt` caps graph JSON at 200KB to prevent prompt overflow
- **Duplicate node warning**: Graph logs warning when a resource address is seen twice
- **Unused imports**: Removed dead `hashlib` import from `loader.py`, dead `_ALLOWED_THREAT_KEYS` from `parser.py`
- **Test global state**: `test_nodes.py` registration tests use `try/finally` for cleanup guarantees
- **`__main__.py`**: Added `if __name__ == "__main__"` guard

### Changed
- **CI**: Added `permissions: contents: read`, `concurrency` group, `timeout-minutes`, `cache: pip`, `fail-fast: false`, `ruff format --check`
- **Build**: Removed unused `setuptools-scm` from build requirements
- **LLM parser**: Logs `DEBUG` message when defaulting invalid `stride_category` or `severity` from LLM output

## [0.4.1] - 2026-03-02

### Fixed
- CI `pip-audit --strict` failing because local editable package not found on PyPI — added `--skip-editable`

## [0.4.0] - 2026-03-02

### Security
- **SSRF protection rewrite**: `_validate_base_url()` now resolves hostnames via DNS and validates ALL resolved IPs using the `ipaddress` module — blocks loopback, private, link-local, reserved, and IPv4-mapped IPv6 addresses (A10-01..04)
- **Safe redirect handler**: OpenAI-compatible client uses `_SafeRedirectHandler` that re-validates redirect targets against SSRF checks
- **HTTP key warning**: Warns when API key is sent over plain HTTP (A07-01)
- **Config auto-discovery hardening**: Auto-discovered configs restricted to safe fields only (`min_severity`, `output_format`, `no_llm`, `dry_run`, `redaction`); security-sensitive fields stripped with warning (A01-01)
- **API key in config warning**: Warns to stderr when `api_key` found in config file — recommends environment variable (A02-01)
- **CI config skip**: Home directory config search skipped when `CI` env var is set (A07-02)
- **Prompt injection hardening**: Rule IDs sanitized before prompt inclusion; graph data wrapped in XML-style delimiters; system prompt reduced architecture exposure (LLM01-01, LLM01-02, LLM07-01)
- **Redaction improvements**: Added `name`, `module`, `provider`, `source_location` to sensitive keys; capped mapping at 10,000 entries; improved AWS account ID regex to require context (LLM02-01, LLM02-02, LLM10-07)
- **MITRE validation**: LLM technique/tactic IDs validated against known databases, not just prefix format; rule loader also validates against TECHNIQUE_DB (LLM05-03, LLM09-01)
- **LLM resource validation**: Resource addresses from LLM output validated against graph — unknown addresses capped at 0.5 confidence (LLM09-02)
- **Structured security logging**: Analysis pipeline logs start/completion with resource count, rule count, LLM status (A09-01)
- **Rule loader**: Blocks symlinks in extra rule paths; rejects rule files over 1 MB; logs SHA-256 checksums of built-in rules (A01-03, A04-03, A08-01, LLM04-03)
- **Graph limits**: MAX_NODES=10,000 (raises error), MAX_EDGES=50,000 (warns and skips) (LLM10-05, LLM10-06)
- **CLI hardening**: Validates output path is not a directory; creates parent dirs; sanitizes filesystem paths in errors (A01-04, A05-01)
- **Formatter sanitization**: Markdown/diff formatters escape `< > [ ] ( )` in LLM-sourced fields; SARIF formatter strips non-URI characters from resource addresses (LLM05-01, LLM05-02)
- **DryRun logging**: Removed prompt content from DEBUG logs entirely — only lengths logged (A02-02, A09-02)
- **Temperature parameter**: AnthropicLLMClient and OpenAICompatibleLLMClient accept and pass `temperature` parameter (LLM10-03)
- **max_tokens validation**: Validates and clamps max_tokens to [1, 8192] range with warning (LLM10-04)
- **CI hardening**: GitHub Actions pinned to SHA hashes; `pip-audit --strict` (A06-02, A08-03)
- **Dependency pinning**: Added upper bounds to all runtime dependencies (A06-01)
- **Removed dead field**: `RedactionConfig.enabled` removed (LLM02-02)

### Changed
- `_validate_base_url()` rewritten to use `ipaddress` module + `socket.getaddrinfo()`
- Auto-discovered configs now restrict which fields are loaded
- `_load_from_file()` accepts `trusted` parameter
- LLM parser validates MITRE IDs against databases instead of prefix-only checks

## [0.3.1] - 2026-03-01

### Added
- **SVG threat model diagram renderer**: `--format diagram` produces a purpose-built data flow diagram with trust zone swim lanes, DFD-standard node shapes (process, data store, data flow, external entity), bezier curve edges, threat severity badges, and a visual legend
- **`analyze()` public API**: New function returning `AnalysisResult` with both the infrastructure graph and threat report — enables diagram rendering and topology analysis from the library API
- **`AnalysisResult` model**: Dataclass wrapping `InfraGraph` + `ThreatReport` with `.to_dict()` and `.to_svg()` convenience methods
- **12 diagram tests**: XML validity, viewBox, zone rendering, node shapes by STRIDE element type, edge rendering, boundary crossing highlighting, threat badges, header metadata, legend, empty graph, multi-service fixture

### Changed
- CLI `--format` choice now includes `diagram` alongside json, sarif, markdown, bitbucket, matrix
- `_format_output()` in CLI accepts optional `graph` parameter for diagram rendering

### Fixed
- **CI typecheck failures**: Added `types-networkx` and `types-PyYAML` stubs to dev dependencies
- Fixed `no-any-return` mypy errors in `edges.py`, `matcher.py`, `client.py`
- Fixed Anthropic client type narrowing for `message.content[0]` union type
- Removed unused `type: ignore` comments in parser registry
- Fixed `DiGraph` missing type parameter in `graph.py`

## [0.3.0] - 2026-03-01

### Added
- **Pluggable parser registry**: `register_parser()` API lets users add custom parsers for any structured format (Kubernetes, Docker Compose, OpenAPI, etc.) without modifying core code
- **Node category registration**: `register_category()` extends resource type → NodeCategory mapping for non-cloud domains
- **Trust zone registration**: `register_trust_zone()` extends resource type → TrustZone mapping for non-cloud domains
- **Containment hint registry**: `register_containment_hint()` adds custom property → resource type mappings for edge inference
- **Validation constants module**: `threatcode.constants` provides `VALID_STRIDE_CATEGORIES` and `VALID_SEVERITIES` as single source of truth
- **GitHub Actions CI workflow**: Matrix testing across Python 3.10–3.13 with lint, typecheck, test, and dependency audit
- **Makefile**: Standard targets for `install`, `dev`, `test`, `lint`, `typecheck`, `format`, `audit`, `docs`, `clean`, `ci`
- **13 new test files** covering CLI, config, LLM client (SSRF tests), all formatters, parser registry, IR nodes, models, and exceptions
- **HCL test fixture**: `tests/fixtures/terraform/simple.tf` for Terraform HCL parser tests

### Changed
- **IR edge inference optimized**: Type-indexed lookups replace O(n²) nested loops in containment and IAM inference — now O(n) per resource
- **Pre-sorted prefix matching**: `categorize_resource()` and `infer_trust_zone()` use pre-sorted prefix lists built at module load instead of sorting on every call
- **IAM role matching improved**: Address-based match (`aws_iam_role.{name}`) tried first, falling back to name-based match — reduces false positives
- **Containment inference generified**: Registry-driven hints support `vpc_id→aws_vpc`, `vnet_id→azurerm_virtual_network`, `network_id→google_compute_network` out of the box, extensible via `register_containment_hint()`
- **Parser detection refactored**: Hardcoded if-elif chain replaced with priority-sorted registry — fully backward compatible
- **Validation constants consolidated**: STRIDE categories and severity levels defined once in `threatcode.constants`, imported by `models/threat.py`, `engine/llm/parser.py`, and `engine/rules/loader.py`

### Removed
- **Dead code**: `ir/boundaries.py` (78 lines, never imported) — boundary analysis was already implemented in `engine/hybrid.py` and `ir/graph.py`

### Fixed
- IAM edge inference could miss role matches when Terraform address format differed from the `role` property value

## [0.2.2] - 2026-02-28

### Changed
- Reposition README around "Threat Model as Code" market positioning
- Update tagline, examples, and value prop to lead with MITRE ATT&CK integration
- Add ATT&CK Navigator and MITRE fields to README examples
- Update pyproject.toml description to match new positioning

## [0.2.1] - 2026-02-28

### Security
- **SSRF protection**: OpenAI-compatible LLM client validates `base_url` — blocks internal/loopback/private IP ranges and cloud metadata endpoints (169.254.169.254)
- **Recursion depth limits**: Rule matcher (max 10), Terraform module walker (max 50), and redactor (max 50) now cap recursion depth to prevent stack overflow from malicious inputs
- **DryRunLLMClient no longer leaks prompt content** to stderr — only shows metadata (lengths); full content available at DEBUG log level only
- **stride_category validation**: Threat dataclass validates STRIDE category values on construction, defaults unknown values to `information_disclosure`
- **Expanded redaction**: Added 11 sensitive field names (secret, password, token, api_key, access_key, secret_key, connection_string, credentials, private_key, certificate)
- **Config auto-discovery warning**: Logs warning when auto-discovered `.threatcode.yml` sets `llm.base_url`, recommending `--config` flag in CI
- **Path traversal protection**: `extra_rule_paths` resolved to absolute paths and validated before loading
- **Rule ID uniqueness**: Enforced across all loaded rules — duplicates now raise `RuleLoadError`
- **MITRE ID validation**: Rule loader validates technique IDs match `T####(.###)?` and tactic IDs match `TA####`
- **Anthropic client empty response guard**: Checks for empty `message.content` before indexing

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
