# Changelog

## [0.9.0] - 2026-03-08

### Added

#### Expanded Misconfig Rules (131 → 221)
- **AWS** (+30 rules, 7 files): WAF web ACL (5), Secrets Manager (4), GuardDuty (4), AWS Config (4), SSM Parameter Store (4), WAFv2 rule groups (5), EKS node groups (4)
- **Azure** (+25 rules, 6 files): Key Vault (5), App Service (5), Functions (4), SQL Database (4), Cosmos DB (4), Monitor (3)
- **GCP** (+20 rules, 5 files): Cloud SQL (5), Cloud Functions (4), BigQuery (4), Pub/Sub (3), Cloud Run (4)
- **Kubernetes** (+10 rules): Pod Security Admission, default service accounts, security context defaults, seccomp profiles, resource quotas, PodDisruptionBudget, ephemeral storage, egress policies, Ingress TLS
- **Docker** (+5 rules): COPY --chown, ADD from URL, apt cleanup, digest pinning, minimal base images

#### OS Advisory Sources (2 → 5 families)
- **Ubuntu OVAL** — advisories for 18.04 (Bionic), 20.04 (Focal), 22.04 (Jammy), 24.04 (Noble) via OVAL XML
- **Amazon Linux ALAS** — advisories for AL2 and AL2023 via ALAS RSS feeds
- **RHEL CVE API** — advisories for RHEL 8 and 9 via Red Hat Security Data API with exponential backoff

#### New Lockfile Parsers (10 → 13 formats)
- **`mix.lock`** (Elixir/Hex) — regex-based parser for Hex dependencies
- **`pubspec.lock`** (Dart/Pub) — YAML-based parser for Pub dependencies
- **`conan.lock`** (C++/Conan) — JSON-based parser for Conan v2 lockfiles
- Added `Hex` and `Pub` ecosystems to OSV database update

#### Helm Chart Scanning
- **`HelmParser`** — renders Helm charts to Kubernetes YAML via `helm template` CLI or raw template fallback
- **Parser registry** — Helm chart detection via `Chart.yaml` at priority 8
- **Filesystem scanner** — automatic Helm chart discovery and misconfig scanning
- Test fixtures: sample insecure Helm chart with privileged deployment

### Changed
- Version bump from 0.8.0 to 0.9.0 (new features: expanded rules, OS advisories, lockfile parsers, Helm scanning)
- `LOCKFILE_NAMES` extended with `mix.lock`, `pubspec.lock`, `conan.lock`
- `OSAdvisoryDownloader.update_all()` now includes Ubuntu, Amazon Linux, and RHEL
- `db update` OSV ecosystems now include Hex and Pub
- Filesystem scanner reports `helm_charts_found` in result metadata
- Unsupported format error message updated with Helm and new lockfile formats

## [0.8.0] - 2026-03-07

### Added
- **`threatcode fs <path>`** — Filesystem scanner command. Walks a directory tree, discovers lockfiles, IaC files (Terraform, CloudFormation, Dockerfile, Kubernetes), and runs vuln, secret, misconfig, and license scanners against discovered files.
- **`threatcode repo <url>`** — Repository scanner command. Shallow-clones a Git repo (HTTPS/SSH) into a temp directory and runs the filesystem scanner. Supports `--branch` flag.
- **`.threatcodeignore` support** — Suppress findings by CVE ID, rule ID, or secret rule ID. Optional `exp:YYYY-MM-DD` expiration dates. Loaded automatically from the scan directory or via `--ignorefile` flag.
- **`scan_filesystem()` public API** — Programmatic filesystem scanning with ignore support.
- **`scan_repository()` public API** — Programmatic repository scanning.
- **`threatcode.ignore` module** — Parser for `.threatcodeignore` files with expiration date support.
- **`threatcode.scanner.fs` module** — Core filesystem walking and multi-scanner orchestration.
- **`threatcode.scanner.repo` module** — Git clone + filesystem scan delegation.

### Changed
- Version bump from 0.7.2 to 0.8.0 (new feature: filesystem and repository scanning).

## [0.7.2] - 2026-03-06

### Security
- **SSRF in registry auth**: Token realm URLs now validated (HTTPS-only, no private/loopback IPs)
- **Credential helper injection**: Helper names validated against `^[a-zA-Z0-9_-]+$` regex
- **Symlink traversal in layer extraction**: Absolute symlinks rejected; relative symlinks validated to stay inside extraction directory
- **ReDoS in secret scanner**: Max pattern length enforced (500 chars); `re.compile` errors caught; skip path patterns use `fnmatch.translate()` instead of naive `*` replacement
- **RPM DB size limit**: SQLite RPM databases over 500 MB skipped to prevent resource exhaustion
- **LLM client HTTPS-only**: Default scheme restriction changed to HTTPS-only; `allow_insecure` param for local Ollama
- **ENV value redaction**: Sensitive environment variables (PASSWORD, SECRET, TOKEN, etc.) redacted in image scan metadata
- **Test fixture secrets removed**: Hardcoded passwords replaced with placeholder references
- **Gitignore hardened**: Added `.env`, `*.pem`, `*.key`, `*.p12`, `.mypy_cache/`, `.ruff_cache/`

### Fixed
- **Resource leak**: `RegistryClient` now used as context manager in CLI and public API
- **Resource leak**: `tarfile.open()` in layer extraction now uses `with` statement
- **Unbounded downloads**: OSV zip downloads enforce 500 MB size limit with chunked reads
- **Unbounded responses**: OS advisory fetcher limits response reads to 100 MB
- **npm recursion bomb**: `_parse_npm_deps` depth limited to 50 levels
- **Silent exceptions**: Alpine community fetch, dependency parse failures, and `scan_all()` scanner errors now logged
- **Severity filter performance**: `sev_order.index()` replaced with O(1) dict lookup
- **VulnDB null safety**: `cursor.fetchone()` result checked before indexing
- **CVSS parse safety**: `float()` conversion wrapped in try/except for malformed scores
- **Registry digest safety**: `entry.get("digest", "")` with validation replaces bare `entry["digest"]`
- **Containment hints immutability**: Built-in hints stored as tuple; custom hints in separate list
- **Hardcoded User-Agent**: OS advisory downloader now uses `threatcode.__version__`
- **RedactionConfig.strategy**: Now wired into `Redactor` constructor in `HybridEngine`

### Changed
- **Centralized constants**: `SEVERITY_MAP`, `cvss_to_severity()`, and `LOCKFILE_NAMES` consolidated into `threatcode.constants`
- **Dead code removed**: `STRIDE_TO_TACTICS`, `STRIDE_ELEMENT_MAP`, `RedactionError`, `ParsedResource.provider_short`/`.service`, `SecretScanConfig.custom_rules_path`, dead URL constants, `RegistryClient.insecure` field
- **Type safety**: `LLMConfig.provider`, `RedactionConfig.strategy`, `ThreatCodeConfig.min_severity`/`.output_format` use `Literal` types; `ScanReport.threat_report` properly typed; `_OPERATORS` dict typed with `Callable`; `ImageScanner.scan_extracted` and `OSDetector.detect` use typed protocols
- **Identical branches collapsed**: `secret` CLI command's identical if/else removed
- **Narrowed exceptions**: TOML fallback, auth decode, and other broad `except` clauses narrowed
- **MITRE metadata validation**: Rule loader validates `metadata.mitre` is a dict before accessing keys
- **Diff formatter**: Uses `.get()` with defaults; skips entries missing required keys
- **Secret rule severity**: Uses `Literal["critical", "high", "medium", "low"]`
- Version bumped to 0.7.2

## [0.7.1] - 2026-03-05

### Changed
- Complete README overhaul: covers all v0.7.0 features including container image scanning, all 8 CLI commands, full Python API, 131 built-in rules, secret detection patterns, SBOM, license compliance, MITRE ATT&CK integration, LLM setup, and architecture diagram
- Rewrote all docs pages (getting-started, api-reference, architecture, configuration, writing-rules, cicd, mitre-attack, security) to reflect v0.7.0 capabilities
- Updated package description to reflect full multi-scanner scope

## [0.7.0] - 2026-03-05

### Added
- **Container image scanning**: `threatcode image <ref>` pulls OCI images from any registry and scans for OS package vulnerabilities, application dependency vulnerabilities, secrets, and configuration misconfigurations
- **Image reference parser**: Full Docker reference grammar — bare names, user/repo, custom registries, digest pins, multi-component paths (e.g. `gcr.io/project/repo/img:tag`)
- **Registry client**: Docker Registry HTTP API V2 with bearer token auth, credential store (`~/.docker/config.json`), manifest list platform selection, SHA-256 digest verification; supports Docker Hub, GHCR, GCR, ECR, ACR, and any OCI-compliant registry
- **Layer extractor**: Downloads and merges OCI image layers with correct whiteout semantics (`.wh.` regular and `.wh..wh..opq` opaque whiteouts); path traversal protection; 2 GB/layer and 10 GB/image size limits
- **OS detection**: Reads `/etc/os-release`, `/etc/alpine-release`, `/etc/debian_version`, `/etc/redhat-release`, `/etc/lsb-release` — detects Alpine, Debian, Ubuntu, RHEL, CentOS, Rocky, AlmaLinux, Amazon Linux, Fedora, SUSE, Arch, Wolfi, Chainguard, and more
- **OS package parsers**: APK (`/lib/apk/db/installed`), DPKG (`/var/lib/dpkg/status` + `/var/lib/dpkg/status.d/*` for distroless), RPM (SQLite `rpmdb.sqlite` + BerkeleyDB Hash `Packages` with full binary header parser)
- **OS vulnerability database**: Extended `VulnDB` with `os_vulnerabilities` table; `OSAdvisoryDownloader` fetches Alpine SecDB and Debian Security Tracker data; `threatcode db update --os` downloads OS advisory data
- **Application dependency detection in images**: Finds and parses lockfiles inside images (all 10 formats); also scans Python `site-packages` METADATA for pip-installed packages
- **Image configuration checks**: `IMG_ROOT_USER`, `IMG_NO_HEALTHCHECK`, `IMG_SECRET_IN_ENV`, `IMG_PRIVILEGED_PORT`, `IMG_NO_MAINTAINER` — checks OCI image config for security best-practice violations
- **`threatcode image` CLI command**: `--format` (json/sarif/table), `--severity`, `--ignore-unfixed`, `--platform`, `--scanners vuln,secret,misconfig`, `--insecure`; table output matches standard security scanner format
- **`scan_image()` public API**: Pull and scan any image reference, returns structured dict with OS info, vulnerabilities, secrets, misconfigs

### Changed
- `VulnDB` schema extended with `os_vulnerabilities` table (backward-compatible; existing databases auto-migrate on next `init_db()`)
- `threatcode db update` gains `--os` flag to also download OS advisory data
- Version bumped to 0.7.0

## [0.6.0] - 2026-03-04

### Added

#### Multi-Scanner Architecture
- **Unified finding model**: New `FindingType` enum and `SecretFinding`, `VulnerabilityFinding`, `LicenseFinding` dataclasses in `models/finding.py` — extensible foundation for non-STRIDE findings alongside existing threat model
- **`ScanReport`** wrapper: Aggregates `ThreatReport` + secret/vuln/license findings into a single report with unified `to_dict()` and `summary`
- **`--scanners` CLI flag**: `threatcode scan <path> --scanners misconfig,secret,vuln,license` runs multiple scanners in one pass; default `misconfig` preserves backward compatibility
- **Public API**: New `scan_secrets()`, `scan_vulnerabilities()`, and `scan_all()` functions in the top-level `threatcode` module

#### Dockerfile Scanning
- **Dockerfile parser**: Parses `FROM`, `RUN`, `COPY`, `ADD`, `EXPOSE`, `USER`, `ENV`, `ARG`, `HEALTHCHECK`, `WORKDIR`, `ENTRYPOINT` instructions with multi-stage build and line continuation support; creates synthetic `dockerfile_image` summary resource with security properties
- **16 Docker security rules**: `DOCKER_NO_USER`, `DOCKER_LATEST_TAG`, `DOCKER_EXPOSED_SSH`, `DOCKER_ADD_INSTEAD_OF_COPY`, `DOCKER_SENSITIVE_FILE_COPY`, `DOCKER_NO_HEALTHCHECK`, `DOCKER_ENV_SECRET`, `DOCKER_APT_NO_RECOMMENDS`, `DOCKER_RUN_SUDO`, `DOCKER_RUN_CURL_PIPE`, `DOCKER_MULTIPLE_ENTRYPOINTS`, `DOCKER_MISSING_WORKDIR`, `DOCKER_ROOT_USER`, `DOCKER_EXPOSED_PRIVILEGED_PORT`, `DOCKER_NO_COPY_CHOWN`, `DOCKER_MISSING_LABEL`

#### Kubernetes Scanning
- **Kubernetes parser**: Multi-document YAML support with `apiVersion`+`kind` detection; flattens PodTemplateSpec security context from Deployments, StatefulSets, DaemonSets, Jobs, CronJobs; 19 resource types including RBAC roles and network policies
- **22 Kubernetes security rules**: `K8S_PRIVILEGED_CONTAINER`, `K8S_NO_RESOURCE_LIMITS`, `K8S_RUN_AS_ROOT`, `K8S_WRITABLE_ROOT_FS`, `K8S_HOST_NETWORK`, `K8S_HOST_PID`, `K8S_AUTOMOUNT_SA_TOKEN`, `K8S_LATEST_TAG`, `K8S_CAPABILITIES_NOT_DROPPED`, `K8S_DANGEROUS_CAPABILITIES`, `K8S_NO_SECURITY_CONTEXT`, `K8S_ALLOW_PRIVILEGE_ESCALATION`, `K8S_NO_NETWORK_POLICY`, `K8S_HOSTPORT_USED`, `K8S_CLUSTER_ADMIN_BINDING`, `K8S_WILDCARD_RBAC`, `K8S_SECRET_ENV_VAR`, `K8S_NO_LIVENESS_PROBE`, `K8S_NO_READINESS_PROBE`, `K8S_HOST_PATH_VOLUME`, `K8S_PROC_MOUNT`, `K8S_NO_SECCOMP`

#### Secret Scanning
- **Secret scanner engine**: Regex + keyword pre-filter pipeline with binary file detection, allow-list filtering, and automatic redaction; supports recursive directory scanning
- **24 built-in secret patterns**: AWS access keys, AWS secret keys, GitHub PATs, GitLab PATs, Slack tokens, private keys (RSA/EC/DSA/OPENSSH), JWT tokens, database connection strings (postgres/mysql/mongodb), Azure client secrets, GCP service account keys, Stripe keys, Twilio tokens, SendGrid keys, NPM tokens, generic API keys and passwords
- **`threatcode secret` CLI command**: Recursive file scanning with `--format` and `--output` options

#### Vulnerability Scanning
- **Lockfile parser**: 10 lockfile formats — `package-lock.json` (v1/v2/v3), `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `go.sum`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`
- **Vulnerability scanner**: SQLite-backed offline database with version comparison (semver, PEP 440, generic) and range-based matching
- **`threatcode vuln` CLI command**: Scan lockfiles with `--ignore-unfixed` flag
- **`threatcode db` CLI command group**: `db status` for database info, `db update` to download OSV bulk data for npm, PyPI, Go, crates.io, RubyGems, and Packagist

#### SBOM & License Scanning
- **CycloneDX 1.5 SBOM formatter**: Standards-compliant JSON with Package URL (PURL) identifiers, dependency relationships, optional vulnerability embedding
- **License compliance scanner**: SPDX classification into permissive, weakly copyleft, copyleft, restrictive, and unknown; configurable alerting
- **`threatcode sbom` CLI command**: Generate SBOM from lockfiles with `--format cyclonedx`
- **`threatcode license` CLI command**: Scan dependencies for license compliance issues

#### Expanded Rule Coverage (76 new rules)
- **AWS** (41 rules across 11 files): CloudTrail (5), KMS (4), SNS (3), SQS (3), ECS (5), EKS (5), CloudFront (4), ElastiCache (3), Elasticsearch (3), ELB (3), DynamoDB (3)
- **Azure** (20 rules across 5 files): Compute (5), Storage (4), Network (4), Database (4), AKS (3)
- **GCP** (15 rules across 5 files): Compute (4), Storage (3), Network (3), GKE (3), IAM (2)

#### MITRE ATT&CK Expansion
- 15 new techniques for container and cloud coverage: T1611 (Escape to Host), T1610 (Deploy Container), T1552.001 (Credentials in Files), T1195.002 (Compromise Software Supply Chain), T1021 (Remote Services), T1528 (Steal Application Access Token), T1565.001 (Stored Data Manipulation), T1613 (Container and Resource Discovery), T1609 (Container Administration Command), T1548 (Abuse Elevation Control), T1053 (Scheduled Task/Job), T1068 (Exploitation for Privilege Escalation)

### Changed
- **Rule loader**: `glob("*.yml")` → `rglob("*.yml")` for subdirectory support; `MAX_TOTAL_RULES` increased from 500 to 1000
- **Rule directory**: Built-in AWS rules reorganized into `builtin/aws/` subdirectory (rule IDs unchanged)
- **IR node mappings**: 47 new entries in `CATEGORY_MAP` and 20 new entries in `TRUST_ZONE_MAP` for Docker, Kubernetes, Azure, GCP, and dependency resource types
- **Rule matcher**: New `evaluate_rule()` convenience function for programmatic rule evaluation
- **Dependencies**: Added `httpx>=0.27`, `packaging>=23.0`, `tomli>=2.0;python_version<"3.11"`

## [0.5.1] - 2026-03-03

### Added
- **Attack path visualization**: New "Attack Paths" section between the diagram and threat table traces exploitable routes from internet-facing entry points (INTERNET/DMZ zones) through to critical backend assets (DATA/MANAGEMENT zones), showing step-by-step how compromise propagates
- **Attack path edge overlays**: Numbered dark-red circle markers on graph edges that are part of attack paths, linking the diagram to the attack path chains below
- **Expanded threat table**: Two new columns — "Description" (truncated to 60 chars, full in tooltip) and "ATT&CK Technique" (MITRE technique ID + name from `TECHNIQUE_DB`)
- **Mitigation in tooltips**: Threat table row tooltips now include `Mitigation:` text when present on the threat
- **Attack path arrow marker**: New `arrow-attack-path` SVG marker definition and `.attack-path-marker` CSS rule
- 14 new diagram tests: `TestAttackPaths` (7 tests covering section presence/absence, node names, max limit, min 2 threatened nodes, edge markers, valid XML) and `TestExpandedThreatTable` (6 tests covering description column, truncation, ATT&CK technique with name, unknown ID fallback, empty techniques dash, mitigation in tooltip) plus 1 CSS test

### Changed
- **Threat table columns**: Widened from 5 to 7 columns (added Description, ATT&CK Technique); adjusted proportional widths to fit expanded layout
- **Canvas minimum width**: Increased `min_legend_w` from 700 to 900 to accommodate wider threat table
- **Layout computation**: Attack path section height and width factored into canvas sizing; `_attack_paths_y` cursor inserted between zone lanes and threat table
- 53 diagram tests total (up from 39)

## [0.5.0] - 2026-03-02

### Added
- **SVG diagram overhaul**: Complete rewrite of `--format diagram` output to be a self-contained, understandable document
- **Node tooltips**: Native browser tooltips (`<title>`) on every node showing full resource ID, zone, category, and all threats with severity/STRIDE details
- **Edge tooltips**: All edges now have tooltips — boundary crossings explain the trust boundary, others show the edge type and endpoints
- **Boundary edge labels**: Trust boundary crossing edges display a `ZONE -> ZONE` label at their midpoint with a contrasting background
- **Summary bar**: Severity breakdown bar below the header with color-coded pills showing threat counts per severity and total STRIDE category count
- **Threat detail table**: Full SVG table below the diagram listing every threat sorted by severity, showing resource, title, STRIDE category, and source with alternating row backgrounds
- **CSS hover interactivity**: `<style>` block with hover effects for nodes (thicker stroke), edges (wider stroke), and threat table rows
- **3-column legend**: Overhauled legend with mini SVG shapes (rounded rect, cylinder, diamond, double-rect), actual line samples for each edge type, and severity badge explanations

### Changed
- **Node labels**: Top line now shows full resource type (e.g., `aws_s3_bucket`), center shows short name (e.g., `data`) in bold — replaces cryptic category-only label
- **Node width**: Widened from 130px to 160px to fit longer resource type labels
- **Legend height**: Expanded from 56px to 140px for proper 3-column layout with real shapes
- **Layout computation**: Canvas height now accounts for summary bar, threat table, and expanded legend
- **Edge rendering**: Edges wrapped in `<g class="edge-group">` groups for proper tooltip targeting
- **Legend content**: Replaced Unicode box-drawing characters with actual SVG shape primitives
- 39 diagram tests (up from 12) covering tooltips, edge labels, summary bar, threat table, legend shapes, CSS styles, and sort ordering

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
