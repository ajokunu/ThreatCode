# Security

ThreatCode is designed to be safe in enterprise environments with strict security requirements. This page documents the security controls built in to the tool itself.

---

## Code Safety

### No `eval()` Policy

The rule condition evaluator uses explicit Python comparison functions for every operator (`equals`, `contains`, `matches_any`, etc.). There is no `eval()`, `exec()`, `compile()`, `pickle`, or `marshal` anywhere in the codebase. Unknown operators fail closed (return False rather than raising).

### YAML `safe_load` Only

All YAML parsing uses `yaml.safe_load()` exclusively — no arbitrary Python object deserialization.

### Rule File Sandboxing

| Control | Value |
|---------|-------|
| Max file size | 1 MB |
| Max rules per file | 100 |
| Max total rules (all files) | 1000 |
| Symlinks in extra rule paths | Blocked |
| Rule ID uniqueness | Enforced globally |
| MITRE ID validation | Against known TECHNIQUE_DB and TACTIC_DB |

### LLM Response Handling

LLM responses are parsed as JSON only — never executed or passed to `eval()`. The schema is validated before any field is used. Unknown MITRE IDs are rejected. Unknown resource addresses from LLM output are capped at 0.5 confidence.

---

## SSRF Protection

All outbound HTTP calls (LLM API, registry API, vulnerability DB download) validate the resolved hostname against:

- Loopback (`127.0.0.0/8`, `::1`)
- Private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`)
- Link-local (`169.254.0.0/16`, `fe80::/10`) — including AWS EC2 metadata endpoint
- Reserved ranges
- Unspecified address (`0.0.0.0`)
- IPv4-mapped IPv6 addresses

Validation uses DNS resolution + Python's `ipaddress` module so no private address reachable by hostname can be called (cloud metadata endpoint: `169.254.169.254`).

Container registry connections additionally support `--insecure` for HTTP (opt-in only).

---

## Data Redaction

Before any data is sent to an external LLM:

1. A regex pass replaces AWS account IDs, ARNs, IPv4/IPv6 addresses, and email addresses with placeholders
2. Fields named in the sensitive key list are redacted (`secret`, `password`, `token`, `api_key`, `access_key`, `secret_key`, `connection_string`, `credentials`, `private_key`, `certificate`, and more)
3. A bidirectional mapping table is maintained — placeholders are reversed back into real values in the LLM's output

Placeholder format: `__REDACTED_ARN_1__` (or `__HASH_a1b2c3d4__` if hash strategy is configured).

**API keys should be passed via environment variable**, not stored in `.threatcode.yml`. ThreatCode warns to stderr if `api_key` is found in a config file.

---

## Prompt Injection Hardening

- Rule IDs are sanitized before inclusion in LLM prompts
- Graph data is wrapped in XML-style delimiters to separate it from instructions
- Bidirectional Unicode override characters (U+200E–U+202E, U+2066–U+2069) are stripped from all prompt content
- LLM response length is capped at 512 KB
- Maximum 100 threats per LLM response

---

## OCI Layer Extraction Security

When pulling container images:

- **Digest verification**: Every downloaded layer blob has its SHA-256 hash verified against the manifest before extraction
- **Path traversal protection**: Tar entries containing `..` path components are rejected before any normalization, preventing writes outside the extraction root
- **Symlink restrictions**: Symlinks are created but their targets are not followed during extraction to prevent TOCTOU issues
- **Size limits**: 2 GB per layer, 10 GB total extraction, 500K files maximum

---

## Configuration Security

**Auto-discovered configs** (`.threatcode.yml` in CWD or `~/.threatcode.yml`) are restricted to safe fields only:
- Allowed: `min_severity`, `output_format`, `no_llm`, `dry_run`, `redaction`
- Stripped with warning: `llm.api_key`, `llm.base_url`, `extra_rule_paths`

The `CI` environment variable disables home-directory config discovery in CI environments.

Use explicit `--config` for full config control.

---

## Input Validation

- IaC files larger than 50 MB are rejected
- LLM prompts are capped at 256 KB
- LLM `max_tokens` is clamped to `[1, 8192]`
- API timeouts enforced: 120 seconds
- Graph node limit: 10,000 (error), edge limit: 50,000 (warn and skip)

---

## Dependency Audit

Run a vulnerability scan on ThreatCode's own dependencies:

```bash
pip-audit --strict -r requirements.txt
```

All CI runs include `pip-audit --strict` as a required gate.

---

## Reporting Security Issues

Please report security vulnerabilities via GitHub Issues (tag: `security`). Do not include exploit code in public issues.
