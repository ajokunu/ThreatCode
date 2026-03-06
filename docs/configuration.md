# Configuration

ThreatCode is configured via a `.threatcode.yml` file and/or environment variables.

---

## Config File Location

ThreatCode searches for config in this order:

1. `--config / -c` flag (explicit path — all fields allowed)
2. `.threatcode.yml` or `.threatcode.yaml` in the current working directory
3. `~/.threatcode.yml` in the home directory (skipped in CI when `CI=true`)
4. Built-in defaults

**Security note:** Auto-discovered configs (2 and 3) are restricted to safe fields only: `min_severity`, `output_format`, `no_llm`, `dry_run`, `redaction`. Security-sensitive fields (`llm.api_key`, `llm.base_url`, `extra_rule_paths`) are stripped with a warning when loaded from auto-discovered locations. Use `--config` for full control.

---

## Full Schema

```yaml
# .threatcode.yml

# LLM configuration
llm:
  provider: anthropic              # anthropic | openai | ollama | local
  model: claude-sonnet-4-20250514  # Model identifier
  api_key: ""                      # Prefer ANTHROPIC_API_KEY env var
  base_url: ""                     # Required for ollama/local endpoints
  max_tokens: 4096                 # Token budget for LLM response
  temperature: 0.2                 # LLM sampling temperature

# Data redaction (applied before any LLM call)
redaction:
  strategy: placeholder            # placeholder | hash
  fields:
    - arn
    - account_id
    - tags
    - ip_address

# Analysis settings
min_severity: info                 # critical | high | medium | low | info
no_llm: false                      # true = rules-only, no LLM call
dry_run: false                     # true = show LLM prompt, don't call API

# Rule loading
extra_rule_paths: []               # Additional YAML rule files

# Output
output_format: json                # Default CLI output format
```

---

## LLM Providers

### Anthropic (Claude)

```yaml
llm:
  provider: anthropic
  model: claude-sonnet-4-20250514
```

Set the API key via environment variable:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

Or in the config file (not recommended — prefer env var):

```yaml
llm:
  provider: anthropic
  api_key: sk-ant-...
```

### OpenAI-compatible

```yaml
llm:
  provider: openai
  model: gpt-4o
  base_url: https://api.openai.com/v1
  api_key: sk-...
```

### Ollama (local, air-gapped)

```yaml
llm:
  provider: ollama
  base_url: http://localhost:11434
  model: llama3.2
```

### Other OpenAI-compatible endpoints

vLLM, llama.cpp, Together AI, Groq, etc.:

```yaml
llm:
  provider: local
  base_url: http://localhost:8080
  model: my-model
  api_key: ""
```

---

## Redaction

Before any data is sent to an external LLM, ThreatCode replaces sensitive values with placeholder tokens like `__REDACTED_ARN_1__`. The original values are stored in a reversible mapping and substituted back into the LLM's output, so all threat findings still reference real resource addresses.

**Redaction strategies:**

| Strategy | Placeholder format | Notes |
|----------|--------------------|-------|
| `placeholder` (default) | `__REDACTED_ARN_1__` | Human-readable, reversible |
| `hash` | `__HASH_a1b2c3d4__` | Consistent per value, reversible |

**Fields always redacted** (hardcoded):
- AWS account IDs (12-digit sequences with `aws` context)
- ARNs (`arn:aws:...`)
- IPv4 and IPv6 addresses
- Email addresses
- Any field named: `secret`, `password`, `token`, `api_key`, `access_key`, `secret_key`, `connection_string`, `credentials`, `private_key`, `certificate`, `name`, `module`, `provider`, `source_location`

**Configurable additional fields** (via `redaction.fields`):

```yaml
redaction:
  fields: [arn, account_id, tags, ip_address]
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Anthropic API key (recommended over config file) |
| `CI` | If set to `true`, disables home directory config discovery |

---

## CLI Flags

All config settings can be overridden per-command:

```bash
# Override config file
threatcode scan tfplan.json --config /etc/threatcode.yml

# Disable LLM
threatcode scan tfplan.json --no-llm

# Dry run (show LLM prompt, no API call)
threatcode scan tfplan.json --dry-run

# Minimum severity threshold
threatcode scan tfplan.json --min-severity high

# Extra custom rules
threatcode scan tfplan.json --rules my_org_rules.yml --rules compliance.yml
```

---

## Minimal Configurations

### Rules-only (no LLM)

```yaml
no_llm: true
min_severity: medium
```

### CI quality gate

```yaml
no_llm: true
min_severity: high
output_format: sarif
```

### Air-gapped with local LLM

```yaml
llm:
  provider: ollama
  base_url: http://localhost:11434
  model: llama3.2
  max_tokens: 2048
no_llm: false
```
