# Configuration

ThreatCode is configured via a `.threatcode.yml` file and environment variables.

## `.threatcode.yml` Schema

```yaml
# LLM configuration
llm:
  provider: anthropic          # "anthropic", "openai", "ollama", "local"
  model: claude-sonnet-4-20250514  # Model identifier
  api_key: ""                  # API key (prefer env var instead)
  base_url: ""                 # Required for local/ollama providers
  max_tokens: 4096             # Maximum response tokens
  temperature: 0.2             # LLM temperature (0.0-1.0)

# Data redaction before LLM calls
redaction:
  enabled: true                # Enable/disable redaction
  strategy: placeholder        # "placeholder" or "hash"
  fields:                      # Fields to redact by key name
    - arn
    - account_id
    - tags
    - ip_address

# Analysis settings
min_severity: info             # Minimum severity: critical, high, medium, low, info
no_llm: false                  # Disable LLM analysis globally
dry_run: false                 # Print LLM payload without calling API

# Additional rule files
extra_rule_paths:
  - /path/to/org_rules.yml
  - /path/to/team_rules.yml

# Output format
output_format: json            # json, sarif, markdown, bitbucket, matrix
```

All fields are optional. Omitted fields use the defaults shown above.

---

## LLM Configuration

### Anthropic (Claude)

```yaml
llm:
  provider: anthropic
  model: claude-sonnet-4-20250514
  max_tokens: 4096
  temperature: 0.2
```

The API key is read from the `ANTHROPIC_API_KEY` environment variable. You can also set it directly in the config file via `api_key`, but environment variables are preferred to avoid committing secrets.

### OpenAI-Compatible (Ollama, vLLM, llama.cpp)

```yaml
llm:
  provider: ollama
  model: llama3
  base_url: http://localhost:11434
  api_key: not-needed
  max_tokens: 4096
```

Any OpenAI-compatible API endpoint works. Set `base_url` to point at your local server. The client calls `{base_url}/v1/chat/completions`.

### Dry Run

```yaml
dry_run: true
```

Or use the CLI flag:

```bash
threatcode scan tfplan.json --dry-run
```

Dry run prints the system prompt and analysis prompt to stderr without making any API calls. This is useful for previewing token usage and debugging prompt construction.

---

## Redaction Configuration

Redaction runs automatically before any data is sent to an LLM. It protects sensitive infrastructure details.

### Strategies

| Strategy | Behavior | Example |
|----------|----------|---------|
| `placeholder` | Replaces values with sequential placeholders | `arn:aws:s3:::my-bucket` becomes `REDACTED_aws_arn_1` |
| `hash` | Replaces values with truncated SHA-256 hashes | `arn:aws:s3:::my-bucket` becomes `REDACTED_aws_arn_a1b2c3d4` |

### What Gets Redacted

By regex pattern (always applied to all string values):

| Pattern | Matches |
|---------|---------|
| AWS account IDs | 12-digit numbers |
| AWS ARNs | `arn:aws*:...` |
| IPv4 addresses | `x.x.x.x` |
| IPv6 addresses | `xxxx:xxxx:...` |
| Email addresses | `user@domain.tld` |

By field name (configurable via `redaction.fields`):

| Field Name | Default |
|------------|---------|
| `arn` | Redacted |
| `account_id` | Redacted |
| `tags` | Redacted |
| `ip_address` | Redacted |
| `private_ip` | Redacted (always) |
| `public_ip` | Redacted (always) |
| `owner_id` | Redacted (always) |

After the LLM responds, redacted resource addresses in the output are automatically unredacted back to their original values.

!!! note "Redaction and rules"
    Redaction only applies to data sent to the LLM. Rule-based analysis always operates on the original, unredacted infrastructure data.

---

## Environment Variables

| Variable | Purpose | Used When |
|----------|---------|-----------|
| `ANTHROPIC_API_KEY` | Anthropic Claude API key | `llm.provider` is `anthropic` and `llm.api_key` is empty |

---

## Config File Search Order

ThreatCode searches for a config file in this order:

1. **Explicit path** -- `--config path/to/.threatcode.yml` (CLI) or `config_path=` (Python API)
2. **Current directory** -- `.threatcode.yml` or `.threatcode.yaml` in the working directory
3. **Home directory** -- `~/.threatcode.yml`
4. **Defaults** -- If no config file is found, all settings use their default values

The first file found is used. Config files are not merged.

!!! warning "Do not commit API keys"
    Never put your `api_key` in a config file that is committed to version control. Use environment variables or a `.threatcode.yml` file listed in `.gitignore`.
