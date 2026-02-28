# Security

ThreatCode is designed to be safe to run in enterprise environments with strict security requirements. This page documents the security controls built into the tool.

## No `eval()` Policy

The rule condition evaluator never uses `eval()`, `exec()`, `compile()`, or any form of dynamic code execution. All condition operators (`equals`, `contains`, `not_exists`, `matches_any`, etc.) are implemented as explicit, bounded Python functions.

Unknown operators fail closed -- if the evaluator encounters an operator it does not recognize, the condition returns `False`. This prevents accidental matches from typos and blocks any attempt to inject executable logic through rule files.

The codebase contains no usage of `pickle`, `marshal`, `exec`, or `compile`.

---

## YAML `safe_load` Only

All YAML parsing in ThreatCode uses `yaml.safe_load()` exclusively. The unsafe `yaml.load()` function (which can execute arbitrary Python objects) is never used. This applies to:

- Configuration files (`.threatcode.yml`)
- Rule files (built-in and custom)
- CloudFormation templates

---

## Data Redaction Before LLM Calls

Before any infrastructure data is sent to an external LLM, ThreatCode applies automatic redaction:

### What is redacted

- **AWS Account IDs** -- 12-digit numbers
- **AWS ARNs** -- `arn:aws*:...` patterns
- **IPv4 and IPv6 addresses**
- **Email addresses**
- **Sensitive field names** -- `arn`, `account_id`, `tags`, `ip_address`, `private_ip`, `public_ip`, `owner_id`, `caller_reference`

### Redaction strategies

| Strategy | Behavior |
|----------|----------|
| `placeholder` (default) | Sequential placeholders: `REDACTED_aws_arn_1`, `REDACTED_aws_arn_2` |
| `hash` | Truncated SHA-256: `REDACTED_aws_arn_a1b2c3d4` |

Both strategies maintain a bidirectional mapping so that resource addresses in LLM responses can be unredacted back to their original values. The mapping is held in memory only and is never persisted.

### Configuration

Redaction is enabled by default. It can be configured in `.threatcode.yml`:

```yaml
redaction:
  enabled: true
  strategy: placeholder
  fields:
    - arn
    - account_id
    - tags
    - ip_address
```

!!! warning "Do not disable redaction for external LLMs"
    Disabling redaction when using an external LLM provider (Anthropic, OpenAI) means your AWS account IDs, ARNs, IP addresses, and other infrastructure details will be sent to the provider. Only disable redaction when using a local LLM.

---

## Local LLM Option for Air-Gapped Environments

For environments where no data can leave the network, ThreatCode supports local LLMs via any OpenAI-compatible API:

- **Ollama** -- `base_url: http://localhost:11434`
- **vLLM** -- `base_url: http://localhost:8000`
- **llama.cpp server** -- `base_url: http://localhost:8080`

```yaml
llm:
  provider: ollama
  model: llama3
  base_url: http://localhost:11434
  api_key: not-needed
```

With a local LLM, all data stays on your network. Redaction still runs by default but can be disabled for local models if desired.

---

## Input Validation

### File size

The parser layer reads input files into memory. Extremely large files may cause high memory usage. Use standard IaC file sizes (Terraform plans are typically under 10MB).

### Rule count

Rules are loaded from YAML files and stored in memory. Each rule is validated for required fields (`id`, `title`, `description`, `stride_category`, `severity`, `resource_type`, `condition`) at load time. Missing fields raise a `RuleLoadError` and halt execution.

### LLM response length

The `max_tokens` configuration (default: 4096) limits the length of LLM responses. The LLM response is parsed as JSON and validated for the expected schema structure (`threats` array with required fields). Malformed responses result in zero LLM-generated threats rather than crashes.

### API timeout

The OpenAI-compatible client enforces a 120-second timeout on HTTP requests to prevent indefinite hangs.

---

## LLM Security Controls

### Prompt injection detection

The system prompt instructs the LLM to respond only with valid JSON in a specific format. The response parser (`parse_llm_threats`) extracts only the `threats` array from the response and validates each threat's fields. Any content outside the expected JSON structure is ignored.

### Output schema validation

LLM responses are parsed as JSON. Each threat object is validated for expected fields before being converted to a `Threat` dataclass. Missing fields receive safe defaults (e.g., `severity` defaults to `"medium"`, `confidence` defaults to `0.7`).

### Token budgets

The `max_tokens` setting (default: 4096) controls the maximum response length from the LLM. This prevents runaway token consumption.

### Timeout controls

HTTP requests to LLM providers enforce a 120-second timeout. The Anthropic SDK client uses its own built-in timeout mechanisms.

### Model pinning

The LLM model is specified in configuration (`model: claude-sonnet-4-20250514` by default). This prevents unintended model switches that might change behavior or cost.

---

## No Pickle, Marshal, Exec, or Compile

ThreatCode does not use any of the following dangerous Python functions or modules:

- `pickle` / `cPickle` -- No deserialization of untrusted data
- `marshal` -- No bytecode serialization
- `exec()` -- No dynamic code execution
- `compile()` -- No dynamic code compilation
- `eval()` -- No expression evaluation
- `__import__()` -- No dynamic imports based on user input

---

## Dependency Audit Process

ThreatCode's dependencies are auditable standard Python packages:

| Package | Purpose |
|---------|---------|
| `click` | CLI framework |
| `pydantic` | Configuration validation |
| `python-hcl2` | HCL parsing |
| `pyyaml` | YAML parsing |
| `networkx` | Graph data structure |
| `anthropic` | Anthropic Claude API client |
| `jinja2` | Template rendering (Markdown formatter) |

Run `pip-audit` to check for known vulnerabilities:

```bash
pip install pip-audit
pip-audit
```

---

## OWASP Considerations

### No string interpolation in shell commands

ThreatCode does not construct or execute shell commands. All file I/O uses Python's `pathlib` and standard library functions.

### No user input in DOM

ThreatCode is a CLI/library tool with no web frontend. Output formatters produce plain text (JSON, SARIF, Markdown) with no HTML rendering or DOM manipulation.

### No `innerHTML` or equivalent

Not applicable -- ThreatCode has no web UI. The ATT&CK Navigator layer is a static JSON file loaded by the Navigator web application, not rendered by ThreatCode itself.
