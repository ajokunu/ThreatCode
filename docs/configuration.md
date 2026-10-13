# Configuration

ThreatCode needs no configuration.
Settings come from four places, and the first one that sets a value wins:

1. the command-line flag,
2. an environment variable (`THREATCODE_FAIL_ON`, `THREATCODE_MIN_SEVERITY`, `THREATCODE_FORMAT`, `THREATCODE_LLM`),
3. a config file,
4. the built-in default.

A flag that is absent counts as not set, so a config file's `min_severity` and `format` take effect when you do not pass the flag.

## Which config file is trusted

**A `.threatcode.yml` that ThreatCode finds on its own is auto-discovered, and an auto-discovered file is not trusted.**
It sits in the repository being scanned, so whoever opens a pull request controls it.
Only two keys are read from it, `min_severity` and `format`, which change what you see and never what gates.
Every other key is ignored with a warning, and a note on stderr names the file and the keys it used:

```text
Warning: Auto-discovered config proj/.threatcode.yml contains restricted fields ['fail_on', 'llm']; these are ignored for security. Use --config to load a trusted config file.
Using config proj/.threatcode.yml (auto-discovered); fields used: min_severity
```

A file you name with `--config` is trusted, and every key is honored.
In CI, always name the file.

Discovery looks for `.threatcode.yml` and `.threatcode.yaml` in the scan root and the current directory, and then, when the `CI` environment variable is empty or unset, for `~/.threatcode.yml`.
Any non-empty value of `CI`, including `0` or `false`, skips the home directory.
The home file is auto-discovered too, so it is subject to the same two-key limit.

The config models reject unknown keys and name the key, with a suggestion for a typo.
A removed key (`no_llm`, `dry_run`) says what replaces it.

## Keys

<!-- gen:config-keys -->
| Key | Type | Default | Read from an auto-discovered file |
| --- | --- | --- | --- |
| `min_severity` | Optional[Literal['critical', 'high', 'medium', 'low', 'info']] | unset | yes |
| `format` (was `output_format`) | str \| None | unset | yes |
| `fail_on` | Optional[Literal['critical', 'high', 'medium', 'low', 'info', 'none']] | unset | no |
| `rules` (was `extra_rule_paths`) | list[str] | none | no |
| `max_nodes` | int \| None | unset | no |
| `max_edges` | int \| None | unset | no |
| `strict_edges` | bool | true | no |
| `llm.enabled` | bool | false | no |
| `llm.provider` | Literal['anthropic', 'openai', 'ollama', 'local'] | anthropic | no |
| `llm.model` | str | claude-sonnet-5-5 | no |
| `llm.api_key` | str | empty | no |
| `llm.api_key_env` | str \| None | unset | no |
| `llm.base_url` | str | empty | no |
| `llm.max_tokens` | int | 4096 | no |
| `llm.temperature` | float \| None | unset | no |
| `llm.timeout` | int | 120 | no |
| `llm.max_retries` | int | 1 | no |
| `llm.max_input_tokens` | int | 60000 | no |
| `llm.allow_local_network` | bool | false | no |
| `redaction.strategy` | Literal['placeholder', 'hash'] | placeholder | no |
| `redaction.fields` | list[str] | ['arn', 'account_id', 'tags', 'ip_address'] | no |
<!-- /gen:config-keys -->

`rules` entries that are relative resolve against the directory of the config file.
The two keys that were called `output_format` and `extra_rule_paths` in earlier versions still load, and each prints a notice that names the new spelling.
Giving both spellings of one key is an error.
`max_nodes` and `max_edges` also have flags and the `THREATCODE_MAX_NODES` and `THREATCODE_MAX_EDGES` environment variables.

### One setting, its names

A setting has the name of its flag everywhere it can be given, except where the rest of the platform fixes a different style.
This table is the whole mapping.

| Setting | Flag | Environment variable | Config key | Action input | `scan()` argument |
| --- | --- | --- | --- | --- | --- |
| Output format | `--format`, `-f` | `THREATCODE_FORMAT` | `format` | `format` | none: `scan()` returns a dict, and `threatcode.formatters.render()` renders a format |
| Extra rule files | `--rules`, `-r` | none | `rules` | `extra-rules` | `extra_rule_paths` |
| Config file | `--config`, `-c` | none | none | `config-file` | `config_path` |
| Failure threshold | `--fail-on` | `THREATCODE_FAIL_ON` | `fail_on` | `fail-on` | `fail_on` |
| Lowest severity shown | `--min-severity` | `THREATCODE_MIN_SEVERITY` | `min_severity` | `min-severity` | `min_severity` |
| Model review | `--llm`, `--no-llm` | `THREATCODE_LLM` | `llm.enabled` | none | `llm` |
| Suppressions file | `--ignore-file` | none | none | none | `ignore_file` |

The Action keeps `extra-rules` and `config-file` because its input names are already in workflows.
`output_format` and `extra_rule_paths` are the first spellings of the `format` and `rules` config keys; they still load, with a notice.

An example, saved as `threatcode.yml` and used with `--config`:

<!-- runnable exit=1 -->

```bash
cat > threatcode.yml <<'EOF'
fail_on: critical
min_severity: low
format: markdown
redaction:
  strategy: hash
EOF
threatcode scan examples/k8s-platform --config threatcode.yml -o report.md
```

## The LLM

The model review is optional and off by default.
It runs only when you ask for it with `--llm`, `THREATCODE_LLM=1` or `llm.enabled: true` in a config you named with `--config`, and only if the `llm` extra is installed.
`--no-llm` always wins, and `--dry-run` implies `--llm` while sending nothing.
An exported `ANTHROPIC_API_KEY` alone does not send anything anywhere.

Because the whole `llm` section is ignored in an auto-discovered file, put it in a file you name:

```yaml
# llm.yml, used with: threatcode scan infra/ --config llm.yml
llm:
  enabled: true
  provider: anthropic
  model: claude-sonnet-5-5
```

### Providers

| Provider | Key comes from | Default endpoint |
|----------|----------------|------------------|
| `anthropic` | `llm.api_key`, else `ANTHROPIC_API_KEY` | the Anthropic API |
| `openai` | `llm.api_key`, else `OPENAI_API_KEY` | `https://api.openai.com` |
| `ollama`, `local` | none unless `llm.api_key_env` names a variable | `llm.base_url` |

`llm.api_key_env` names a different variable for any provider.
A key written into a config file produces a warning that names the variable to use instead.
With no key, no `Authorization` header is sent.

The default model is `claude-sonnet-5-5`.
`llm.temperature` is unset by default and sent only when you set it; a model that rejects it gets one retry without it.

A model on your own network needs an explicit opt-in:

```yaml
llm:
  enabled: true
  provider: ollama
  base_url: http://localhost:11434
  model: llama3.2
  allow_local_network: true
```

`allow_local_network` lets the `ollama`, `local` and `anthropic` providers use plain HTTP to loopback, private and shared (`100.64.0.0/10`) addresses.
Without it, a `base_url` must be HTTPS and resolve to a public address.
Link-local addresses, including the cloud metadata address `169.254.169.254`, are blocked either way, and a redirect to another scheme, host or port is refused, so the API key and the request are never forwarded.

### Limits

`llm.max_input_tokens` (default 60000, estimated as characters / 3.5) caps the request.
A request over the limit is never cut: the infrastructure context is summarized first, then resources without findings lose their properties, then low-value resources are dropped with their edges.
If it still does not fit, the LLM step fails with a clear error and the rule results are kept.
What was summarized or dropped is counted in the report's `llm.context` block.

## Redaction

Before anything is sent, resources become opaque handles and sensitive values become placeholders.
`redaction.strategy` is `placeholder` (`REDACTED_<label>_<n>`) or `hash` (`REDACTED_<label>_<16 hex digits>`, an HMAC with a random per-run key, so a provider cannot confirm a guess by hashing it).
`redaction.fields` adds names that are redacted at any depth, case-insensitively, on top of the built-in sensitive names; a listed name wins over the allowlist.
Both keys are read only from a `--config` file, so a scanned repository cannot weaken redaction.

[Security](security.md) shows real redactor output and `--dry-run`.

## Environment variables

| Variable | Effect |
|----------|--------|
| `THREATCODE_FAIL_ON` | Default for `--fail-on`. |
| `THREATCODE_MIN_SEVERITY` | Default for `--min-severity`. |
| `THREATCODE_FORMAT` | Default for `-f`. |
| `THREATCODE_LLM` | `1`, `true`, `yes` or `on` enables the model review; `0`, `false`, `no` or `off` disables it. |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` | API keys, read only when the model review runs. |
| `ANTHROPIC_BASE_URL` | Endpoint for the Anthropic provider; goes through the same address check as `llm.base_url`. |
| `THREATCODE_MAX_NODES`, `THREATCODE_MAX_EDGES`, `THREATCODE_MAX_FANOUT` | Graph size limits. |
| `THREATCODE_HELM` | `auto`, `off` or `required`. |
| `SOURCE_DATE_EPOCH`, `NO_COLOR`, `CI` | See the [CLI reference](cli.md). |

An invalid value is an error that names the variable.

## Minimal configurations

**Report only, never fail the build:**

```yaml
fail_on: none
```

**A CI gate that a pull request cannot edit** (save it outside the paths the pull request controls, or in a protected branch, and pass `--config`):

```yaml
fail_on: high
min_severity: low
```

**Air-gapped review with a local model:**

```yaml
llm:
  enabled: true
  provider: local
  base_url: http://gpu-box.internal:8000
  model: my-model
  allow_local_network: true
```
