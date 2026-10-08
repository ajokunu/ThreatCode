# Migrating from 0.9

This release narrows ThreatCode to what it is good at: a threat model and attack paths from infrastructure code.
The scanning layer that duplicated Trivy, Grype, Syft and OSV-Scanner is gone, the CLI has two commands, and the exit codes mean something stricter.
This page lists what changed and what to use instead.
The [changelog](https://github.com/ajokunu/ThreatCode/blob/main/CHANGELOG.md) has the full list.

## Commands

| Before | Now |
|--------|-----|
| `threatcode fs DIR` | `threatcode scan DIR`. It reads every supported file under the directory into one graph. |
| `threatcode repo URL` | Clone the repository, then `threatcode scan DIR`. |
| `threatcode image IMAGE` | Run Trivy or Grype on the image and pass the JSON to `--ingest`. The CVE is placed on the workloads that run the image. |
| `threatcode vuln FILE`, `threatcode db` | Run OSV-Scanner, Grype or Trivy and pass the JSON to `--ingest`. There is no vulnerability database and no `db` command. |
| `threatcode secret DIR` | `threatcode scan DIR` runs the secret detectors over the files it models and attaches each finding to its resource. For a whole-repository secret scan, run Gitleaks and pass its SARIF to `--ingest`. |
| `threatcode sbom`, `threatcode license` | Removed. Use Syft or Trivy. |
| `--scanners`, `--ignore-unfixed` | Removed with the scanners. |
| `-f cyclonedx` | Removed with the SBOM output. |
| `-f matrix` | Renamed `-f navigator`. `matrix` still works as a deprecated alias. |
| `--ignorefile` | `--ignore-file`. |

The scanning layer was removed, not patched, because none of it fed the threat model and the image scanner extracted layers to disk where whiteouts and symlink chains could be steered into deleting files on the host.

## Exit codes and the gate

| Before | Now |
|--------|-----|
| Any finding exits 1. | Exit 1 means a finding or attack path at or above `--fail-on`, and the default is `high`. A scan whose worst finding is medium exits 0. `--fail-on info` restores the old behavior, and `--fail-on none` never fails on findings. |
| A parse error, a missing file or a bad config exits 1. | These exit 2, so a script that tests for exactly 1 to mean "findings" gets that meaning back. |
| A file that did not parse was skipped. | It is an input error and exit 2. Nothing to scan is exit 2 too. |
| Coverage gaps were invisible. | They are printed on stderr, listed in the reports and turned into exit 2 by `--strict`. |
| Terraform state scanned as an empty plan and exited 0. | State JSON and destroy-only plans are rejected with the command that fixes them. |

## The LLM

The LLM is opt-in.
Before, an exported `ANTHROPIC_API_KEY` sent a redacted graph to a model.
Now nothing is sent unless you pass `--llm`, set `THREATCODE_LLM=1`, or set `llm.enabled: true` in a config you name with `--config`.
The model client is an optional extra: `pip install "threatcode[llm] @ git+https://github.com/ajokunu/ThreatCode.git"`.
The default model is `claude-sonnet-5-5`.
`--no-llm` still works and wins over the config.

## Configuration

- `no_llm` and `dry_run` are no longer config keys.
  The error message says what replaces them.
- An auto-discovered `.threatcode.yml` can set only `min_severity` and `format`.
  `fail_on`, `rules`, `llm`, `redaction` and the graph limits need `--config`.
- The config keys `output_format` and `extra_rule_paths` are now `format` and `rules`, the names of the flags.
  The old spellings still load and print a notice that names the new one.
- A flag wins over an environment variable, which wins over the config file, which wins over the default.
  A config's `min_severity` and `format` now actually take effect when the flag is absent.

## Reports and integrations

- Every report has `schema_version`, `attack_paths` and `coverage`, and paths in it are relative to the scan root.
- A finding keeps its base `severity` and gains `effective_severity` and `severity_reason` when context changes it.
  The summary counts, the gate and SARIF use the effective severity.
- Cluster-scoped Kubernetes kinds are addressed `<type>.<name>` with no namespace segment, for example `kubernetes_cluster_role.admin`.
  A suppression or baseline that names the old address needs updating.
- Boundary findings are one per traffic flow, and their fingerprint names both ends, so a baseline written before this release shows its boundary findings as new once.
  Write the baseline again.
- Rules match their resource type exactly.
  A custom rule that relied on `resource_type: aws_s3_bucket` also matching `aws_s3_bucket_versioning` needs `resource_type: "aws_s3_bucket*"` or an explicit list.
- Removed rule ids are listed in the [rule catalog](rules.md#removed-rules).
  A `.threatcodeignore` line that names one now warns.
- SARIF results point at the file and line of the resource and carry a stable fingerprint, so existing code scanning alerts may close and reopen once.

## Python API

| Before | Now |
|--------|-----|
| `scan(input_path, no_llm=True, output_format="sarif")` | `scan(paths, **settings)` returns the report dict. `output_format` is a `TypeError`; render other formats with `threatcode.formatters.render(name, analysis)`. |
| `scan_filesystem`, `scan_repository`, `scan_image`, `scan_secrets`, `scan_vulnerabilities`, `scan_all` | Removed. |
| `LOCKFILE_NAMES`, `cvss_to_severity`, `SecretFinding`, `VulnerabilityFinding`, `ScanReport` | Removed. Secret findings are `Threat` objects. |
| `threatcode.ignore` | `threatcode.suppressions`. |
| A custom rule on `property_path` | The operator is removed; use a path in the property key. |

The new entry points are `scan`, `analyze` and `run_scan`; see the [API reference](api-reference.md).
