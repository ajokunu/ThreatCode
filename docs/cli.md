# CLI reference

ThreatCode has two commands.
`threatcode scan PATH...` builds a threat model from files, directories or standard input.
`threatcode diff BASELINE CURRENT` compares two JSON reports.

The tables on this page are generated from the click commands, so an option that is listed here exists.

## Options before the command

These belong to the group and go before the command name: `threatcode -q scan infra/`, not `threatcode scan infra/ -q`.

<!-- gen:group -->
| Option | Values | What it does |
| --- | --- | --- |
| `--version` |  | Print the version and exit. |
| `--version` |  | Show the version and exit. |
| `-v`, `--verbose` |  | More log detail on stderr (-vv for debug). |
| `-q`, `--quiet` |  | Hide progress and notices; errors stay. |
| `--debug` |  | Debug logging and tracebacks for unexpected errors. |
| `--no-color` |  | Never use colors (NO_COLOR does the same). |
| `-h`, `--help` |  | Show help and exit. Every command has it too. |
<!-- /gen:group -->

## `threatcode scan`

```text
threatcode scan [OPTIONS] PATH...
```

`PATH` is a file, a directory, or `-` for standard input, and you can name several.
Everything found goes into one graph, so an attack path can cross files.

### What a directory means

A directory is walked by a reader that is safe to point at a repository you did not write.

- It reads only regular files.
  Symlinks inside the tree are skipped and counted, which ends link cycles and stops a link from pulling in a file outside the scan root.
  A symlink you name on the command line is followed.
- Named pipes, sockets and devices are skipped and counted, so a pipe called `main.tf` cannot hang a scan.
- `.git`, `node_modules`, `.terraform`, `vendor`, virtualenvs, build output, tool caches and every dot-directory except `.cursor` and `.vscode` are not entered.
- A JSON or YAML file over 50 MB is set aside as not infrastructure.
- A directory with `.tf`, `.tofu` or `.tf.json` files is one Terraform module.
  A Terraform plan JSON in the same directory replaces the module, because the plan holds the resolved values, and the scan records an info diagnostic saying so.
- Every `Chart.yaml` is one Helm chart that owns its `templates/` and `charts/` folders and its values files, so templates are never scanned as raw manifests.
- Any other JSON, YAML, `.template`, `.cfn`, Dockerfile-family or MCP config file is its own unit.
- When two units declare the same address, each one is prefixed with its path, such as `infra/net::aws_vpc.main`, in the same order on every run.

### Standard input

`-` reads standard input.
Input that starts with `{` or `[` is read as JSON and anything else as YAML.
`--stdin-name` names the file so the right parser is chosen:

<!-- runnable exit=1 -->

```bash
cat examples/aws-webapp/tfplan.json | threatcode scan - --stdin-name plan.json -o report.json
```

### Options

<!-- gen:scan -->
| Option | Values | What it does |
| --- | --- | --- |
| `--format`, `-f` | json \\| sarif \\| markdown \\| bitbucket \\| navigator \\| mermaid \\| diagram \\| text \\| matrix | Output format. Default: the config's output_format, else text on a terminal, else json. |
| `--output`, `-o` | PATH | Write the report to this file instead of stdout. |
| `--min-severity` | critical \\| high \\| medium \\| low \\| info | Hide findings below this severity. Display only: the gate is --fail-on. |
| `--fail-on` | critical \\| high \\| medium \\| low \\| info \\| none | Exit 1 when a finding or attack path at or above this severity remains. 'none' never fails on findings. Default: high. |
| `--strict` |  | Exit 2 when any coverage gap was reported (unanalysed module, fallback render, unknown value, unresolved intrinsic, skipped document). |
| `--config`, `-c` | PATH | Path to a .threatcode.yml. Only an explicit config can set fail_on, rules or the LLM. |
| `--rules`, `-r` | PATH | Additional rule file (repeatable). (repeatable) |
| `--ignore-file` | PATH | Suppressions file. Default: .threatcodeignore in the scan root. |
| `--no-ignore` |  | Do not read any suppressions file. |
| `--baseline` | PATH | Hide findings already in this baseline from the gate and the listings. |
| `--write-baseline` | PATH | Write every finding's fingerprint to this file. Exits 0 unless an input error occurred. |
| `--ingest` | PATH | A scanner result (Trivy, Grype, OSV-Scanner or SARIF) to join to the graph (repeatable). (repeatable) |
| `--llm`, `--no-llm` |  | Send a redacted graph to an LLM for extra findings. Off by default. |
| `--dry-run` |  | Build the LLM request without sending it. Implies --llm; nothing leaves the machine. |
| `--dry-run-output` | PATH | Where --dry-run writes the request. Default: stdout. |
| `--no-timestamp` |  | Leave the timestamp out of the report. SOURCE_DATE_EPOCH fixes it instead. |
| `--stdin-name` | TEXT | File name for standard input (main.tf, Dockerfile, plan.json) so its format is found. |
| `--max-nodes` | N | Graph node limit. |
| `--max-edges` | N | Graph edge limit. |
<!-- /gen:scan -->

### Output formats

<!-- gen:formats -->
| `-f` value | Extension | What it is |
| --- | --- | --- |
| `json` | .json | Machine-readable report with coverage |
| `sarif` | .sarif | SARIF 2.1.0 for GitHub code scanning |
| `markdown` | .md | Markdown for pull request comments |
| `bitbucket` | .json | Bitbucket Code Insights report |
| `navigator` | .json | MITRE ATT&CK Navigator layer |
| `mermaid` | .mmd | Mermaid flowchart by trust zone with attack paths |
| `diagram` | .svg | SVG diagram of the infrastructure |
| `text` | .txt | Human summary for a terminal |
| `matrix` | .json | Deprecated alias of navigator |
<!-- /gen:formats -->

`-o` writes the report to a file and prints `Report written to <absolute path>` on stderr, so standard output stays empty.
A directory, or a path that cannot be written, is `Error: cannot write <absolute path>: <reason>` and exit 2.
`matrix` is the old name of `navigator` and will be removed in a later release.

Reports are reproducible.
Findings are sorted by effective severity, then resource address, rule id and id.
Every path in a report is POSIX and relative to the scan root, the common parent directory of the named paths, so the same tree gives byte-identical output wherever it is checked out.
`SOURCE_DATE_EPOCH` fixes the timestamp and `--no-timestamp` leaves it out.

### The coverage block

Every report says what was not analysed.
The `coverage` block of the JSON report lists the files discovered, the units parsed, the files that are not infrastructure (a count and the first 20 paths), symlinks and special files skipped, input errors with the file, a code and the message, coverage gaps, failed rule evaluations, and how many findings were suppressed or baselined.

A gap is a warning that a parser or the graph recorded: an unanalysed module call, a Helm fallback render, values known only after apply, an unresolved CloudFormation intrinsic, a skipped document.
Gaps and errors always reach stderr, even with `-q`.
`--strict` turns any gap into exit 2.

## `threatcode diff`

```text
threatcode diff [OPTIONS] BASELINE CURRENT
```

Both files must be JSON reports written by `threatcode scan -f json`.
SARIF and other JSON get their own error message instead of reading as "no changes".
Findings are matched by id, counting duplicates, and a finding with the same id and a different severity or title is reported as changed.
Attack paths that appeared or were closed are compared by id and listed first.

<!-- gen:diff -->
| Option | Values | What it does |
| --- | --- | --- |
| `--format`, `-f` | json \\| markdown \\| text | Output format. Default: text on a terminal, else json. |
| `--output`, `-o` | PATH | Write the diff to this file instead of stdout. |
| `--fail-on-new` | critical \\| high \\| medium \\| low \\| info | Exit 1 when a threat at or above SEVERITY was added or got worse (critical, high, medium, low, info). |
<!-- /gen:diff -->

Compare the findings of two scans, and fail when the second has a new critical one:

<!-- runnable exit=1 -->

```bash
threatcode scan examples/aws-webapp -f json -o base.json --fail-on none --no-timestamp
threatcode scan examples/k8s-platform -f json -o current.json --fail-on none --no-timestamp
threatcode diff base.json current.json -f markdown -o diff.md --fail-on-new critical
```

## Exit codes

| Code | `scan` | `diff` |
|------|--------|--------|
| 0 | Nothing at or above `--fail-on` remains after suppressions and the baseline, or `--fail-on none`. | No new or worsened finding at or above `--fail-on-new`, or the flag was not given. |
| 1 | A finding or attack path at or above `--fail-on` remains. LLM findings never count. | A finding or attack path was added, or got worse, at or above `--fail-on-new`. |
| 2 | An input could not be analysed, nothing was found to scan, an option is wrong, or `--strict` met a coverage gap. | An input is not a ThreatCode JSON report, or another usage error. |

2 wins over 1 and 1 wins over 0.
`--write-baseline` exits 0 unless an input error occurred, and it does not write a baseline when the scan had input errors, because the baseline would hide the findings of the files that failed.

## Environment variables

| Variable | Effect |
|----------|--------|
| `THREATCODE_FAIL_ON`, `THREATCODE_MIN_SEVERITY`, `THREATCODE_FORMAT`, `THREATCODE_LLM` | Defaults below the flags and above a config file. |
| `THREATCODE_DEBUG=1` | Show tracebacks for unexpected errors (also `--debug`). |
| `THREATCODE_MAX_NODES`, `THREATCODE_MAX_EDGES`, `THREATCODE_MAX_FANOUT` | Graph size limits. |
| `THREATCODE_HELM` | `auto` (default), `off` (always the built-in renderer) or `required` (a missing or failing `helm` is an error). |
| `THREATCODE_STRICT_RULES=1` | Built-in rules re-raise instead of recording a rule error. Used by the test suite. |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` | Read only when the model is requested with `--llm`; see [configuration](configuration.md). |
| `SOURCE_DATE_EPOCH` | Fixed report timestamp for reproducible output. |
| `NO_COLOR` | Plain text output (also `--no-color`). |
| `CI` | Any non-empty value skips the home directory when looking for a config file. |

## Not in the command line yet

These exist in the Python modules but are not wired to `threatcode scan`, so the CLI neither accepts nor honors them:

- Suppressing an attack path by id in `.threatcodeignore`, and recording attack paths in `--write-baseline`.
  Findings are suppressed and baselined, attack paths are not, so a path at or above `--fail-on` still gates.
- A report of what the ignore file applied.
- `--include-graph`, `--source-root`, `--helm`, `--diagram-*` options, a `secrets:` config section, `--llm-gating` and `--require-llm`.
