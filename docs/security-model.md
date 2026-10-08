# Security model

ThreatCode reads files that other people wrote, often in CI, on a pull request from a contributor you have not met.
This page states who and what the tool trusts, which limits keep a hostile file cheap to scan, and what it does with the result.
[Security](security.md) describes the controls in more detail.

## Trust boundaries

| Input | Trusted? | What that means |
|-------|----------|-----------------|
| The files being scanned: Terraform, templates, manifests, charts, Dockerfiles, MCP configs, plans | **No** | Parsed by ThreatCode's own readers, never executed. Size, depth and work are bounded. |
| Scanner results given to `--ingest` | **No** | Read as data, size capped, secrets in them never copied. |
| A `.threatcode.yml` found in the scanned tree or the home directory | **No** | Only `min_severity` and `format` are read. |
| A `.threatcodeignore` and a baseline file inside the scanned tree | **No** | Honored, with a CI notice that a pull request can edit them. Keep them outside the tree and name them with `--ignore-file` and `--baseline`. |
| Container images and registries | Not read | ThreatCode does not pull images. It reads Trivy, Grype and OSV-Scanner JSON about them. |
| The command-line flags | Yes | They come from whoever runs the tool. |
| A file named with `--config` | Yes | Every key is honored: the gate, rule files, the model endpoint and redaction. |
| Extra rule files from `--rules` or the `rules` config key | Yes | They are data, not code, and are validated and size limited, but they decide what is reported. Review them like code. |
| The model's reply | **No** | Parsed as JSON, validated per item, never executed, advisory only. |

A scanned repository can therefore influence the report it gets, and nothing else.
It cannot turn off the gate, load its own rules, point the tool at its own model server, weaken redaction or raise a limit by adding a config file.

## What the tool does to the machine

- **Reads:** the files you name and the files the walker finds under them, and the files you pass to `--config`, `--rules`, `--ingest`, `--ignore-file`, `--baseline`, a `terraform.tfvars` beside a module and the local modules a Terraform file calls.
- **Writes:** only what you name: `-o`, `--write-baseline`, `--dry-run-output`.
  A directory or an unwritable path is an error that names the absolute path.
- **Starts processes:** only `helm template`, when `helm` is installed and a chart is scanned.
  It runs without a shell, with stdin closed, in its own process group, with a time limit and an output limit, and it is killed on timeout.
- **Connects:** only the optional model client, and only when asked.
  There is no telemetry and no update check.
- **Environment:** reads `THREATCODE_*`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` (or the variable `llm.api_key_env` names), `ANTHROPIC_BASE_URL`, `SOURCE_DATE_EPOCH`, `NO_COLOR`, `CI` and `HOME`.

## Symlinks and special files

The directory walker reads only regular files.
It skips symlinks inside the tree, counts them in the report, and never lets one pull in a file outside the scan root or loop.
A symlink you name on the command line is followed, because you named it.
Named pipes, sockets and devices are skipped and counted, so a FIFO called `main.tf` cannot hang a scan.
`.git`, `node_modules`, `.terraform`, `vendor`, virtualenvs, build output, tool caches and every dot-directory except `.cursor` and `.vscode` are not entered.

Every later read of a discovered file is guarded again.
The secret scanner opens a file with `O_NOFOLLOW` and checks it with `fstat`, so a link created after discovery, or a device, is never read.
The Terraform reader never reads a symlinked module file or directory, and a local module path may leave the scanned directory (an environment directory calling `../../modules/vpc`) but only `.tf`, `.tofu` and `.tf.json` files of that directory are read.
Extra rule paths that are symlinks are refused.

## Resource limits

Each limit below is read from the code when this page is generated, so the table is the build's, not a promise.
A value past a limit becomes `Unknown` or a coverage gap with a diagnostic that names the limit.
It is never a silent truncation, and a scan whose result a limit changed says so.

<!-- gen:limits -->
| Area | What is bounded | Limit |
| --- | --- | --- |
| Input | size of a JSON, YAML or HCL file a parser reads | 50 MiB |
| Input | size of standard input | 50 MiB |
| Input | size of one scanner result passed to `--ingest` | 256 MiB |
| Graph | nodes (`--max-nodes`) | 10,000 |
| Graph | edges (`--max-edges`) | 50,000 |
| Graph | reachability edges one rule may add | 500 |
| Graph | resources one IAM wildcard fans out to, per role | 25 |
| Attack paths | edges on one path | 8 |
| Attack paths | paths kept per target | 5 |
| Attack paths | paths kept in all | 100 |
| Attack paths | routes the search may collect | 5,000 |
| Attack paths | steps the search may take | 250,000 |
| Terraform source | characters in a string that evaluation builds | 1,048,576 |
| Terraform source | elements in a list or object that evaluation builds | 10,000 |
| Terraform source | units of evaluation work in one parse | 4,000,000 |
| Terraform source | levels of local module calls followed | 8 |
| Terraform source | local module calls followed | 200 |
| Terraform source | blocks one resource may expand `dynamic` blocks into | 256 |
| Terraform source | levels locals, inputs and outputs may refer to each other | 24 |
| Terraform plan | references resolved in one plan | 500,000 |
| Terraform plan | levels of nested modules | 50 |
| CloudFormation | units of intrinsic-function work in one template | 3,000,000 |
| Kubernetes | documents in one input | 20,000 |
| Kubernetes | levels of `List` nesting | 5 |
| Helm renderer | size of one template file | 2 MiB |
| Helm renderer | characters in one template line | 65,536 |
| Helm renderer | characters in one template action | 8,192 |
| Helm renderer | evaluation steps per chart | 2,000,000 |
| Helm renderer | rendered output | 16 MiB |
| Helm renderer | charts and subcharts in one render | 40 |
| `helm template` | output read from the `helm` binary | 20 MiB |
| Policies | characters in one policy document | 1,000,000 |
| Policies | statements in one policy document | 5,000 |
| Secret scan | size of a file the secret detectors read | 5 MiB |
| Secret scan | findings listed per file | 100 |
| Secret scan | findings listed per rule | 25 |
| Rule files | size of one rule file | 1 MiB |
| Rule files | rules in one file | 100 |
| Rule files | rules in all files | 1,000 |
| Model review | distinct values the redactor tracks before it fails closed | 10,000 |
| Model review | size of the model's reply | 512 KiB |
| Model review | findings accepted from one reply | 100 |
| Mermaid | nodes drawn before the diagram collapses | 150 |
<!-- /gen:limits -->

The test suite scans hostile inputs in a child process under a time and memory budget: unterminated Helm actions, symlink escapes and cycles, FIFOs, single lines of megabytes, JSON and YAML nested 100,000 levels deep, a YAML alias bomb, locals that double at every level, and `dynamic` blocks nested inside each other (`tests/hostile/`).
Property tests with a fixed seed cover the JSONC stripper and the redactor.

## Output safety

A report contains text from the scanned files: resource names, tags, descriptions.
Each format escapes it for where it will be shown.

- **Markdown** (pull request comments) escapes characters that are syntax, breaks `@mentions`, `#123` references and bare URLs, collapses newlines, and fences resource addresses with a backtick run longer than any inside them.
- **Mermaid** generates node ids, and quotes, entity-encodes and caps every label, so a hostile name cannot add a statement to the diagram.
- **SVG** sanitizes the ids it builds from addresses and escapes text.
- **SARIF** puts a resource address in a logical location and never in a URI, and percent-encodes file paths.

Secret values never reach any output.
A secret finding carries a preview of the form `[REDACTED <rule id> len=<n>]` and a fingerprint that is built from the rule, the file, the resource and the attribute, never from the value.
MCP server configs store only the names of environment variables and headers, and secret-bearing launch arguments are replaced in place.
Ingested scanner results are read without their matched text.

## What the model review sends

Only with `--llm`, and never the files themselves.
It sends a pseudonymized graph: opaque resource handles, zones, exposure, the ids of the rules that already fired, an allowlist of security properties and the edges between resources.
Names, accounts, addresses, tags, file names and line numbers do not leave the machine, and `--dry-run` prints the exact request.
[Security](security.md) has the redaction rules and a real sample.

## Known limits of this model

- ThreatCode analyses what a file says, not what is deployed.
  A plan is the closest thing to what Terraform will do, and a directory of source is an approximation of it.
- A custom rule file is trusted code in the sense that it decides what is reported.
  A hostile rule file cannot run anything, but it can hide a finding.
- The ignore file and the baseline are accepted by design in the repository; the mitigation is where you keep them.
- An attack path can be suppressed by id in an ignore file and is recorded by `--write-baseline`, so a pull request that edits either file can hide a path as well as a finding.
  The mitigation is the same: keep both files outside the tree the pull request controls.
